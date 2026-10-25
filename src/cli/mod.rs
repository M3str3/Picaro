//! `picaro` entry point.
//!
//! Four subcommands:
//! - `pack`: payload + flags → generated YAML → encrypt payloads → render Rust
//!   stub → compile → out.exe. No hand-written plan required.
//! - `build`: YAML → encrypt payloads → render Rust stub → compile → out.exe.
//!   `build interactive <payload>` generates that YAML from a few questions.
//! - `audit`: static analysis of a PE (measurement infrastructure).
//! - `techniques`: inspect the technique registry.
//!
//! Running with no subcommand prints the banner plus the generated help.

use crate::paths::{file_url_to_path, package_paths};
use crate::{audit, engine, error, features, pack, plan, techniques, ui, wizard};

mod build;
mod helpers;

use build::*;
use helpers::*;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::Instant;

use clap::{CommandFactory, Parser, Subcommand};

use crate::engine::entropy::{BuildEntropy, Domain};
use crate::engine::{
    api_resolution, build_lock, compiler, crypto, obfuscation, pe, polymorphism, steps, stub,
    syscalls,
};
use crate::error::Result;
use crate::plan::schema::{
    Arch, CryptoAlgorithm, KeySource, OutputKind, PayloadFormat, PayloadPlan, PayloadReproduction,
    Predecessor, SecretsPolicy, Subsystem, TrimPaths,
};
use crate::plan::steps::ResolvedStep;
use crate::techniques::{network_stager, Category, RuntimeStep, TechniqueKind};
use crate::ui::{format_elapsed, glyph, human_size, Palette};

/// Extra help printed under the generated usage block.
const AFTER_HELP: &str = "\
Examples:
  picaro pack mimikatz.exe
  picaro pack mimikatz.exe --patch-amsi --erase-header --hollow
  picaro pack beacon.bin --syscalls indirect --resolver tartarus-gate
  picaro pack app.exe --print-plan > app.yaml
  picaro build examples/plans/mimikatz.yaml
  picaro build examples/plans/mimikatz.yaml --dry-run
  picaro build interactive mimikatz.exe
  picaro audit dist/test_amsi_patch.exe --focus imports,strings
  picaro audit dist/out.exe --json > baseline.json
  picaro audit dist/out.exe --baseline baseline.json
  picaro techniques list
  picaro techniques show process_hollowing

Colors are disabled automatically when the output is not a terminal; set
NO_COLOR=1 (or pass --no-color) to disable them explicitly. Pass -q (or
--quiet) to skip the banner, and -v (or --verbose) to print per-step build
detail (paths, sizes, timings). `techniques show` renders the README as styled
Markdown and pages it full-screen when it is taller than the terminal; pass
--raw for the verbatim Markdown or --no-pager to always print it inline.

audit --baseline exits 3 when it finds a regression, so it can gate a CI
job; every other failure exits 1.";

/// `picaro` CLI.
#[derive(Debug, Parser)]
#[command(name = "picaro", bin_name = "picaro", version, about = ui::TAGLINE, after_help = AFTER_HELP)]
struct Cli {
    /// Disable colored output (also honors the `NO_COLOR` environment variable).
    #[arg(long, global = true)]
    no_color: bool,

    /// Do not print the banner.
    #[arg(short, long, global = true)]
    quiet: bool,

    /// Print per-step build detail (paths, sizes and timings).
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

/// Available subcommands.
///
/// The variants carry every flag, and `Pack` has the most. The enum is parsed
/// once at startup, so its size costs nothing; boxing the fields would only hurt
/// readability.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Subcommand)]
enum Commands {
    /// Build a packed PE: from a YAML plan file, or interactively.
    #[command(subcommand_precedence_over_arg = true)]
    Build {
        /// Generate the plan interactively instead of reading a file.
        #[command(subcommand)]
        action: Option<BuildAction>,

        /// Path to the YAML plan file.
        #[arg(value_name = "PLAN")]
        plan: Option<PathBuf>,

        /// Positional arguments referenced by the YAML as `$arg.N$`.
        #[arg(value_name = "ARG")]
        args: Vec<String>,

        /// Resolve and validate the build without compiling or writing anything.
        #[arg(long)]
        dry_run: bool,

        /// Build the stub as a debug artifact: the techniques log what they do
        /// and the binary keeps symbols, debug info and source paths. Overrides
        /// `build.stub.debug`. Laboratory use only.
        #[arg(long)]
        debug: bool,

        /// Name the scratch directory `build/<NAME>` instead of a unique
        /// `build/run-<pid>-<nanos>`, so a run lands on a stable path. The
        /// generated `main.rs`, `out.exe` and `out.pdb` live there, together,
        /// which is exactly what a debugger needs (see `--debug`).
        #[arg(long, value_name = "NAME", visible_alias = "build-debug-name")]
        build_name: Option<String>,

        /// Master entropy seed (decimal or 0x hex). Overrides the value in a
        /// manifest's `reproduce` block.
        #[arg(long, value_name = "U64")]
        seed: Option<String>,

        /// Raw 32-byte (or 64-hex-char) payload key. Supplies the key for a
        /// `secrets: audit` manifest that no longer stores it.
        #[arg(long, value_name = "PATH")]
        key_file: Option<PathBuf>,

        /// Fail if `rustc --version` differs from the manifest's recorded
        /// toolchain (exit 5).
        #[arg(long)]
        strict: bool,

        /// Compare the new artifact's unsigned SHA-256 with the manifest's
        /// recorded `predecessor` (exit 4 on mismatch).
        #[arg(long)]
        verify: bool,

        /// Artifact path; its directory is the package root (the plan folder is
        /// created inside it).
        #[arg(long, value_name = "PATH")]
        out: Option<PathBuf>,

        /// Relocate a payload whose source moved: `--payload name=path`.
        #[arg(long, value_name = "NAME=PATH")]
        payload: Vec<String>,

        /// Write a shareable copy of the manifest with keys stripped
        /// (`secrets: audit`).
        #[arg(long, value_name = "PATH")]
        redact: Option<PathBuf>,
    },

    /// Pack a payload with safe defaults; no hand-written plan needed.
    ///
    /// The flags are compiled into a schema-6 plan, saved in
    /// `packed/<payload>/plan.yaml` and built through the same path as
    /// `picaro build`. Change the defaults in `picaro.config.yaml` (or pass
    /// `--config`); CLI flags always win.
    Pack {
        /// Payload to pack: a PE, DLL, .NET assembly, raw shellcode or .ps1.
        #[arg(value_name = "PAYLOAD")]
        payload: PathBuf,

        /// Execution technique, or auto (the default). Every registered
        /// execution technique is accepted; a non-Stable one also needs
        /// --allow-experimental.
        #[arg(
            long,
            value_name = "TECHNIQUE",
            conflicts_with_all = ["reflective_loading", "hollow"]
        )]
        exec: Option<String>,

        /// Add any technique step, in order. Repeatable; use --step for params.
        #[arg(short = 't', long = "technique", value_name = "TECHNIQUE")]
        technique: Vec<String>,

        /// Add one RuntimeStep YAML document (the escape hatch for params).
        #[arg(long, value_name = "FILE")]
        step: Vec<PathBuf>,

        /// Syscall mode: none or indirect (default: indirect on x64).
        #[arg(long, value_name = "none|indirect")]
        syscalls: Option<String>,

        /// Indirect syscall resolver: hells_gate, tartarus_gate, api_hash or
        /// halos_gate (default: hells_gate).
        #[arg(long, value_name = "RESOLVER")]
        resolver: Option<String>,

        /// Fabricate ntdll-shaped frames around every indirect syscall.
        #[arg(long, overrides_with = "no_stack_spoofing")]
        stack_spoofing: bool,

        /// Do not fabricate syscall frames (overrides the config).
        #[arg(long, overrides_with = "stack_spoofing")]
        no_stack_spoofing: bool,

        /// String-obfuscation strategy: xor or stack (default: xor).
        #[arg(long, value_name = "xor|stack")]
        strings: Option<String>,

        /// Output root (default: packed); each payload gets its own folder.
        #[arg(long, value_name = "DIR")]
        dir: Option<PathBuf>,

        /// Artifact name, or an existing directory; the plan folder is created
        /// inside the selected directory.
        #[arg(short = 'o', long, value_name = "PATH")]
        out: Option<PathBuf>,

        /// Where to write the generated plan (default: inside the package).
        #[arg(long, value_name = "PATH")]
        plan_out: Option<PathBuf>,

        /// Print the generated YAML and exit without building.
        #[arg(long)]
        print_plan: bool,

        /// Do not write the generated plan next to the artifact.
        #[arg(long)]
        no_save_plan: bool,

        /// Target architecture: x64 or x86 (default: x64).
        #[arg(long, value_name = "x64|x86")]
        arch: Option<String>,

        /// Output kind: exe, dll, shellcode or psmodule (default: exe).
        #[arg(long, value_name = "KIND")]
        kind: Option<String>,

        /// DLL/shellcode output entry: auto, jni_on_load or export:<name>.
        #[arg(long, value_name = "ENTRY")]
        entry: Option<String>,

        /// Exported function to call in a DLL payload (e.g. Run). When
        /// omitted, the only callable export is selected; several require this.
        #[arg(long, value_name = "NAME")]
        export: Option<String>,

        /// Sign the artifact: none, lab, store or file (default: none).
        #[arg(long, value_name = "MODE")]
        sign: Option<String>,

        /// Certificate subject for --sign lab/store.
        #[arg(long, value_name = "SUBJECT")]
        sign_subject: Option<String>,

        /// Certificate thumbprint for --sign store.
        #[arg(long, value_name = "THUMBPRINT")]
        sign_thumbprint: Option<String>,

        /// .pfx/.p12 path for --sign file.
        #[arg(long, value_name = "PFX")]
        sign_file: Option<PathBuf>,

        /// Environment variable holding the .pfx password.
        #[arg(long, value_name = "ENV")]
        sign_password_env: Option<String>,

        /// RFC 3161 timestamp server used while signing.
        #[arg(long, value_name = "URL")]
        timestamp_url: Option<String>,

        /// Embed an icon: random or a .ico path.
        #[arg(long, value_name = "random|PATH")]
        icon: Option<String>,

        /// Strip the symbol/debug tables (the default).
        #[arg(long, overrides_with = "no_strip")]
        strip: bool,

        /// Keep the symbol/debug tables (overrides `strip: true`).
        #[arg(long, overrides_with = "strip")]
        no_strip: bool,

        /// Build a GUI-subsystem artifact (no console window).
        #[arg(long, overrides_with = "console")]
        gui: bool,

        /// Build a console-subsystem artifact (the default).
        #[arg(long, overrides_with = "gui")]
        console: bool,

        /// Target process for the execution technique that takes one.
        #[arg(long, value_name = "PATH")]
        target: Option<String>,

        /// Delay before the execution step, in milliseconds.
        #[arg(long = "sleep", value_name = "MS")]
        sleep_ms: Option<u64>,

        /// Shortcut for --exec reflective_loading (non-Stable: needs
        /// --allow-experimental).
        #[arg(long, conflicts_with_all = ["exec", "hollow"])]
        reflective_loading: bool,

        /// Shortcut for --exec process_hollowing (target defaults to svchost).
        #[arg(long, conflicts_with_all = ["exec", "reflective_loading"])]
        hollow: bool,

        /// Add the patch_amsi preparation.
        #[arg(long)]
        patch_amsi: bool,

        /// Add the patch_etw preparation.
        #[arg(long)]
        patch_etw: bool,

        /// Add the erase_pe_header preparation.
        #[arg(long)]
        erase_header: bool,

        /// Add the unhook_ntdll preparation.
        #[arg(long)]
        unhook: bool,

        /// Add the hide_module preparation.
        #[arg(long)]
        hide_module: bool,

        /// Accept Experimental (and other non-Stable) techniques explicitly.
        #[arg(long)]
        allow_experimental: bool,

        /// Defaults file (default: picaro.config.yaml in the current directory).
        #[arg(long, value_name = "PATH")]
        config: Option<PathBuf>,

        /// Resolve and validate without compiling or writing the artifact.
        #[arg(long)]
        dry_run: bool,

        /// Compile a debuggable stub (technique traces, no hardening).
        /// Laboratory use only.
        #[arg(long)]
        debug: bool,

        /// Master entropy seed (decimal or 0x hex).
        #[arg(long, value_name = "U64")]
        seed: Option<String>,
    },

    /// Run a static audit of a PE and print a readable report.
    Audit {
        /// Path to the PE to analyze.
        #[arg(value_name = "BINARY")]
        binary: PathBuf,

        /// Comma-separated sections to report (e.g. "imports,strings").
        #[arg(long)]
        focus: Option<String>,

        /// Emit the machine-readable report (JSON) instead of the pretty one.
        #[arg(long)]
        json: bool,

        /// Compare against a previous `--json` report and fail on regressions.
        #[arg(long, value_name = "FILE")]
        baseline: Option<PathBuf>,

        /// Entropy increase (bits/byte) tolerated before it counts as a
        /// regression (only used with --baseline).
        #[arg(long, value_name = "F", default_value_t = audit::DEFAULT_ENTROPY_TOLERANCE)]
        entropy_tolerance: f64,
    },

    /// Inspect the technique registry.
    Techniques {
        #[command(subcommand)]
        command: TechniquesCommand,
    },
}

/// Ways to build that do not start from a hand-written YAML file.
#[derive(Debug, Subcommand)]
enum BuildAction {
    /// Answer a few questions, write the YAML, then build it.
    Interactive {
        /// Path to the payload PE to pack.
        #[arg(value_name = "PAYLOAD")]
        payload: PathBuf,

        /// Where to write the generated YAML (default: `dist/<name>.yaml`).
        #[arg(long, value_name = "PATH")]
        plan_out: Option<PathBuf>,
    },
}

/// The command line a build reports in its heading.
///
/// `build` prints `build <plan.yaml>`; `pack` prints `pack <payload>`, so a
/// pasted report shows what the operator actually ran.
#[derive(Debug, Clone)]
struct BuildHeading {
    command: String,
    target: String,
}

/// One `label  value` line printed under the heading.
#[derive(Debug, Clone)]
struct BuildField {
    label: String,
    value: String,
}

/// Reproduction and output overrides for one build.
///
/// Precedence: CLI > `reproduce` block > plan defaults > random.
#[derive(Debug, Default)]
struct BuildOptions {
    seed: Option<u64>,
    key_file: Option<PathBuf>,
    strict: bool,
    verify: bool,
    out: Option<PathBuf>,
    payloads: BTreeMap<String, PathBuf>,
    redact: Option<PathBuf>,
    verbose: bool,
    debug: bool,
    build_name: Option<String>,
    heading: Option<BuildHeading>,
    prelude: Vec<BuildField>,
    /// Warnings produced before the build starts (for example by `pack`), shown
    /// together with the ones collected during it at the very end.
    warnings: Vec<String>,
}

/// Parses the `--seed` value (decimal or `0x` hex).
fn parse_seed_arg(value: Option<String>) -> Result<Option<u64>> {
    match value {
        Some(value) => Ok(Some(engine::entropy::parse_seed(&value).ok_or_else(
            || {
                error::PackerError::Usage(format!(
                    "--seed expects a u64 (decimal or 0x hex), got {value:?}"
                ))
            },
        )?)),
        None => Ok(None),
    }
}

/// Parses repeated `--payload name=path` flags.
fn parse_payload_overrides(values: &[String]) -> Result<BTreeMap<String, PathBuf>> {
    let mut overrides = BTreeMap::new();
    for value in values {
        let Some((name, path)) = value.split_once('=') else {
            return Err(error::PackerError::Usage(format!(
                "--payload expects NAME=PATH (got {value:?})"
            )));
        };
        let name = name.trim();
        let path = path.trim();
        if name.is_empty() || path.is_empty() {
            return Err(error::PackerError::Usage(format!(
                "--payload expects NAME=PATH (got {value:?})"
            )));
        }
        overrides.insert(name.to_string(), PathBuf::from(path));
    }
    Ok(overrides)
}

/// Subcommands of `picaro techniques`.
#[derive(Debug, Subcommand)]
enum TechniquesCommand {
    /// List registered techniques.
    List,

    /// Show a technique's full README.
    Show {
        /// Technique YAML key (e.g. `process_hollowing`).
        #[arg(value_name = "NAME")]
        name: String,

        /// Print the README verbatim instead of rendering it.
        #[arg(long)]
        raw: bool,

        /// Never page the output, even when it is longer than the terminal.
        #[arg(long)]
        no_pager: bool,
    },

    /// Validate the technique registry (CI helper; never fails).
    Validate,
}

pub fn main_entry() {
    // `run` returns `Result`; here we turn it into an exit code and a clean
    // error message, with no `unwrap`/`panic` traces. A cancelled interactive
    // prompt is not a failure (exit 0); a baseline regression is a distinct,
    // non-zero code (3) so CI can tell it apart from a broken run (1).
    if let Err(err) = run() {
        let ui = Palette::auto();
        match err {
            error::PackerError::Cancelled | error::PackerError::Back => {
                anstream::eprintln!("  {}", ui.dim("cancelled"));
                std::process::exit(0);
            }
            error::PackerError::AuditRegression { count } => {
                anstream::eprintln!(
                    "{} {}",
                    ui.bang(),
                    ui.error(format!("baseline regression: {count} change(s)"))
                );
                std::process::exit(3);
            }
            error::PackerError::VerifyMismatch { .. } => {
                anstream::eprintln!("{} {}", ui.cross(), ui.error(err.to_string()));
                std::process::exit(4);
            }
            error::PackerError::ToolchainMismatch { .. } => {
                anstream::eprintln!("{} {}", ui.cross(), ui.error(err.to_string()));
                std::process::exit(5);
            }
            _ => {
                anstream::eprintln!("{} {}", ui.cross(), ui.error(format!("error: {err}")));
                std::process::exit(1);
            }
        }
    }
}

/// Main logic, split from `main` so it can return `Result`.
fn run() -> Result<()> {
    let cli = Cli::parse();
    let ui = if cli.no_color {
        Palette::plain()
    } else {
        Palette::auto()
    };

    // `--print-plan` writes to stdout so it can be redirected; the banner would
    // corrupt the YAML.
    let print_plan_only = matches!(
        cli.command.as_ref(),
        Some(Commands::Pack {
            print_plan: true,
            ..
        })
    );
    if !cli.quiet && !print_plan_only {
        print_banner(&ui);
    }

    let Some(command) = cli.command else {
        Cli::command().print_help()?;
        anstream::println!();
        return Ok(());
    };

    match command {
        Commands::Build {
            action,
            plan,
            args,
            dry_run: is_dry_run,
            debug: debug_flag,
            build_name,
            seed,
            key_file,
            strict,
            verify,
            out,
            payload,
            redact,
        } => {
            let seed = parse_seed_arg(seed)?;
            let options = BuildOptions {
                seed,
                key_file,
                strict,
                verify,
                out,
                payloads: parse_payload_overrides(&payload)?,
                redact,
                verbose: cli.verbose,
                debug: debug_flag,
                build_name,
                heading: None,
                prelude: Vec::new(),
                warnings: Vec::new(),
            };
            match action {
                Some(BuildAction::Interactive { payload, plan_out }) => {
                    if plan.is_some() {
                        return Err(error::PackerError::Validation(
                            "`build interactive` takes a payload, not a plan file".to_string(),
                        ));
                    }
                    // The wizard writes the YAML and hands back its path; loading it
                    // through the normal path proves the file is what gets built.
                    if let Some(path) = wizard::run(&payload, plan_out.as_deref(), &ui)? {
                        let build_args = BTreeMap::new();
                        let plan = plan::load_plan(&path, &build_args)?;
                        if is_dry_run {
                            let entropy = BuildEntropy::from_plan(&plan, options.seed);
                            let heading = BuildHeading {
                                command: "build".to_string(),
                                target: path.display().to_string(),
                            };
                            dry_run(&plan, &path, &ui, &entropy, &heading, None, &[])?;
                        } else {
                            build(&plan, &build_args, &path, &ui, &options)?;
                        }
                    }
                }
                None => {
                    let Some(plan) = plan else {
                        return Err(error::PackerError::Validation(
                            "missing PLAN: use `picaro build <plan.yaml>` or \
                         `picaro build interactive <payload>`"
                                .to_string(),
                        ));
                    };
                    let plan_path = plan.clone();
                    let build_args = plan::build_args::parse(&args);
                    let plan = plan::load_plan(&plan, &build_args)?;
                    if is_dry_run {
                        let entropy = BuildEntropy::from_plan(&plan, options.seed);
                        let heading = BuildHeading {
                            command: "build".to_string(),
                            target: plan_path.display().to_string(),
                        };
                        dry_run(&plan, &plan_path, &ui, &entropy, &heading, None, &[])?;
                    } else {
                        build(&plan, &build_args, &plan_path, &ui, &options)?;
                    }
                }
            }
        }
        Commands::Pack {
            payload,
            exec,
            technique,
            step,
            syscalls,
            resolver,
            stack_spoofing,
            no_stack_spoofing,
            strings,
            dir,
            out,
            plan_out,
            print_plan,
            no_save_plan,
            arch,
            kind,
            entry,
            export,
            sign,
            sign_subject,
            sign_thumbprint,
            sign_file,
            sign_password_env,
            timestamp_url,
            icon,
            strip,
            no_strip,
            gui,
            console,
            target,
            sleep_ms,
            reflective_loading,
            hollow,
            patch_amsi,
            patch_etw,
            erase_header,
            unhook,
            hide_module,
            allow_experimental,
            config,
            dry_run: is_dry_run,
            debug: debug_flag,
            seed,
        } => {
            let seed = parse_seed_arg(seed)?;
            let args = pack::PackArgs {
                payload: payload.clone(),
                exec,
                techniques: technique,
                steps: step,
                syscalls,
                resolver,
                stack_spoofing: if no_stack_spoofing {
                    Some(false)
                } else if stack_spoofing {
                    Some(true)
                } else {
                    None
                },
                strings,
                out,
                dir,
                plan_out,
                no_save_plan,
                arch,
                kind,
                entry,
                export,
                sign,
                sign_subject,
                sign_thumbprint,
                sign_file,
                sign_password_env,
                timestamp_url,
                icon,
                strip: if no_strip {
                    Some(false)
                } else if strip {
                    Some(true)
                } else {
                    None
                },
                gui: if console {
                    Some(false)
                } else if gui {
                    Some(true)
                } else {
                    None
                },
                target,
                sleep_ms,
                debug: debug_flag,
                reflective_loading,
                hollow,
                patch_amsi,
                patch_etw,
                erase_header,
                unhook,
                hide_module,
                allow_experimental,
            };
            let defaults = pack::load_config(config.as_deref())?;
            let outcome = pack::compose(&args, &defaults)?;

            if outcome.save_plan {
                pack::write_plan(&outcome)?;
            }
            if print_plan {
                anstream::print!("{}", outcome.plan_yaml);
                if !outcome.plan_yaml.ends_with('\n') {
                    anstream::println!();
                }
                // The YAML stays clean on stdout; the advisories are still shown.
                for warning in &outcome.warnings {
                    for line in ui.warn_lines(warning, ui::term_width()) {
                        anstream::eprintln!("{line}");
                    }
                }
                return Ok(());
            }

            let heading = BuildHeading {
                command: "pack".to_string(),
                target: payload.display().to_string(),
            };
            if is_dry_run {
                let entropy = BuildEntropy::from_plan(&outcome.plan, seed);
                let written_plan = outcome.save_plan.then_some(outcome.plan_path.as_path());
                dry_run(
                    &outcome.plan,
                    &outcome.plan_path,
                    &ui,
                    &entropy,
                    &heading,
                    written_plan,
                    &outcome.warnings,
                )?;
                return Ok(());
            }

            let mut prelude = vec![BuildField {
                label: "payload".to_string(),
                value: format!(
                    "{} → {}",
                    outcome.format.label(),
                    outcome.executions.join(", ")
                ),
            }];
            if outcome.save_plan {
                prelude.push(BuildField {
                    label: "plan".to_string(),
                    value: outcome.plan_path.display().to_string(),
                });
            }
            prelude.push(BuildField {
                label: "artifact".to_string(),
                value: outcome.artifact_path.display().to_string(),
            });

            let options = BuildOptions {
                seed,
                key_file: None,
                strict: false,
                verify: false,
                out: None,
                payloads: BTreeMap::new(),
                redact: None,
                verbose: cli.verbose,
                debug: debug_flag,
                build_name: None,
                heading: Some(heading),
                prelude,
                warnings: outcome.warnings.clone(),
            };
            let build_args = BTreeMap::new();
            build(
                &outcome.plan,
                &build_args,
                &outcome.plan_path,
                &ui,
                &options,
            )?;
        }
        Commands::Audit {
            binary,
            focus,
            json,
            baseline,
            entropy_tolerance,
        } => {
            let options = audit::AuditOptions {
                focus,
                json,
                baseline,
                entropy_tolerance,
            };
            let outcome = audit::run(&binary, &options, &ui)?;
            anstream::print!("{}", outcome.output);
            if outcome.regressions > 0 {
                return Err(error::PackerError::AuditRegression {
                    count: outcome.regressions,
                });
            }
        }
        Commands::Techniques { command } => match command {
            TechniquesCommand::List => {
                anstream::println!("{}", ui.command_line("techniques", "list"));
                anstream::println!();
                anstream::print!("{}", techniques::list(&ui));
            }
            TechniquesCommand::Show {
                name,
                raw,
                no_pager,
            } => {
                anstream::println!("{}", ui.command_line("techniques", &name));
                anstream::println!();
                let content = if raw {
                    techniques::readme(&name)?.to_string()
                } else {
                    techniques::show(&name, &ui)?
                };
                if !no_pager && ui::pager::page(&content, &ui) {
                    // The pager displayed it full-screen and restored the
                    // terminal already.
                } else {
                    anstream::print!("{content}");
                }
            }
            TechniquesCommand::Validate => validate_techniques(&ui),
        },
    }

    Ok(())
}

/// Prints the banner followed by the tagline and version.
///
/// Shown before every subcommand, unless `--quiet` is passed.
fn print_banner(ui: &Palette) {
    anstream::println!("{}", ui.banner());
    anstream::println!(
        "  {}",
        ui.dim(format!(
            "{}  {}  v{}",
            ui::TAGLINE,
            glyph::DOT,
            env!("CARGO_PKG_VERSION")
        ))
    );
    anstream::println!();
}

/// Reports the outcome of the technique-registry validation.
fn validate_techniques(ui: &Palette) {
    let problems = techniques::validate();
    if problems.is_empty() {
        anstream::println!(
            "{} {}",
            ui.check(),
            ui.ok(format!(
                "all {} techniques and {} loader features OK",
                techniques::all().len(),
                features::all().len(),
            ))
        );
        return;
    }

    anstream::eprintln!(
        "{} {}",
        ui.cross(),
        ui.error(format!("{} problem(s) found", problems.len()))
    );
    for problem in &problems {
        anstream::eprintln!("  {} {}", ui.bang(), ui.warn(problem));
    }
}

/// Runs the full packing flow, logging each step as it succeeds.
///
/// `verbose` adds a resolved-plan block, per-step detail lines and
/// timings; the compact form stays on one line per step. `debug_override`
/// forces the debug build on (`--debug`), on top of `build.stub.debug`.
/// How every `network_stager` step delivers its payload: strictly staged (the
/// payload is left out of the artifact) or staged with the embedded copy as a
/// fallback (`fallback: embedded`).
fn stager_sources(steps: &[ResolvedStep]) -> BTreeMap<String, steps::PayloadSource> {
    steps
        .iter()
        .filter_map(|step| match &step.technique {
            TechniqueKind::NetworkStager { params } => Some((
                params.payload.clone(),
                match params.fallback {
                    network_stager::StagerFallback::None => steps::PayloadSource::Staged,
                    network_stager::StagerFallback::Embedded => {
                        steps::PayloadSource::StagedWithFallback
                    }
                },
            )),
            _ => None,
        })
        .collect()
}

#[cfg(test)]
mod tests;
