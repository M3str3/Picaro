//! `picaro` entry point.
//!
//! Three subcommands:
//! - `build`: YAML → encrypt payloads → render Rust stub → compile → out.exe.
//!   `build interactive <payload>` generates that YAML from a few questions.
//! - `audit`: static analysis of a PE (measurement infrastructure).
//! - `techniques`: inspect the technique registry.
//!
//! Running with no subcommand prints the banner plus the generated help.

mod audit;
mod engine;
mod error;
mod features;
mod plan;
mod techniques;
mod ui;
mod wizard;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Instant;

use clap::{CommandFactory, Parser, Subcommand};

use engine::{
    api_resolution, build_lock, compiler, crypto, obfuscation, pe, steps, stub, syscalls,
};
use error::Result;
use plan::schema::{
    Arch, CryptoAlgorithm, KeySource, OutputKind, PayloadFormat, PayloadPlan, Subsystem, TrimPaths,
};
use plan::steps::ResolvedStep;
use techniques::{Category, RuntimeStep};
use ui::{format_elapsed, glyph, human_size, Palette};

/// Extra help printed under the generated usage block.
const AFTER_HELP: &str = "\
Examples:
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

fn main() {
    // `run` returns `Result`; here we turn it into an exit code and a clean
    // error message, with no `unwrap`/`panic` traces. A cancelled interactive
    // prompt is not a failure (exit 0); a baseline regression is a distinct,
    // non-zero code (3) so CI can tell it apart from a broken run (1).
    if let Err(err) = run() {
        let ui = Palette::auto();
        match err {
            error::PackerError::Cancelled => {
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

    if !cli.quiet {
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
        } => match action {
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
                        dry_run(&plan, &path, &ui)?;
                    } else {
                        build(&plan, &build_args, &path, &ui, cli.verbose, debug_flag)?;
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
                    dry_run(&plan, &plan_path, &ui)?;
                } else {
                    build(&plan, &build_args, &plan_path, &ui, cli.verbose, debug_flag)?;
                }
            }
        },
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
fn build(
    plan: &plan::Plan,
    build_args: &BTreeMap<String, String>,
    plan_path: &Path,
    ui: &Palette,
    verbose: bool,
    debug_override: bool,
) -> Result<()> {
    let started = Instant::now();
    let debug = plan.build.stub.debug || debug_override;

    anstream::println!("{}", ui.command_line("build", plan_path.display()));
    anstream::println!();

    if debug {
        anstream::eprintln!(
            "  {} {}",
            ui.bang(),
            ui.warn(
                "debug build: technique traces are enabled and the artifact is built without \
                 hardening (symbols, debug info and source paths are kept). Lab use only."
            )
        );
    }

    if verbose {
        print_plan(plan, plan_path, ui);
    }

    // 1. Resolve the flat runtime into concrete steps (payloads pinned down).
    let steps = plan::steps::resolve(plan)?;

    // 2. String-obfuscation, syscall and API-resolution configurations.
    if plan.build.stub.strings.is_none() {
        anstream::eprintln!(
            "  {} {}",
            ui.bang(),
            ui.warn("build.stub.strings not specified, defaulting to xor+random")
        );
    }
    let strings = obfuscation::StringsConfig::from_yaml(plan.build.stub.strings.as_ref())?;
    let syscalls = syscalls::SyscallsConfig::from_yaml(plan.build.stub.syscalls.as_ref())?;
    let api_resolution =
        api_resolution::ApiResolutionConfig::from_yaml(plan.build.stub.api_resolution.as_ref())?;
    let union: Vec<RuntimeStep> = steps
        .iter()
        .map(|step| RuntimeStep::new(step.technique.clone()))
        .collect();
    if syscalls.mode == syscalls::SyscallsMode::Indirect && syscalls::required(&union).is_empty() {
        anstream::eprintln!(
            "  {} {}",
            ui.bang(),
            ui.warn(
                "build.stub.syscalls.mode is 'indirect' but no technique in the runtime \
                 uses NT syscalls yet (phase 6a: only process_hollowing does)"
            )
        );
    }
    // Plan-level advisories from semantic validation (e.g. a no-op bouncer).
    for warning in plan::validate::advisories(plan) {
        anstream::eprintln!("  {} {}", ui.bang(), ui.warn(format!("warning: {warning}")));
    }

    // 3. Encrypt every Execution step's payload and collect the renderer input.
    let build_dir = scratch_dir();
    prepare_build_dir(&build_dir)?;

    let mut step_payloads = Vec::new();
    let mut step_records = Vec::new();
    let mut total_plaintext: usize = 0;
    let mut nonces: Vec<(usize, [u8; 24], [u8; 32])> = Vec::new();

    for step in &steps {
        let mut record = engine::manifest::StepRecord {
            index: step.index,
            label: step.label.clone(),
            technique: step.technique.name().to_string(),
            payload: step.payload.as_ref().map(|payload| payload.name.clone()),
            payload_sha256: None,
            payload_size: None,
            nonce: None,
        };

        let cipher = match &step.payload {
            Some(payload) => {
                // Read the input payload and validate it (fail early, before
                // encrypting or compiling).
                let timer = Instant::now();
                let plaintext = load_source(&payload.plan.source)?;
                verify_payload_hash(&plaintext, payload.plan.sha256.as_deref())?;
                let summary =
                    inspect_payload(payload.plan.format, &plaintext, plan.build.output.arch)?;
                let read_time = timer.elapsed();

                // Derive the key and encrypt with XChaCha20-Poly1305.
                let timer = Instant::now();
                let key = match payload.crypto.key {
                    KeySource::Random => crypto::generate_key(),
                };
                let encrypted = crypto::encrypt_payload(&plaintext, &key)?;
                let encrypt_time = timer.elapsed();

                let path = format!("payload_{}.bin", step.index);
                std::fs::write(build_dir.join(&path), &encrypted.ciphertext)?;
                total_plaintext += plaintext.len();
                record.payload_sha256 = Some(engine::hash::sha256_hex(&plaintext));
                record.payload_size = Some(plaintext.len() as u64);
                record.nonce = Some(hex::encode(encrypted.nonce));
                nonces.push((step.index, encrypted.nonce, encrypted.key));

                let mut parts = vec![
                    ui.target(describe_source(&payload.plan.source)),
                    ui.dim(summary.label),
                    human_size(plaintext.len()),
                ];
                if let Some(export) = &payload.plan.export {
                    parts.push(ui.dim(format!("export {export}")));
                }
                parts.push(ui.brand(crypto_label(payload.crypto.algo)));
                anstream::println!(
                    "{}",
                    ui.done(
                        &format!("step {} {}", step.index, ui.brand(step.technique.name())),
                        dotted(ui, &parts)
                    )
                );
                if verbose {
                    if let Some(info) = &summary.pe {
                        anstream::println!(
                            "{}",
                            ui.detail("machine", ui.dim(format!("0x{:04x}", info.machine)))
                        );
                    }
                    anstream::println!(
                        "{}",
                        ui.detail("sha256", ui.dim(engine::hash::sha256_hex(&plaintext)))
                    );
                    anstream::println!(
                        "{}",
                        ui.detail(
                            "payload",
                            ui.dim(format!("read {}", format_elapsed(read_time)))
                        )
                    );
                    let tag = encrypted.ciphertext.len().saturating_sub(plaintext.len());
                    anstream::println!(
                        "{}",
                        ui.detail(
                            "encrypt",
                            ui.dim(format!(
                                "{} -> {} (+{tag} tag) {}",
                                human_size(plaintext.len()),
                                human_size(encrypted.ciphertext.len()),
                                format_elapsed(encrypt_time)
                            ))
                        )
                    );
                }

                Some(steps::PayloadCipher {
                    nonce: encrypted.nonce,
                    key: encrypted.key,
                    plaintext_len: encrypted.plaintext_len,
                    path,
                    format: payload.plan.format,
                    export: payload.plan.export.clone(),
                    args: payload.plan.args.clone().unwrap_or_default(),
                    args_override: payload.plan.args_mode == engine::args::ArgsMode::Override,
                    marker: stub::generate_stub_marker(),
                })
            }
            None => {
                anstream::println!(
                    "{}",
                    ui.done(
                        &format!("step {} {}", step.index, ui.brand(step.technique.name())),
                        ui.dim(step.technique.category().label())
                    )
                );
                None
            }
        };

        step_payloads.push(steps::StepPayload {
            index: step.index,
            label: step.label.clone(),
            technique: step.technique.clone(),
            control: step.control,
            payload: cipher,
        });
        step_records.push(record);
    }

    // 4. Load the stub template (builtin or custom) and render the step stub.
    let timer = Instant::now();
    let (template, template_display, is_custom) = load_stub_template(plan)?;
    let params = steps::StepsParams {
        steps: step_payloads,
        build_args: build_args.clone(),
        debug,
        windows_subsystem: plan.build.output.subsystem == Subsystem::Windows,
        kind: plan.build.output.kind,
        entry: plan.build.output.entry.clone(),
    };
    let stub_src = if is_custom {
        stub::validate_custom_stub_template(&template)?;
        let rendered =
            steps::render_custom(&template, &params, &strings, &syscalls, &api_resolution)?;
        for warning in &rendered.warnings {
            anstream::eprintln!("  {} {}", ui.bang(), ui.warn(format!("warning: {warning}")));
        }
        rendered.source
    } else {
        steps::render_builtin(&template, &params, &strings, &syscalls, &api_resolution)?
    };
    // A DLL has no subsystem: the host's applies, and `#![windows_subsystem]`
    // would be ignored (or, worse, silently taken as an instruction).
    let stub_src = if plan.build.output.kind == OutputKind::Exe {
        apply_subsystem(stub_src, plan.build.output.subsystem)
    } else {
        stub_src
    };
    let stub_path = build_dir.join("main.rs");
    std::fs::write(&stub_path, &stub_src)?;
    let stub_time = timer.elapsed();

    let mut stub_parts = vec![
        runtime_chain(ui, &steps),
        format!("{} {}", ui.dim("strings"), strings.strategy.label()),
        format!("{} {}", ui.dim("syscalls"), syscalls.mode.label()),
    ];
    if plan.build.output.kind == OutputKind::Dll {
        stub_parts.push(ui.brand(format!(
            "{} {}",
            plan.build.output.kind.label(),
            plan.build.output.entry.label()
        )));
    }
    if debug {
        stub_parts.push(ui.warn("debug"));
    }
    anstream::println!("{}", ui.done("stub", dotted(ui, &stub_parts)));
    if verbose {
        anstream::println!("{}", ui.detail("template", ui.dim(&template_display)));
        anstream::println!(
            "{}",
            ui.detail("resolver", ui.dim(syscalls.resolver.label()))
        );
        anstream::println!(
            "{}",
            ui.detail(
                "source",
                format!(
                    "{} {} {} lines",
                    stub_path.display(),
                    ui.faint(glyph::DOT),
                    stub_src.lines().count()
                )
            )
        );
        anstream::println!("{}", ui.detail("time", ui.dim(format_elapsed(stub_time))));
    }

    // 5. Locate the dependencies and compile the stub.
    let timer = Instant::now();
    let arch = plan.build.output.arch;
    let deps = compiler::locate_stub_deps(arch)?;
    let out = intermediate_path(&build_dir, &plan.build.output);
    let options = compiler::CompileOptions {
        strip: plan.build.output.strip,
        trim_paths: match plan.build.output.trim_paths {
            TrimPaths::None => compiler::PathTrim::None,
            TrimPaths::Relative => compiler::PathTrim::Relative,
            TrimPaths::All => compiler::PathTrim::All,
        },
        debug,
        arch,
        kind: plan.build.output.kind,
    };
    compiler::compile_stub(&stub_path, &out, &deps, options)?;
    // D-21: a proxy must never import the API it intercepts, or the signature
    // would simply move from the payload's IAT into the stub's.
    verify_no_intercepted_imports(&out, &api_resolution)?;
    let compile_time = timer.elapsed();

    anstream::println!(
        "{}",
        ui.done(
            "compile",
            dotted(
                ui,
                &["rustc".to_string(), ui.dim(compiler::stub_target(arch)),]
            )
        )
    );
    if verbose {
        anstream::println!(
            "{}",
            ui.detail(
                "rustc",
                ui.dim(compiler::find_rustc()?.display().to_string())
            )
        );
        anstream::println!("{}", ui.detail("output", ui.dim(out.display().to_string())));
        anstream::println!(
            "{}",
            ui.detail("time", ui.dim(format_elapsed(compile_time)))
        );
    }

    // 5b. Embed PE resources into the compiled stub (icon, VERSIONINFO and the
    //     application manifest), written into a new `.rsrc` section.
    let resources = resolve_resources(plan);
    if let Some(resources) = &resources {
        let pe_bytes = std::fs::read(&out)?;
        let injected = engine::resources::embed(&pe_bytes, resources)?;
        if injected.len() != pe_bytes.len() {
            std::fs::write(&out, &injected)?;
            if verbose {
                anstream::println!(
                    "{}",
                    ui.detail(
                        "resources",
                        ui.dim(format!(
                            "+{} bytes (.rsrc)",
                            injected.len() - pe_bytes.len()
                        ))
                    )
                );
            }
        }
    }

    // 6. Lock the shared output, then copy the compiled stub to the output path
    //    from the YAML, sign it and write the manifest. The lock is keyed on the
    //    output path so two concurrent `picaro build` runs cannot interleave
    //    their copy/sign/manifest writes into the same artifact.
    let _output_lock = build_lock::OutputLock::acquire(&plan.build.output.path)?;
    std::fs::copy(&out, &plan.build.output.path)?;
    let out_size = std::fs::metadata(&plan.build.output.path)?.len() as usize;

    // 6b. Sign the artifact (Authenticode), if configured. Signing must be the
    //     last modification, so the manifest below hashes the signed file.
    let sign_plan = resolve_sign(plan, resources.as_ref());
    let signature = engine::signing::sign(&plan.build.output.path, sign_plan.as_ref())?;
    if let Some(sig) = &signature {
        let mut parts = vec![ui.brand(sig.mode.clone())];
        if let Some(thumbprint) = &sig.thumbprint {
            parts.push(ui.dim(short_thumbprint(thumbprint)));
        }
        if sig.timestamp_url.is_some() {
            parts.push(ui.dim("timestamped"));
        }
        anstream::println!("{}", ui.done("sign", dotted(ui, &parts)));
        if verbose {
            if let Some(ca_file) = &sig.ca_file {
                anstream::println!("{}", ui.detail("certificate", ui.dim(ca_file.clone())));
            }
        }
    }

    // 6c. Provenance: a manifest next to the artifact (artifact hash, the
    //     per-step payload records, resolved plan, toolchain). The payload keys
    //     are never written.
    if plan.build.output.manifest {
        let manifest_path = engine::manifest::manifest_path(&plan.build.output.path);
        let mut manifest =
            engine::manifest::BuildManifest::new(plan, plan_path, &plan.build.output.path)?;
        manifest.signature = signature;
        manifest.version_info = resources.as_ref().and_then(|r| r.version_info.clone());
        manifest.steps = step_records;
        manifest.write(&manifest_path)?;
        if verbose {
            anstream::println!(
                "{}",
                ui.detail("manifest", ui.dim(manifest_path.display().to_string()))
            );
        }
    }

    let total = started.elapsed();

    // 7. The result, standing apart from the per-step lines.
    anstream::println!();
    anstream::println!(
        "{}",
        ui.result(
            "packed",
            dotted(
                ui,
                &[
                    ui.target(plan.build.output.path.display().to_string()),
                    human_size(out_size),
                    ui.dim(format_elapsed(total)),
                ]
            )
        )
    );
    if verbose {
        let delta = out_size.saturating_sub(total_plaintext);
        anstream::println!(
            "{}",
            ui.detail("delta", format!("+{} over the input", human_size(delta)))
        );
    }

    // 8. Per-build material: the nonces are public; the keys are printed in
    //    debug builds only, never in release.
    anstream::println!();
    for (index, nonce, key) in &nonces {
        anstream::println!(
            "{}",
            ui.field(&format!("nonce {index}"), hex::encode(nonce))
        );
        #[cfg(debug_assertions)]
        {
            let _ = key;
            anstream::println!("{}", ui.field(&format!("key {index}"), hex::encode(key)));
        }
    }
    #[cfg(debug_assertions)]
    {
        if let Some(key) = strings.key {
            anstream::println!("{}", ui.field("strings key", hex::encode(key)));
        }
    }

    Ok(())
}

/// Loads the stub template: the builtin one, or a custom loader stub.
fn load_stub_template(plan: &plan::Plan) -> Result<(String, String, bool)> {
    match &plan.build.stub.path {
        Some(path) => {
            let path = path.clone();
            let source = std::fs::read_to_string(&path).map_err(|source| {
                error::PackerError::ReadLoader {
                    path: path.clone(),
                    source,
                }
            })?;
            Ok((
                source,
                format!("custom {} {}", glyph::DOT, path.display()),
                true,
            ))
        }
        None => {
            let relative = "templates/stub/main.rs.tpl";
            let template_path = Path::new(env!("CARGO_MANIFEST_DIR")).join(relative);
            let source = std::fs::read_to_string(&template_path).map_err(|source| {
                error::PackerError::ReadLoader {
                    path: template_path.clone(),
                    source,
                }
            })?;
            Ok((source, format!("builtin {} {relative}", glyph::DOT), false))
        }
    }
}

/// Resolves and validates a build without encrypting, compiling or writing.
///
/// `build --dry-run` is a pre-flight check: it loads every payload (fetching a
/// URL as a real build would), verifies each `sha256` when pinned, validates the
/// PEs and prints the resolved plan. Nothing is written, so it is safe to run
/// against a plan before committing it.
fn dry_run(plan: &plan::Plan, plan_path: &Path, ui: &Palette) -> Result<()> {
    anstream::println!("{}", ui.command_line("build", plan_path.display()));
    anstream::println!();
    print_plan(plan, plan_path, ui);

    // Resource building is cheap and validates the icon/versions, so a dry run
    // can check it without touching the compiled stub.
    let resources = resolve_resources(plan);

    let steps = plan::steps::resolve(plan)?;
    for step in &steps {
        let Some(payload) = &step.payload else {
            anstream::println!(
                "{}",
                ui.detail(
                    &format!("step {}", step.index),
                    ui.dim(format!(
                        "{} {}",
                        step.technique.name(),
                        step.technique.category().label()
                    ))
                )
            );
            continue;
        };
        let bytes = load_source(&payload.plan.source)?;
        verify_payload_hash(&bytes, payload.plan.sha256.as_deref())?;
        let summary = inspect_payload(payload.plan.format, &bytes, plan.build.output.arch)?;
        let mut parts = vec![
            ui.target(describe_source(&payload.plan.source)),
            ui.dim(summary.label),
            human_size(bytes.len()),
        ];
        if let Some(export) = &payload.plan.export {
            parts.push(ui.dim(format!("export {export}")));
        }
        if payload.plan.sha256.is_some() {
            parts.push(ui.ok("sha256 verified"));
        }
        anstream::println!(
            "{}",
            ui.done(
                &format!("step {} {}", step.index, ui.brand(step.technique.name())),
                dotted(ui, &parts)
            )
        );
    }

    if plan.build.output.subsystem == Subsystem::Windows {
        anstream::println!("{}", ui.detail("subsystem", ui.dim("windows")));
    }
    if let Some(resources) = &resources {
        let blob = engine::resources::build(resources, 0)?;
        if !blob.is_empty() {
            anstream::println!(
                "{}",
                ui.detail("resources", ui.dim(format!("{} B", blob.len())))
            );
        }
    }

    // Signing is validated without signing: the configured inputs are checked
    // (a missing .pfx fails without needing a tool) and a backend is located
    // (the certificate itself is resolved at build time).
    let sign = resolve_sign(plan, resources.as_ref());
    if let Some(sign) = &sign {
        if sign.mode != "none" {
            if let Some(file) = &sign.file {
                if !file.is_file() {
                    return Err(error::PackerError::Validation(format!(
                        "output.sign.file '{}' does not exist",
                        file.display()
                    )));
                }
            }
            let signer = engine::signing::locate_signer(sign)?;
            anstream::println!("{}", ui.detail("sign", ui.dim(sign_label(sign))));
            anstream::println!(
                "{}",
                ui.detail(signer.label, ui.dim(signer.path.display().to_string()))
            );
        }
    }

    anstream::println!();
    anstream::println!(
        "{}",
        ui.warn("dry run: nothing was encrypted, compiled or written")
    );
    Ok(())
}

/// The input payload after format-specific validation.
struct PayloadSummary {
    /// Human label for the build log (`x64 PE`, `x64 DLL`, `shellcode`).
    label: &'static str,
    /// Parsed PE info for the PE-backed formats; `None` for shellcode.
    pe: Option<pe::PeInfo>,
}

/// Parses and validates the payload according to its `format` and the requested
/// `arch`.
///
/// `pe`/`dll` must be a well-formed PE of the matching kind **and** the matching
/// architecture: the stub and the payload share one address space, so a 32-bit
/// payload cannot run in a 64-bit stub and vice versa. `shellcode` has no
/// headers to check, only that it is not empty, so it follows
/// `build.output.arch`. The checks run at build time so a mismatched plan fails
/// before anything is encrypted or compiled.
fn inspect_payload(format: PayloadFormat, data: &[u8], arch: Arch) -> Result<PayloadSummary> {
    match format {
        PayloadFormat::Shellcode => {
            if data.is_empty() {
                return Err(error::PackerError::Validation(
                    "the shellcode payload is empty".to_string(),
                ));
            }
            Ok(PayloadSummary {
                label: "shellcode",
                pe: None,
            })
        }
        PayloadFormat::Dotnet => {
            let info = pe::parse(data)?;
            let Some(clr) = info.com else {
                return Err(error::PackerError::Validation(
                    "a payload has 'format: dotnet' but no CLR header (data directory 14 is empty): it is a native image, so use 'format: pe'"
                        .to_string(),
                ));
            };
            // A managed assembly is portable when it is IL-only: the CLR of the
            // stub's bitness runs it. `32BITREQUIRED` pins it to a 32-bit
            // runtime, and a mixed-mode (non-IL-only) assembly to its own
            // machine.
            let portable = clr.is_il_only() && !clr.requires_32bit();
            let arch_ok = if portable {
                true
            } else if clr.requires_32bit() {
                arch == Arch::X86
            } else {
                info.arch() == Some(arch)
            };
            if !arch_ok {
                let requirement = if clr.requires_32bit() {
                    "a 32-bit runtime (COMIMAGE_FLAGS_32BITREQUIRED)"
                } else {
                    "the matching architecture (it is not IL-only)"
                };
                return Err(error::PackerError::Validation(format!(
                    "build.output.arch is '{}' but the .NET payload requires {requirement}: a managed assembly runs on the CLR of the stub's bitness",
                    arch.label()
                )));
            }
            Ok(PayloadSummary {
                label: match info.arch() {
                    Some(Arch::X64) => "x64 .NET assembly",
                    Some(Arch::X86) => "x86 .NET assembly",
                    None => ".NET assembly",
                },
                pe: Some(info),
            })
        }

        PayloadFormat::Pe | PayloadFormat::Dll => {
            let info = pe::parse(data)?;
            if info.is_dotnet() {
                return Err(error::PackerError::Validation(
                    "a payload is a .NET assembly (it has a CLR header): a managed image is not mapped as native code; use 'format: dotnet' with 'technique: dotnet_hosting', which hosts the CLR and loads the assembly from memory"
                        .to_string(),
                ));
            }
            let payload_arch = info.arch().ok_or_else(|| {
                error::PackerError::Validation(format!(
                    "unsupported PE machine 0x{:04x}: picaro packs x86 (PE32) and x64 (PE32+) images",
                    info.machine
                ))
            })?;

            if payload_arch != arch {
                return Err(error::PackerError::Validation(format!(
                    "build.output.arch is '{}' but the payload is an {} PE (machine 0x{:04x}): the \
                     stub and the payload must share an architecture",
                    arch.label(),
                    payload_arch.label(),
                    info.machine
                )));
            }
            let is_dll = pe::is_dll(info.characteristics);
            match format {
                PayloadFormat::Dll if !is_dll => {
                    return Err(error::PackerError::Validation(
                        "a payload has 'format: dll' but is an executable \
                         (IMAGE_FILE_DLL is not set)"
                            .to_string(),
                    ));
                }
                PayloadFormat::Pe if is_dll => {
                    return Err(error::PackerError::Validation(
                        "a payload has 'format: pe' but is a DLL; use 'format: dll'".to_string(),
                    ));
                }
                _ => {}
            }
            Ok(PayloadSummary {
                label: match (payload_arch, is_dll) {
                    (Arch::X64, false) => "x64 PE",
                    (Arch::X64, true) => "x64 DLL",
                    (Arch::X86, false) => "x86 PE",
                    (Arch::X86, true) => "x86 DLL",
                },
                pe: Some(info),
            })
        }
    }
}

/// Fails when the payload does not match its `sha256`.
///
/// The comparison is case-insensitive hex; the format is already validated in
/// `plan::validate`, so a mismatch here means the payload changed.
fn verify_payload_hash(payload: &[u8], expected: Option<&str>) -> Result<()> {
    let Some(expected) = expected else {
        return Ok(());
    };
    let expected = expected.trim();
    let actual = engine::hash::sha256_hex(payload);
    if !actual.eq_ignore_ascii_case(expected) {
        return Err(error::PackerError::Validation(format!(
            "payload sha256 mismatch: plan expects {expected}, payload is {actual}"
        )));
    }
    Ok(())
}

/// Prints the resolved plan (verbose mode).
///
/// Dumping what the YAML resolved to makes a build reproducible from the log
/// alone, without opening the plan file.
fn print_plan(plan: &plan::Plan, plan_path: &Path, ui: &Palette) {
    anstream::println!("{}", ui.heading("PLAN"));
    anstream::println!("{}", ui.field("name", &plan.name));
    anstream::println!("{}", ui.field("plan", ui.target(plan_path.display())));
    for (name, payload) in &plan.build.payloads {
        anstream::println!(
            "{}",
            ui.field(
                &format!("payload {name}"),
                ui.target(describe_source(&payload.source))
            )
        );
        anstream::println!(
            "{}",
            ui.field(&format!("  {name} args"), payload_args_label(payload))
        );
    }
    anstream::println!(
        "{}",
        ui.field("output", ui.target(plan.build.output.path.display()))
    );
    anstream::println!("{}", ui.field("arch", plan.build.output.arch.label()));
    anstream::println!(
        "{}",
        ui.field("strip", if plan.build.output.strip { "yes" } else { "no" })
    );
    anstream::println!(
        "{}",
        ui.field("trim paths", trim_label(plan.build.output.trim_paths))
    );
    anstream::println!(
        "{}",
        ui.field("subsystem", plan.build.output.subsystem.label())
    );
    anstream::println!("{}", ui.field("stub", stub_label(plan)));
    if plan.build.stub.debug {
        anstream::println!("{}", ui.field("debug", ui.warn("yes")));
    }
    if let Some(resolution) = &plan.build.stub.api_resolution {
        if resolution.mode == "proxy" {
            anstream::println!(
                "{}",
                ui.field("api resolution", api_resolution_label(resolution))
            );
        }
    }
    if let Some(resources) = &plan.build.output.resources {
        anstream::println!("{}", ui.field("resources", resources_label(resources)));
    }
    if let Some(sign) = &plan.build.output.sign {
        // A lab certificate without a subject takes its name from the generated
        // metadata, so the echo says where the name comes from.
        let derived = sign.mode == "lab"
            && sign.subject.is_none()
            && plan
                .build
                .output
                .resources
                .as_ref()
                .and_then(|resources| resources.version_info.as_ref())
                .is_some_and(|info| info.randomize);
        let label = if derived {
            "lab (subject derived from metadata)".to_string()
        } else {
            sign_label(sign)
        };
        anstream::println!("{}", ui.field("sign", label));
    }
    if let Ok(steps) = plan::steps::resolve(plan) {
        anstream::println!("{}", ui.field("runtime", runtime_chain(ui, &steps)));
    }
    anstream::println!("{}", ui.field("schema", plan.schema));
    anstream::println!();
}

/// `patch_amsi → reflective_loading`, step labels in the accent colors.
fn runtime_chain(ui: &Palette, steps: &[ResolvedStep]) -> String {
    if steps.is_empty() {
        return ui.dim("no techniques");
    }
    steps
        .iter()
        .map(|step| match step.technique.category() {
            Category::Control => ui.target(step.label.clone()),
            Category::Preparation | Category::Execution => ui.brand(step.label.clone()),
        })
        .collect::<Vec<_>>()
        .join(&format!(" {} ", ui.dim(glyph::ARROW)))
}

/// Joins already-styled fragments with a faint `·` separator.
fn dotted(ui: &Palette, parts: &[String]) -> String {
    parts.join(&format!(" {} ", ui.faint(glyph::DOT)))
}

/// Lowercase label for the debug-info path policy.
fn trim_label(trim: TrimPaths) -> &'static str {
    match trim {
        TrimPaths::All => "all",
        TrimPaths::None => "none",
        TrimPaths::Relative => "relative",
    }
}

/// Which stub template the build resolved to (plus the syscall mode).
fn stub_label(plan: &plan::Plan) -> String {
    match &plan.build.stub.path {
        Some(path) => format!("custom {}", path.display()),
        None => {
            let mode = stub_mode_label(plan);
            format!("builtin (syscalls {mode})")
        }
    }
}

/// Lowercase label of the resolved syscall mode (used by [`stub_label`]).
fn stub_mode_label(plan: &plan::Plan) -> &'static str {
    plan.build
        .stub
        .syscalls
        .as_ref()
        .map(|s| match s.mode.as_str() {
            "indirect" => "indirect",
            _ => "none",
        })
        .unwrap_or("none")
}

/// Verifies that the compiled stub does not import any API that
/// `build.stub.api_resolution` routes or forwards (D-21).
///
/// The whole point of the feature is that the intercepted calls leave the IAT; a
/// proxy that imported the very API it intercepts would move the signature from
/// the payload's IAT into the stub's instead of removing it.
///
/// `Strategy::Handler` entries are exempt: `GetProcAddress` is imported by the
/// loader itself (the import resolver and the syscall resolvers use it), so its
/// presence is not a regression and cannot be told apart from the handler's own
/// dynamic resolver.
fn verify_no_intercepted_imports(
    artifact: &Path,
    config: &api_resolution::ApiResolutionConfig,
) -> Result<()> {
    if config.mode != api_resolution::ApiResolutionMode::Proxy || config.apis.is_empty() {
        return Ok(());
    }
    let bytes = std::fs::read(artifact)?;
    let audit = audit::pe_info::analyze(&bytes).map_err(|e| {
        error::PackerError::Validation(format!("could not audit the compiled stub: {e}"))
    })?;
    for entry in &config.apis {
        if entry.strategy == api_resolution::Strategy::Handler {
            continue;
        }
        for dll in &audit.imports {
            let hit = dll
                .functions
                .iter()
                .any(|f| matches!(f, audit::pe_info::ImportItem::Named(n) if n == entry.func));
            if hit {
                return Err(error::PackerError::Validation(format!(
                    "the stub imports '{}' (from '{}') while build.stub.api_resolution proxies it: a \
                     proxy must not import the API it intercepts",
                    entry.func, dll.name
                )));
            }
        }
    }
    Ok(())
}

/// Prepends `#![windows_subsystem = "windows"]` for a GUI build.
///
/// Runs on the rendered source (builtin or custom) so `rustc` links a GUI
/// binary. A source that already sets `windows_subsystem` is left untouched.
fn apply_subsystem(source: String, subsystem: Subsystem) -> String {
    if subsystem == Subsystem::Windows && !source.contains("windows_subsystem") {
        let mut out = String::with_capacity(source.len() + 40);
        out.push_str("#![windows_subsystem = \"windows\"]\n");
        out.push_str(&source);
        out
    } else {
        source
    }
}

/// Where the compiled stub is written inside the build directory.
///
/// An executable keeps the fixed `out.exe`. A DLL is named after the artifact
/// the operator asked for: the linker records the link output's name inside the
/// PE (the export directory's `Name` field), so the file should report the name
/// it will be delivered under rather than the build's scratch name.
fn intermediate_path(build_dir: &Path, output: &plan::schema::OutputPlan) -> PathBuf {
    match output.kind {
        OutputKind::Exe => build_dir.join("out.exe"),
        OutputKind::Dll => {
            let stem = output
                .path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .unwrap_or("loader");
            build_dir.join(format!("{stem}.dll"))
        }
    }
}

/// First 16 hex digits of a thumbprint, for a compact step line.
fn short_thumbprint(thumbprint: &str) -> String {
    thumbprint.chars().take(16).collect()
}

/// Human summary of `output.sign`.
fn sign_label(sign: &plan::schema::SignPlan) -> String {
    match sign.mode.as_str() {
        "lab" => format!(
            "lab ({})",
            sign.subject.as_deref().unwrap_or("default subject")
        ),
        "store" => format!(
            "store ({})",
            sign.thumbprint
                .as_deref()
                .or(sign.subject.as_deref())
                .unwrap_or("?")
        ),
        "file" => format!(
            "file ({})",
            sign.file
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_default()
        ),
        other => other.to_string(),
    }
}

/// The `api_resolution` echo: `proxy (5 APIs, unmatched forward)`.
fn api_resolution_label(yaml: &engine::api_resolution::YamlApiResolutionPlan) -> String {
    let apis = yaml.apis.len();
    format!("proxy ({apis} APIs, unmatched {})", yaml.unmatched)
}

/// Human summary of the configured PE resources (`output.resources`).
fn resources_label(resources: &plan::schema::ResourcesPlan) -> String {
    let mut parts = Vec::new();
    if let Some(icon) = &resources.icon {
        parts.push(format!("icon {}", icon.display()));
    }
    if resources.version_info.is_some() {
        parts.push("version info".to_string());
    }
    if let Some(manifest) = &resources.manifest {
        parts.push(format!("manifest ({})", manifest.level.xml_value()));
    }
    if parts.is_empty() {
        "(none)".to_string()
    } else {
        parts.join(", ")
    }
}

/// Resolves `output.resources`, applying random metadata when requested.
///
/// `version_info.randomize` fills the unset fields with generated values, so the
/// artifact carries plausible company/product/version metadata instead of empty
/// strings. The generated company is later reused as the lab certificate
/// subject (see [`resolve_sign`]).
fn resolve_resources(plan: &plan::Plan) -> Option<plan::schema::ResourcesPlan> {
    let resources = plan.build.output.resources.as_ref()?;
    let mut resolved = resources.clone();
    if let Some(info) = &resolved.version_info {
        resolved.version_info = Some(engine::identity::apply(info));
    }
    Some(resolved)
}

/// Resolves `output.sign`, deriving the lab certificate subject from the
/// generated company when one is available and no subject was configured.
fn resolve_sign(
    plan: &plan::Plan,
    resources: Option<&plan::schema::ResourcesPlan>,
) -> Option<plan::schema::SignPlan> {
    let sign = plan.build.output.sign.as_ref()?;
    let mut resolved = sign.clone();
    if resolved.mode == "lab" && resolved.subject.is_none() {
        if let Some(company) = resources
            .and_then(|r| r.version_info.as_ref())
            .and_then(|info| info.company.clone())
        {
            resolved.subject = Some(format!("CN={company}"));
        }
    }
    Some(resolved)
}

/// The configured payload source, or a placeholder when empty.
fn describe_source(source: &str) -> String {
    if source.trim().is_empty() {
        "(unspecified)".to_string()
    } else {
        source.to_string()
    }
}

/// Lowercase label for the crypto algorithm, as printed by `build`.
fn crypto_label(algo: CryptoAlgorithm) -> &'static str {
    match algo {
        CryptoAlgorithm::XChaCha20Poly1305 => "xchacha20poly1305",
    }
}

/// `(none)` or `N (mode)` for a payload's configured runtime arguments.
fn payload_args_label(payload: &PayloadPlan) -> String {
    match &payload.args {
        Some(args) if !args.is_empty() => {
            format!("{} ({})", args.len(), payload.args_mode.label())
        }
        _ => "(none)".to_string(),
    }
}

/// Reads an input payload into memory from its configured source.
///
/// `http://` and `https://` sources are fetched in memory (never written to
/// disk); a `file://` source is read from disk after stripping the scheme; any
/// other value is treated as a local path. `ftp://` is recognized but rejected
/// with a clear message because no FTP client is implemented.
fn load_source(source: &str) -> Result<Vec<u8>> {
    if source.starts_with("http://") || source.starts_with("https://") {
        return engine::fetch::fetch_url(source);
    }
    if source.starts_with("ftp://") {
        return Err(error::PackerError::Validation(
            "a payload 'source' uses ftp://, which is not supported; \
             use http(s):// or a local path"
                .to_string(),
        ));
    }
    let path = match source.strip_prefix("file://") {
        Some(rest) => file_url_to_path(rest),
        None => source.to_string(),
    };
    std::fs::read(&path).map_err(|source| error::PackerError::ReadInput {
        path: PathBuf::from(path),
        source,
    })
}

/// Turns the part after `file://` into a local path.
///
/// Handles the `file:///C:/x` form produced by URL libraries, which points at
/// `C:/x` (the leading slash before a drive letter is an artifact).
fn file_url_to_path(rest: &str) -> String {
    let bytes = rest.as_bytes();
    if bytes.len() >= 3 && bytes[0] == b'/' && bytes[1].is_ascii_alphabetic() && bytes[2] == b':' {
        rest[1..].to_string()
    } else {
        rest.to_string()
    }
}

/// Removes `dir` if it exists and recreates it empty.
fn prepare_build_dir(dir: &Path) -> Result<()> {
    if dir.exists() {
        std::fs::remove_dir_all(dir)?;
    }
    std::fs::create_dir_all(dir)?;
    Ok(())
}

/// The scratch directory for intermediate artifacts (the ciphertexts, the
/// rendered stub, the compiled `out.exe`).
///
/// Defaults to a unique `build/run-<pid>-<nanos>` directory next to the
/// manifest, so concurrent `picaro build` runs never share — and never wipe —
/// each other's intermediate files. `PICARO_BUILD_DIR`, when set and non-empty,
/// is used verbatim for reproducible single-directory workflows (e.g. the
/// read-only Docker source tree).
fn scratch_dir() -> PathBuf {
    let override_dir = std::env::var_os("PICARO_BUILD_DIR").map(PathBuf::from);
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    match &override_dir {
        Some(dir) if !dir.as_os_str().is_empty() => scratch_dir_in(override_dir, manifest_dir),
        _ => unique_scratch_dir_in(manifest_dir, &run_nonce()),
    }
}

/// Resolves [`scratch_dir`] from an explicit `PICARO_BUILD_DIR` value (when set
/// and non-empty) and the manifest directory. Split out so both branches are
/// testable without touching the process environment.
fn scratch_dir_in(override_dir: Option<PathBuf>, manifest_dir: &Path) -> PathBuf {
    match override_dir {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => manifest_dir.join("build"),
    }
}

/// A unique scratch directory for one build run, derived from `nonce`.
///
/// Split from [`scratch_dir`] so tests can inject a deterministic nonce.
fn unique_scratch_dir_in(manifest_dir: &Path, nonce: &str) -> PathBuf {
    manifest_dir.join("build").join(format!("run-{nonce}"))
}

/// A process- and time-unique label (`<pid>-<nanos>`) for a build run.
fn run_nonce() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    format!("{}-{nanos}", std::process::id())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn console_subsystem_leaves_the_source_untouched() {
        let source = "fn main() {}\n".to_string();
        assert_eq!(apply_subsystem(source.clone(), Subsystem::Console), source);
    }

    #[test]
    fn windows_subsystem_prepends_the_attribute() {
        let source = "fn main() {}\n".to_string();
        let out = apply_subsystem(source, Subsystem::Windows);
        assert!(out.starts_with("#![windows_subsystem = \"windows\"]\n"));
        assert!(out.ends_with("fn main() {}\n"));
    }

    #[test]
    fn an_existing_subsystem_attribute_is_not_duplicated() {
        let source = "#![windows_subsystem = \"console\"]\nfn main() {}\n".to_string();
        let out = apply_subsystem(source.clone(), Subsystem::Windows);
        assert_eq!(out, source, "a stub that sets its own subsystem wins");
    }

    #[test]
    fn short_thumbprint_keeps_the_first_16_digits() {
        assert_eq!(short_thumbprint("DEADBEEF00112233AABB"), "DEADBEEF00112233");
    }

    #[test]
    fn scratch_dir_defaults_to_build_next_to_the_manifest() {
        let dir = scratch_dir_in(None, Path::new("/usr/src/picaro"));
        assert_eq!(dir, Path::new("/usr/src/picaro/build"));
    }

    #[test]
    fn scratch_dir_honors_the_picaro_build_dir_override() {
        let dir = scratch_dir_in(
            Some(PathBuf::from("/tmp/picaro-build")),
            Path::new("/usr/src/picaro"),
        );
        assert_eq!(dir, Path::new("/tmp/picaro-build"));
    }

    #[test]
    fn an_empty_scratch_override_falls_back_to_the_default() {
        let dir = scratch_dir_in(Some(PathBuf::new()), Path::new("/usr/src/picaro"));
        assert_eq!(dir, Path::new("/usr/src/picaro/build"));
    }

    #[test]
    fn unique_scratch_dirs_differ_across_nonces() {
        let first = unique_scratch_dir_in(Path::new("/usr/src/picaro"), "1-100");
        let second = unique_scratch_dir_in(Path::new("/usr/src/picaro"), "2-200");
        assert_ne!(first, second, "each run must get its own scratch directory");
    }

    #[test]
    fn unique_scratch_dir_lives_in_a_run_folder_under_build() {
        let dir = unique_scratch_dir_in(Path::new("/usr/src/picaro"), "42-123");
        assert_eq!(dir, Path::new("/usr/src/picaro/build/run-42-123"));
    }
}
