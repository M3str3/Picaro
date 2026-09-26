//! `batesian` entry point.
//!
//! Three subcommands:
//! - `build`: YAML → encrypt payload → render Rust stub → compile → out.exe.
//!   `build interactive <payload>` generates that YAML from a few questions.
//! - `audit`: static analysis of a PE (measurement infrastructure).
//! - `techniques`: inspect the technique registry.
//!
//! Running with no subcommand prints the banner plus the generated help.

mod audit;
mod config;
mod engine;
mod error;
mod techniques;
mod ui;
mod wizard;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Instant;

use clap::{CommandFactory, Parser, Subcommand};

use config::schema::{
    Arch, CryptoAlgorithm, KeySource, PayloadConfig, PayloadFormat, Subsystem, TrimPaths,
};
use engine::{compiler, crypto, obfuscation, pe, stub, syscalls};
use error::Result;
use techniques::RuntimeStep;
use ui::{format_elapsed, glyph, human_size, Palette};

/// Extra help printed under the generated usage block.
const AFTER_HELP: &str = "\
Examples:
  batesian build examples/configs/mimikatz.yaml
  batesian build examples/configs/mimikatz.yaml --dry-run
  batesian build interactive mimikatz.exe
  batesian audit dist/test_amsi_patch.exe --focus imports,strings
  batesian audit dist/out.exe --json > baseline.json
  batesian audit dist/out.exe --baseline baseline.json
  batesian techniques list

Colors are disabled automatically when the output is not a terminal; set
NO_COLOR=1 (or pass --no-color) to disable them explicitly. Pass -q (or
--quiet) to skip the banner, and -v (or --verbose) to print per-step build
detail (paths, sizes, timings).

audit --baseline exits 3 when it finds a regression, so it can gate a CI
job; every other failure exits 1.";

/// `batesian` CLI.
#[derive(Debug, Parser)]
#[command(name = "batesian", bin_name = "batesian", version, about = ui::TAGLINE, after_help = AFTER_HELP)]
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
    /// Build a packed PE: from a YAML configuration file, or interactively.
    #[command(subcommand_precedence_over_arg = true)]
    Build {
        /// Generate the configuration interactively instead of reading a file.
        #[command(subcommand)]
        action: Option<BuildAction>,

        /// Path to the YAML configuration file.
        #[arg(value_name = "CONFIG")]
        config: Option<PathBuf>,

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
        config_out: Option<PathBuf>,
    },
}

/// Subcommands of `batesian techniques`.
#[derive(Debug, Subcommand)]
enum TechniquesCommand {
    /// List registered techniques.
    List,

    /// Show a technique's full README.
    Show {
        /// Technique YAML key (e.g. `process_hollowing`).
        #[arg(value_name = "NAME")]
        name: String,
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
            config,
            args,
            dry_run: is_dry_run,
            debug: debug_flag,
        } => match action {
            Some(BuildAction::Interactive {
                payload,
                config_out,
            }) => {
                if config.is_some() {
                    return Err(error::PackerError::Validation(
                        "`build interactive` takes a payload, not a config file".to_string(),
                    ));
                }
                // The wizard writes the YAML and hands back its path; loading it
                // through the normal path proves the file is what gets built.
                if let Some(path) = wizard::run(&payload, config_out.as_deref(), &ui)? {
                    let build_args = BTreeMap::new();
                    let config = config::load_config(&path, &build_args)?;
                    if is_dry_run {
                        dry_run(&config, &path, &ui)?;
                    } else {
                        build(&config, &build_args, &path, &ui, cli.verbose, debug_flag)?;
                    }
                }
            }
            None => {
                let Some(config) = config else {
                    return Err(error::PackerError::Validation(
                        "missing CONFIG: use `batesian build <config.yaml>` or \
                         `batesian build interactive <payload>`"
                            .to_string(),
                    ));
                };
                let config_path = config.clone();
                let build_args = config::build_args::parse(&args);
                let config = config::load_config(&config, &build_args)?;
                if is_dry_run {
                    dry_run(&config, &config_path, &ui)?;
                } else {
                    build(
                        &config,
                        &build_args,
                        &config_path,
                        &ui,
                        cli.verbose,
                        debug_flag,
                    )?;
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
            TechniquesCommand::Show { name } => anstream::print!("{}", techniques::show(&name)?),
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
            ui.ok(format!("all {} techniques OK", techniques::all().len()))
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
/// `verbose` adds a resolved-configuration block, per-step detail lines and
/// timings; the compact form stays on one line per step. `debug_override`
/// forces the debug build on (`--debug`), on top of `build.stub.debug`.
fn build(
    config: &config::Config,
    build_args: &BTreeMap<String, String>,
    config_path: &Path,
    ui: &Palette,
    verbose: bool,
    debug_override: bool,
) -> Result<()> {
    let started = Instant::now();
    let debug = config.build.stub.debug || debug_override;

    anstream::println!("{}", ui.command_line("build", config_path.display()));
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
        print_config(config, config_path, ui);
    }

    // 1. Read the input payload and validate it against its declared format
    //    (fail early, before encrypting or compiling).
    let timer = Instant::now();
    let plaintext = load_source(&config.build.payload.source)?;
    verify_payload_hash(&plaintext, config.build.payload.sha256.as_deref())?;
    let summary = inspect_payload(config.build.payload.format, &plaintext)?;
    let read_time = timer.elapsed();
    let mut read_parts = vec![
        ui.target(describe_source(&config.build.payload.source)),
        ui.dim(summary.label),
        human_size(plaintext.len()),
    ];
    if let Some(export) = &config.build.payload.export {
        read_parts.push(ui.dim(format!("export {export}")));
    }
    anstream::println!("{}", ui.done("read", dotted(ui, &read_parts)));
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
        anstream::println!("{}", ui.detail("time", ui.dim(format_elapsed(read_time))));
    }

    // 2. Derive the key and encrypt the payload with XChaCha20-Poly1305.
    let timer = Instant::now();
    let key = match config.build.payload.crypto.key {
        KeySource::Random => crypto::generate_key(),
    };
    let encrypted = crypto::encrypt_payload(&plaintext, &key)?;
    let encrypt_time = timer.elapsed();
    anstream::println!(
        "{}",
        ui.done(
            "encrypt",
            dotted(
                ui,
                &[
                    ui.brand(crypto_label(config.build.payload.crypto.algo)),
                    format!(
                        "{} {} {}",
                        human_size(plaintext.len()),
                        ui.faint(glyph::ARROW),
                        human_size(encrypted.ciphertext.len())
                    ),
                ]
            )
        )
    );
    if verbose {
        let tag = encrypted.ciphertext.len().saturating_sub(plaintext.len());
        anstream::println!(
            "{}",
            ui.detail("key", format!("random {} 32 bytes", ui.faint(glyph::DOT)))
        );
        anstream::println!(
            "{}",
            ui.detail("nonce", format!("random {} 24 bytes", ui.faint(glyph::DOT)))
        );
        anstream::println!(
            "{}",
            ui.detail(
                "tag",
                format!("poly1305 {} {tag} bytes", ui.faint(glyph::DOT))
            )
        );
        anstream::println!(
            "{}",
            ui.detail("time", ui.dim(format_elapsed(encrypt_time)))
        );
    }

    // 3. Per-build marker, the string-obfuscation and syscall configurations.
    let stub_marker = stub::generate_stub_marker();
    if config.build.stub.strings.is_none() {
        anstream::eprintln!(
            "  {} {}",
            ui.bang(),
            ui.warn("build.stub.strings not specified, defaulting to xor+random")
        );
    }
    let strings = obfuscation::StringsConfig::from_yaml(config.build.stub.strings.as_ref())?;
    let syscalls = syscalls::SyscallsConfig::from_yaml(config.build.stub.syscalls.as_ref())?;
    if syscalls.mode == syscalls::SyscallsMode::Indirect
        && syscalls::required(&config.runtime).is_empty()
    {
        anstream::eprintln!(
            "  {} {}",
            ui.bang(),
            ui.warn(
                "build.stub.syscalls.mode is 'indirect' but no technique in the pipeline \
                 uses NT syscalls yet (phase 6a: only process_hollowing does)"
            )
        );
    }
    // Config-level advisories from semantic validation (e.g. a no-op bouncer).
    for warning in config::validate::advisories(config) {
        anstream::eprintln!("  {} {}", ui.bang(), ui.warn(format!("warning: {warning}")));
    }

    // 4. Prepare `build/` and write the ciphertext the builtin template embeds.
    let timer = Instant::now();
    let build_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("build");
    prepare_build_dir(&build_dir)?;
    std::fs::write(build_dir.join("payload.bin"), &encrypted.ciphertext)?;

    // 5. Load the stub template: the builtin one, or a custom loader stub.
    //    A custom stub receives the payload as `$PAYLOAD_BYTES$` and does not
    //    need `build/payload.bin`. `build.stub.syscalls` applies to both.
    let (template, template_display, is_custom) = match &config.build.stub.path {
        Some(path) => {
            let path = path.clone();
            let source = std::fs::read_to_string(&path).map_err(|source| {
                error::PackerError::ReadLoader {
                    path: path.clone(),
                    source,
                }
            })?;
            let display = format!("custom {} {}", glyph::DOT, path.display());
            (source, display, true)
        }
        None => {
            let relative = "templates/stub/main.rs.tpl";
            let template_path = Path::new(env!("CARGO_MANIFEST_DIR")).join(relative);
            let display = format!("builtin {} {relative}", glyph::DOT);
            (std::fs::read_to_string(&template_path)?, display, false)
        }
    };

    let params = stub::StubParams {
        nonce: encrypted.nonce,
        key: encrypted.key,
        ciphertext: encrypted.ciphertext.clone(),
        plaintext_len: encrypted.plaintext_len,
        payload_format: config.build.payload.format,
        payload_export: config.build.payload.export.clone(),
        stub_marker: stub_marker.clone(),
        payload_path: "payload.bin".to_string(),
        build_args: build_args.clone(),
        payload_args: config.build.payload.args.clone().unwrap_or_default(),
        args_mode: config.build.payload.args_mode,
        debug,
        windows_subsystem: config.build.output.subsystem == Subsystem::Windows,
    };

    let stub_src = if is_custom {
        stub::validate_custom_stub_template(&template)?;
        let rendered =
            stub::render_custom_stub(&template, &params, &config.runtime, &strings, &syscalls)?;
        for warning in &rendered.warnings {
            anstream::eprintln!("  {} {}", ui.bang(), ui.warn(format!("warning: {warning}")));
        }
        rendered.source
    } else {
        stub::render_main_rs(&template, &params, &config.runtime, &strings, &syscalls)?
    };
    let stub_src = apply_subsystem(stub_src, config.build.output.subsystem);
    let stub_path = build_dir.join("main.rs");
    std::fs::write(&stub_path, &stub_src)?;
    let stub_time = timer.elapsed();

    let mut stub_parts = vec![
        pipeline_chain(ui, &config.runtime),
        format!("{} {}", ui.dim("strings"), strings.strategy.label()),
        format!("{} {}", ui.dim("syscalls"), syscalls.mode.label()),
        format!(
            "{} {}",
            ui.dim("format"),
            config.build.payload.format.label()
        ),
    ];
    if !params.payload_args.is_empty() {
        stub_parts.push(format!(
            "{} {} ({})",
            ui.dim("args"),
            params.payload_args.len(),
            config.build.payload.args_mode.label()
        ));
    }
    if debug {
        stub_parts.push(ui.warn("debug"));
    }
    anstream::println!("{}", ui.done("stub", dotted(ui, &stub_parts)));
    if verbose {
        anstream::println!("{}", ui.detail("template", ui.dim(&template_display)));
        anstream::println!("{}", ui.detail("marker", ui.dim(&stub_marker)));
        anstream::println!(
            "{}",
            ui.detail("resolver", ui.dim(syscalls.resolver.label()))
        );
        anstream::println!(
            "{}",
            ui.detail(
                "payload args",
                ui.dim(payload_args_label(&config.build.payload))
            )
        );
        anstream::println!(
            "{}",
            ui.detail(
                "source",
                format!(
                    "build/main.rs {} {} lines",
                    ui.faint(glyph::DOT),
                    stub_src.lines().count()
                )
            )
        );
        anstream::println!("{}", ui.detail("time", ui.dim(format_elapsed(stub_time))));
    }

    // 6. Locate the dependencies and compile the stub.
    let timer = Instant::now();
    let deps = compiler::locate_stub_deps()?;
    let out = build_dir.join("out.exe");
    let options = compiler::CompileOptions {
        strip: config.build.output.strip,
        trim_paths: match config.build.output.trim_paths {
            TrimPaths::None => compiler::PathTrim::None,
            TrimPaths::Relative => compiler::PathTrim::Relative,
            TrimPaths::All => compiler::PathTrim::All,
        },
        debug,
    };
    compiler::compile_stub(&stub_path, &out, &deps, options)?;
    let compile_time = timer.elapsed();

    anstream::println!(
        "{}",
        ui.done(
            "compile",
            dotted(
                ui,
                &["rustc".to_string(), ui.dim(compiler::stub_target_label())]
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

    // 6b. Embed PE resources into the compiled stub (icon, VERSIONINFO and the
    //     application manifest), written into a new `.rsrc` section. Nothing is
    //     injected when `output.resources` is absent.
    let resources = resolve_resources(config);
    if let Some(resources) = &resources {
        let pe = std::fs::read(&out)?;
        let injected = engine::resources::embed(&pe, resources)?;
        if injected.len() != pe.len() {
            std::fs::write(&out, &injected)?;
            if verbose {
                anstream::println!(
                    "{}",
                    ui.detail(
                        "resources",
                        ui.dim(format!("+{} bytes (.rsrc)", injected.len() - pe.len()))
                    )
                );
            }
        }
    }

    // 7. Copy `out.exe` to the output path from the YAML.
    if let Some(parent) = config.build.output.path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    std::fs::copy(&out, &config.build.output.path)?;
    let out_size = std::fs::metadata(&config.build.output.path)?.len() as usize;

    // 7b. Sign the artifact (Authenticode), if configured. Signing must be the
    //     last modification, so the manifest below hashes the signed file.
    let sign_config = resolve_sign(config, resources.as_ref());
    let signature = engine::signing::sign(&config.build.output.path, sign_config.as_ref())?;
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

    // 7c. Provenance: a manifest next to the artifact (artifact and payload
    //     hashes, resolved config, toolchain). The payload key is never written.
    if config.build.output.manifest {
        let manifest_path = engine::manifest::manifest_path(&config.build.output.path);
        let mut manifest = engine::manifest::BuildManifest::new(
            config,
            config_path,
            &config.build.output.path,
            &plaintext,
            encrypted.nonce,
        )?;
        manifest.signature = signature;
        manifest.version_info = resources.as_ref().and_then(|r| r.version_info.clone());
        manifest.write(&manifest_path)?;
        if verbose {
            anstream::println!(
                "{}",
                ui.detail("manifest", ui.dim(manifest_path.display().to_string()))
            );
        }
    }

    let total = started.elapsed();

    // 8. The result, standing apart from the per-step lines.
    anstream::println!();
    anstream::println!(
        "{}",
        ui.result(
            "packed",
            dotted(
                ui,
                &[
                    ui.target(config.build.output.path.display().to_string()),
                    human_size(out_size),
                    ui.dim(format_elapsed(total)),
                ]
            )
        )
    );
    if verbose {
        let delta = out_size.saturating_sub(plaintext.len());
        anstream::println!(
            "{}",
            ui.detail("delta", format!("+{} over the input", human_size(delta)))
        );
    }

    // 9. Per-build material: the nonce is public; the keys are printed in debug
    //    builds only, never in release.
    anstream::println!();
    anstream::println!("{}", ui.field("nonce", hex::encode(encrypted.nonce)));
    #[cfg(debug_assertions)]
    {
        anstream::println!("{}", ui.field("key", hex::encode(encrypted.key)));
        if let Some(key) = strings.key {
            anstream::println!("{}", ui.field("strings key", hex::encode(key)));
        }
    }

    Ok(())
}

/// Resolves and validates a build without encrypting, compiling or writing.
///
/// `build --dry-run` is a pre-flight check: it loads the payload (fetching a URL
/// as a real build would), verifies `build.payload.sha256` when pinned,
/// validates the PE and prints the resolved config. Nothing is written, so it is
/// safe to run against a config before committing it.
fn dry_run(config: &config::Config, config_path: &Path, ui: &Palette) -> Result<()> {
    anstream::println!("{}", ui.command_line("build", config_path.display()));
    anstream::println!();
    print_config(config, config_path, ui);

    let payload = load_source(&config.build.payload.source)?;
    verify_payload_hash(&payload, config.build.payload.sha256.as_deref())?;
    let summary = inspect_payload(config.build.payload.format, &payload)?;

    let mut parts = vec![
        ui.target(describe_source(&config.build.payload.source)),
        ui.dim(summary.label),
        human_size(payload.len()),
    ];
    if let Some(export) = &config.build.payload.export {
        parts.push(ui.dim(format!("export {export}")));
    }
    if config.build.output.subsystem == Subsystem::Windows {
        parts.push(ui.dim("windows subsystem"));
    }
    if config.build.payload.sha256.is_some() {
        parts.push(ui.ok("sha256 verified"));
    }
    // Resource building is cheap and validates the icon/versions, so a dry run
    // can check it without touching the compiled stub.
    let resources = resolve_resources(config);
    if let Some(resources) = &resources {
        let blob = engine::resources::build(resources, 0)?;
        if !blob.is_empty() {
            parts.push(ui.ok(format!("{} B resources", blob.len())));
        }
    }
    anstream::println!("{}", ui.done("payload", dotted(ui, &parts)));

    // Signing is validated without signing: locate `signtool` and check the
    // configured .pfx exists (the certificate itself is resolved at build time).
    let sign = resolve_sign(config, resources.as_ref());
    if let Some(sign) = &sign {
        if sign.mode != "none" {
            let tool = engine::signing::signtool_path(sign)?;
            if let Some(file) = &sign.file {
                if !file.is_file() {
                    return Err(error::PackerError::Validation(format!(
                        "output.sign.file '{}' does not exist",
                        file.display()
                    )));
                }
            }
            anstream::println!("{}", ui.detail("sign", ui.dim(sign_label(sign))));
            anstream::println!(
                "{}",
                ui.detail("signtool", ui.dim(tool.display().to_string()))
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

/// Parses and validates the payload according to `build.payload.format`.
///
/// `pe`/`dll` must be a well-formed x64 PE image of the matching kind;
/// `shellcode` has no headers to check, only that it is not empty. The checks
/// run at build time so a mismatched config fails before anything is encrypted
/// or compiled.
fn inspect_payload(format: PayloadFormat, data: &[u8]) -> Result<PayloadSummary> {
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
        PayloadFormat::Pe | PayloadFormat::Dll => {
            let info = pe::parse(data)?;
            if !pe::is_x64(info.machine) {
                return Err(error::PackerError::Validation(format!(
                    "input payload is not an x64 PE (machine 0x{:04x})",
                    info.machine
                )));
            }
            let is_dll = pe::is_dll(info.characteristics);
            match format {
                PayloadFormat::Dll if !is_dll => {
                    return Err(error::PackerError::Validation(
                        "build.payload.format is 'dll' but the payload is an executable \
                         (IMAGE_FILE_DLL is not set)"
                            .to_string(),
                    ));
                }
                PayloadFormat::Pe if is_dll => {
                    return Err(error::PackerError::Validation(
                        "build.payload.format is 'pe' but the payload is a DLL; use 'format: dll'"
                            .to_string(),
                    ));
                }
                _ => {}
            }
            Ok(PayloadSummary {
                label: if is_dll { "x64 DLL" } else { "x64 PE" },
                pe: Some(info),
            })
        }
    }
}

/// Fails when the payload does not match `build.payload.sha256`.
///
/// The comparison is case-insensitive hex; the format is already validated in
/// `config::validate`, so a mismatch here means the payload changed.
fn verify_payload_hash(payload: &[u8], expected: Option<&str>) -> Result<()> {
    let Some(expected) = expected else {
        return Ok(());
    };
    let expected = expected.trim();
    let actual = engine::hash::sha256_hex(payload);
    if !actual.eq_ignore_ascii_case(expected) {
        return Err(error::PackerError::Validation(format!(
            "payload sha256 mismatch: config expects {expected}, payload is {actual}"
        )));
    }
    Ok(())
}

/// Prints the resolved configuration (verbose mode).
///
/// Dumping what the YAML resolved to makes a build reproducible from the log
/// alone, without opening the config file.
fn print_config(config: &config::Config, config_path: &Path, ui: &Palette) {
    anstream::println!("{}", ui.heading("CONFIG"));
    anstream::println!("{}", ui.field("name", &config.name));
    anstream::println!("{}", ui.field("config", ui.target(config_path.display())));
    anstream::println!(
        "{}",
        ui.field(
            "source",
            ui.target(describe_source(&config.build.payload.source))
        )
    );
    anstream::println!(
        "{}",
        ui.field("payload args", payload_args_label(&config.build.payload))
    );
    anstream::println!(
        "{}",
        ui.field("output", ui.target(config.build.output.path.display()))
    );
    anstream::println!("{}", ui.field("arch", arch_label(config.build.output.arch)));
    anstream::println!(
        "{}",
        ui.field(
            "strip",
            if config.build.output.strip {
                "yes"
            } else {
                "no"
            }
        )
    );
    anstream::println!(
        "{}",
        ui.field("trim paths", trim_label(config.build.output.trim_paths))
    );
    anstream::println!(
        "{}",
        ui.field("subsystem", config.build.output.subsystem.label())
    );
    anstream::println!("{}", ui.field("stub", stub_label(config)));
    if config.build.stub.debug {
        anstream::println!("{}", ui.field("debug", ui.warn("yes")));
    }
    if let Some(resources) = &config.build.output.resources {
        anstream::println!("{}", ui.field("resources", resources_label(resources)));
    }
    if let Some(sign) = &config.build.output.sign {
        // A lab certificate without a subject takes its name from the generated
        // metadata, so the echo says where the name comes from.
        let derived = sign.mode == "lab"
            && sign.subject.is_none()
            && config
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
    anstream::println!(
        "{}",
        ui.field("runtime", pipeline_chain(ui, &config.runtime))
    );
    anstream::println!("{}", ui.field("schema", config.schema));
    anstream::println!();
}

/// `patch_amsi → reflective_loading`, technique names in the brand color.
fn pipeline_chain(ui: &Palette, pipeline: &[RuntimeStep]) -> String {
    if pipeline.is_empty() {
        return ui.dim("no techniques");
    }
    pipeline
        .iter()
        .map(|step| ui.brand(step.name()))
        .collect::<Vec<_>>()
        .join(&format!(" {} ", ui.dim(glyph::ARROW)))
}

/// Joins already-styled fragments with a faint `·` separator.
fn dotted(ui: &Palette, parts: &[String]) -> String {
    parts.join(&format!(" {} ", ui.faint(glyph::DOT)))
}

/// Lowercase label for the output architecture.
fn arch_label(arch: Arch) -> &'static str {
    match arch {
        Arch::X64 => "x64",
        Arch::X86 => "x86",
    }
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
fn stub_label(config: &config::Config) -> String {
    match &config.build.stub.path {
        Some(path) => format!("custom {}", path.display()),
        None => {
            let mode = stub_mode_label(config);
            format!("builtin (syscalls {mode})")
        }
    }
}

/// Lowercase label of the resolved syscall mode (used by [`stub_label`]).
fn stub_mode_label(config: &config::Config) -> &'static str {
    config
        .build
        .stub
        .syscalls
        .as_ref()
        .map(|s| match s.mode.as_str() {
            "indirect" => "indirect",
            _ => "none",
        })
        .unwrap_or("none")
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

/// First 16 hex digits of a thumbprint, for a compact step line.
fn short_thumbprint(thumbprint: &str) -> String {
    thumbprint.chars().take(16).collect()
}

/// Human summary of `output.sign`.
fn sign_label(sign: &config::schema::SignConfig) -> String {
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

/// Human summary of the configured PE resources (`output.resources`).
fn resources_label(resources: &config::schema::ResourcesConfig) -> String {
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
fn resolve_resources(config: &config::Config) -> Option<config::schema::ResourcesConfig> {
    let resources = config.build.output.resources.as_ref()?;
    let mut resolved = resources.clone();
    if let Some(info) = &resolved.version_info {
        resolved.version_info = Some(engine::identity::apply(info));
    }
    Some(resolved)
}

/// Resolves `output.sign`, deriving the lab certificate subject from the
/// generated company when one is available and no subject was configured.
fn resolve_sign(
    config: &config::Config,
    resources: Option<&config::schema::ResourcesConfig>,
) -> Option<config::schema::SignConfig> {
    let sign = config.build.output.sign.as_ref()?;
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

/// The configured `build.payload.source`, or a placeholder when empty.
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

/// `(none)` or `N (mode)` for the payload's configured runtime arguments.
fn payload_args_label(payload: &PayloadConfig) -> String {
    match &payload.args {
        Some(args) if !args.is_empty() => {
            format!("{} ({})", args.len(), payload.args_mode.label())
        }
        _ => "(none)".to_string(),
    }
}

/// Reads the input payload into memory from its configured source.
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
            "'build.payload.source' uses ftp://, which is not supported; \
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
}
