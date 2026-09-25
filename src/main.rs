//! `batesian` entry point.
//!
//! Three subcommands:
//! - `build`: YAML → encrypt payload → render Rust stub → compile → out.exe.
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

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Instant;

use clap::{CommandFactory, Parser, Subcommand};

use config::schema::{Arch, CryptoAlgorithm, InputConfig, KeySource, TrimPaths};
use engine::{compiler, crypto, obfuscation, pe, stub};
use error::Result;
use techniques::PipelineStep;
use ui::{format_elapsed, glyph, human_size, Palette};

/// Extra help printed under the generated usage block.
const AFTER_HELP: &str = "\
Examples:
  batesian build examples/configs/mimikatz.yaml
  batesian audit dist/test_amsi_patch.exe --focus imports,strings
  batesian techniques list

Colors are disabled automatically when the output is not a terminal; set
NO_COLOR=1 (or pass --no-color) to disable them explicitly. Pass -q (or
--quiet) to skip the banner, and -v (or --verbose) to print per-step build
detail (paths, sizes, timings).";

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
    /// Build a packed PE from a YAML configuration file.
    Build {
        /// Path to the YAML configuration file.
        #[arg(value_name = "CONFIG")]
        config: PathBuf,

        /// Positional arguments referenced by the YAML as `$build.N$`.
        #[arg(value_name = "ARG")]
        args: Vec<String>,
    },

    /// Run a static audit of a PE and print a readable report.
    Audit {
        /// Path to the PE to analyze.
        #[arg(value_name = "BINARY")]
        binary: PathBuf,

        /// Comma-separated sections to report (e.g. "imports,strings").
        #[arg(long)]
        focus: Option<String>,
    },

    /// Inspect the technique registry.
    Techniques {
        #[command(subcommand)]
        command: TechniquesCommand,
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
    // error message, with no `unwrap`/`panic` traces.
    if let Err(err) = run() {
        let ui = Palette::auto();
        anstream::eprintln!("{} {}", ui.cross(), ui.error(format!("error: {err}")));
        std::process::exit(1);
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
        Commands::Build { config, args } => {
            let config_path = config.clone();
            let config = config::load_config(&config, &args)?;
            build(&config, &args, &config_path, &ui, cli.verbose)?;
        }
        Commands::Audit { binary, focus } => {
            let report = audit::run(&binary, focus.as_deref(), &ui)?;
            anstream::print!("{report}");
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
/// timings; the compact form stays on one line per step.
fn build(
    config: &config::Config,
    args: &[String],
    config_path: &Path,
    ui: &Palette,
    verbose: bool,
) -> Result<()> {
    let started = Instant::now();

    anstream::println!("{}", ui.command_line("build", config_path.display()));
    anstream::println!();

    if verbose {
        print_config(config, config_path, ui);
    }

    // 1. Read the input payload and validate that it is an x64 PE (fail early).
    let timer = Instant::now();
    let plaintext = load_input(&config.input)?;
    let pe_info = pe::parse(&plaintext)?;
    if !pe::is_x64(pe_info.machine) {
        return Err(error::PackerError::Validation(format!(
            "input payload is not an x64 PE (machine 0x{:04x})",
            pe_info.machine
        )));
    }
    let read_time = timer.elapsed();
    anstream::println!(
        "{}",
        ui.done(
            "read",
            dotted(
                ui,
                &[
                    ui.target(describe_input(&config.input)),
                    ui.dim("x64 PE"),
                    human_size(plaintext.len()),
                ]
            )
        )
    );
    if verbose {
        anstream::println!(
            "{}",
            ui.detail("machine", ui.dim(format!("0x{:04x}", pe_info.machine)))
        );
        anstream::println!("{}", ui.detail("time", ui.dim(format_elapsed(read_time))));
    }

    // 2. Derive the key and encrypt the payload with XChaCha20-Poly1305.
    let timer = Instant::now();
    let key = match config.payload.crypto.key {
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
                    ui.brand(crypto_label(config.payload.crypto.algo)),
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

    // 3. Per-build marker and the string-obfuscation configuration.
    let stub_marker = stub::generate_stub_marker();
    if config.payload.strings.is_none() {
        anstream::eprintln!(
            "  {} {}",
            ui.bang(),
            ui.warn("obfuscation.strings not specified, defaulting to xor+random")
        );
    }
    let strings = obfuscation::StringsConfig::from_yaml(config.payload.strings.as_ref())?;

    // 4. Prepare `build/` and write the ciphertext the builtin template embeds.
    let timer = Instant::now();
    let build_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("build");
    prepare_build_dir(&build_dir)?;
    std::fs::write(build_dir.join("payload.bin"), &encrypted.ciphertext)?;

    // 5. Load the stub template: the builtin one, or a custom loader stub.
    //    A custom stub receives the payload as `$PAYLOAD_BYTES$` and does not
    //    need `build/payload.bin`.
    let (template, template_display, is_custom) = match &config.loader {
        Some(loader) => {
            let source = std::fs::read_to_string(&loader.path).map_err(|source| {
                error::PackerError::ReadLoader {
                    path: loader.path.clone(),
                    source,
                }
            })?;
            let display = format!("custom {} {}", glyph::DOT, loader.path.display());
            (source, display, true)
        }
        None => {
            let relative = "templates/stub/main.rs.tpl";
            let template_path = Path::new(env!("CARGO_MANIFEST_DIR")).join(relative);
            let display = format!("builtin {} {relative}", glyph::DOT);
            (std::fs::read_to_string(&template_path)?, display, false)
        }
    };

    let build_args: BTreeMap<String, String> = args
        .iter()
        .enumerate()
        .map(|(index, value)| (index.to_string(), value.clone()))
        .collect();

    let params = stub::StubParams {
        nonce: encrypted.nonce,
        key: encrypted.key,
        ciphertext: encrypted.ciphertext.clone(),
        plaintext_len: encrypted.plaintext_len,
        stub_marker: stub_marker.clone(),
        payload_path: "payload.bin".to_string(),
        build_args,
    };

    let stub_src = if is_custom {
        stub::validate_custom_stub_template(&template)?;
        let rendered = stub::render_custom_stub(&template, &params, &config.pipeline, &strings)?;
        for warning in &rendered.warnings {
            anstream::eprintln!("  {} {}", ui.bang(), ui.warn(format!("warning: {warning}")));
        }
        rendered.source
    } else {
        stub::render_main_rs(&template, &params, &config.pipeline, &strings)?
    };
    let stub_path = build_dir.join("main.rs");
    std::fs::write(&stub_path, &stub_src)?;
    let stub_time = timer.elapsed();

    anstream::println!(
        "{}",
        ui.done(
            "stub",
            dotted(
                ui,
                &[
                    pipeline_chain(ui, &config.pipeline),
                    format!("{} {}", ui.dim("strings"), strings.strategy.label()),
                ]
            )
        )
    );
    if verbose {
        anstream::println!("{}", ui.detail("template", ui.dim(&template_display)));
        anstream::println!("{}", ui.detail("marker", ui.dim(&stub_marker)));
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
    compiler::compile_stub(&stub_path, &out, &deps)?;
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

    // 7. Copy `out.exe` to the output path from the YAML.
    if let Some(parent) = config.output.path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    std::fs::copy(&out, &config.output.path)?;
    let out_size = std::fs::metadata(&config.output.path)?.len() as usize;
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
                    ui.target(config.output.path.display().to_string()),
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
        ui.field("input", ui.target(describe_input(&config.input)))
    );
    anstream::println!(
        "{}",
        ui.field("output", ui.target(config.output.path.display()))
    );
    anstream::println!("{}", ui.field("arch", arch_label(config.output.arch)));
    anstream::println!(
        "{}",
        ui.field("strip", if config.output.strip { "yes" } else { "no" })
    );
    anstream::println!(
        "{}",
        ui.field("trim paths", trim_label(config.output.trim_paths))
    );
    anstream::println!("{}", ui.field("loader", loader_label(config)));
    anstream::println!("{}", ui.field("schema", config.schema));
    anstream::println!();
}

/// `patch_amsi → reflective_loading`, technique names in the brand color.
fn pipeline_chain(ui: &Palette, pipeline: &[PipelineStep]) -> String {
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

/// Which stub template the build resolved to.
fn loader_label(config: &config::Config) -> String {
    match &config.loader {
        Some(loader) => format!("custom {}", loader.path.display()),
        None => "builtin (templates/stub/main.rs.tpl)".to_string(),
    }
}

/// `input.path` or `input.url`, however the payload is configured.
fn describe_input(input: &InputConfig) -> String {
    match (input.path.as_ref(), input.url.as_ref()) {
        (Some(path), _) => path.display().to_string(),
        (None, Some(url)) => url.clone(),
        _ => "(unspecified)".to_string(),
    }
}

/// Lowercase label for the crypto algorithm, as printed by `build`.
fn crypto_label(algo: CryptoAlgorithm) -> &'static str {
    match algo {
        CryptoAlgorithm::XChaCha20Poly1305 => "xchacha20poly1305",
    }
}

/// Reads the input payload into memory from its configured source.
///
/// A `path` is read from disk; a `url` is fetched over HTTP(S) without writing
/// to disk. Validation has already guaranteed exactly one of the two is set.
fn load_input(input: &InputConfig) -> Result<Vec<u8>> {
    match (input.path.as_ref(), input.url.as_ref()) {
        (Some(path), None) => std::fs::read(path).map_err(|source| error::PackerError::ReadInput {
            path: path.clone(),
            source,
        }),
        (None, Some(url)) => engine::fetch::fetch_url(url),
        _ => Err(error::PackerError::Validation(
            "'input' must set exactly one of 'path' or 'url'".to_string(),
        )),
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
