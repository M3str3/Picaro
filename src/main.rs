//! Packer entry point.
//!
//! Two subcommands:
//! - `build`: YAML → encrypt payload → render Rust stub → compile → out.exe.
//! - `audit`: static analysis of a PE (measurement infrastructure).

mod audit;
mod config;
mod engine;
mod error;
mod techniques;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};

use config::schema::{CryptoAlgorithm, InputConfig, KeySource};
use engine::{compiler, crypto, obfuscation, pe, stub};
use error::Result;

/// `packerman` CLI.
#[derive(Debug, Parser)]
#[command(
    name = "packerman",
    version,
    about = "Declarative PE packer for authorized red team research",
    arg_required_else_help = true
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

/// Available subcommands.
#[derive(Debug, Subcommand)]
enum Commands {
    /// Build a packed PE from a YAML configuration file.
    Build {
        /// Path to the YAML configuration file.
        #[arg(value_name = "CONFIG")]
        config: PathBuf,

        /// Positional arguments referenced by the YAML as `{{build.N}}`.
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

/// Subcommands of `packerman techniques`.
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
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

/// Main logic, split from `main` so it can return `Result`.
fn run() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Build { config, args } => {
            let config = config::load_config(&config, &args)?;
            build(&config, &args)?;
        }
        Commands::Audit { binary, focus } => {
            let report = audit::run(&binary, focus.as_deref())?;
            println!("{report}");
        }
        Commands::Techniques { command } => match command {
            TechniquesCommand::List => print!("{}", techniques::list()),
            TechniquesCommand::Show { name } => print!("{}", techniques::show(&name)?),
            TechniquesCommand::Validate => {
                let problems = techniques::validate();
                if problems.is_empty() {
                    println!("All techniques OK.");
                } else {
                    for problem in &problems {
                        eprintln!("warning: {problem}");
                    }
                }
            }
        },
    }

    Ok(())
}

/// Runs the full packing flow.
fn build(config: &config::Config, args: &[String]) -> Result<()> {
    // 1. Read the input payload (from a local file, or in memory from a URL).
    let plaintext = load_input(&config.input)?;

    // 2. Validate that it is a valid x64 PE (fail early).
    let pe_info = pe::parse(&plaintext)?;
    if !pe::is_x64(pe_info.machine) {
        return Err(error::PackerError::Validation(format!(
            "input payload is not an x64 PE (machine 0x{:04x})",
            pe_info.machine
        )));
    }

    // 3. Derive the key according to the configuration (`random` only, for now).
    let key = match config.payload.crypto.key {
        KeySource::Random => crypto::generate_key(),
    };

    // 4. Encrypt with XChaCha20-Poly1305.
    let encrypted = crypto::encrypt_payload(&plaintext, &key)?;

    // 5. Per-build unique marker.
    let stub_marker = stub::generate_stub_marker();

    // 5b. String obfuscation config (defaults to xor+random if unspecified).
    if config.payload.strings.is_none() {
        eprintln!("obfuscation.strings not specified, defaulting to xor+random");
    }
    let strings = obfuscation::StringsConfig::from_yaml(config.payload.strings.as_ref())?;

    // 6. Prepare `build/` (wipe it first if it existed).
    let build_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("build");
    prepare_build_dir(&build_dir)?;

    // 8. Write `build/payload.bin` (the ciphertext).
    std::fs::write(build_dir.join("payload.bin"), &encrypted.ciphertext)?;

    // 9. Load the stub template: the builtin one, or a custom loader stub.
    //    The payload bytes are written to `build/payload.bin` so the builtin
    //    template's `include_bytes!` works; a custom stub uses `{{PAYLOAD_BYTES}}`
    //    (an inline array literal) and does not need that file.
    let (template, is_custom) = match &config.loader {
        Some(loader) => {
            let source = std::fs::read_to_string(&loader.path).map_err(|source| {
                error::PackerError::ReadLoader {
                    path: loader.path.clone(),
                    source,
                }
            })?;
            (source, true)
        }
        None => {
            let template_path = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("templates")
                .join("stub")
                .join("main.rs.tpl");
            (std::fs::read_to_string(&template_path)?, false)
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
        stub_marker,
        payload_path: "payload.bin".to_string(),
        build_args,
    };

    let stub_src = if is_custom {
        stub::validate_custom_stub_template(&template)?;
        let rendered = stub::render_custom_stub(&template, &params, &config.pipeline, &strings)?;
        for warning in &rendered.warnings {
            eprintln!("warning: {warning}");
        }
        rendered.source
    } else {
        stub::render_main_rs(&template, &params, &config.pipeline, &strings)?
    };
    let stub_path = build_dir.join("main.rs");
    std::fs::write(&stub_path, stub_src)?;

    // 10. Locate dependencies and compile the stub.
    let deps = compiler::locate_stub_deps()?;
    let out = build_dir.join("out.exe");
    compiler::compile_stub(&stub_path, &out, &deps)?;

    // 11. Copy `out.exe` to the output path from the YAML.
    if let Some(parent) = config.output.path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    std::fs::copy(&out, &config.output.path)?;

    // 12. Readable summary of the result.
    let algo = match config.payload.crypto.algo {
        CryptoAlgorithm::XChaCha20Poly1305 => "xchacha20poly1305",
    };
    println!("Algorithm:       {algo}");
    println!("Original size:   {} bytes", encrypted.plaintext_len);
    println!("Encrypted size:  {} bytes", encrypted.ciphertext.len());
    println!("Nonce (hex):     {}", hex::encode(encrypted.nonce));
    // The key is only printed in debug builds; never in release.
    #[cfg(debug_assertions)]
    println!("Key (hex):       {}", hex::encode(encrypted.key));
    println!("Strings:         {}", strings.strategy.label());
    // The obfuscation key is only printed in debug builds; never in release.
    #[cfg(debug_assertions)]
    if let Some(key) = strings.key {
        println!("Strings key:     {}", hex::encode(key));
    }
    println!("Output:          {}", config.output.path.display());

    Ok(())
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
