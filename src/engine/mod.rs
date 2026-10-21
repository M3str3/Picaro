//! `engine` module: the packer engine.
//!
//! Phase 4:
//! - `crypto`: payload encryption (XChaCha20-Poly1305).
//! - `pe`: minimal PE parsing/validation.
//! - `stub`: stub rendering from the template.
//! - `debug`: the `tech_dbg!` trace macro appended to a debug stub.
//! - `obfuscation`: string obfuscation for stub literals.
//! - `polymorphism`: per-build diversity (the seeded codegen profile) so two
//!   builds of one plan do not share a `.text`.
//! - `compiler`: stub compilation with `rustc`.
//! - `entry`: the stub's entry point (`fn main` or the DLL's exports,
//!   selected by `build.output.kind`).
//! - `fetch`: in-memory HTTP(S) fetch of the input payload (URL input).
//! - `api_resolution`: how the loader resolves the payload's imports
//!   (`build.stub.api_resolution`) — the proxy catalogue and its validation.
//! - `args`: payload command-line construction and argument spoofing.
//! - `build_lock`: a dependency-free per-output lock that serializes the
//!   copy/sign/manifest section of concurrent builds targeting one artifact.
//! - `manifest`: the build manifest (provenance record written next to the
//!   artifact).
//! - `hash`: SHA-256 for provenance and payload pinning.
//! - `identity`: plausible randomized metadata (company, product, versions).
//! - `resources`: PE resources (icon, `VERSIONINFO`, application manifest)
//!   built in Rust and written into a `.rsrc` section.
//! - `signing`: optional Authenticode signing of the artifact (`signtool` on
//!   Windows, `osslsigncode` elsewhere, including the Docker image).
//! - `scrub`: overwrites build-path literals the compiler remap cannot reach
//!   (the scratch dir outside the manifest dir, and paths baked into precompiled
//!   dependency rlibs), in place and with a per-build filler.

pub mod api_resolution;
pub mod args;
pub mod build_lock;
pub mod compiler;
pub mod crypto;
pub mod debug;
pub mod entry;
pub mod fetch;
pub mod hash;
pub mod identity;
pub mod imports;
pub mod managed;
pub mod manifest;
pub mod obfuscation;
pub mod pe;
pub mod polymorphism;
pub mod resources;
pub mod scrub;
pub mod shellcode;
pub mod signing;
pub mod stager;
pub mod steps;
pub mod stub;
pub mod syscalls;
pub mod tls;

/// Build engine error (stub rendering and compilation).
#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    /// The .NET Framework C# compiler (`csc.exe`) is not available.
    #[error("the .NET Framework compiler (csc.exe) is not available: {0}")]
    DotnetCompilerNotFound(String),

    /// Windows PowerShell's engine assembly could not be located.
    #[error("Windows PowerShell is not available: {0}")]
    PowershellAssemblyNotFound(String),

    /// The generated managed launcher failed to compile.
    #[error("managed launcher compilation failed:\n{0}")]
    ManagedCompilationFailed(String),

    /// The stub template is invalid (missing or unsubstituted placeholder).
    #[error("invalid stub template: {0}")]
    InvalidTemplate(String),

    /// `rustc` is not available in the PATH.
    #[error("rustc is not available: {0}")]
    RustcNotFound(String),

    /// A required `.rlib` could not be located.
    #[error("could not locate the .rlib for '{crate_name}': {detail}")]
    RlibNotFound { crate_name: String, detail: String },

    /// The requested stub target is not installed or its dependencies have not
    /// been built for it.
    #[error(
        "the '{target}' target is not available. Install and build it with:\n  rustup target add {target}\n  cargo build --target {target}"
    )]
    MissingTarget { target: String },

    /// The Windows native import lib could not be located.
    #[error("could not locate the Windows import lib: {0}")]
    WindowsImportLibNotFound(String),

    /// The stub compilation failed.
    #[error("stub compilation failed:\n{0}")]
    CompilationFailed(String),

    /// The compiled stub is not a Windows PE (it lacks the `MZ` header).
    #[error("the compiled stub is not a Windows PE (missing 'MZ' header): {0}")]
    NotPeExecutable(String),

    /// The sRDI converter (a `ConvertToShellcode.py` on `PICARO_SRDI`) is not
    /// available.
    #[error("the sRDI converter is not available: {0}")]
    ShellcodeConverterNotFound(String),

    /// The sRDI converter ran but did not produce shellcode.
    #[error("shellcode conversion failed: {0}")]
    ShellcodeConversionFailed(String),

    /// `rustc --version` could not be read (build provenance).
    #[error("could not read the rustc version: {0}")]
    RustcVersion(String),

    /// The build manifest could not be serialized.
    #[error("could not serialize the build manifest: {0}")]
    Manifest(String),

    /// `build.polymorphism` is invalid (e.g. a non-positive `codegen-units`).
    #[error("invalid build.polymorphism: {0}")]
    InvalidPolymorphism(String),

    /// PE resource embedding failed (icon, version info or manifest).
    #[error("could not embed PE resources: {0}")]
    Resource(#[from] resources::ResourceError),

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// `Result` alias with [`BuildError`] as the error type.
pub type Result<T> = std::result::Result<T, BuildError>;
