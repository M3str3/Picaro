//! `engine` module: the packer engine.
//!
//! Phase 4:
//! - `crypto`: payload encryption (XChaCha20-Poly1305).
//! - `pe`: minimal PE parsing/validation.
//! - `stub`: stub rendering from the template.
//! - `debug`: the `tech_dbg!` trace macro appended to a debug stub.
//! - `obfuscation`: string obfuscation for stub literals.
//! - `compiler`: stub compilation with `rustc`.
//! - `fetch`: in-memory HTTP(S) fetch of the input payload (URL input).
//! - `api_resolution`: how the loader resolves the payload's imports
//!   (`build.stub.api_resolution`) — the proxy catalogue and its validation.
//! - `args`: payload command-line construction and argument spoofing.
//! - `manifest`: the build manifest (provenance record written next to the
//!   artifact).
//! - `hash`: SHA-256 for provenance and payload pinning.
//! - `identity`: plausible randomized metadata (company, product, versions).
//! - `resources`: PE resources (icon, `VERSIONINFO`, application manifest)
//!   built in Rust and written into a `.rsrc` section.
//! - `signing`: optional Authenticode signing of the artifact (`signtool` on
//!   Windows, `osslsigncode` elsewhere, including the Docker image).

pub mod api_resolution;
pub mod args;
pub mod compiler;
pub mod crypto;
pub mod debug;
pub mod fetch;
pub mod hash;
pub mod identity;
pub mod imports;
pub mod manifest;
pub mod obfuscation;
pub mod pe;
pub mod resources;
pub mod signing;
pub mod stub;
pub mod syscalls;

/// Build engine error (stub rendering and compilation).
#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    /// The stub template is invalid (missing or unsubstituted placeholder).
    #[error("invalid stub template: {0}")]
    InvalidTemplate(String),

    /// `rustc` is not available in the PATH.
    #[error("rustc is not available: {0}")]
    RustcNotFound(String),

    /// A required `.rlib` could not be located.
    #[error("could not locate the .rlib for '{crate_name}': {detail}")]
    RlibNotFound { crate_name: String, detail: String },

    /// The `x86_64-pc-windows-gnu` cross-compilation target is not installed.
    #[error(
        "the cross-compilation target is missing. Install it with:\n  rustup target add x86_64-pc-windows-gnu"
    )]
    MissingCrossTarget,

    /// The Windows native import lib could not be located.
    #[error("could not locate the Windows import lib: {0}")]
    WindowsImportLibNotFound(String),

    /// The stub compilation failed.
    #[error("stub compilation failed:\n{0}")]
    CompilationFailed(String),

    /// The compiled stub is not a Windows PE (it lacks the `MZ` header).
    #[error("the compiled stub is not a Windows PE (missing 'MZ' header): {0}")]
    NotPeExecutable(String),

    /// `rustc --version` could not be read (build provenance).
    #[error("could not read the rustc version: {0}")]
    RustcVersion(String),

    /// The build manifest could not be serialized.
    #[error("could not serialize the build manifest: {0}")]
    Manifest(String),

    /// PE resource embedding failed (icon, version info or manifest).
    #[error("could not embed PE resources: {0}")]
    Resource(#[from] resources::ResourceError),

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// `Result` alias with [`BuildError`] as the error type.
pub type Result<T> = std::result::Result<T, BuildError>;
