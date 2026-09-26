//! `engine` module: the packer engine.
//!
//! Phase 4:
//! - `crypto`: payload encryption (XChaCha20-Poly1305).
//! - `pe`: minimal PE parsing/validation.
//! - `stub`: stub rendering from the template.
//! - `obfuscation`: string obfuscation for stub literals.
//! - `compiler`: stub compilation with `rustc`.
//! - `fetch`: in-memory HTTP(S) fetch of the input payload (URL input).
//! - `args`: payload command-line construction and argument spoofing.

pub mod args;
pub mod compiler;
pub mod crypto;
pub mod fetch;
pub mod imports;
pub mod obfuscation;
pub mod pe;
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
        "Falta el target de cross-compile. Instálalo con:\n  rustup target add x86_64-pc-windows-gnu"
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

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// `Result` alias with [`BuildError`] as the error type.
pub type Result<T> = std::result::Result<T, BuildError>;
