//! Packer error types.
//!
//! We use `thiserror` for typed errors with clear messages that can be
//! propagated with `?`, avoiding `panic!`/`unwrap` in the main flow. Each
//! variant maps to a different stage of the process (reading, parsing,
//! validation...).

use std::path::PathBuf;

use crate::audit::AuditError;
use crate::engine::crypto::CryptoError;
use crate::engine::pe::PeError;
use crate::engine::BuildError;

/// Main project error.
#[derive(Debug, thiserror::Error)]
pub enum PackerError {
    /// The configuration file could not be read from disk.
    #[error("could not read config file '{path}': {source}")]
    ReadConfig {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// The input payload (the PE to be packed) could not be read.
    #[error("could not read input payload '{path}': {source}")]
    ReadInput {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// The custom loader stub (`build.stub.path`) could not be read.
    #[error("could not read loader stub '{path}': {source}")]
    ReadLoader {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// The input payload could not be fetched from a URL.
    #[error("could not fetch input payload from '{url}': {source}")]
    FetchInput {
        url: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// The file is not valid YAML or does not match the schema.
    #[error("invalid YAML in '{path}': {source}")]
    ParseConfig {
        path: PathBuf,
        #[source]
        source: serde_yml::Error,
    },

    /// The YAML deserialized correctly but violates a business rule.
    #[error("invalid configuration: {0}")]
    Validation(String),

    /// The input payload is not a valid PE.
    #[error("invalid input PE: {0}")]
    Pe(#[from] PeError),

    /// Error while encrypting/decrypting the payload.
    #[error("payload encryption: {0}")]
    Crypto(#[from] CryptoError),

    /// Build engine error (stub rendering and compilation).
    #[error("build error: {0}")]
    Build(#[from] BuildError),

    /// Generic I/O error during the build flow.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Static audit error.
    #[error("audit error: {0}")]
    Audit(#[from] AuditError),
}

/// `Result` alias used across the crate.
pub type Result<T> = std::result::Result<T, PackerError>;
