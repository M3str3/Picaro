//! Picaro library.
//!
//! The command tree and the orchestration live in [`cli`]; the binary is a thin
//! wrapper over it. The modules are public so integration tests can exercise
//! the loader and the registries without spawning a subprocess.

pub mod audit;
pub mod cli;
pub mod engine;
pub mod error;
pub mod features;
pub mod pack;
pub mod paths;
pub mod plan;
pub mod techniques;
pub mod ui;
pub mod wizard;
