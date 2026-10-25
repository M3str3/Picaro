//! `picaro` entry point.
//!
//! The command tree and the build pipeline live in the library
//! ([`picaro::cli`]); keeping the binary thin means the integration tests and
//! the library share one compilation unit.

fn main() {
    picaro::cli::main_entry();
}
