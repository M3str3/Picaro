//! Test payload: prints a fixed marker.
//!
//! It is a minimal binary with no external dependencies, so that
//! `build_test_payload.ps1` can compile it with a single `rustc`. It prints its
//! marker to stdout instead of opening a modal dialog: automated runs stay
//! observable (a modal `MessageBox` blocks until it is dismissed and is not
//! visible to a headless agent). The marker `PAYLOAD_MARKER_7f3a9c2e` is used to
//! verify that the payload arrives intact after packing (and that it does not
//! appear in cleartext inside the final binary).

use std::io::Write;

const MARKER: &str = "PAYLOAD_MARKER_7f3a9c2e";

fn main() {
    // Ignore write errors on purpose: a hollowed payload runs in a process
    // without an inherited console, and a failed print must not abort it.
    let mut stdout = std::io::stdout();
    let _ = writeln!(stdout, "{MARKER}");
    let _ = stdout.flush();
}
