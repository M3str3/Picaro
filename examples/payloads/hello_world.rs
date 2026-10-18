//! Example payload: prints `Hello, world!`.
//!
//! It is the smallest useful payload to pack: no dependencies, one `rustc` call,
//! and a single observable line on stdout. That makes it the first thing to try
//! when validating a new plan — if the line arrives, the whole pipeline (embed,
//! encrypt, decrypt, map or hollow, run) worked.
//!
//! It differs from `msgbox.rs` on purpose: that one is the *visible* check and
//! blocks on a modal dialog, while this one is the *scriptable* check and exits
//! immediately. It also differs from `test_payload.rs` in that it has no marker
//! to grep for; the output is the message itself.
//!
//! Build it with `examples/payloads/build_hello_world.ps1`.

use std::io::Write;

fn main() {
    // Ignore write errors on purpose: under process hollowing the payload runs
    // in a process without an inherited console, and a failed print must not
    // abort it. Flush explicitly because stdout is block-buffered when it is
    // redirected to a pipe or a file.
    let mut stdout = std::io::stdout();
    let _ = writeln!(stdout, "Hello, world!");
    let _ = stdout.flush();
}
