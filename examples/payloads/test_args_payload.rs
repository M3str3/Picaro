//! Test payload: prints its own command-line arguments.
//!
//! Used by the `#[ignore]` payload-argument e2e tests and the manual checks in
//! `examples/README.md`. It prints one argument per line between two markers so
//! a caller can parse the exact `argv` the payload received, plus the raw
//! `GetCommandLineW` value (the PEB command line the stub rewrote). It opens no
//! dialog, so a reflective-loading run never blocks and its stdout can be
//! captured.
//!
//! Build it with `examples/payloads/build_args_payload.ps1`.

use std::io::Write;

extern "system" {
    /// Returns the process command line (backed by the PEB).
    fn GetCommandLineW() -> *const u16;
}

/// Converts a NUL-terminated wide string into an owned `String`.
fn wide_to_string(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    unsafe {
        while *ptr.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len))
    }
}

fn main() {
    let mut stdout = std::io::stdout();
    // Ignore write errors: a payload run in a hollowed process has no console.
    let _ = writeln!(stdout, "ARGS_BEGIN");
    for arg in std::env::args() {
        let _ = writeln!(stdout, "{arg}");
    }
    let _ = writeln!(stdout, "ARGS_END");
    let raw = unsafe { wide_to_string(GetCommandLineW()) };
    let _ = writeln!(stdout, "CMDLINE_BEGIN");
    let _ = writeln!(stdout, "{raw}");
    let _ = writeln!(stdout, "CMDLINE_END");
    let _ = stdout.flush();
}
