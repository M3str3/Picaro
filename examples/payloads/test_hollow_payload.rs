//! Test payload for `process_hollowing`.
//!
//! A hollowed payload runs in a process that has no console, so a marker on
//! stdout cannot be observed from the test runner. This payload writes the
//! marker (and a `thread_local` value) to the file named by its first argument
//! and then exits with `42`, so the stub's relayed exit code is the payload's.
//!
//! The `thread_local` read is deliberate: it fails (garbage instead of `42`, or
//! a crash) when the stub's TLS provisioning for the target thread is wrong.

use std::cell::Cell;

thread_local! {
    static COUNTER: Cell<u32> = const { Cell::new(41) };
}

fn main() {
    let value = COUNTER.with(|counter| {
        counter.set(counter.get() + 1);
        counter.get()
    });
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "hollow_marker.txt".to_string());
    let _ = std::fs::write(&path, format!("PAYLOAD_MARKER_7f3a9c2e tls={value}\n"));
    std::process::exit(42);
}
