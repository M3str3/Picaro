//! Sleep-hook probe payload.
//!
//! Calls `Sleep` through its IAT (which the stub may replace with the ekko
//! hook) and measures how long it took. The hook's chain encrypts the mapped
//! payload for the duration of the sleep; the caller is parked inside the stub,
//! so the process must survive and the sleep must last at least as long as
//! requested.
//!
//! Compiled by the test with a single `rustc` (no external dependencies).

use std::io::Write;
use std::time::Instant;

#[link(name = "kernel32")]
extern "system" {
    fn Sleep(milliseconds: u32);
}

fn main() {
    let mut out = std::io::stdout();
    let _ = writeln!(out, "SLEEP_PROBE before");
    let _ = out.flush();

    let started = Instant::now();
    unsafe { Sleep(2500) };
    let elapsed = started.elapsed().as_millis();

    let _ = writeln!(out, "SLEEP_PROBE after elapsed={elapsed}");
    let _ = out.flush();
}
