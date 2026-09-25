//! Minimal x64 Windows PE used as a test fixture for the PE parser.
//!
//! Compiled once with `rustc --target x86_64-pc-windows-gnu` (see
//! `scripts/build_test_fixture.sh`). The committed `minimal_x64.exe` keeps the
//! parser tests independent of a working MinGW toolchain on every machine.
//!
//! It does nothing: it is only exercised by the static parser, never executed.

#![no_main]
#![no_std]

use core::panic::PanicInfo;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

/// Entry point called by the MinGW CRT's `mainCRTStartup`. It never returns.
#[no_mangle]
pub extern "C" fn main() -> i32 {
    loop {}
}
