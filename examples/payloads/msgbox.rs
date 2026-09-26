//! Test payload: opens a "Hello world" message box.
//!
//! It is the visible counterpart of `test_payload.rs`. That one *prints* a marker
//! so a headless run stays observable; this one blocks on a modal dialog, which
//! makes it the manual check that a payload is really running: under process
//! hollowing the dialog appears from `svchost.exe`, and under reflective loading
//! from the packed stub's own process.
//!
//! It needs nothing beyond `user32.dll`, so `build_msgbox.ps1` compiles it with a
//! single `rustc` call (no Cargo, no `--extern`).
//!
//! Build it with `examples/payloads/build_msgbox.ps1`.

// A payload is not stub code: it never goes through `StringsConfig`, so the
// literals can stay in cleartext.
const TEXT: &str = "Hello world";
const CAPTION: &str = "batesian payload";

// `MB_OK | MB_ICONINFORMATION`.
const MB_OK: u32 = 0x0000_0000;
const MB_ICONINFORMATION: u32 = 0x0000_0040;

// Payloads are built with a bare `rustc`, which has no way to link the `windows`
// crate, so this is the "absolutely necessary" raw FFI case; it stays behind the
// safe `message_box` wrapper below.
extern "system" {
    /// Shows a modal message box and returns the id of the button pressed.
    fn MessageBoxW(
        hwnd: *mut core::ffi::c_void,
        text: *const u16,
        caption: *const u16,
        u_type: u32,
    ) -> i32;
}

/// Encodes `s` for `MessageBoxW`, which takes NUL-terminated UTF-16.
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Shows a message box with `text` as its body and `caption` in its title bar.
///
/// A null owner window is deliberate: the dialog belongs to no other window, so
/// it shows up regardless of which process hosts the payload.
fn message_box(text: &str, caption: &str) -> i32 {
    let text = wide(text);
    let caption = wide(caption);
    // SAFETY: both buffers are NUL-terminated and outlive the call, and a null
    // `hwnd` is a documented "no owner" value.
    unsafe {
        MessageBoxW(
            core::ptr::null_mut(),
            text.as_ptr(),
            caption.as_ptr(),
            MB_OK | MB_ICONINFORMATION,
        )
    }
}

fn main() {
    // The call blocks until the dialog is dismissed. The button id is not
    // interesting, so the payload exits with the default status.
    let _ = message_box(TEXT, CAPTION);
}
