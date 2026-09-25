//! Test payload: shows a `MessageBoxA` with a fixed marker.
//!
//! It is a minimal binary with no external dependencies, so that
//! `build_test_payload.ps1` can compile it with a single `rustc`. The marker
//! `PAYLOAD_MARKER_7f3a9c2e` is used to verify that the payload arrives intact
//! after packing (and that it does not appear in cleartext inside the final
//! binary).

use std::ffi::c_void;

#[link(name = "user32")]
extern "system" {
    fn MessageBoxA(
        hwnd: *mut c_void,
        lp_text: *const u8,
        lp_caption: *const u8,
        u_type: u32,
    ) -> i32;
}

fn main() {
    let text = b"PAYLOAD_MARKER_7f3a9c2e\0";
    let caption = b"Payload\0";

    unsafe {
        MessageBoxA(
            std::ptr::null_mut(),
            text.as_ptr(),
            caption.as_ptr(),
            0, // MB_OK
        );
    }
}
