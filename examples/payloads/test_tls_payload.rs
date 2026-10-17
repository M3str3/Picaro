//! Test payload for the mapped-image TLS path.
//!
//! The PE carries one real TLS callback (a pointer placed in `.CRT$XLB`, the
//! section the MSVC linker turns into the image's TLS callback array). The
//! callback writes a marker file when it sees `DLL_PROCESS_ATTACH`, and the
//! entry point writes a second marker and exits `42`.
//!
//! Packed with `process_hollowing` or `pe_injection` — both hand the image to a
//! thread the loader created — the two markers together prove that the stub
//! provisioned the payload's TLS: the callback ran before the entry point.
//!
//! The callback uses raw `kernel32` calls and stack buffers on purpose: TLS
//! callbacks run before the image's CRT is initialized, so it must not depend
//! on `std` (an allocation inside the callback has been measured to kill the
//! target process under a manually mapped image).
//!
//! The callback writes the path named by `PICARO_TLS_MARKER` (inherited from the
//! process that launched the artifact). Without the variable it does nothing, so
//! running the fixture standalone stays silent.

const TLS_MARKER: &[u8] = b"TLS_CALLBACK_MARKER_3b1f9d\n";
const MAIN_MARKER: &str = "MAIN_ENTRY_MARKER_a1c2e4";

/// The environment variable that names the TLS marker file, UTF-16 with its
/// NUL terminator (built by hand: the callback must not allocate).
const MARKER_VAR_UTF16: [u16; 18] = [
    b'P' as u16,
    b'I' as u16,
    b'C' as u16,
    b'A' as u16,
    b'R' as u16,
    b'O' as u16,
    b'_' as u16,
    b'T' as u16,
    b'L' as u16,
    b'S' as u16,
    b'_' as u16,
    b'M' as u16,
    b'A' as u16,
    b'R' as u16,
    b'K' as u16,
    b'E' as u16,
    b'R' as u16,
    0,
];

type Handle = isize;
const INVALID_HANDLE: Handle = -1;
const GENERIC_WRITE: u32 = 0x4000_0000;
const FILE_SHARE_READ: u32 = 1;
const CREATE_ALWAYS: u32 = 2;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
const DLL_PROCESS_ATTACH: u32 = 1;

#[link(name = "kernel32")]
extern "system" {
    fn GetEnvironmentVariableW(name: *const u16, buf: *mut u16, size: u32) -> u32;
    fn CreateFileW(
        name: *const u16,
        access: u32,
        share: u32,
        attributes: *const core::ffi::c_void,
        disposition: u32,
        flags: u32,
        template: Handle,
    ) -> Handle;
    fn WriteFile(
        file: Handle,
        buf: *const u8,
        size: u32,
        written: *mut u32,
        overlapped: *const core::ffi::c_void,
    ) -> i32;
    fn CloseHandle(handle: Handle) -> i32;
}

/// The TLS callback: writes the TLS marker file on process attach.
unsafe extern "system" fn tls_callback(_module: *mut u8, reason: u32, _reserved: *mut u8) {
    if reason != DLL_PROCESS_ATTACH {
        return;
    }
    let mut buf = [0u16; 512];
    let len = GetEnvironmentVariableW(
        MARKER_VAR_UTF16.as_ptr(),
        buf.as_mut_ptr(),
        buf.len() as u32,
    ) as usize;
    if len == 0 || len >= buf.len() {
        return;
    }
    buf[len] = 0;
    let file = CreateFileW(
        buf.as_ptr(),
        GENERIC_WRITE,
        FILE_SHARE_READ,
        core::ptr::null(),
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        0,
    );
    if file == INVALID_HANDLE {
        return;
    }
    let mut written = 0u32;
    WriteFile(
        file,
        TLS_MARKER.as_ptr(),
        TLS_MARKER.len() as u32,
        &mut written,
        core::ptr::null(),
    );
    CloseHandle(file);
}

/// The callback pointer the linker collects into the TLS callback array.
#[used]
#[link_section = ".CRT$XLB"]
static TLS_CALLBACK: unsafe extern "system" fn(*mut u8, u32, *mut u8) = tls_callback;

fn main() {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "main_marker.txt".to_string());
    let _ = std::fs::write(&path, format!("{MAIN_MARKER}\n"));
    println!("{MAIN_MARKER}");
    std::process::exit(42);
}
