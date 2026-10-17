//! In-process observation payload for the preparation techniques.
//!
//! Packed with `reflective_loading` (or any in-process Execution technique), it
//! runs inside the stub's process, where a Preparation's effect is observable.
//! It prints one `PROBE ...` line per observation and exits `0`:
//!
//! - `self` — the image path `GetModuleFileNameW(NULL)` reports, whether the
//!   loader's own module is listed by the userland module enumerator, and
//!   whether the in-memory PE header at the image base is intact.
//! - `load <path>` — whether an unsigned DLL can be loaded into this process.
//! - `amsi` — the HRESULT and out-parameter an `AmsiScanBuffer` call with a
//!   **null** context returns. The real `amsi.dll` rejects the call before any
//!   provider runs; a trap that answers at the function's entry returns `S_OK`.
//!
//! Compiled by the tests with a single `rustc` (no external dependencies).

use std::io::Write;

type Bool = i32;
type Handle = isize;

#[link(name = "kernel32")]
extern "system" {
    fn GetCurrentProcess() -> Handle;
    fn GetModuleHandleW(name: *const u16) -> Handle;
    fn GetModuleFileNameW(module: Handle, buf: *mut u16, size: u32) -> u32;
    fn K32EnumProcessModules(
        process: Handle,
        modules: *mut Handle,
        size: u32,
        needed: *mut u32,
    ) -> Bool;
    fn LoadLibraryA(name: *const u8) -> Handle;
    fn LoadLibraryW(name: *const u16) -> Handle;
    fn GetProcAddress(module: Handle, name: *const u8) -> isize;
    fn GetLastError() -> u32;
}

/// A NUL-terminated wide string.
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// The path `GetModuleFileNameW(NULL)` reports for the running image.
fn image_path() -> String {
    let mut buf = [0u16; 1024];
    let len = unsafe { GetModuleFileNameW(0, buf.as_mut_ptr(), buf.len() as u32) } as usize;
    String::from_utf16_lossy(&buf[..len.min(buf.len())])
}

/// The PEB's `ProcessParameters->ImagePathName`, read directly — the field
/// `image_path_spoofing` rewrites. `GetModuleFileNameW(NULL)` is compared
/// against it to tell a failed write from an API that reads elsewhere.
fn peb_image_path() -> String {
    const PROCESS_PARAMETERS_OFFSET: usize = if cfg!(target_arch = "x86") { 0x10 } else { 0x20 };
    const IMAGE_PATH_OFFSET: usize = if cfg!(target_arch = "x86") { 0x38 } else { 0x60 };
    const BUFFER_OFFSET: usize = if cfg!(target_arch = "x86") { 0x04 } else { 0x08 };
    unsafe {
        let peb: *mut u8;
        #[cfg(target_arch = "x86_64")]
        core::arch::asm!(
            "mov {}, gs:[0x60]",
            out(reg) peb,
            options(nostack, preserves_flags, readonly)
        );
        #[cfg(target_arch = "x86")]
        core::arch::asm!(
            "mov {}, fs:[0x30]",
            out(reg) peb,
            options(nostack, preserves_flags, readonly)
        );
        if peb.is_null() {
            return "<no peb>".to_string();
        }
        let params = peb.add(PROCESS_PARAMETERS_OFFSET).cast::<*mut u8>().read();
        if params.is_null() {
            return "<no params>".to_string();
        }
        let field = params.add(IMAGE_PATH_OFFSET);
        let length = field.cast::<u16>().read() as usize;
        let buffer = field.add(BUFFER_OFFSET).cast::<*const u16>().read();
        if buffer.is_null() {
            return "<null buffer>".to_string();
        }
        let units = core::slice::from_raw_parts(buffer, length / 2);
        String::from_utf16_lossy(units)
    }
}

/// Whether the module enumerator lists the loader's own module.
fn loader_listed() -> bool {
    let base = unsafe { GetModuleHandleW(std::ptr::null()) };
    let mut modules = [0 as Handle; 512];
    let mut needed = 0u32;
    let ok = unsafe {
        K32EnumProcessModules(
            GetCurrentProcess(),
            modules.as_mut_ptr(),
            (modules.len() * size_of::<Handle>()) as u32,
            &mut needed,
        )
    };
    ok != 0 && modules.iter().any(|&module| module == base)
}

/// Whether the PE header at the image base still carries its DOS/NT signatures.
fn header_state() -> &'static str {
    let base = unsafe { GetModuleHandleW(std::ptr::null()) } as *const u8;
    if base.is_null() {
        return "no-base";
    }
    let mz = unsafe { *base == b'M' && *base.add(1) == b'Z' };
    let mut lfanew_bytes = [0u8; 4];
    for (index, byte) in lfanew_bytes.iter_mut().enumerate() {
        *byte = unsafe { *base.add(0x3C + index) };
    }
    let lfanew = u32::from_le_bytes(lfanew_bytes) as usize;
    let pe = lfanew < 0x1000 && unsafe {
        let nt = base.add(lfanew);
        *nt == b'P' && *nt.add(1) == b'E' && *nt.add(2) == 0 && *nt.add(3) == 0
    };
    if mz && pe {
        "intact"
    } else if !mz && !pe {
        "erased"
    } else {
        "partial"
    }
}

/// Tries to load `path` and reports the outcome (and `GetLastError` on failure).
fn try_load(path: &str) -> String {
    let handle = unsafe { LoadLibraryW(wide(path).as_ptr()) };
    if handle == 0 {
        format!("fail err={}", unsafe { GetLastError() })
    } else {
        "ok".to_string()
    }
}

/// Calls `AmsiScanBuffer(NULL, "x", 1, "probe", NULL, &result)` and returns
/// `(HRESULT, out-parameter)`.
fn amsi_null_context() -> (i32, u32) {
    let amsi = unsafe { LoadLibraryA(b"amsi.dll\0".as_ptr()) };
    if amsi == 0 {
        return (-1, 0);
    }
    let scan = unsafe { GetProcAddress(amsi, b"AmsiScanBuffer\0".as_ptr()) };
    if scan == 0 {
        return (-2, 0);
    }
    type ScanFn = extern "system" fn(
        *mut core::ffi::c_void,
        *const u8,
        u32,
        *const u16,
        *mut core::ffi::c_void,
        *mut u32,
    ) -> i32;
    let scan: ScanFn = unsafe { core::mem::transmute(scan) };
    let mut result: u32 = 0xDEAD_BEEF;
    let content = b"x";
    let name: Vec<u16> = "probe".encode_utf16().collect();
    let hr = scan(
        std::ptr::null_mut(),
        content.as_ptr(),
        1,
        name.as_ptr(),
        std::ptr::null_mut(),
        &mut result,
    );
    (hr, result)
}

fn main() {
    let mut out = std::io::stdout();
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("self") => {
            let _ = writeln!(out, "PROBE image_path={}", image_path());
            let _ = writeln!(out, "PROBE peb_image_path={}", peb_image_path());
            let _ = writeln!(
                out,
                "PROBE loader_listed={}",
                if loader_listed() { "yes" } else { "no" }
            );
            let _ = writeln!(out, "PROBE header={}", header_state());
        }
        Some("load") => {
            let path = args.get(2).cloned().unwrap_or_default();
            let _ = writeln!(out, "PROBE dll_load={}", try_load(&path));
        }
        Some("amsi") => {
            let (hr, result) = amsi_null_context();
            let _ = writeln!(out, "PROBE amsi_status=0x{hr:08X} result=0x{result:08X}");
        }
        _ => {
            let _ = writeln!(
                out,
                "PROBE usage: probe_payload {{self|load <path>|amsi}}"
            );
        }
    }
    let _ = out.flush();
}
