// --- Hide thread from debugger (technique fragment) ---

use windows::Win32::System::Threading::GetCurrentThread;

/// `ThreadHideFromDebugger` (`THREADINFOCLASS` 0x11): the thread raises no debug
/// events, and a debugger attached to the process is detached. The `windows`
/// binding defines the `THREAD_INFORMATION_CLASS` enum but not this member, so
/// the class is built from the documented value.
const THREAD_HIDE_FROM_DEBUGGER: i32 = 0x11;

/// Hides the current thread (the loader's main thread) from any debugger.
///
/// Goes through the syscall layer's `nt_set_info_thread`: kernel32's
/// `SetThreadInformation` rejects class 0x11 with `ERROR_INVALID_PARAMETER`
/// (`0x57`) on Windows 11 26200 — measured against the native call, which
/// returns `STATUS_SUCCESS` — and a kernel-facing call belongs behind `nt_*`
/// anyway, so `build.stub.syscalls.mode: indirect` routes it through the
/// gadget as well.
pub fn hide_thread_from_debugger() -> Result<bool, String> {
    let thread = unsafe { GetCurrentThread() };
    let status = crate::nt_set_info_thread(thread, THREAD_HIDE_FROM_DEBUGGER, std::ptr::null(), 0);
    if status < 0 {
        return Err($MSG_HIDE_FAILED$);
    }
    crate::tech_dbg!(
        "hide_thread_from_debugger",
        "the main thread no longer raises debug events"
    );
    // A Preparation always continues the pipeline when it does not error.
    Ok(true)
}
