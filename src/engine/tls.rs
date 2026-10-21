//! TLS handoff for shellcode stubs (`$TLS_HANDOFF_BLOCK$`).
//!
//! A `kind: shellcode` stub is mapped by sRDI and never goes through the image
//! loader's TLS pass, so its `_tls_index` keeps the zero the linker left and
//! every `#[thread_local]` access aliases the static-TLS block of the module
//! that owns index 0 on the current thread. Measured (2026-10-21, dotnet host):
//! the host's CRT writes into that block and the stub's first thread-local
//! registration aborts in release (`the global allocator may not use TLS with
//! destructors`); debug builds survive by layout luck. Borrowing a `TlsAlloc`
//! index instead collides numerically with the loader's static module indices
//! (index 1 = KERNELBASE) and corrupts both sides (`docs/measurements.md`).
//!
//! The block below gives the stub an index *past every loaded module's*: a
//! private per-thread array seeded with the loader's entries plus the stub's
//! template block at the fresh index, swapped into
//! `TEB->ThreadLocalStoragePointer` for the calling thread only. [`PauseGuard`]
//! keeps the loader's array in place while modules may load — the import walk
//! and the payload handoff — because `LdrpHandleTlsData` grows the per-thread
//! array when a module with static TLS loads and would treat the private array
//! as a loader-heap block (measured: loading the payload's TLS-bearing imports
//! crashed in ntdll). A resume rebuilds the private array from the loader's
//! *current* array, so a module loaded during the pause also gets its entry.
//! The guards must not span stub diagnostics: a debug stub prints while the
//! array is active, never while paused.
//!
//! The block renders for every output kind but self-gates: nothing happens
//! unless [`provision`] ran, and only a release shellcode render calls it (a
//! debug stub keeps the historical index-0 aliasing its traces were built
//! around). The known limitation: a module with static TLS loaded while the
//! private array is active (no pause around it) makes the loader try to grow
//! an array it does not own, exactly like the historical designs.

pub(crate) const BLOCK: &str = r#"// --- TLS handoff (injected; see engine/tls.rs for the design) ---
#[allow(dead_code)]
mod tls_handoff {
    use core::sync::atomic::{AtomicBool, Ordering};

    /// The installed handoff: `(loader_array, private_array, stub_block, index)`.
    static STATE: std::sync::Mutex<Option<(usize, usize, usize, u32)>> =
        std::sync::Mutex::new(None);
    /// Whether a private array is installed (or installable again).
    static PROVISIONED: AtomicBool = AtomicBool::new(false);

    /// The `STATE` guard: a poisoned mutex still yields the last handoff.
    fn lock_state() -> std::sync::MutexGuard<'static, Option<(usize, usize, usize, u32)>> {
        STATE.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The linker's image base symbol: lets the stub find its own TLS directory
    /// without being a registered module.
    unsafe extern "C" {
        #[link_name = "__ImageBase"]
        static IMAGE_BASE: u8;
    }

    #[cfg(target_arch = "x86_64")]
    #[inline(always)]
    unsafe fn swap_array(array: usize) {
        core::arch::asm!("mov gs:[0x58], {0}", in(reg) array, options(nostack));
    }
    #[cfg(not(target_arch = "x86_64"))]
    unsafe fn swap_array(_array: usize) {}

    #[cfg(target_arch = "x86_64")]
    #[inline(always)]
    unsafe fn read_gs(offset: usize) -> Option<usize> {
        let value: usize;
        core::arch::asm!("mov {0}, gs:[{1}]", out(reg) value, in(reg) offset, options(nostack));
        Some(value)
    }
    #[cfg(not(target_arch = "x86_64"))]
    unsafe fn read_gs(_offset: usize) -> Option<usize> {
        None
    }

    unsafe fn read_u16(at: usize) -> Option<u16> {
        if at == 0 {
            return None;
        }
        Some(core::ptr::read_unaligned(at as *const u16))
    }
    unsafe fn read_u32(at: usize) -> Option<u32> {
        if at == 0 {
            return None;
        }
        Some(core::ptr::read_unaligned(at as *const u32))
    }
    unsafe fn read_u64(at: usize) -> Option<usize> {
        if at == 0 {
            return None;
        }
        Some(core::ptr::read_unaligned(at as *const usize) as usize)
    }
    unsafe fn write_u32(at: usize, value: u32) {
        core::ptr::write_unaligned(at as *mut u32, value);
    }
    unsafe fn write_u64(at: usize, value: usize) {
        core::ptr::write_unaligned(at as *mut usize, value);
    }

    /// Allocates one RW region (direct `VirtualAlloc`: the handoff runs before
    /// the syscall layer is initialized).
    unsafe fn alloc_region(size: usize) -> Option<*mut core::ffi::c_void> {
        use windows::Win32::System::Memory::{
            VirtualAlloc, MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE,
        };
        let base = VirtualAlloc(None, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if base.is_null() {
            return None;
        }
        Some(base)
    }

    /// The stub's own TLS directory: `(template_data, template_size, index_at)`.
    unsafe fn own_tls() -> Option<(usize, usize, usize)> {
        let base = core::ptr::addr_of!(IMAGE_BASE) as usize;
        let nt = base + read_u32(base + 0x3c)? as usize;
        if read_u32(nt)? != 0x4550 {
            return None;
        }
        let opt = nt + 24;
        let preferred = read_u64(opt + 24)?;
        let dd = opt + 112;
        let tls_rva = read_u32(dd + 72)? as usize;
        if tls_rva == 0 {
            return None;
        }
        let tls = base + tls_rva;
        // The MSVC linker bakes absolute VAs into the TLS directory of the
        // on-disk image; a mapped image may sit anywhere, so rebase onto the
        // actual base before touching them.
        let start = read_u64(tls)?;
        let end = read_u64(tls + 8)?;
        let index_va = read_u64(tls + 16)?;
        if start == 0 || end <= start || index_va < preferred || start < preferred {
            return None;
        }
        let index_at = base + (index_va - preferred);
        Some((base + (start - preferred), end - start, index_at))
    }

    /// The static TLS index of a loaded module at `base`, from its in-memory TLS
    /// directory. The loader patches `AddressOfIndex` to an absolute VA on load;
    /// a value below 4 GB is treated as an RVA of the module that carries it.
    unsafe fn module_tls_index(base: usize) -> Option<u32> {
        if read_u16(base)? != 0x5a4d {
            return None;
        }
        let nt = base + read_u32(base + 0x3c)? as usize;
        if read_u32(nt)? != 0x4550 {
            return None;
        }
        let magic = read_u16(nt + 24)?;
        let dd = nt + 24 + if magic == 0x20b { 112 } else { 96 };
        let tls_rva = read_u32(dd + 72)? as usize;
        if tls_rva == 0 {
            return None;
        }
        let mut index_addr = read_u64(base + tls_rva + 16)?;
        if index_addr < 0x1_0000_0000 {
            index_addr += base;
        }
        read_u32(index_addr)
    }

    /// The highest static TLS index among the loaded modules (the PEB walk the
    /// image loader numbers its indices from).
    unsafe fn highest_tls_index() -> Option<u32> {
        let peb = read_gs(0x60)?;
        let ldr = read_u64(peb + 0x18)?;
        let head = ldr + 0x10;
        let mut entry = read_u64(head)?;
        let mut max_index = 0u32;
        let mut steps = 0usize;
        while entry != head && steps < 4096 {
            steps += 1;
            if let Some(index) = module_tls_index(read_u64(entry + 0x30)?) {
                if index != u32::MAX && index > max_index {
                    max_index = index;
                }
            }
            entry = read_u64(entry)?;
        }
        Some(max_index)
    }

    /// Builds a fresh private array from the loader's *current* array and
    /// publishes it: `gs:[0x58]` points at the private array, the stub's
    /// `_tls_index` at the fresh index and `STATE` at the new handoff. With
    /// `fresh_block` the stub's template is copied into a new block; otherwise
    /// the installed block (its live thread-local state) is kept.
    unsafe fn install(fresh_block: bool) -> bool {
        let Some((template_data, template_size, index_at)) = own_tls() else {
            return false;
        };
        let Some(max_index) = highest_tls_index() else {
            return false;
        };
        let Some(tls_index) = max_index.checked_add(1) else {
            return false;
        };
        let count = tls_index as usize + 1;
        let Some(loader_array) = read_gs(0x58) else {
            return false;
        };
        let Some(array) = alloc_region(count * core::mem::size_of::<usize>()) else {
            return false;
        };
        let block = if fresh_block {
            let Some(block) = alloc_region(template_size) else {
                return false;
            };
            core::ptr::copy_nonoverlapping(
                template_data as *const u8,
                block as *mut u8,
                template_size,
            );
            block
        } else {
            let Some(handoff) = *lock_state() else {
                return false;
            };
            handoff.2 as *mut core::ffi::c_void
        };
        for i in 0..tls_index as usize {
            let Some(slot) = read_u64(loader_array + i * 8) else {
                return false;
            };
            write_u64(array as usize + i * 8, slot);
        }
        write_u64(array as usize + tls_index as usize * 8, block as usize);
        // Publish the index: the stub's `_tls_index` lives at `index_at`.
        write_u32(index_at, tls_index);
        swap_array(array as usize);
        *lock_state() = Some((loader_array, array as usize, block as usize, tls_index));
        true
    }

    /// Installs the private TLS array on the calling thread. Only a release
    /// shellcode stub calls it; a failure leaves the historical index-0
    /// aliasing in place.
    pub fn provision() {
        if !PROVISIONED.load(Ordering::Relaxed) {
            if unsafe { install(true) } {
                PROVISIONED.store(true, Ordering::Relaxed);
            }
        }
    }

    fn pause() {
        // Put the loader's array back: the saved one is current unless a module
        // load reallocated it, which only happens while paused (a reallocation
        // over the active private array is the crash the pause prevents).
        if PROVISIONED.load(Ordering::Relaxed) {
            if let Some(&(loader_array, _, _, _)) = lock_state().as_ref() {
                unsafe { swap_array(loader_array) };
            }
        }
    }
    fn resume() {
        // Rebuild from the loader's current array: a module that loaded during
        // the pause gets its entry in the fresh private array.
        if PROVISIONED.load(Ordering::Relaxed) {
            unsafe {
                install(false);
            }
        }
    }
    /// Puts the loader's array back for good (the chain finished).
    pub fn restore() {
        if PROVISIONED.load(Ordering::Relaxed) {
            if let Some(&(loader_array, _, _, _)) = lock_state().as_ref() {
                unsafe { swap_array(loader_array) };
            }
            PROVISIONED.store(false, Ordering::Relaxed);
        }
    }

    /// Keeps the loader's array in place for the guard's lifetime and reinstalls
    /// the private one on drop. Wrap module loads (a module with static TLS
    /// makes the loader grow the per-thread array, which must see the array it
    /// owns) and the payload handoff (payload code must run on the array its
    /// own threads will see).
    pub struct PauseGuard;
    impl PauseGuard {
        pub fn enter() -> Self {
            pause();
            Self
        }
    }
    impl Drop for PauseGuard {
        fn drop(&mut self) {
            resume();
        }
    }

    /// Restores the loader's array when dropped: the shellcode export wraps the
    /// chain with it, so a panic (panic=unwind) still leaves the thread with the
    /// array its teardown expects.
    pub struct RestoreGuard;
    impl RestoreGuard {
        pub fn new() -> Self {
            Self
        }
    }
    impl Drop for RestoreGuard {
        fn drop(&mut self) {
            restore();
        }
    }
}
"#;

#[cfg(test)]
mod tests {
    /// The block's only quoted content must be compile-time metadata: `cfg`
    /// targets, the linker symbol name and asm templates. Nothing quoted may
    /// ever reach the binary (runtime strings come from `StringsConfig`).
    #[test]
    fn the_block_is_self_gating_and_literal_free() {
        let allowed = [
            "C",
            "x86_64",
            "__ImageBase",
            "mov gs:[0x58], {0}",
            "mov {0}, gs:[{1}]",
        ];
        let quoted: Vec<&str> = super::BLOCK
            .split('"')
            .enumerate()
            .filter_map(|(i, part)| (i % 2 == 1).then_some(part))
            .collect();
        assert!(
            quoted.iter().all(|part| allowed.contains(part)),
            "runtime literal in the TLS block: {quoted:?}"
        );
        assert!(
            !super::BLOCK.contains('$'),
            "placeholder left in the TLS block"
        );
        assert!(
            super::BLOCK.contains("pub fn provision"),
            "provision missing"
        );
        assert!(
            super::BLOCK.contains("pub struct PauseGuard"),
            "pause guard missing"
        );
        assert!(
            super::BLOCK.contains("pub struct RestoreGuard"),
            "restore guard missing"
        );
        // The handoff runs in release shellcode stubs; the block carries the
        // unconditional install machinery and no release-only gate of its own
        // (the renderer decides whether to call it).
        assert!(
            !super::BLOCK.contains("cfg(not(debug_assertions))"),
            "provision must not be release-gated inside the block"
        );
        // The pause/resume cycle rebuilds from the loader's current array.
        assert!(
            super::BLOCK.contains("install(false)"),
            "the resume rebuild is missing"
        );
    }
}
