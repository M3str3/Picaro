//! PE-file walk helpers shared by the resolvers.
//!
//! Tartarus Gate and API hashing read a *clean* copy of `ntdll.dll` from disk
//! and walk its export directory; Hell's Gate uses the same walk as a
//! per-function fallback when the live stub is hooked. Injected into a resolver
//! body through the `$FILE_PE_HELPERS$` placeholder.

/// PE-file walk helpers: RVA→file-offset conversion, bounds-checked u16/u32
/// reads, and one export-directory walk parameterized by a name predicate
/// (`export_rva` matches a name; API hashing matches a hash). Injected into the
/// resolver body through `$FILE_PE_HELPERS$`.
pub(crate) const FILE_PE_HELPERS: &str = r#"    /// Converts a PE RVA to a file offset using the section table.
    fn rva_to_offset(file: &[u8], rva: usize) -> Option<usize> {
        let e_lfanew = pe32_at(file, 0x3C)? as usize;
        if pe32_at(file, e_lfanew)? != 0x0000_4550 {
            return None;
        }
        let num_sections = pe16_at(file, e_lfanew + 4 + 2)? as usize;
        let opt_size = pe16_at(file, e_lfanew + 4 + 16)? as usize;
        let table = e_lfanew + 4 + 20 + opt_size as usize;

        let mut first_va: Option<usize> = None;
        for i in 0..num_sections {
            let s = table + i * 40;
            let va = pe32_at(file, s + 12)? as usize;
            let raw_size = pe32_at(file, s + 16)? as usize;
            let raw = pe32_at(file, s + 20)? as usize;
            first_va = Some(first_va.map_or(va, |f| f.min(va)));
            if rva >= va && rva - va < raw_size {
                return Some(raw + (rva - va));
            }
        }
        // RVAs below the first section live in the headers, which map 1:1.
        match first_va {
            Some(first) if rva < first => Some(rva),
            _ => None,
        }
    }

    /// Bounds-checked little-endian u16 read from the clean file image.
    fn pe16_at(file: &[u8], off: usize) -> Option<u16> {
        let s = file.get(off..off.checked_add(2)?)?;
        Some(u16::from_le_bytes([s[0], s[1]]))
    }

    /// Bounds-checked little-endian u32 read from the clean file image.
    fn pe32_at(file: &[u8], off: usize) -> Option<u32> {
        let s = file.get(off..off.checked_add(4)?)?;
        Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }

    /// Walks the file's export directory and returns the RVA of the first
    /// exported function whose name satisfies `matches`. `file` is the raw
    /// bytes of a (clean) PE image; every read is bounds-checked. This is the
    /// single walk shared by the name- and hash-based resolvers.
    fn export_rva_where(file: &[u8], matches: impl Fn(&[u8]) -> bool) -> Option<u32> {
        let e_lfanew = pe32_at(file, 0x3C)? as usize;
        if pe32_at(file, e_lfanew)? != 0x0000_4550 {
            return None;
        }
        let opt = e_lfanew + 4 + 20;
        let magic = pe16_at(file, opt)?;
        // The data directory starts at optional-header offset 112 (PE32+) or
        // 96 (PE32); ntdll on x64 is PE32+.
        let dir_off = if magic == 0x20b { opt + 112 } else { opt + 96 };
        let export_va = pe32_at(file, dir_off)? as usize;
        if export_va == 0 {
            return None;
        }
        let ed = rva_to_offset(file, export_va)?;
        let num_names = pe32_at(file, ed + 24)? as usize;
        let addr_functions = pe32_at(file, ed + 28)? as usize;
        let addr_names = pe32_at(file, ed + 32)? as usize;
        let addr_ordinals = pe32_at(file, ed + 36)? as usize;

        for i in 0..num_names {
            let name_rva =
                pe32_at(file, rva_to_offset(file, addr_names.checked_add(i.checked_mul(4)?)?)?)?
                    as usize;
            let name_off = rva_to_offset(file, name_rva)?;
            let rest = file.get(name_off..)?;
            let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
            if matches(&rest[..end]) {
                let ordinal = pe16_at(
                    file,
                    rva_to_offset(file, addr_ordinals.checked_add(i.checked_mul(2)?)?)?,
                )? as usize;
                return pe32_at(
                    file,
                    rva_to_offset(file, addr_functions.checked_add(ordinal.checked_mul(4)?)?)?,
                );
            }
        }
        None
    }

    /// Returns the RVA of an export by name (used by Tartarus Gate and by the
    /// Hell's Gate fallback).
    fn export_rva(file: &[u8], name: &str) -> Option<u32> {
        export_rva_where(file, |candidate| candidate == name.as_bytes())
    }

    /// Reads a clean on-disk copy of the native library that `name` is loaded
    /// from.
    ///
    /// The path comes from the live module (`GetModuleFileNameW`), so a
    /// non-default Windows directory works and the file read matches the module
    /// that is mapped. The file's PE `TimeDateStamp` (at `IMAGE_NT_HEADERS + 8`)
    /// is compared against the live module's: if a Windows update replaced the
    /// file after boot, reading it would yield SSNs that no longer match the
    /// running kernel stubs.
    fn read_clean_ntdll(name: &str) -> Result<Vec<u8>, SyscallError> {
        let cname = std::ffi::CString::new(name).map_err(|_| SyscallError::NtdllNotFound)?;
        let module = unsafe { GetModuleHandleA(PCSTR(cname.as_ptr() as *const u8)) }
            .map_err(|_| SyscallError::NtdllNotFound)?;

        let mut buffer = [0u16; 260];
        let len = unsafe { GetModuleFileNameW(module, &mut buffer) } as usize;
        if len == 0 || len >= buffer.len() {
            return Err(SyscallError::NtdllNotFound);
        }
        let path = String::from_utf16_lossy(&buffer[..len]);
        let file = std::fs::read(path).map_err(|_| SyscallError::NtdllNotFound)?;

        let base = module.0 as usize;
        let live =
            pe_u32(base, pe_u32(base, 0x3C).ok_or(SyscallError::NtdllNotFound)? as usize + 8)
                .ok_or(SyscallError::NtdllNotFound)?;
        let on_disk =
            pe32_at(&file, pe32_at(&file, 0x3C).ok_or(SyscallError::NtdllNotFound)? as usize + 8)
                .ok_or(SyscallError::NtdllNotFound)?;
        if live != on_disk {
            return Err(SyscallError::NtdllMismatch);
        }
        Ok(file)
    }
"#;
