//! PE parsing for the static audit: header, sections, imports, exports,
//! signature, manifest and overlay.
//!
//! This is a richer parser than `engine::pe` (which only extracts what process
//! hollowing needs). It operates on the raw file bytes and never uses `unsafe`.

use crate::audit::AuditError;

const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D;
const IMAGE_NT_SIGNATURE: u32 = 0x0000_4550;
const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
const IMAGE_FILE_MACHINE_I386: u16 = 0x014C;

const IMAGE_SUBSYSTEM_WINDOWS_GUI: u16 = 2;
const IMAGE_SUBSYSTEM_WINDOWS_CUI: u16 = 3;

// Data directory indexes.
const DIR_EXPORT: usize = 0;
const DIR_IMPORT: usize = 1;
const DIR_RESOURCE: usize = 2;
const DIR_SECURITY: usize = 4;

// Resource type ID for the embedded manifest.
const RT_MANIFEST: u32 = 24;

// Certificate type for Authenticode (PKCS #7 signed data).
const WIN_CERT_TYPE_PKCS_SIGNED_DATA: u16 = 0x0002;

/// A section with its size, file offset and Shannon entropy.
#[derive(Debug, Clone, PartialEq)]
pub struct SectionAudit {
    pub name: String,
    pub size: usize,
    pub entropy: f64,
    /// File offset of the section's raw data.
    pub file_offset: usize,
}

/// One imported item.
#[derive(Debug, Clone, PartialEq)]
pub enum ImportItem {
    Named(String),
    Ordinal(u16),
}

/// One imported DLL and its functions.
#[derive(Debug, Clone, PartialEq)]
pub struct DllImport {
    pub name: String,
    pub functions: Vec<ImportItem>,
}

/// Everything the audit extracts from the PE.
#[derive(Debug, Clone, PartialEq)]
pub struct PeAudit {
    pub arch: &'static str,
    pub subsystem: &'static str,
    pub timestamp: Option<u32>,
    pub has_signature: bool,
    pub has_manifest: bool,
    pub overlay: usize,
    pub sections: Vec<SectionAudit>,
    pub imports: Vec<DllImport>,
    pub exports: Vec<String>,
}

/// Internal section view used for RVA → file-offset mapping.
#[derive(Clone, Copy)]
struct RawSection {
    virtual_address: u32,
    virtual_size: u32,
    size_of_raw_data: u32,
    pointer_to_raw_data: u32,
}

/// Parses the PE and returns the audit-relevant information.
pub fn analyze(data: &[u8]) -> Result<PeAudit, AuditError> {
    if data.len() < 64 {
        return Err(AuditError::InvalidPe("file too small for a PE".to_string()));
    }
    if read_u16(data, 0)? != IMAGE_DOS_SIGNATURE {
        return Err(AuditError::InvalidPe("missing MZ signature".to_string()));
    }
    let e_lfanew = read_u32(data, 0x3C)? as usize;
    if read_u32(data, e_lfanew)? != IMAGE_NT_SIGNATURE {
        return Err(AuditError::InvalidPe("missing PE signature".to_string()));
    }

    let machine = read_u16(data, e_lfanew + 4)?;
    let arch: &'static str = match machine {
        IMAGE_FILE_MACHINE_AMD64 => "x64",
        IMAGE_FILE_MACHINE_I386 => "x86",
        _ => "unknown",
    };

    let timestamp = read_u32(data, e_lfanew + 8)?;
    let num_sections = read_u16(data, e_lfanew + 6)? as usize;
    let size_of_optional_header = read_u16(data, e_lfanew + 20)? as usize;

    let opt = e_lfanew + 4 + 20;
    let is_pe32plus = read_u16(data, opt)? == 0x20B;
    let subsystem: &'static str = match read_u16(data, opt + 68)? {
        IMAGE_SUBSYSTEM_WINDOWS_GUI => "GUI",
        IMAGE_SUBSYSTEM_WINDOWS_CUI => "console",
        _ => "unknown",
    };

    // Sections.
    let section_table = opt + size_of_optional_header;
    let mut raw_sections = Vec::with_capacity(num_sections);
    let mut sections = Vec::with_capacity(num_sections);
    let mut pe_end = 0usize;
    for i in 0..num_sections {
        let s = section_table + i * 40;
        let raw = RawSection {
            virtual_size: read_u32(data, s + 8)?,
            virtual_address: read_u32(data, s + 12)?,
            size_of_raw_data: read_u32(data, s + 16)?,
            pointer_to_raw_data: read_u32(data, s + 20)?,
        };
        let name = read_section_name(data, s)?;
        let raw_start = raw.pointer_to_raw_data as usize;
        let raw_end = raw_start
            .saturating_add(raw.size_of_raw_data as usize)
            .min(data.len());
        let raw_data = data.get(raw_start..raw_end).unwrap_or(&[]);
        sections.push(SectionAudit {
            name,
            size: raw.size_of_raw_data as usize,
            entropy: shannon_entropy(raw_data),
            file_offset: raw.pointer_to_raw_data as usize,
        });
        pe_end = pe_end.max(raw_end);
        raw_sections.push(raw);
    }

    let rva_to_offset = |rva: u32| -> Option<usize> {
        for sec in &raw_sections {
            let size = sec.virtual_size.max(sec.size_of_raw_data);
            if rva >= sec.virtual_address && rva < sec.virtual_address + size {
                return Some((rva - sec.virtual_address + sec.pointer_to_raw_data) as usize);
            }
        }
        None
    };

    let data_dir_rva =
        |idx: usize| -> Result<u32, AuditError> { read_u32(data, opt + 112 + idx * 8) };

    // Imports.
    let mut imports = Vec::new();
    let import_rva = data_dir_rva(DIR_IMPORT)?;
    if import_rva != 0 {
        if let Some(off) = rva_to_offset(import_rva) {
            imports = parse_imports(data, off, is_pe32plus, &rva_to_offset)?;
        }
    }

    // Exports.
    let mut exports = Vec::new();
    let export_rva = data_dir_rva(DIR_EXPORT)?;
    if export_rva != 0 {
        if let Some(off) = rva_to_offset(export_rva) {
            exports = parse_exports(data, off, &rva_to_offset)?;
        }
    }

    // Signature (the security directory's "RVA" field is actually a file offset).
    let security_off = data_dir_rva(DIR_SECURITY)?;
    let security_size = read_u32(data, opt + 112 + DIR_SECURITY * 8 + 4)?;
    let has_signature = security_off != 0
        && security_size >= 8
        && read_u16(data, security_off as usize + 6)? == WIN_CERT_TYPE_PKCS_SIGNED_DATA;

    // Manifest (resource directory, type 24 at the root level).
    let resource_rva = data_dir_rva(DIR_RESOURCE)?;
    let has_manifest = match (resource_rva, rva_to_offset(resource_rva)) {
        (0, _) => false,
        (_, None) => false,
        (_, Some(off)) => has_manifest(data, off)?,
    };

    // Overlay: bytes after the last section's raw data.
    let overlay = data.len().saturating_sub(pe_end);

    Ok(PeAudit {
        arch,
        subsystem,
        timestamp: if timestamp == 0 {
            None
        } else {
            Some(timestamp)
        },
        has_signature,
        has_manifest,
        overlay,
        sections,
        imports,
        exports,
    })
}

fn parse_imports(
    data: &[u8],
    start: usize,
    is_pe32plus: bool,
    rva_to_offset: &dyn Fn(u32) -> Option<usize>,
) -> Result<Vec<DllImport>, AuditError> {
    let thunk_size = if is_pe32plus { 8 } else { 4 };
    let ord_flag: u64 = if is_pe32plus {
        0x8000_0000_0000_0000
    } else {
        0x8000_0000
    };
    let name_mask: u64 = if is_pe32plus {
        0x7FFF_FFFF_FFFF_FFFF
    } else {
        0x7FFF_FFFF
    };

    let mut imports = Vec::new();
    let mut i = 0usize;
    loop {
        let desc = start + i * 20;
        // The array is terminated by a null descriptor (Name RVA == 0).
        let name_rva = read_u32(data, desc + 12)?;
        if name_rva == 0 {
            break;
        }

        let orig_thunk = read_u32(data, desc)?;
        let first_thunk = read_u32(data, desc + 16)?;

        let dll_name = rva_to_offset(name_rva)
            .and_then(|o| read_cstring(data, o))
            .unwrap_or_else(|| "<unnamed>".to_string());

        let thunk_rva = if orig_thunk != 0 {
            orig_thunk
        } else {
            first_thunk
        };
        let mut functions = Vec::new();
        if let Some(thunk_off) = rva_to_offset(thunk_rva) {
            let mut j = 0usize;
            loop {
                let t_off = thunk_off + j * thunk_size;
                let thunk = if is_pe32plus {
                    read_u64(data, t_off)?
                } else {
                    read_u32(data, t_off)? as u64
                };
                if thunk == 0 {
                    break;
                }
                if thunk & ord_flag != 0 {
                    functions.push(ImportItem::Ordinal((thunk & 0xFFFF) as u16));
                } else {
                    let name = rva_to_offset((thunk & name_mask) as u32)
                        .and_then(|o| read_cstring(data, o + 2))
                        .map(ImportItem::Named)
                        .unwrap_or(ImportItem::Ordinal(0));
                    functions.push(name);
                }
                j += 1;
            }
        }
        imports.push(DllImport {
            name: dll_name,
            functions,
        });
        i += 1;
    }
    Ok(imports)
}

fn parse_exports(
    data: &[u8],
    start: usize,
    rva_to_offset: &dyn Fn(u32) -> Option<usize>,
) -> Result<Vec<String>, AuditError> {
    let num_names = read_u32(data, start + 24)?;
    let addr_of_names = read_u32(data, start + 32)?;
    let mut names = Vec::new();
    if let Some(names_off) = rva_to_offset(addr_of_names) {
        for i in 0..num_names {
            let name_rva = read_u32(data, names_off + (i as usize) * 4)?;
            if let Some(o) = rva_to_offset(name_rva) {
                if let Some(n) = read_cstring(data, o) {
                    names.push(n);
                }
            }
        }
    }
    Ok(names)
}

fn has_manifest(data: &[u8], dir_off: usize) -> Result<bool, AuditError> {
    let named = read_u16(data, dir_off + 12)? as usize;
    let id = read_u16(data, dir_off + 14)? as usize;
    let entries_off = dir_off + 16;
    for i in 0..(named + id) {
        let e = entries_off + i * 8;
        let name = read_u32(data, e)?;
        // ID entry (high bit clear) with the RT_MANIFEST type.
        if name & 0x8000_0000 == 0 && name == RT_MANIFEST {
            return Ok(true);
        }
    }
    Ok(false)
}

fn read_section_name(data: &[u8], s: usize) -> Result<String, AuditError> {
    let raw = data
        .get(s..s + 8)
        .ok_or_else(|| AuditError::InvalidPe("truncated section header".to_string()))?;
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    Ok(String::from_utf8_lossy(&raw[..end]).to_string())
}

fn read_cstring(data: &[u8], off: usize) -> Option<String> {
    let mut end = off;
    while end < data.len() && data[end] != 0 {
        end += 1;
    }
    if end == off {
        return None;
    }
    Some(String::from_utf8_lossy(&data[off..end]).to_string())
}

/// Shannon entropy in bits per byte (0.0 ..= 8.0).
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u64; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let n = data.len() as f64;
    let mut h = 0.0;
    for &f in &freq {
        if f > 0 {
            let p = f as f64 / n;
            h -= p * p.log2();
        }
    }
    h
}

/// PE sections whose raw bytes are metadata (import table, relocations, unwind
/// info) rather than stub code/data. Sensitive-literal scans exclude these so
/// DLL names in the import table (e.g. `kernel32.dll`) are not false positives.
const METADATA_SECTIONS: &[&str] = &[
    ".idata", ".reloc", ".pdata", ".xdata", ".CRT", ".tls", ".bss",
];

/// Returns the concatenated raw bytes of the stub's code and data sections
/// (everything except the metadata sections in [`METADATA_SECTIONS`]).
///
/// This is the slice to scan when looking for cleartext stub string literals:
/// the import table (`.idata`) legitimately contains DLL/function names that
/// are not under the packer's control.
pub fn code_data(data: &[u8], sections: &[SectionAudit]) -> Vec<u8> {
    let mut out = Vec::new();
    for section in sections {
        if METADATA_SECTIONS
            .iter()
            .any(|m| section.name.eq_ignore_ascii_case(m))
        {
            continue;
        }
        let start = section.file_offset.min(data.len());
        let end = start.saturating_add(section.size).min(data.len());
        out.extend_from_slice(&data[start..end]);
    }
    out
}

fn read_u16(data: &[u8], off: usize) -> Result<u16, AuditError> {
    let b = data
        .get(off..off + 2)
        .ok_or_else(|| AuditError::InvalidPe("truncated data".to_string()))?;
    Ok(u16::from_le_bytes([b[0], b[1]]))
}

fn read_u32(data: &[u8], off: usize) -> Result<u32, AuditError> {
    let b = data
        .get(off..off + 4)
        .ok_or_else(|| AuditError::InvalidPe("truncated data".to_string()))?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn read_u64(data: &[u8], off: usize) -> Result<u64, AuditError> {
    let b = data
        .get(off..off + 8)
        .ok_or_else(|| AuditError::InvalidPe("truncated data".to_string()))?;
    Ok(u64::from_le_bytes([
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parses a committed minimal x64 PE fixture (see
    /// `scripts/build_test_fixture.sh`), so the test does not depend on the
    /// host toolchain or on running on Windows.
    #[test]
    fn parses_embedded_test_pe() {
        let data: &[u8] = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/minimal_x64.exe"
        ));

        // The first two bytes must be the DOS "MZ" signature.
        assert_eq!(&data[0..2], b"MZ");

        // e_lfanew (offset 0x3C) must point at the "PE\0\0" signature.
        let e_lfanew =
            u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
        assert_eq!(&data[e_lfanew..e_lfanew + 4], b"PE\0\0");

        // The machine type (right after the PE signature) must be AMD64.
        let machine = u16::from_le_bytes([data[e_lfanew + 4], data[e_lfanew + 5]]);
        assert_eq!(machine, 0x8664);

        let pe = analyze(data).expect("parse embedded test PE");
        assert!(!pe.sections.is_empty(), "a PE must have sections");
    }

    #[test]
    fn rejects_non_pe_data() {
        assert!(analyze(b"this is definitely not a PE file").is_err());
    }

    #[test]
    fn entropy_is_bounded() {
        assert_eq!(shannon_entropy(&[0u8; 100]), 0.0);
        // A buffer with every byte value exactly once is uniform → max entropy.
        let uniform: Vec<u8> = (0..=255).collect();
        assert!(shannon_entropy(&uniform) > 7.9);
    }
}
