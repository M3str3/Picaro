//! Minimal PE parser.
//!
//! Only what the packer needs to validate an input payload: `e_lfanew`, the
//! `PE\0\0` signature, the machine type (to tell x86 from x64), the optional
//! header magic (PE32 vs PE32+), the preferred image base, the size of the
//! image, the section table and whether the image carries base relocations. The
//! generated stub performs its own equivalent parsing at runtime.

use crate::plan::schema::Arch;

/// PE machine type for x86 (PE32).
pub const IMAGE_FILE_MACHINE_I386: u16 = 0x014C;

/// PE machine type for x86-64 (PE32+).
pub const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;

/// `IMAGE_FILE_DLL`: the file header flag that marks a library image.
pub const IMAGE_FILE_DLL: u16 = 0x2000;

/// DOS header `MZ` signature.
const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D;

/// NT header `PE\0\0` signature.
const IMAGE_NT_SIGNATURE: u32 = 0x0000_4550;

/// Optional-header magic of a 32-bit image.
const PE32_MAGIC: u16 = 0x010B;

/// Optional-header magic of a 64-bit image.
const PE32_PLUS_MAGIC: u16 = 0x020B;

/// `IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR`: the data directory a managed
/// assembly points at its CLR header with.
const COM_DESCRIPTOR_DIRECTORY: usize = 14;

/// `IMAGE_DIRECTORY_ENTRY_BASERELOC`: the data directory a relocatable image
/// lists its base relocations in.
const BASE_RELOCATION_DIRECTORY: usize = 5;

/// `IMAGE_DIRECTORY_ENTRY_TLS`: the data directory an image with static TLS
/// points at its `IMAGE_TLS_DIRECTORY` with.
const TLS_DIRECTORY: usize = 9;

/// `IMAGE_COR20_HEADER::Flags`: the assembly is IL-only (no native code, so it
/// can run in either bitness).
pub const COMIMAGE_FLAGS_ILONLY: u32 = 0x0000_0001;

/// `IMAGE_COR20_HEADER::Flags`: the assembly must run on a 32-bit runtime.
pub const COMIMAGE_FLAGS_32BITREQUIRED: u32 = 0x0000_0002;

/// The CLR header of a managed assembly (`IMAGE_COR20_HEADER`, pointed at by
/// data directory 14).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClrHeader {
    /// `VirtualAddress` of the header (its RVA).
    pub rva: u32,
    /// `Size` of the header.
    pub size: u32,
    /// `Flags`, or `None` when the header itself cannot be read (a truncated
    /// image: the directory is there but its contents are not).
    pub flags: Option<u32>,
}

impl ClrHeader {
    /// Whether the assembly is IL-only (no native code).
    pub fn is_il_only(&self) -> bool {
        self.flags
            .is_some_and(|flags| flags & COMIMAGE_FLAGS_ILONLY != 0)
    }

    /// Whether the assembly requires a 32-bit runtime.
    pub fn requires_32bit(&self) -> bool {
        self.flags
            .is_some_and(|flags| flags & COMIMAGE_FLAGS_32BITREQUIRED != 0)
    }
}

/// A single section header entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SectionInfo {
    /// Section name (8 bytes, not necessarily NUL-terminated).
    pub name: [u8; 8],
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
}

/// The parsed bits of a PE we care about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeInfo {
    pub machine: u16,
    /// Whether the optional header is PE32+ (`0x20B`) rather than PE32 (`0x10B`).
    pub is_pe32plus: bool,
    /// `FileHeader.Characteristics` (e.g. `IMAGE_FILE_DLL`).
    pub characteristics: u16,
    pub image_base: u64,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub entry_point_rva: u32,
    /// Whether the image carries base relocations (data directory 5 is
    /// non-empty), so a loader can map it away from its preferred base. A
    /// `/FIXED` image has none and only runs at `image_base`; the in-process
    /// mapper refuses to relocate one (`reflective_loading`).
    pub has_relocations: bool,
    /// Bytes of per-thread data the image's static TLS needs (`End - Start` of
    /// the raw template plus `SizeOfZeroFill`), or `None` when the image has no
    /// TLS directory. A manually mapped image never receives a `_tls_index`, so
    /// a payload with per-thread data reads and writes another module's block;
    /// `reflective_loading` warns about it. An unreadable directory counts as
    /// zero.
    pub tls_template_size: Option<u32>,
    pub sections: Vec<SectionInfo>,
    /// The CLR header, when the image is a managed assembly (`.NET`).
    pub com: Option<ClrHeader>,
}

impl PeInfo {
    /// Whether the image is a managed (.NET) assembly.
    pub fn is_dotnet(&self) -> bool {
        self.com.is_some()
    }

    /// The image's architecture, or `None` for a machine picaro does not pack.
    pub fn arch(&self) -> Option<Arch> {
        arch_of(self.machine)
    }
}

/// Maps a PE machine type to an [`Arch`] (`None` for an unsupported machine).
pub fn arch_of(machine: u16) -> Option<Arch> {
    match machine {
        IMAGE_FILE_MACHINE_I386 => Some(Arch::X86),
        IMAGE_FILE_MACHINE_AMD64 => Some(Arch::X64),
        _ => None,
    }
}

/// PE parsing error.
#[derive(Debug, thiserror::Error)]
pub enum PeError {
    /// The buffer is too small to hold the DOS header.
    #[error("buffer too small for a PE (DOS header)")]
    TooSmall,
    /// The DOS header is missing the `MZ` signature.
    #[error("invalid DOS header (missing MZ signature)")]
    InvalidDosHeader,
    /// The NT header is missing the `PE\0\0` signature.
    #[error("invalid NT header (missing PE signature)")]
    InvalidNtHeader,
    /// The optional header magic is neither PE32 nor PE32+.
    #[error("unknown optional-header magic 0x{0:04x} (expected 0x010b PE32 or 0x020b PE32+)")]
    UnknownOptionalHeader(u16),
    /// A field read went past the end of the buffer.
    #[error("unexpected end of PE data while reading offsets")]
    ReadOutOfBounds,
}

/// Returns true if the file-header `characteristics` mark a DLL.
pub fn is_dll(characteristics: u16) -> bool {
    characteristics & IMAGE_FILE_DLL != 0
}

/// Parses the minimal PE information needed to validate a payload.
pub fn parse(data: &[u8]) -> Result<PeInfo, PeError> {
    // DOS header.
    if data.len() < 64 {
        return Err(PeError::TooSmall);
    }
    if read_u16(data, 0)? != IMAGE_DOS_SIGNATURE {
        return Err(PeError::InvalidDosHeader);
    }
    let e_lfanew = read_u32(data, 0x3C)? as usize;

    // NT header signature.
    if read_u32(data, e_lfanew)? != IMAGE_NT_SIGNATURE {
        return Err(PeError::InvalidNtHeader);
    }

    // File header.
    let machine = read_u16(data, e_lfanew + 4)?;
    let num_sections = read_u16(data, e_lfanew + 6)? as usize;
    let characteristics = read_u16(data, e_lfanew + 22)?;
    let size_of_optional_header = read_u16(data, e_lfanew + 20)? as usize;

    // Optional header (starts right after the file header).
    let opt = e_lfanew + 4 + 20;
    let is_pe32plus = match read_u16(data, opt)? {
        PE32_PLUS_MAGIC => true,
        PE32_MAGIC => false,
        other => return Err(PeError::UnknownOptionalHeader(other)),
    };
    let entry_point_rva = read_u32(data, opt + 16)?;
    // `ImageBase` is a `u64` at `opt + 24` in PE32+ and a `u32` at `opt + 28` in
    // PE32. `SizeOfImage`/`SizeOfHeaders` sit at the same offsets in both.
    let image_base = if is_pe32plus {
        read_u64(data, opt + 24)?
    } else {
        u64::from(read_u32(data, opt + 28)?)
    };
    let size_of_image = read_u32(data, opt + 56)?;
    let size_of_headers = read_u32(data, opt + 60)?;

    // Section table (right after the optional header).
    let mut sections = Vec::with_capacity(num_sections);
    for i in 0..num_sections {
        let s = opt + size_of_optional_header + i * 40;
        if s + 40 > data.len() {
            return Err(PeError::ReadOutOfBounds);
        }
        let mut name = [0u8; 8];
        name.copy_from_slice(&data[s..s + 8]);
        sections.push(SectionInfo {
            name,
            virtual_size: read_u32(data, s + 8)?,
            virtual_address: read_u32(data, s + 12)?,
            size_of_raw_data: read_u32(data, s + 16)?,
            pointer_to_raw_data: read_u32(data, s + 20)?,
        });
    }

    // Data directories. `NumberOfRvaAndSizes` sits at 92 in PE32 and 108 in
    // PE32+; the directory array starts 4 bytes later in both.
    let num_directories = read_u32(data, opt + if is_pe32plus { 108 } else { 92 })? as usize;
    let directories = opt + if is_pe32plus { 112 } else { 96 };
    let com = if num_directories > COM_DESCRIPTOR_DIRECTORY {
        let rva = read_u32(data, directories + COM_DESCRIPTOR_DIRECTORY * 8)?;
        let size = read_u32(data, directories + COM_DESCRIPTOR_DIRECTORY * 8 + 4)?;
        if rva == 0 || size == 0 {
            None
        } else {
            // `IMAGE_COR20_HEADER::Flags` is the fourth field: cb (4),
            // MajorRuntimeVersion (2), MinorRuntimeVersion (2), MetaData (8).
            let flags =
                rva_to_offset(&sections, rva).and_then(|offset| read_u32(data, offset + 16).ok());
            Some(ClrHeader { rva, size, flags })
        }
    } else {
        None
    };

    // Base relocations. An image with an empty directory 5 was linked `/FIXED`
    // (or had its relocations stripped): it cannot be mapped at another base.
    let has_relocations = if num_directories > BASE_RELOCATION_DIRECTORY {
        let rva = read_u32(data, directories + BASE_RELOCATION_DIRECTORY * 8)?;
        let size = read_u32(data, directories + BASE_RELOCATION_DIRECTORY * 8 + 4)?;
        rva != 0 && size != 0
    } else {
        false
    };

    // Static TLS. The directory points at an `IMAGE_TLS_DIRECTORY`, whose raw
    // template range is the bytes a thread copies before running; an image with
    // per-thread data always reports more than zero. A directory that is present
    // but unreadable (or a callbacks-only one) counts as zero rather than failing
    // the parse: the advisory that uses this only fires on a non-zero size.
    let tls_template_size = if num_directories > TLS_DIRECTORY {
        let rva = read_u32(data, directories + TLS_DIRECTORY * 8)?;
        let size = read_u32(data, directories + TLS_DIRECTORY * 8 + 4)?;
        if rva == 0 || size == 0 {
            None
        } else {
            let template = rva_to_offset(&sections, rva)
                .and_then(|offset| {
                    let (start, end) = if is_pe32plus {
                        (
                            read_u64(data, offset).ok()?,
                            read_u64(data, offset + 8).ok()?,
                        )
                    } else {
                        (
                            u64::from(read_u32(data, offset).ok()?),
                            u64::from(read_u32(data, offset + 4).ok()?),
                        )
                    };
                    let zero_fill =
                        read_u32(data, offset + if is_pe32plus { 32 } else { 16 }).ok()?;
                    Some(
                        end.saturating_sub(start)
                            .saturating_add(u64::from(zero_fill)),
                    )
                })
                .unwrap_or(0);
            Some(template.min(u64::from(u32::MAX)) as u32)
        }
    } else {
        None
    };

    Ok(PeInfo {
        machine,
        is_pe32plus,
        characteristics,
        image_base,
        size_of_image,
        size_of_headers,
        entry_point_rva,
        has_relocations,
        tls_template_size,
        sections,
        com,
    })
}

/// Maps an RVA to a file offset through the section table.
fn rva_to_offset(sections: &[SectionInfo], rva: u32) -> Option<usize> {
    for section in sections {
        let size = section.virtual_size.max(section.size_of_raw_data);
        if rva >= section.virtual_address && rva < section.virtual_address + size {
            return Some((rva - section.virtual_address + section.pointer_to_raw_data) as usize);
        }
    }
    None
}

fn read_u16(data: &[u8], off: usize) -> Result<u16, PeError> {
    let b = data
        .get(off..off.checked_add(2).ok_or(PeError::ReadOutOfBounds)?)
        .ok_or(PeError::ReadOutOfBounds)?;
    Ok(u16::from_le_bytes([b[0], b[1]]))
}

fn read_u32(data: &[u8], off: usize) -> Result<u32, PeError> {
    let b = data
        .get(off..off.checked_add(4).ok_or(PeError::ReadOutOfBounds)?)
        .ok_or(PeError::ReadOutOfBounds)?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn read_u64(data: &[u8], off: usize) -> Result<u64, PeError> {
    let b = data
        .get(off..off.checked_add(8).ok_or(PeError::ReadOutOfBounds)?)
        .ok_or(PeError::ReadOutOfBounds)?;
    Ok(u64::from_le_bytes([
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a minimal, well-formed PE with one section.
    ///
    /// `pe32plus` selects the optional-header layout: PE32+ keeps a `u64`
    /// `ImageBase` at `opt + 24` and a 240-byte optional header, PE32 a `u32` at
    /// `opt + 28` and 224 bytes.
    fn minimal_pe(machine: u16, pe32plus: bool) -> Vec<u8> {
        let opt_size = if pe32plus { 240 } else { 224 };
        let mut b = vec![0u8; 64 + 24 + opt_size + 40];
        b[0] = b'M';
        b[1] = b'Z';
        b[0x3C] = 64; // e_lfanew
        b[64..68].copy_from_slice(b"PE\0\0");
        b[68..70].copy_from_slice(&machine.to_le_bytes());
        b[70..72].copy_from_slice(&1u16.to_le_bytes()); // one section
        b[84..86].copy_from_slice(&(opt_size as u16).to_le_bytes()); // SizeOfOptionalHeader
        let opt = 88;
        let magic = if pe32plus {
            PE32_PLUS_MAGIC
        } else {
            PE32_MAGIC
        };
        b[opt..opt + 2].copy_from_slice(&magic.to_le_bytes());
        b[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes()); // entry point
        if pe32plus {
            b[opt + 24..opt + 32].copy_from_slice(&0x140000000u64.to_le_bytes());
        // image base
        } else {
            b[opt + 28..opt + 32].copy_from_slice(&0x00400000u32.to_le_bytes());
            // image base
        }
        b[opt + 56..opt + 60].copy_from_slice(&0x2000u32.to_le_bytes()); // size of image
        b[opt + 60..opt + 64].copy_from_slice(&0x200u32.to_le_bytes()); // size of headers
        let s = opt + opt_size; // section table
        b[s + 12..s + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // VA
        b[s + 16..s + 20].copy_from_slice(&0x200u32.to_le_bytes()); // size of raw data
        b[s + 20..s + 24].copy_from_slice(&0x200u32.to_le_bytes()); // pointer to raw data
        b
    }

    /// The `Characteristics` field lives 22 bytes past the NT signature in both
    /// layouts (FileHeader starts after `PE\0\0`, Characteristics at +18).
    const CHARACTERISTICS_OFFSET: usize = 64 + 4 + 18;

    #[test]
    fn parses_minimal_pe64() {
        let pe = parse(&minimal_pe(IMAGE_FILE_MACHINE_AMD64, true)).expect("valid PE");
        assert!(pe.is_pe32plus);
        assert_eq!(pe.arch(), Some(Arch::X64));
        assert_eq!(pe.image_base, 0x140000000);
        assert_eq!(pe.size_of_image, 0x2000);
        assert_eq!(pe.size_of_headers, 0x200);
        assert_eq!(pe.entry_point_rva, 0x1000);
        assert_eq!(pe.sections.len(), 1);
        assert_eq!(pe.sections[0].virtual_address, 0x1000);
    }

    #[test]
    fn parses_minimal_pe32() {
        let pe = parse(&minimal_pe(IMAGE_FILE_MACHINE_I386, false)).expect("valid PE32");
        assert!(!pe.is_pe32plus);
        assert_eq!(pe.arch(), Some(Arch::X86));
        assert_eq!(pe.image_base, 0x00400000);
        assert_eq!(pe.size_of_image, 0x2000);
        assert_eq!(pe.size_of_headers, 0x200);
        assert_eq!(pe.entry_point_rva, 0x1000);
        assert_eq!(pe.sections.len(), 1);
        assert_eq!(pe.sections[0].virtual_address, 0x1000);
    }

    #[test]
    fn parses_the_committed_pe32_fixture() {
        // A real compiler-produced PE32 (see `scripts/build_test_fixture.sh`),
        // so the PE32 path is covered beyond the synthetic builder above.
        let data: &[u8] = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/minimal_x86.exe"
        ));
        let pe = parse(data).expect("valid PE32 fixture");
        assert_eq!(pe.machine, IMAGE_FILE_MACHINE_I386);
        assert_eq!(pe.arch(), Some(Arch::X86));
        assert!(!pe.is_pe32plus);
        assert!(!pe.sections.is_empty());
        assert!(pe.image_base > 0);
        assert!(pe.size_of_image > 0);
        // rustc-linked images are relocatable, so the in-process mapper may move
        // them off their preferred base.
        assert!(pe.has_relocations, "the fixture carries base relocations");
    }

    /// Sets `NumberOfRvaAndSizes` and the base-relocation directory (index 5) of
    /// a synthetic PE32+ image.
    fn with_relocation_directory(mut pe: Vec<u8>, rva: u32, size: u32) -> Vec<u8> {
        let opt = 88;
        pe[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes()); // NumberOfRvaAndSizes
        let dir = opt + 112 + BASE_RELOCATION_DIRECTORY * 8;
        pe[dir..dir + 4].copy_from_slice(&rva.to_le_bytes());
        pe[dir + 4..dir + 8].copy_from_slice(&size.to_le_bytes());
        pe
    }

    #[test]
    fn an_image_with_a_relocation_directory_reports_relocations() {
        let pe = parse(&with_relocation_directory(
            minimal_pe(IMAGE_FILE_MACHINE_AMD64, true),
            0x2000,
            0x40,
        ))
        .expect("valid PE");
        assert!(pe.has_relocations);
    }

    #[test]
    fn an_image_without_relocations_reports_none() {
        // No directories at all...
        let pe = parse(&minimal_pe(IMAGE_FILE_MACHINE_AMD64, true)).expect("valid PE");
        assert!(!pe.has_relocations);

        // ...and an empty directory 5 is not a relocation set either.
        let pe = parse(&with_relocation_directory(
            minimal_pe(IMAGE_FILE_MACHINE_AMD64, true),
            0,
            0,
        ))
        .expect("valid PE");
        assert!(!pe.has_relocations);
    }

    /// Adds a TLS directory (data directory 9) at RVA `0x1000` with a synthetic
    /// `IMAGE_TLS_DIRECTORY` describing a `start..end` raw range and `zero_fill`
    /// bytes.
    fn with_tls_directory(
        mut pe: Vec<u8>,
        pe32plus: bool,
        start: u64,
        end: u64,
        zero_fill: u32,
    ) -> Vec<u8> {
        pe.resize(0x200 + 0x28, 0);
        let opt = 88;
        let (num_directories, directories) = if pe32plus { (108, 112) } else { (92, 96) };
        pe[opt + num_directories..opt + num_directories + 4].copy_from_slice(&16u32.to_le_bytes());
        let dir = opt + directories + TLS_DIRECTORY * 8;
        pe[dir..dir + 4].copy_from_slice(&0x1000u32.to_le_bytes());
        pe[dir + 4..dir + 8].copy_from_slice(&0x28u32.to_le_bytes());
        let tls = 0x200;
        if pe32plus {
            pe[tls..tls + 8].copy_from_slice(&start.to_le_bytes());
            pe[tls + 8..tls + 16].copy_from_slice(&end.to_le_bytes());
            pe[tls + 32..tls + 36].copy_from_slice(&zero_fill.to_le_bytes());
        } else {
            pe[tls..tls + 4].copy_from_slice(&(start as u32).to_le_bytes());
            pe[tls + 4..tls + 8].copy_from_slice(&(end as u32).to_le_bytes());
            pe[tls + 16..tls + 20].copy_from_slice(&zero_fill.to_le_bytes());
        }
        pe
    }

    #[test]
    fn a_pe32plus_tls_template_is_measured() {
        let pe = parse(&with_tls_directory(
            minimal_pe(IMAGE_FILE_MACHINE_AMD64, true),
            true,
            0x140001000,
            0x140001058,
            0x10,
        ))
        .expect("valid PE");
        assert_eq!(pe.tls_template_size, Some(0x58 + 0x10));
    }

    #[test]
    fn a_pe32_tls_template_is_measured() {
        let pe = parse(&with_tls_directory(
            minimal_pe(IMAGE_FILE_MACHINE_I386, false),
            false,
            0x00401000,
            0x00401020,
            0x8,
        ))
        .expect("valid PE");
        assert_eq!(pe.tls_template_size, Some(0x20 + 0x8));
    }

    #[test]
    fn a_callbacks_only_tls_directory_reports_zero() {
        let pe = parse(&with_tls_directory(
            minimal_pe(IMAGE_FILE_MACHINE_AMD64, true),
            true,
            0,
            0,
            0,
        ))
        .expect("valid PE");
        assert_eq!(pe.tls_template_size, Some(0));
    }

    #[test]
    fn an_image_without_a_tls_directory_reports_none() {
        let pe = parse(&minimal_pe(IMAGE_FILE_MACHINE_AMD64, true)).expect("valid PE");
        assert_eq!(pe.tls_template_size, None);

        // A present but empty directory 9 is not a TLS template either.
        let mut image = minimal_pe(IMAGE_FILE_MACHINE_AMD64, true);
        image[88 + 108..88 + 112].copy_from_slice(&16u32.to_le_bytes());
        let dir = 88 + 112 + TLS_DIRECTORY * 8;
        image[dir..dir + 8].copy_from_slice(&[0u8; 8]);
        let pe = parse(&image).expect("valid PE");
        assert_eq!(pe.tls_template_size, None);
    }

    #[test]
    fn an_unknown_machine_has_no_arch() {
        // ARM64: a valid PE picaro does not pack.
        let pe = parse(&minimal_pe(0xAA64, true)).expect("valid PE");
        assert_eq!(pe.arch(), None);
    }

    #[test]
    fn rejects_an_unknown_optional_header_magic() {
        let mut b = minimal_pe(IMAGE_FILE_MACHINE_AMD64, true);
        b[88..90].copy_from_slice(&0x020Cu16.to_le_bytes());
        assert!(matches!(
            parse(&b),
            Err(PeError::UnknownOptionalHeader(0x020C))
        ));
    }

    #[test]
    fn an_executable_is_not_a_dll() {
        let pe = parse(&minimal_pe(IMAGE_FILE_MACHINE_AMD64, true)).expect("valid PE");
        assert_eq!(pe.characteristics, 0);
        assert!(!is_dll(pe.characteristics));
    }

    #[test]
    fn a_library_image_is_a_dll() {
        let mut b = minimal_pe(IMAGE_FILE_MACHINE_AMD64, true);
        b[CHARACTERISTICS_OFFSET..CHARACTERISTICS_OFFSET + 2]
            .copy_from_slice(&IMAGE_FILE_DLL.to_le_bytes());
        let pe = parse(&b).expect("valid PE");
        assert_eq!(pe.characteristics, IMAGE_FILE_DLL);
        assert!(is_dll(pe.characteristics));
    }

    #[test]
    fn rejects_non_pe_data() {
        assert!(parse(b"this is definitely not a PE file").is_err());
    }

    #[test]
    fn rejects_bad_nt_signature() {
        let mut b = minimal_pe(IMAGE_FILE_MACHINE_AMD64, true);
        b[64] = b'X';
        assert!(matches!(parse(&b), Err(PeError::InvalidNtHeader)));
    }

    #[test]
    fn rejects_bad_dos_signature() {
        let mut b = minimal_pe(IMAGE_FILE_MACHINE_AMD64, true);
        b[0] = b'X';
        assert!(matches!(parse(&b), Err(PeError::InvalidDosHeader)));
    }
}
