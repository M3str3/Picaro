//! Minimal PE parser.
//!
//! Only what process hollowing needs: `e_lfanew`, the `PE\0\0` signature, the
//! machine type (to reject 32-bit payloads), the preferred image base, the size
//! of the image and the section table. The packer uses this to validate the
//! input payload before packing; the generated stub performs its own equivalent
//! parsing at runtime.

/// PE machine type for x86-64 (PE32+).
pub const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;

/// `IMAGE_FILE_DLL`: the file header flag that marks a library image.
pub const IMAGE_FILE_DLL: u16 = 0x2000;

/// DOS header `MZ` signature.
const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D;

/// NT header `PE\0\0` signature.
const IMAGE_NT_SIGNATURE: u32 = 0x0000_4550;

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
    /// `FileHeader.Characteristics` (e.g. `IMAGE_FILE_DLL`).
    pub characteristics: u16,
    pub image_base: u64,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub entry_point_rva: u32,
    pub sections: Vec<SectionInfo>,
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
    /// The NT header is missing the `PE\\0\\0` signature.
    #[error("invalid NT header (missing PE signature)")]
    InvalidNtHeader,
    /// A field read went past the end of the buffer.
    #[error("unexpected end of PE data while reading offsets")]
    ReadOutOfBounds,
}

/// Returns true if `machine` is x86-64.
pub fn is_x64(machine: u16) -> bool {
    machine == IMAGE_FILE_MACHINE_AMD64
}

/// Returns true if the file-header `characteristics` mark a DLL.
pub fn is_dll(characteristics: u16) -> bool {
    characteristics & IMAGE_FILE_DLL != 0
}

/// Parses the minimal PE information needed for hollowing.
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
    let entry_point_rva = read_u32(data, opt + 16)?;
    let image_base = read_u64(data, opt + 24)?;
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

    Ok(PeInfo {
        machine,
        characteristics,
        image_base,
        size_of_image,
        size_of_headers,
        entry_point_rva,
        sections,
    })
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

    /// Builds a minimal, well-formed PE buffer with one section, using the
    /// PE32+ layout (image base as `u64`).
    fn minimal_pe(machine: u16) -> Vec<u8> {
        let mut b = vec![0u8; 64 + 24 + 240 + 40];
        b[0] = b'M';
        b[1] = b'Z';
        b[0x3C] = 64; // e_lfanew
        b[64..68].copy_from_slice(b"PE\0\0");
        b[68..70].copy_from_slice(&machine.to_le_bytes());
        b[70..72].copy_from_slice(&1u16.to_le_bytes()); // one section
        b[84..86].copy_from_slice(&240u16.to_le_bytes()); // SizeOfOptionalHeader
        let opt = 88;
        b[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes()); // entry point
        b[opt + 24..opt + 32].copy_from_slice(&0x140000000u64.to_le_bytes()); // image base
        b[opt + 56..opt + 60].copy_from_slice(&0x2000u32.to_le_bytes()); // size of image
        b[opt + 60..opt + 64].copy_from_slice(&0x200u32.to_le_bytes()); // size of headers
        let s = 328; // section table
        b[s + 12..s + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // VA
        b[s + 16..s + 20].copy_from_slice(&0x200u32.to_le_bytes()); // size of raw data
        b[s + 20..s + 24].copy_from_slice(&0x200u32.to_le_bytes()); // pointer to raw data
        b
    }

    /// The `Characteristics` field lives 22 bytes past the NT signature in a
    /// PE32+ image (FileHeader starts after `PE\0\0`, Characteristics at +18).
    const CHARACTERISTICS_OFFSET: usize = 64 + 4 + 18;

    #[test]
    fn parses_minimal_pe64() {
        let pe = parse(&minimal_pe(IMAGE_FILE_MACHINE_AMD64)).expect("valid PE");
        assert!(is_x64(pe.machine));
        assert_eq!(pe.image_base, 0x140000000);
        assert_eq!(pe.size_of_image, 0x2000);
        assert_eq!(pe.size_of_headers, 0x200);
        assert_eq!(pe.entry_point_rva, 0x1000);
        assert_eq!(pe.sections.len(), 1);
        assert_eq!(pe.sections[0].virtual_address, 0x1000);
    }

    #[test]
    fn an_executable_is_not_a_dll() {
        let pe = parse(&minimal_pe(IMAGE_FILE_MACHINE_AMD64)).expect("valid PE");
        assert_eq!(pe.characteristics, 0);
        assert!(!is_dll(pe.characteristics));
    }

    #[test]
    fn a_library_image_is_a_dll() {
        let mut b = minimal_pe(IMAGE_FILE_MACHINE_AMD64);
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
        let mut b = minimal_pe(IMAGE_FILE_MACHINE_AMD64);
        b[64] = b'X';
        assert!(matches!(parse(&b), Err(PeError::InvalidNtHeader)));
    }

    #[test]
    fn rejects_bad_dos_signature() {
        let mut b = minimal_pe(IMAGE_FILE_MACHINE_AMD64);
        b[0] = b'X';
        assert!(matches!(parse(&b), Err(PeError::InvalidDosHeader)));
    }

    #[test]
    fn reads_x86_machine() {
        // x86 (PE32) machine type.
        let pe = parse(&minimal_pe(0x014c)).expect("valid PE32");
        assert!(!is_x64(pe.machine));
        assert_eq!(pe.machine, 0x014c);
    }
}
