//! Appends a `.rsrc` section to a compiled PE.
//!
//! The linker never sees the resources: the stub is compiled first, then this
//! runs on the resulting image, which keeps the build free of `rc.exe` and
//! identical for the MSVC and GNU toolchains. A section header is written into
//! the slack between the section table and the first section's raw data (the
//! linkers always leave some), the `RESOURCE` data directory is set and
//! `SizeOfImage` is grown to cover the new section.
//!
//! Note the two offset spaces in play: a directory entry points at the next
//! level *relative to the resource directory*, while
//! `IMAGE_RESOURCE_DATA_ENTRY.OffsetToData` is an **image RVA**. The blob is
//! therefore built with the section's final RVA (see [`super::embed`]).

use super::ResourceError;

/// Resource data-directory index in the optional header.
const DIR_RESOURCE: usize = 2;
/// `IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ`.
const RSRC_CHARACTERISTICS: u32 = 0x4000_0000 | 0x0000_0002;
/// `IMAGE_NT_SIGNATURE` (`PE\0\0`).
const PE_SIGNATURE: u32 = 0x0000_4550;
/// Optional-header magics.
const PE32_MAGIC: u16 = 0x010B;
const PE32_PLUS_MAGIC: u16 = 0x020B;

/// Where a new section would be placed in a compiled PE.
///
/// Parsed once so the resource blob and the section header agree on the RVA.
struct Layout {
    file_header: usize,
    opt: usize,
    num_sections: usize,
    section_table_end: usize,
    dirs_off: usize,
    section_align: u64,
    file_align: u64,
    /// RVA the new section will be loaded at.
    rva: u32,
}

impl Layout {
    fn parse(pe: &[u8]) -> Result<Self, ResourceError> {
        if pe.len() < 2 || &pe[..2] != b"MZ" {
            return Err(invalid("missing MZ signature"));
        }
        let e_lfanew = read_u32(pe, 0x3C).ok_or_else(|| invalid("truncated DOS header"))? as usize;
        if read_u32(pe, e_lfanew) != Some(PE_SIGNATURE) {
            return Err(invalid("missing PE signature"));
        }

        let file_header = e_lfanew + 4;
        let num_sections =
            read_u16(pe, file_header + 2).ok_or_else(|| invalid("truncated file header"))? as usize;
        let size_optional = read_u16(pe, file_header + 16)
            .ok_or_else(|| invalid("truncated file header"))? as usize;
        let opt = file_header + 20;
        let magic = read_u16(pe, opt).ok_or_else(|| invalid("truncated optional header"))?;

        let (num_dirs, dirs_off) = match magic {
            PE32_PLUS_MAGIC => (read_u32(pe, opt + 108), opt + 112),
            PE32_MAGIC => (read_u32(pe, opt + 92), opt + 96),
            _ => return Err(invalid("unknown optional-header magic")),
        };
        let num_dirs = num_dirs.ok_or_else(|| invalid("truncated optional header"))? as usize;
        if num_dirs <= DIR_RESOURCE {
            return Err(ResourceError::NoResourceDirectory);
        }

        let section_align =
            read_u32(pe, opt + 32).ok_or_else(|| invalid("truncated header"))? as u64;
        let file_align = read_u32(pe, opt + 36).ok_or_else(|| invalid("truncated header"))? as u64;
        if section_align == 0 || file_align == 0 {
            return Err(invalid("zero section/file alignment"));
        }

        let section_table = opt + size_optional;
        let section_table_end = section_table + num_sections * 40;
        if pe.len() < section_table_end {
            return Err(invalid("section table extends past the end of the file"));
        }

        let mut first_raw = usize::MAX;
        let mut max_va_end: u64 = 0;
        for index in 0..num_sections {
            let section = section_table + index * 40;
            let virtual_address = read_u32(pe, section + 12).unwrap_or(0) as u64;
            let virtual_size = read_u32(pe, section + 8).unwrap_or(0) as u64;
            let raw_size = read_u32(pe, section + 16).unwrap_or(0) as u64;
            let raw_pointer = read_u32(pe, section + 20).unwrap_or(0) as usize;
            // Sections without raw data (e.g. `.bss`) have a zero pointer and
            // must not be mistaken for the start of the file's payload.
            if raw_size > 0 {
                first_raw = first_raw.min(raw_pointer);
            }
            max_va_end = max_va_end.max(virtual_address + virtual_size.max(raw_size));
        }
        let first_raw = if first_raw == usize::MAX {
            section_table_end
        } else {
            first_raw
        };
        let available = first_raw.saturating_sub(section_table_end);
        if available < 40 {
            return Err(ResourceError::NoHeaderRoom { available });
        }

        let rva = align_up(max_va_end, section_align)?;
        u32::try_from(rva).map_err(|_| ResourceError::TooLarge)?;

        Ok(Self {
            file_header,
            opt,
            num_sections,
            section_table_end,
            dirs_off,
            section_align,
            file_align,
            rva: rva as u32,
        })
    }

    /// Appends `rsrc` as a `.rsrc` section loaded at [`Layout::rva`].
    fn append(&self, pe: &[u8], rsrc: &[u8]) -> Result<Vec<u8>, ResourceError> {
        let raw_offset = align_up(pe.len() as u64, self.file_align)?;
        let raw_size = align_up(rsrc.len() as u64, self.file_align)?;
        let size_of_image = align_up(self.rva as u64 + rsrc.len() as u64, self.section_align)?;
        let as_u32 = |value: u64| -> Result<u32, ResourceError> {
            u32::try_from(value).map_err(|_| ResourceError::TooLarge)
        };

        let mut out = pe.to_vec();
        out.resize(raw_offset as usize, 0);
        out.extend_from_slice(rsrc);
        out.resize((raw_offset + raw_size) as usize, 0);

        let header = self.section_table_end;
        out[header..header + 8].copy_from_slice(b".rsrc\0\0\0");
        write_u32(&mut out, header + 8, as_u32(rsrc.len() as u64)?);
        write_u32(&mut out, header + 12, self.rva);
        write_u32(&mut out, header + 16, as_u32(raw_size)?);
        write_u32(&mut out, header + 20, as_u32(raw_offset)?);
        write_u32(&mut out, header + 24, 0);
        write_u32(&mut out, header + 28, 0);
        write_u16(&mut out, header + 32, 0);
        write_u16(&mut out, header + 34, 0);
        write_u32(&mut out, header + 36, RSRC_CHARACTERISTICS);

        write_u16(
            &mut out,
            self.file_header + 2,
            (self.num_sections + 1) as u16,
        );
        write_u32(&mut out, self.opt + 56, as_u32(size_of_image)?);
        write_u32(&mut out, self.opt + 64, 0);
        write_u32(&mut out, self.dirs_off + DIR_RESOURCE * 8, self.rva);
        write_u32(
            &mut out,
            self.dirs_off + DIR_RESOURCE * 8 + 4,
            as_u32(rsrc.len() as u64)?,
        );

        Ok(out)
    }
}

/// The RVA a new resource section would be loaded at.
pub(crate) fn next_section_rva(pe: &[u8]) -> Result<u32, ResourceError> {
    Ok(Layout::parse(pe)?.rva)
}

/// Returns `pe` with `rsrc` appended as a `.rsrc` section.
///
/// `rsrc` must have been built with the RVA from [`next_section_rva`]
/// (`super::embed` takes care of that). An empty `rsrc` is a no-op.
pub fn inject(pe: &[u8], rsrc: &[u8]) -> Result<Vec<u8>, ResourceError> {
    if rsrc.is_empty() {
        return Ok(pe.to_vec());
    }
    Layout::parse(pe)?.append(pe, rsrc)
}

/// Rounds `value` up to a multiple of `align`.
fn align_up(value: u64, align: u64) -> Result<u64, ResourceError> {
    if align == 0 {
        return Err(invalid("zero alignment"));
    }
    Ok(value.div_ceil(align) * align)
}

/// A malformed-PE error with a static detail.
fn invalid(detail: &str) -> ResourceError {
    ResourceError::InvalidPe(detail.to_string())
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    let slice = bytes.get(offset..offset + 2)?;
    Some(u16::from_le_bytes([slice[0], slice[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let slice = bytes.get(offset..offset + 4)?;
    Some(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn write_u16(buf: &mut [u8], offset: usize, value: u16) {
    buf[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32(buf: &mut [u8], offset: usize, value: u32) {
    buf[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::schema::{ExecutionLevel, ManifestConfig, ResourcesConfig};
    use std::path::Path;

    fn fixture() -> Vec<u8> {
        std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests")
                .join("fixtures")
                .join("minimal_x64.exe"),
        )
        .expect("read the PE fixture")
    }

    fn manifest_config() -> ResourcesConfig {
        ResourcesConfig {
            icon: None,
            version_info: None,
            manifest: Some(ManifestConfig {
                level: ExecutionLevel::RequireAdministrator,
                ui_access: false,
                dpi_aware: true,
            }),
        }
    }

    #[test]
    fn embedding_a_manifest_adds_a_resource_section() {
        let pe = fixture();
        let before = crate::audit::pe_info::analyze(&pe).expect("fixture parses");
        assert!(!before.has_manifest);

        let out = crate::engine::resources::embed(&pe, &manifest_config()).expect("embed");
        let after = crate::audit::pe_info::analyze(&out).expect("output parses");
        assert_eq!(after.sections.len(), before.sections.len() + 1);
        assert!(
            after.sections.iter().any(|s| s.name == ".rsrc"),
            "sections: {:?}",
            after.sections.iter().map(|s| &s.name).collect::<Vec<_>>()
        );
        assert!(after.has_manifest, "the RT_MANIFEST must be found");
    }

    #[test]
    fn the_resource_data_entry_points_inside_the_section() {
        // `OffsetToData` is an image RVA: it must fall within
        // `[section_rva, section_rva + section_size)`.
        let pe = fixture();
        let rva = next_section_rva(&pe).expect("rva");
        let blob = crate::engine::resources::build(&manifest_config(), rva).expect("build");
        // Walk root -> type 24 -> name 1 -> lang 0x409 to the data entry.
        let root = 0usize;
        let find = |dir: usize, id: u32| -> u32 {
            let count = read_u16(&blob, dir + 14).unwrap() as usize;
            for i in 0..count {
                let entry = dir + 16 + i * 8;
                if read_u32(&blob, entry).unwrap() == id {
                    return read_u32(&blob, entry + 4).unwrap();
                }
            }
            panic!("id {id} not found");
        };
        let type_dir = (find(root, 24) & 0x7fff_ffff) as usize;
        let name_dir = (find(type_dir, 1) & 0x7fff_ffff) as usize;
        let data_entry = (find(name_dir, 0x0409) & 0x7fff_ffff) as usize;
        let offset_to_data = read_u32(&blob, data_entry).unwrap();
        assert!(
            offset_to_data >= rva && (offset_to_data as usize) < rva as usize + blob.len(),
            "OffsetToData {offset_to_data:#x} outside [{rva:#x}, {:#x})",
            rva as usize + blob.len()
        );
    }

    #[test]
    fn injecting_zero_bytes_is_a_no_op() {
        let pe = fixture();
        assert_eq!(inject(&pe, &[]).expect("inject"), pe);
    }

    #[test]
    fn a_non_pe_is_rejected() {
        let err = crate::engine::resources::embed(b"not a pe at all", &manifest_config())
            .expect_err("must fail");
        assert!(err.to_string().contains("MZ"), "unclear: {err}");
    }
}
