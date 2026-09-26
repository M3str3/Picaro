//! Builder for the `.rsrc` resource-directory blob.
//!
//! The Windows resource directory is a three-level tree (type → name →
//! language) whose entries hold offsets *relative to the start of the resource
//! section*, plus a flat array of `IMAGE_RESOURCE_DATA_ENTRY` records that point
//! at the payload bytes. Because every offset is relative, the blob can be built
//! before the section's final RVA is known; [`super::inject`] then places it.
//!
//! Layout produced (all offsets relative to the blob start):
//!
//! ```text
//! [ root directory + entries ]
//! [ type directories ] ... [ name directories ] ... [ language dirs ]
//! [ IMAGE_RESOURCE_DATA_ENTRY * n ]   (16 bytes each)
//! [ payload bytes ]
//! ```

use std::collections::BTreeMap;

/// `RT_ICON`: a single icon image.
pub const RT_ICON: u16 = 3;
/// `RT_GROUP_ICON`: the icon directory that groups the images.
pub const RT_GROUP_ICON: u16 = 14;
/// `RT_VERSION`: the `VERSIONINFO` resource.
pub const RT_VERSION: u16 = 16;
/// `RT_MANIFEST`: the Windows application manifest.
pub const RT_MANIFEST: u16 = 24;

/// One resource leaf: `(type, name, language)` → bytes.
#[derive(Debug, Clone)]
pub struct Resource {
    pub type_id: u16,
    pub name_id: u16,
    pub lang_id: u16,
    pub codepage: u32,
    pub data: Vec<u8>,
}

/// A directory entry: an id and either a child directory or a leaf index.
enum Child {
    Dir(Vec<Entry>),
    Leaf(usize),
}

struct Entry {
    id: u16,
    child: Child,
}

/// Serializes `resources` into a `.rsrc` blob (see the module docs).
///
/// `rva_base` is the RVA the section will be loaded at; it is baked into each
/// `IMAGE_RESOURCE_DATA_ENTRY.OffsetToData` (an image RVA), while the directory
/// offsets stay relative to the blob start.
pub fn build_blob(resources: &[Resource], rva_base: u32) -> Vec<u8> {
    if resources.is_empty() {
        return Vec::new();
    }
    let root = build_tree(resources);
    let mut builder = Builder {
        buf: Vec::new(),
        leaf_fields: Vec::new(),
    };
    builder.write_dir(&root);

    // Data entries first, then the raw payloads (see the module layout).
    let leaf_fields = std::mem::take(&mut builder.leaf_fields);
    let mut data_entries: Vec<(usize, usize)> = Vec::with_capacity(leaf_fields.len());
    for (field, index) in leaf_fields {
        let entry_pos = builder.buf.len();
        builder.buf.extend_from_slice(&[0u8; 16]);
        let relative = entry_pos as u32;
        builder.buf[field..field + 4].copy_from_slice(&relative.to_le_bytes());
        data_entries.push((entry_pos, index));
    }

    for (entry_pos, index) in data_entries {
        align4(&mut builder.buf);
        let offset = builder.buf.len() as u32;
        let resource = &resources[index];
        builder.buf.extend_from_slice(&resource.data);
        let size = resource.data.len() as u32;
        write_u32(&mut builder.buf, entry_pos, rva_base + offset);
        write_u32(&mut builder.buf, entry_pos + 4, size);
        write_u32(&mut builder.buf, entry_pos + 8, resource.codepage);
        write_u32(&mut builder.buf, entry_pos + 12, 0);
    }

    align4(&mut builder.buf);
    builder.buf
}

/// Groups `resources` by `(type, name, language)` into the directory tree.
///
/// Entries are kept in ascending id order (required for the loader's binary
/// search), which a `BTreeMap` gives for free.
fn build_tree(resources: &[Resource]) -> Vec<Entry> {
    let mut types: BTreeMap<u16, BTreeMap<u16, BTreeMap<u16, usize>>> = BTreeMap::new();
    for (index, resource) in resources.iter().enumerate() {
        types
            .entry(resource.type_id)
            .or_default()
            .entry(resource.name_id)
            .or_default()
            .insert(resource.lang_id, index);
    }

    types
        .into_iter()
        .map(|(type_id, names)| Entry {
            id: type_id,
            child: Child::Dir(
                names
                    .into_iter()
                    .map(|(name_id, langs)| Entry {
                        id: name_id,
                        child: Child::Dir(
                            langs
                                .into_iter()
                                .map(|(lang_id, index)| Entry {
                                    id: lang_id,
                                    child: Child::Leaf(index),
                                })
                                .collect(),
                        ),
                    })
                    .collect(),
            ),
        })
        .collect()
}

struct Builder {
    buf: Vec<u8>,
    /// `(offset of the entry's OffsetToData field, leaf index)`.
    leaf_fields: Vec<(usize, usize)>,
}

impl Builder {
    /// Writes a directory (header + entries) and then its child directories,
    /// returning the directory's offset relative to the blob start.
    ///
    /// All entries of a directory must stay contiguous (the loader reads
    /// `NumberOfIdEntries` of them starting right after the header), so child
    /// directories are written *after* the entries array, not interleaved.
    fn write_dir(&mut self, entries: &[Entry]) -> u32 {
        let start = self.buf.len() as u32;
        self.buf.extend_from_slice(&0u32.to_le_bytes()); // Characteristics
        self.buf.extend_from_slice(&0u32.to_le_bytes()); // TimeDateStamp
        self.buf.extend_from_slice(&0u16.to_le_bytes()); // MajorVersion
        self.buf.extend_from_slice(&0u16.to_le_bytes()); // MinorVersion
        self.buf.extend_from_slice(&0u16.to_le_bytes()); // NumberOfNamedEntries
        self.buf
            .extend_from_slice(&(entries.len() as u16).to_le_bytes()); // NumberOfIdEntries

        // Record the children while writing the contiguous entries array.
        let mut directories: Vec<(usize, &Vec<Entry>)> = Vec::new();
        let mut leaves: Vec<(usize, usize)> = Vec::new();
        for entry in entries {
            self.buf.extend_from_slice(&(entry.id as u32).to_le_bytes());
            let field = self.buf.len();
            self.buf.extend_from_slice(&0u32.to_le_bytes());
            match &entry.child {
                Child::Dir(children) => directories.push((field, children)),
                Child::Leaf(index) => leaves.push((field, *index)),
            }
        }

        for (field, children) in directories {
            let offset = self.write_dir(children);
            write_u32(&mut self.buf, field, offset | 0x8000_0000);
        }
        self.leaf_fields.extend(leaves);
        start
    }
}

/// Pads `buf` with zeros up to a multiple of four.
fn align4(buf: &mut Vec<u8>) {
    while !buf.len().is_multiple_of(4) {
        buf.push(0);
    }
}

/// Overwrites four little-endian bytes at `offset`.
fn write_u32(buf: &mut [u8], offset: usize, value: u32) {
    buf[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal reader that walks the tree from the root along *ids*.
    struct Reader<'a> {
        blob: &'a [u8],
    }

    impl<'a> Reader<'a> {
        fn u16(&self, off: usize) -> u16 {
            u16::from_le_bytes([self.blob[off], self.blob[off + 1]])
        }

        fn u32(&self, off: usize) -> u32 {
            u32::from_le_bytes([
                self.blob[off],
                self.blob[off + 1],
                self.blob[off + 2],
                self.blob[off + 3],
            ])
        }

        /// Returns `(offset, is_directory)` of the child with `id`.
        fn find(&self, dir: usize, id: u16) -> (usize, bool) {
            let count = self.u16(dir + 12) as usize + self.u16(dir + 14) as usize;
            for i in 0..count {
                let entry = dir + 16 + i * 8;
                if self.u32(entry) == id as u32 {
                    let target = self.u32(entry + 4);
                    return ((target & 0x7fff_ffff) as usize, target & 0x8000_0000 != 0);
                }
            }
            panic!("id {id} not found in directory at {dir}");
        }

        /// Follows `type → name → language` to the `IMAGE_RESOURCE_DATA_ENTRY`
        /// offset and returns it.
        fn leaf_entry(&self, type_id: u16, name_id: u16, lang_id: u16) -> usize {
            let (type_dir, is_dir) = self.find(0, type_id);
            assert!(is_dir);
            let (name_dir, is_dir) = self.find(type_dir, name_id);
            assert!(is_dir);
            let (lang_entry, is_dir) = self.find(name_dir, lang_id);
            assert!(!is_dir);
            lang_entry
        }

        /// The leaf's `OffsetToData` field (an image RVA).
        fn data_offset(&self, type_id: u16, name_id: u16, lang_id: u16) -> u32 {
            let entry = self.leaf_entry(type_id, name_id, lang_id);
            self.u32(entry)
        }

        /// Follows `type → name → language` and returns the leaf payload.
        fn data(&self, type_id: u16, name_id: u16, lang_id: u16) -> &'a [u8] {
            let entry = self.leaf_entry(type_id, name_id, lang_id);
            // `entry` points at an IMAGE_RESOURCE_DATA_ENTRY whose OffsetToData
            // is an image RVA; these tests build with base 0, so it is also the
            // blob-relative offset.
            let offset = self.u32(entry) as usize;
            let size = self.u32(entry + 4) as usize;
            &self.blob[offset..offset + size]
        }
    }

    fn resource(type_id: u16, name_id: u16, data: &[u8]) -> Resource {
        Resource {
            type_id,
            name_id,
            lang_id: 0x0409,
            codepage: 0,
            data: data.to_vec(),
        }
    }

    #[test]
    fn round_trips_a_single_resource() {
        let resources = vec![resource(RT_MANIFEST, 1, b"<assembly/>")];
        let blob = build_blob(&resources, 0);
        let reader = Reader { blob: &blob };
        assert_eq!(reader.data(RT_MANIFEST, 1, 0x0409), b"<assembly/>");
    }

    #[test]
    fn round_trips_several_types_and_names() {
        let resources = vec![
            resource(RT_ICON, 1, b"icon-one"),
            resource(RT_ICON, 2, b"icon-two"),
            resource(RT_GROUP_ICON, 1, b"group"),
            resource(RT_VERSION, 1, b"version"),
            resource(RT_MANIFEST, 1, b"manifest"),
        ];
        let blob = build_blob(&resources, 0);
        let reader = Reader { blob: &blob };
        assert_eq!(reader.data(RT_ICON, 1, 0x0409), b"icon-one");
        assert_eq!(reader.data(RT_ICON, 2, 0x0409), b"icon-two");
        assert_eq!(reader.data(RT_GROUP_ICON, 1, 0x0409), b"group");
        assert_eq!(reader.data(RT_VERSION, 1, 0x0409), b"version");
        assert_eq!(reader.data(RT_MANIFEST, 1, 0x0409), b"manifest");
    }

    #[test]
    fn entries_are_sorted_by_id() {
        // Insertion order is deliberately unsorted.
        let resources = vec![resource(RT_VERSION, 1, b"v"), resource(RT_ICON, 1, b"i")];
        let blob = build_blob(&resources, 0);
        let reader = Reader { blob: &blob };
        assert_eq!(reader.u16(14), 2, "two id entries at the root");
        assert_eq!(reader.u32(16), RT_ICON as u32);
        assert_eq!(reader.u32(24), RT_VERSION as u32);
    }

    #[test]
    fn the_blob_is_four_byte_aligned() {
        let resources = vec![resource(RT_MANIFEST, 1, b"odd")];
        assert!(build_blob(&resources, 0).len().is_multiple_of(4));
    }

    #[test]
    fn data_offsets_carry_the_section_rva() {
        let resources = vec![resource(RT_MANIFEST, 1, b"x")];
        let relative = build_blob(&resources, 0);
        let shifted = build_blob(&resources, 0x1000);
        // The data entry's OffsetToData is an image RVA, so a non-zero base
        // shifts it by exactly that amount; the blob size is unchanged.
        let rel = Reader { blob: &relative }.data_offset(RT_MANIFEST, 1, 0x0409);
        let val = Reader { blob: &shifted }.data_offset(RT_MANIFEST, 1, 0x0409);
        assert_eq!(val, rel + 0x1000);
        assert_eq!(shifted.len(), relative.len());
    }
}
