//! `.ico` parsing and the `RT_GROUP_ICON` directory it maps to.
//!
//! An icon file (`ICONDIR`) is a small directory of images, each with its own
//! size and pixel format. Windows wants the images as separate `RT_ICON`
//! resources plus a `GRPICONDIR` (`RT_GROUP_ICON`) that names them, which is
//! what this module produces: the raw image blobs and the group directory.

use super::ResourceError;

/// A parsed icon: the image blobs and the group directory that references them.
pub struct Icon {
    /// One blob per image, in file order (`RT_ICON` id = `index + 1`).
    pub images: Vec<Vec<u8>>,
    /// The `GRPICONDIR` bytes (`RT_GROUP_ICON`).
    pub group: Vec<u8>,
}

/// Parses a `.ico` file.
pub fn parse(bytes: &[u8]) -> Result<Icon, ResourceError> {
    if bytes.len() < 6 {
        return Err(ResourceError::InvalidIcon("truncated header".to_string()));
    }
    if read_u16(bytes, 0) != 0 {
        return Err(ResourceError::InvalidIcon(
            "reserved field is not zero".to_string(),
        ));
    }
    if read_u16(bytes, 2) != 1 {
        return Err(ResourceError::InvalidIcon(
            "not an icon (type is not 1; cursors are not supported)".to_string(),
        ));
    }
    let count = read_u16(bytes, 4) as usize;
    if count == 0 {
        return Err(ResourceError::InvalidIcon("no images".to_string()));
    }
    if bytes.len() < 6 + count * 16 {
        return Err(ResourceError::InvalidIcon(
            "truncated image directory".to_string(),
        ));
    }

    let mut images = Vec::with_capacity(count);
    let mut group = Vec::with_capacity(6 + count * 14);
    group.extend_from_slice(&0u16.to_le_bytes()); // reserved
    group.extend_from_slice(&1u16.to_le_bytes()); // type: icon
    group.extend_from_slice(&(count as u16).to_le_bytes());

    for index in 0..count {
        let entry = 6 + index * 16;
        let width = bytes[entry];
        let height = bytes[entry + 1];
        let colors = bytes[entry + 2];
        let planes = read_u16(bytes, entry + 4);
        let bit_count = read_u16(bytes, entry + 6);
        let size = read_u32(bytes, entry + 8) as usize;
        let offset = read_u32(bytes, entry + 12) as usize;

        if size == 0 {
            return Err(ResourceError::InvalidIcon(format!(
                "image {index} is empty"
            )));
        }
        let end = offset
            .checked_add(size)
            .ok_or_else(|| ResourceError::InvalidIcon(format!("image {index} overflows")))?;
        if end > bytes.len() {
            return Err(ResourceError::InvalidIcon(format!(
                "image {index} extends past the end of the file"
            )));
        }
        images.push(bytes[offset..end].to_vec());

        // GRPICONDIRENTRY: the same fields plus the RT_ICON id.
        group.push(width);
        group.push(height);
        group.push(colors);
        group.push(0); // reserved
        group.extend_from_slice(&planes.to_le_bytes());
        group.extend_from_slice(&bit_count.to_le_bytes());
        group.extend_from_slice(&(size as u32).to_le_bytes());
        group.extend_from_slice(&((index + 1) as u16).to_le_bytes());
    }

    Ok(Icon { images, group })
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a minimal two-image `.ico` around `images`.
    fn ico_with(images: &[&[u8]]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&(images.len() as u16).to_le_bytes());
        let mut offset = 6 + images.len() * 16;
        for image in images {
            out.push(16); // width
            out.push(16); // height
            out.push(0); // colors
            out.push(0); // reserved
            out.extend_from_slice(&1u16.to_le_bytes()); // planes
            out.extend_from_slice(&32u16.to_le_bytes()); // bit count
            out.extend_from_slice(&(image.len() as u32).to_le_bytes());
            out.extend_from_slice(&(offset as u32).to_le_bytes());
            offset += image.len();
        }
        for image in images {
            out.extend_from_slice(image);
        }
        out
    }

    #[test]
    fn parses_images_and_builds_a_group_directory() {
        let bytes = ico_with(&[b"first-image", b"second-image"]);
        let icon = parse(&bytes).expect("parse");
        assert_eq!(icon.images[0], b"first-image");
        assert_eq!(icon.images[1], b"second-image");
        // GRPICONDIR header: reserved, type, count.
        assert_eq!(&icon.group[..6], &[0, 0, 1, 0, 2, 0]);
        // First GRPICONDIRENTRY's id is 1 (14-byte entries from offset 6).
        assert_eq!(&icon.group[6 + 12..6 + 14], &[1, 0]);
        assert_eq!(&icon.group[6 + 14 + 12..6 + 14 + 14], &[2, 0]);
    }

    #[test]
    fn rejects_a_truncated_header() {
        assert!(matches!(
            parse(&[0, 0, 1, 0]),
            Err(ResourceError::InvalidIcon(_))
        ));
    }

    #[test]
    fn rejects_a_non_icon_type() {
        let mut bytes = ico_with(&[b"x"]);
        bytes[2] = 2; // cursor
        assert!(parse(&bytes).is_err());
    }

    #[test]
    fn rejects_an_image_that_runs_past_the_file() {
        let mut bytes = ico_with(&[b"tiny"]);
        // Corrupt the first entry's size to overrun the file.
        let size_off = 6 + 8;
        bytes[size_off..size_off + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(parse(&bytes).is_err());
    }

    #[test]
    fn rejects_an_empty_image_list() {
        let mut bytes = vec![0, 0, 1, 0, 0, 0];
        bytes.truncate(6);
        assert!(parse(&bytes).is_err());
    }
}
