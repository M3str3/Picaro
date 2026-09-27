//! `VERSIONINFO` (`RT_VERSION`) resource builder.
//!
//! Builds the nested `VS_VERSIONINFO` structure Windows reads through
//! `GetFileVersionInfo`/`VerQueryValue`: a fixed 52-byte `VS_FIXEDFILEINFO`
//! plus `StringFileInfo` and `VarFileInfo` children.
//!
//! Length convention: text nodes (`wType == 1`) store their `wValueLength` in
//! UTF-16 code units including the terminating null, container nodes use 0, and
//! the root uses the 52-byte fixed struct. Every node is padded to 4 bytes.

use super::ResourceError;
use crate::plan::schema::VersionInfoPlan;

/// Language id encoded in the string-table key and the translation entry.
const LANG: u16 = 0x0409;
/// Code page encoded in the string-table key and the translation entry.
const CODEPAGE: u16 = 1200;

/// The version used when the plan omits one.
const DEFAULT_VERSION: (u16, u16, u16, u16) = (1, 0, 0, 0);

/// Parses `MAJOR.MINOR.PATCH.BUILD` (1 to 4 dot-separated numbers).
pub fn parse_version(s: &str) -> Result<(u16, u16, u16, u16), String> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.is_empty() || parts.len() > 4 {
        return Err(format!(
            "'{s}' must be 1 to 4 dot-separated numbers (MAJOR.MINOR.PATCH.BUILD)"
        ));
    }
    let mut out = [0u16; 4];
    for (index, part) in parts.iter().enumerate() {
        if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
            return Err(format!("'{part}' in '{s}' is not a number"));
        }
        let value: u32 = part
            .parse()
            .map_err(|_| format!("'{part}' in '{s}' is not a number"))?;
        if value > u16::MAX as u32 {
            return Err(format!("'{part}' in '{s}' exceeds 65535"));
        }
        out[index] = value as u16;
    }
    Ok((out[0], out[1], out[2], out[3]))
}

/// Builds the `RT_VERSION` payload for `plan`.
pub fn build(plan: &VersionInfoPlan) -> Result<Vec<u8>, ResourceError> {
    let file = match &plan.file_version {
        Some(value) => parse_version(value).map_err(ResourceError::InvalidVersion)?,
        None => DEFAULT_VERSION,
    };
    let product = match &plan.product_version {
        Some(value) => parse_version(value).map_err(ResourceError::InvalidVersion)?,
        None => file,
    };

    let file_string = version_string(file);
    let product_string = version_string(product);

    let mut entries: Vec<(&str, &str)> = Vec::new();
    if let Some(value) = &plan.company {
        entries.push(("CompanyName", value));
    }
    if let Some(value) = &plan.description {
        entries.push(("FileDescription", value));
    }
    entries.push(("FileVersion", &file_string));
    if let Some(value) = &plan.internal_name {
        entries.push(("InternalName", value));
    }
    if let Some(value) = &plan.copyright {
        entries.push(("LegalCopyright", value));
    }
    if let Some(value) = &plan.original_filename {
        entries.push(("OriginalFilename", value));
    }
    if let Some(value) = &plan.product {
        entries.push(("ProductName", value));
    }
    entries.push(("ProductVersion", &product_string));
    // Conventional order: the string table is kept alphabetically sorted.
    entries.sort_by_key(|(key, _)| *key);

    let string_children: Vec<Vec<u8>> = entries
        .iter()
        .map(|(key, value)| string_node(key, value))
        .collect();
    let string_table = node(
        &format!("{LANG:04X}{CODEPAGE:04X}"),
        0,
        1,
        &[],
        &string_children,
    );
    let string_file_info = node("StringFileInfo", 0, 1, &[], &[string_table]);

    let translation: u32 = ((LANG as u32) << 16) | CODEPAGE as u32;
    let var = node("Translation", 4, 0, &translation.to_le_bytes(), &[]);
    let var_file_info = node("VarFileInfo", 0, 1, &[], &[var]);

    let fixed = fixed_file_info(file, product);
    let root = node(
        "VS_VERSION_INFO",
        fixed.len() as u16,
        0,
        &fixed,
        &[string_file_info, var_file_info],
    );

    if root.len() > u16::MAX as usize {
        return Err(ResourceError::TooLarge);
    }
    Ok(root)
}

/// A `String` node: `wType` 1, `wValueLength` in UTF-16 code units incl. null.
fn string_node(key: &str, value: &str) -> Vec<u8> {
    let units: Vec<u16> = value.encode_utf16().chain(std::iter::once(0)).collect();
    let mut bytes = Vec::with_capacity(units.len() * 2);
    for unit in &units {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    node(key, units.len() as u16, 1, &bytes, &[])
}

/// Builds one version node: header, UTF-16 key, value and children, each 4-byte
/// aligned, with `wLength` patched to the total size.
fn node(
    key: &str,
    value_length: u16,
    value_type: u16,
    value: &[u8],
    children: &[Vec<u8>],
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&0u16.to_le_bytes()); // wLength (patched below)
    out.extend_from_slice(&value_length.to_le_bytes());
    out.extend_from_slice(&value_type.to_le_bytes());
    for unit in key.encode_utf16().chain(std::iter::once(0)) {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    align4(&mut out);
    out.extend_from_slice(value);
    align4(&mut out);
    for child in children {
        out.extend_from_slice(child);
    }

    let length = u16::try_from(out.len()).unwrap_or(u16::MAX);
    out[0..2].copy_from_slice(&length.to_le_bytes());
    out
}

/// The 52-byte `VS_FIXEDFILEINFO`.
fn fixed_file_info(file: (u16, u16, u16, u16), product: (u16, u16, u16, u16)) -> Vec<u8> {
    let mut out = Vec::with_capacity(52);
    let mut dword = |value: u32| out.extend_from_slice(&value.to_le_bytes());
    dword(0xFEEF_04BD); // dwSignature
    dword(0x0001_0000); // dwStrucVersion
    dword(pack(file.0, file.1)); // dwFileVersionMS
    dword(pack(file.2, file.3)); // dwFileVersionLS
    dword(pack(product.0, product.1)); // dwProductVersionMS
    dword(pack(product.2, product.3)); // dwProductVersionLS
    dword(0x3F); // dwFileFlagsMask
    dword(0x0); // dwFileFlags
    dword(0x0004_0004); // dwFileOS: VOS_NT_WINDOWS32
    dword(0x0000_0001); // dwFileType: VFT_APP
    dword(0x0); // dwFileSubtype
    dword(0x0); // dwFileDateMS
    dword(0x0); // dwFileDateLS
    out
}

/// Packs two 16-bit halves into one 32-bit dword.
fn pack(high: u16, low: u16) -> u32 {
    ((high as u32) << 16) | low as u32
}

/// Pads `buf` with zeros up to a multiple of four.
fn align4(buf: &mut Vec<u8>) {
    while !buf.len().is_multiple_of(4) {
        buf.push(0);
    }
}

/// `1.2.3.4` for a version tuple.
fn version_string(version: (u16, u16, u16, u16)) -> String {
    format!("{}.{}.{}.{}", version.0, version.1, version.2, version.3)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_u16(bytes: &[u8], offset: usize) -> u16 {
        u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
    }

    #[test]
    fn parses_full_and_partial_versions() {
        assert_eq!(parse_version("1.2.3.4").unwrap(), (1, 2, 3, 4));
        assert_eq!(parse_version("2").unwrap(), (2, 0, 0, 0));
        assert_eq!(parse_version("1.2").unwrap(), (1, 2, 0, 0));
    }

    #[test]
    fn rejects_malformed_versions() {
        assert!(parse_version("").is_err());
        assert!(parse_version("1.2.3.4.5").is_err());
        assert!(parse_version("a.b").is_err());
        assert!(parse_version("65536").is_err());
        assert!(parse_version("1..2").is_err());
    }

    #[test]
    fn a_node_is_aligned_and_length_prefixed() {
        let built = node("Key", 0, 1, &[], &[]);
        assert!(built.len().is_multiple_of(4));
        assert_eq!(read_u16(&built, 0) as usize, built.len());
        assert_eq!(read_u16(&built, 2), 0);
        assert_eq!(read_u16(&built, 4), 1);
    }

    #[test]
    fn the_root_starts_with_the_version_signature() {
        let plan = VersionInfoPlan {
            company: Some("Contoso".to_string()),
            file_version: Some("1.2.3.4".to_string()),
            ..VersionInfoPlan::default()
        };
        let built = build(&plan).expect("build");
        assert!(built.len().is_multiple_of(4));
        assert_eq!(read_u16(&built, 2), 52, "wValueLength is the fixed struct");
        assert_eq!(read_u16(&built, 4), 0, "root is binary");
        // The VS_FIXEDFILEINFO signature sits right after the padded key.
        let key_len = "VS_VERSION_INFO".encode_utf16().count() * 2 + 2;
        let value_start = 6 + key_len;
        let value_start = (value_start + 3) & !3;
        let signature = u32::from_le_bytes([
            built[value_start],
            built[value_start + 1],
            built[value_start + 2],
            built[value_start + 3],
        ]);
        assert_eq!(signature, 0xFEEF_04BD);
    }

    #[test]
    fn a_version_round_trips_through_the_fixed_struct() {
        let plan = VersionInfoPlan {
            file_version: Some("1.2.3.4".to_string()),
            ..VersionInfoPlan::default()
        };
        let built = build(&plan).expect("build");
        let key_len = "VS_VERSION_INFO".encode_utf16().count() * 2 + 2;
        let value_start = (6 + key_len + 3) & !3;
        let file_ms =
            u32::from_le_bytes(built[value_start + 8..value_start + 12].try_into().unwrap());
        let file_ls = u32::from_le_bytes(
            built[value_start + 12..value_start + 16]
                .try_into()
                .unwrap(),
        );
        assert_eq!(file_ms, (1 << 16) | 2);
        assert_eq!(file_ls, (3 << 16) | 4);
    }
}
