//! PE resource embedding: icon, `VERSIONINFO` and the application manifest.
//!
//! Everything is built in Rust and written into a new `.rsrc` section of the
//! already-compiled stub, so no `rc.exe`/`windres` (and no cross-platform
//! resource compiler) is needed. See [`build`] for the blob and [`inject`] for
//! the section placement.

pub mod icon;
pub mod inject;
pub mod manifest;
pub mod tree;
pub mod version;

use std::path::PathBuf;

use crate::config::schema::ResourcesConfig;
use tree::{Resource, RT_GROUP_ICON, RT_ICON, RT_MANIFEST, RT_VERSION};

/// Language id attached to every resource we emit (en-US).
const LANG_EN_US: u16 = 0x0409;
/// Unicode code page, used for the version resource.
const CODEPAGE_UNICODE: u32 = 1200;
/// UTF-8 code page, used for the manifest resource.
const CODEPAGE_UTF8: u32 = 65001;

/// Resource embedding error.
#[derive(Debug, thiserror::Error)]
pub enum ResourceError {
    /// The icon file could not be read.
    #[error("could not read icon '{path}': {source}")]
    IconRead {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// The icon file is not a valid `.ico`.
    #[error("invalid .ico file: {0}")]
    InvalidIcon(String),
    /// A version string is not `MAJOR.MINOR.PATCH.BUILD`.
    #[error("invalid version string: {0}")]
    InvalidVersion(String),
    /// The compiled stub is not a parseable PE.
    #[error("the compiled stub is not a valid PE: {0}")]
    InvalidPe(String),
    /// There is no room for another section header in the PE header region.
    #[error(
        "no room for another section header ({available} bytes free, 40 needed); \
         the PE header layout is unexpected"
    )]
    NoHeaderRoom { available: usize },
    /// The PE has no resource data-directory slot.
    #[error("the PE has no resource data-directory slot")]
    NoResourceDirectory,
    /// A section value does not fit in the PE's 32-bit fields.
    #[error("the resource section is too large to embed")]
    TooLarge,
    /// The icon has more images than the format can name.
    #[error("the icon has too many images ({0})")]
    TooManyIcons(usize),
}

/// Returns `pe` with the resources described by `config` embedded.
///
/// The section RVA is resolved first so the blob can bake it into its data
/// entries (see [`inject`]). A config with no resource set is a no-op.
pub fn embed(pe: &[u8], config: &ResourcesConfig) -> Result<Vec<u8>, ResourceError> {
    if config.icon.is_none() && config.version_info.is_none() && config.manifest.is_none() {
        return Ok(pe.to_vec());
    }
    let rva = inject::next_section_rva(pe)?;
    let blob = build(config, rva)?;
    if blob.is_empty() {
        return Ok(pe.to_vec());
    }
    inject::inject(pe, &blob)
}

/// Builds the `.rsrc` blob described by `config`.
///
/// `rva_base` is the RVA the section will be loaded at; it becomes each data
/// entry's `OffsetToData`. Callers that only validate the config (e.g.
/// `--dry-run`) can pass `0`. Returns an empty vector when no resource is set.
pub fn build(config: &ResourcesConfig, rva_base: u32) -> Result<Vec<u8>, ResourceError> {
    let mut resources = Vec::new();

    if let Some(path) = &config.icon {
        let bytes = std::fs::read(path).map_err(|source| ResourceError::IconRead {
            path: path.clone(),
            source,
        })?;
        let parsed = icon::parse(&bytes)?;
        // The group icon (id 1) is the one the shell shows; the images follow.
        resources.push(Resource {
            type_id: RT_GROUP_ICON,
            name_id: 1,
            lang_id: LANG_EN_US,
            codepage: 0,
            data: parsed.group,
        });
        for (index, image) in parsed.images.into_iter().enumerate() {
            let name_id =
                u16::try_from(index + 1).map_err(|_| ResourceError::TooManyIcons(index + 1))?;
            resources.push(Resource {
                type_id: RT_ICON,
                name_id,
                lang_id: LANG_EN_US,
                codepage: 0,
                data: image,
            });
        }
    }

    if let Some(info) = &config.version_info {
        resources.push(Resource {
            type_id: RT_VERSION,
            name_id: 1,
            lang_id: LANG_EN_US,
            codepage: CODEPAGE_UNICODE,
            data: version::build(info)?,
        });
    }

    if let Some(settings) = &config.manifest {
        resources.push(Resource {
            type_id: RT_MANIFEST,
            name_id: 1,
            lang_id: LANG_EN_US,
            codepage: CODEPAGE_UTF8,
            data: manifest::build(settings),
        });
    }

    Ok(tree::build_blob(&resources, rva_base))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::schema::{ExecutionLevel, ManifestConfig, VersionInfoConfig};

    #[test]
    fn an_empty_config_produces_an_empty_blob() {
        let config = ResourcesConfig::default();
        assert!(build(&config, 0).expect("build").is_empty());
    }

    #[test]
    fn a_manifest_alone_produces_a_blob() {
        let config = ResourcesConfig {
            icon: None,
            version_info: None,
            manifest: Some(ManifestConfig {
                level: ExecutionLevel::RequireAdministrator,
                ui_access: false,
                dpi_aware: true,
            }),
        };
        assert!(!build(&config, 0).expect("build").is_empty());
    }

    #[test]
    fn version_and_manifest_together_produce_a_blob() {
        let config = ResourcesConfig {
            icon: None,
            version_info: Some(VersionInfoConfig {
                description: Some("Widget".to_string()),
                file_version: Some("1.2.3.4".to_string()),
                ..VersionInfoConfig::default()
            }),
            manifest: Some(ManifestConfig::default()),
        };
        let blob = build(&config, 0).expect("build");
        assert!(blob.len().is_multiple_of(4) && !blob.is_empty());
    }
}
