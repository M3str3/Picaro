//! Build manifest: a machine-readable provenance record for a packed artifact.
//!
//! Written next to the artifact as `<stem>.manifest.json`, it captures what was
//! produced (the SHA-256 and size of the artifact), from what (the payload's
//! SHA-256, the resolved plan and its hash) and with what (the rustc version
//! and stub target). It records the public nonce but **never** the payload key,
//! so the manifest is safe to archive alongside the artifact.
//!
//! Reproducing an artifact byte for byte is not possible by design (the payload
//! key and nonce are random per build), but the manifest makes a build
//! auditable: the same plan and payload always yield the same
//! `plan_sha256` / `payload_sha256` pair.

use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::plan::Plan;

use super::compiler;
use super::hash::sha256_hex;
use super::signing::Signature;
use super::{BuildError, Result};

/// Version of the manifest document itself.
pub const MANIFEST_SCHEMA: u32 = 2;

/// Length of the XChaCha20-Poly1305 nonce, in bytes.
const NONCE_LEN: usize = 24;

/// Provenance record for one build.
#[derive(Debug, Serialize)]
pub struct BuildManifest {
    /// Manifest format version.
    pub manifest_schema: u32,
    /// `name:` from the plan.
    pub name: String,
    /// Path of the packed artifact.
    pub artifact: String,
    /// SHA-256 of the packed artifact (lowercase hex).
    pub artifact_sha256: String,
    /// Size of the packed artifact, in bytes.
    pub artifact_size: u64,
    /// Path of the plan file the build read.
    pub plan_path: String,
    /// SHA-256 of the resolved plan, re-serialized as YAML.
    pub plan_sha256: String,
    /// SHA-256 of the input payload, before encryption.
    pub payload_sha256: String,
    /// Size of the input payload, in bytes.
    pub payload_size: u64,
    /// Public nonce (hex) used for this build.
    pub nonce: String,
    /// Authenticode signature applied to the artifact, when signing ran.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<Signature>,
    /// Resolved `VERSIONINFO` (after any `randomize`), when the artifact has one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_info: Option<crate::plan::schema::VersionInfoPlan>,
    /// Compiler that produced the stub.
    pub toolchain: Toolchain,
    /// The plan after build-arg substitution and defaults.
    pub resolved_plan: Plan,
}

/// The compiler that produced the stub.
#[derive(Debug, Serialize)]
pub struct Toolchain {
    /// `rustc --version` output.
    pub rustc: String,
    /// Target triple the stub was compiled for.
    pub target: String,
}

impl BuildManifest {
    /// Builds the manifest for `artifact`, reading it back to hash it.
    ///
    /// `payload` is the plaintext input, before encryption; `nonce` is the
    /// public per-build nonce.
    pub fn new(
        plan: &Plan,
        plan_path: &Path,
        artifact: &Path,
        payload: &[u8],
        nonce: [u8; NONCE_LEN],
    ) -> Result<Self> {
        let artifact_bytes = std::fs::read(artifact)?;
        Ok(Self {
            manifest_schema: MANIFEST_SCHEMA,
            name: plan.name.clone(),
            artifact: artifact.display().to_string(),
            artifact_sha256: sha256_hex(&artifact_bytes),
            artifact_size: artifact_bytes.len() as u64,
            plan_path: plan_path.display().to_string(),
            plan_sha256: plan_hash(plan)?,
            payload_sha256: sha256_hex(payload),
            payload_size: payload.len() as u64,
            nonce: hex::encode(nonce),
            signature: None,
            version_info: None,
            toolchain: Toolchain {
                rustc: compiler::rustc_version()?,
                target: compiler::stub_target(plan.build.output.arch).to_string(),
            },
            resolved_plan: plan.clone(),
        })
    }

    /// Writes the manifest as pretty JSON to `path`.
    pub fn write(&self, path: &Path) -> Result<()> {
        let json =
            serde_json::to_string_pretty(self).map_err(|e| BuildError::Manifest(e.to_string()))?;
        std::fs::write(path, json)?;
        Ok(())
    }
}

/// SHA-256 of the resolved plan, re-serialized to a canonical YAML string.
///
/// Hashing the *resolved* plan (after `$arg.N$` substitution and defaults)
/// means two invocations that build the same thing hash the same, regardless of
/// how the YAML was formatted.
pub fn plan_hash(plan: &Plan) -> Result<String> {
    let yaml = serde_yml::to_string(plan)
        .map_err(|e| BuildError::Manifest(format!("could not re-serialize the plan: {e}")))?;
    Ok(sha256_hex(yaml.as_bytes()))
}

/// The manifest path for `artifact`: a sibling with `.manifest.json`.
///
/// `dist/foo.exe` → `dist/foo.manifest.json`.
pub fn manifest_path(artifact: &Path) -> PathBuf {
    let stem = artifact
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("artifact");
    let name = format!("{stem}.manifest.json");
    match artifact.parent().filter(|p| !p.as_os_str().is_empty()) {
        Some(dir) => dir.join(name),
        None => PathBuf::from(name),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_YAML: &str = r#"
schema: 4
name: manifest-test
build:
  payload:
    source: ./payload.exe
    crypto:
      algo: xchacha20poly1305
      key: random
  output:
    path: ./dist/out.exe
    arch: x64
    strip: true
    trim_paths: all
runtime:
  - technique: reflective_loading
"#;

    #[test]
    fn manifest_path_is_a_sibling_with_the_manifest_suffix() {
        assert_eq!(
            manifest_path(Path::new("dist/foo.exe")),
            PathBuf::from("dist/foo.manifest.json")
        );
        assert_eq!(
            manifest_path(Path::new("foo.exe")),
            PathBuf::from("foo.manifest.json")
        );
    }

    #[test]
    fn plan_hash_is_stable_and_hex() {
        let plan: Plan = serde_yml::from_str(VALID_YAML).expect("valid plan");
        let first = plan_hash(&plan).expect("hash");
        let second = plan_hash(&plan).expect("hash");
        assert_eq!(first, second, "the hash must be deterministic");
        assert_eq!(first.len(), 64, "sha256 is 32 bytes of hex");
        assert!(first.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
