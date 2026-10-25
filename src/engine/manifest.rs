//! Build manifest: the resolved plan plus a `reproduce` record.
//!
//! A manifest is not a sidecar that *describes* a build: it **is** the build.
//! The top level has the same shape as a plan (`schema`, `name`, `build`,
//! `runtime`), so feeding it back into `picaro build` reloads the plan through
//! the ordinary loader; the `reproduce` block adds the entropy and payload
//! pins that a plan cannot express.
//!
//! Two hashes are recorded:
//!
//! - `unsigned_sha256` — the artifact before signing. This is the
//!   reproducibility target (an Authenticode signature is not reproducible).
//! - `artifact_sha256` — the file that was actually written, after signing.
//!
//! The payload key is stored by default (`secrets: exact`): a reproducible
//! build that cannot recover its own key is not reproducible. That makes the
//! manifest as sensitive as the payload, so the build prints a warning and
//! [`redact`] produces a shareable copy with the keys stripped.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::plan::schema::{
    EntropyRecord, KeySource, PayloadReproduction, Predecessor, ReproducePlan, SecretsPolicy,
    StringsRecord, ToolchainRecord, VersionInfoPlan,
};
use crate::plan::Plan;

use super::compiler;
use super::entropy::BuildEntropy;
use super::hash::sha256_hex;
use super::polymorphism::PolymorphismRecord;
use super::signing::Signature;
use super::{BuildError, Result};

/// Version of the manifest document itself.
///
/// Schema 4 is "the manifest is a plan": top-level `schema`/`name`/`build`/
/// `runtime` plus `reproduce`.
pub const MANIFEST_SCHEMA: u32 = 4;

/// Everything the caller collected during the build and the manifest records.
pub struct ManifestInputs {
    /// Resolved `VERSIONINFO`, when the artifact carries one.
    pub identity: Option<VersionInfoPlan>,
    /// Seed of a generated icon, when one was embedded.
    pub icon: Option<u64>,
    /// Resolved polymorphism profile, when the artifact is a Rust stub.
    pub polymorphism: Option<PolymorphismRecord>,
    /// Resolved string-obfuscation strategy, when the artifact has stub strings.
    pub strings_strategy: Option<String>,
    /// Signature applied to the artifact.
    pub signature: Option<Signature>,
    /// Per-payload pins and cipher inputs.
    pub payloads: BTreeMap<String, PayloadReproduction>,
    /// The build this one replays, when it is a replay.
    pub predecessor: Option<Predecessor>,
    /// Whether keys are stored.
    pub secrets: SecretsPolicy,
}

/// Builds the manifest plan for a finished build.
///
/// The returned document validates as a normal plan: replaying it does not
/// need a second parser or a special shape.
pub fn compose(plan: &Plan, entropy: &BuildEntropy, inputs: ManifestInputs) -> Result<Plan> {
    let seed = format!("{:#x}", entropy.seed);
    let reproduce = ReproducePlan {
        manifest_schema: MANIFEST_SCHEMA,
        picaro: env!("CARGO_PKG_VERSION").to_string(),
        toolchain: ToolchainRecord {
            rustc: compiler::rustc_version()?,
            target: compiler::stub_target(plan.build.output.arch).to_string(),
        },
        seed: None,
        entropy: EntropyRecord {
            seed,
            polymorphism: inputs.polymorphism,
            strings: inputs
                .strings_strategy
                .map(|strategy| StringsRecord { strategy }),
            icon: inputs.icon,
        },
        secrets: inputs.secrets,
        payloads: inputs.payloads,
        identity: inputs.identity,
        predecessor: inputs.predecessor,
        signature: inputs.signature,
        effective_sha256: None,
        plan_sha256: None,
    };

    let mut manifest = plan.clone();
    manifest.reproduce = Some(reproduce);

    // The hash covers the *plan* and the payload inputs, never the record that
    // carries the hash itself (that would be circular) nor the predecessor.
    let payloads = manifest
        .reproduce
        .as_ref()
        .map(|record| &record.payloads)
        .cloned()
        .unwrap_or_default();
    let hash = effective_hash(&manifest, entropy, &payloads)?;
    if let Some(record) = manifest.reproduce.as_mut() {
        record.effective_sha256 = Some(hash.clone());
        // Deprecated alias, kept for one release.
        record.plan_sha256 = Some(hash);
    }
    Ok(manifest)
}

/// Writes `plan` as pretty JSON to `path`.
pub fn write(plan: &Plan, path: &Path) -> Result<()> {
    let json =
        serde_json::to_string_pretty(plan).map_err(|e| BuildError::Manifest(e.to_string()))?;
    std::fs::write(path, json)?;
    Ok(())
}

/// Writes a shareable copy of `plan`: `secrets: audit`, keys stripped.
pub fn redact(plan: &Plan, path: &Path) -> Result<()> {
    let mut copy = plan.clone();
    if let Some(record) = copy.reproduce.as_mut() {
        record.secrets = SecretsPolicy::Audit;
        for payload in record.payloads.values_mut() {
            payload.key = None;
        }
    }
    strip_literal_keys(&mut copy);
    write(&copy, path)
}

/// Replaces literal keys in the plan with `random`; file paths are kept.
fn strip_literal_keys(plan: &mut Plan) {
    if let Some(crypto) = plan.build.crypto.as_mut() {
        strip_literal_key(&mut crypto.key);
    }
    for payload in plan.build.payloads.values_mut() {
        if let Some(crypto) = payload.crypto.as_mut() {
            strip_literal_key(&mut crypto.key);
        }
    }
    if let Some(strings) = plan.build.stub.strings.as_mut() {
        if strings.key.starts_with("literal:") {
            strings.key = "random".to_string();
        }
    }
}

fn strip_literal_key(key: &mut KeySource) {
    if matches!(key, KeySource::Literal(_)) {
        *key = KeySource::Random;
    }
}

/// The hash of the effective inputs: resolved plan, master seed and payload
/// SHA-256s (with the cipher inputs that go with them).
///
/// This replaces the old `plan_sha256`, which hashed only the plan and so gave
/// two different builds the same identifier. A normal build and its replay hash
/// the same because the `reproduce` block itself is excluded from the input.
pub fn effective_hash(
    plan: &Plan,
    entropy: &BuildEntropy,
    payloads: &BTreeMap<String, PayloadReproduction>,
) -> Result<String> {
    let mut canonical = plan.clone();
    canonical.reproduce = None;
    let inputs = EffectiveInputs {
        plan: &canonical,
        seed: entropy.seed,
        payloads,
    };
    let json = serde_json::to_vec(&inputs)
        .map_err(|e| BuildError::Manifest(format!("could not serialize the inputs: {e}")))?;
    Ok(sha256_hex(&json))
}

/// The canonical shape [`effective_hash`] hashes.
#[derive(Serialize)]
struct EffectiveInputs<'a> {
    plan: &'a Plan,
    seed: u64,
    payloads: &'a BTreeMap<String, PayloadReproduction>,
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

/// A manifest path that never overwrites the source document.
///
/// Replaying `dist/hello.manifest.json` writes `dist/hello.manifest.json`
/// again when the output is `dist/hello.exe`; that is the same recipe file. To
/// keep the source intact, the new record goes to
/// `dist/hello.manifest.replay.json` in that one case.
pub fn replay_manifest_path(artifact: &Path, source: &Path) -> PathBuf {
    let candidate = manifest_path(artifact);
    if same_path(&candidate, source) {
        let stem = artifact
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("artifact");
        let name = format!("{stem}.manifest.replay.json");
        match artifact.parent().filter(|p| !p.as_os_str().is_empty()) {
            Some(dir) => dir.join(name),
            None => PathBuf::from(name),
        }
    } else {
        candidate
    }
}

/// Best-effort path comparison (`canonicalize` needs the file to exist).
fn same_path(a: &Path, b: &Path) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => a == b,
    }
}

/// The current UTC time as `YYYY-MM-DDTHH:MM:SSZ`.
pub fn built_at_now() -> String {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    format_utc(seconds)
}

/// Formats Unix seconds as an RFC 3339 UTC timestamp.
fn format_utc(seconds: u64) -> String {
    let days = (seconds / 86_400) as i64;
    let clock = seconds % 86_400;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        clock / 3_600,
        (clock % 3_600) / 60,
        clock % 60
    )
}

/// Days since the Unix epoch to a civil `(year, month, day)`.
///
/// Howard Hinnant's `civil_from_days`, valid for the whole range a build can
/// produce.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = if month <= 2 { y + 1 } else { y };
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_YAML: &str = r#"
schema: 6
name: manifest-test
build:
  crypto:
    algo: xchacha20poly1305
    key: random
  payloads:
    implant:
      source: ./payload.exe
      format: pe
  output:
    path: ./dist/out.exe
    arch: x64
    strip: true
    trim_paths: all
runtime:
  - technique: reflective_loading
"#;

    fn plan() -> Plan {
        serde_yml::from_str(VALID_YAML).expect("valid plan")
    }

    fn payload(key: Option<&str>) -> PayloadReproduction {
        PayloadReproduction {
            sha256: Some("aa".repeat(32)),
            size: Some(10),
            nonce: Some("bb".repeat(24)),
            key: key.map(str::to_string),
        }
    }

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
    fn a_replay_never_overwrites_the_source_recipe() {
        let source = Path::new("dist/hello.manifest.json");
        assert_eq!(
            replay_manifest_path(Path::new("dist/hello.exe"), source),
            PathBuf::from("dist/hello.manifest.replay.json")
        );
        assert_eq!(
            replay_manifest_path(Path::new("dist/other.exe"), source),
            PathBuf::from("dist/other.manifest.json")
        );
    }

    #[test]
    fn effective_hash_is_stable_and_covers_the_seed() {
        let plan = plan();
        let payloads = BTreeMap::from([("implant".to_string(), payload(None))]);
        let first = effective_hash(&plan, &BuildEntropy::from_seed(1), &payloads).expect("hash");
        let second = effective_hash(&plan, &BuildEntropy::from_seed(1), &payloads).expect("hash");
        let other = effective_hash(&plan, &BuildEntropy::from_seed(2), &payloads).expect("hash");
        assert_eq!(first, second);
        assert_ne!(first, other, "the seed is part of the identity");
        assert_eq!(first.len(), 64);
    }

    #[test]
    fn effective_hash_ignores_the_reproduce_block() {
        let plan = plan();
        let payloads = BTreeMap::new();
        let before = effective_hash(&plan, &BuildEntropy::from_seed(3), &payloads).expect("hash");

        let mut replayed = plan.clone();
        replayed.reproduce = Some(ReproducePlan {
            seed: Some("0x3".to_string()),
            predecessor: Some(Predecessor {
                built_at: "2026-01-01T00:00:00Z".to_string(),
                artifact: "dist/out.exe".to_string(),
                artifact_sha256: "cc".repeat(32),
                unsigned_sha256: "dd".repeat(32),
            }),
            ..default_reproduce()
        });
        let after =
            effective_hash(&replayed, &BuildEntropy::from_seed(3), &payloads).expect("hash");
        assert_eq!(before, after);
    }

    fn default_reproduce() -> ReproducePlan {
        ReproducePlan {
            manifest_schema: MANIFEST_SCHEMA,
            picaro: "test".to_string(),
            toolchain: ToolchainRecord::default(),
            seed: None,
            entropy: EntropyRecord::default(),
            secrets: SecretsPolicy::Exact,
            payloads: BTreeMap::new(),
            identity: None,
            predecessor: None,
            signature: None,
            effective_sha256: None,
            plan_sha256: None,
        }
    }

    #[test]
    fn compose_produces_a_plan_that_round_trips() {
        let plan = plan();
        let entropy = BuildEntropy::from_seed(0x1234);
        let inputs = ManifestInputs {
            identity: None,
            icon: Some(7),
            polymorphism: Some(PolymorphismRecord {
                mode: crate::engine::polymorphism::PolymorphismMode::Full,
                seed: 0x1234,
                codegen_units: 1,
                opt_level: crate::engine::polymorphism::OptLevel::Z,
                lto: crate::engine::polymorphism::LtoMode::Off,
                inline_threshold: Some(100),
                mir_opt_level: Some(2),
                randomize_layout: false,
                layout_seed: 9,
            }),
            strings_strategy: Some("xor".to_string()),
            signature: None,
            payloads: BTreeMap::from([("implant".to_string(), payload(Some("11")))]),
            predecessor: None,
            secrets: SecretsPolicy::Exact,
        };

        let manifest = compose(&plan, &entropy, inputs).expect("compose");
        let json = serde_json::to_string(&manifest).expect("json");
        let reloaded: Plan = serde_yml::from_str(&json).expect("JSON is valid YAML");
        assert_eq!(reloaded, manifest);
        assert_eq!(
            reloaded.reproduce.as_ref().map(|r| r.manifest_schema),
            Some(MANIFEST_SCHEMA)
        );
    }

    #[test]
    fn redact_strips_keys_and_marks_audit() {
        let manifest = ReproducePlan {
            secrets: SecretsPolicy::Exact,
            payloads: BTreeMap::from([("implant".to_string(), payload(Some("11")))]),
            ..default_reproduce()
        };
        let mut plan = plan();
        plan.reproduce = Some(manifest);

        let dir = std::env::temp_dir().join("picaro_manifest_redact");
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("redacted.json");
        redact(&plan, &path).expect("redact");

        let text = std::fs::read_to_string(&path).expect("read");
        let value: serde_json::Value = serde_json::from_str(&text).expect("redacted JSON");
        assert!(
            value["reproduce"]["payloads"]["implant"]
                .get("key")
                .is_none(),
            "the recorded key was not stripped: {text}"
        );
        assert_eq!(value["reproduce"]["secrets"], "audit");
        assert_eq!(
            value["build"]["crypto"]["key"], "random",
            "the plan's literal key source was not redacted"
        );
    }

    #[test]
    fn timestamps_are_rfc3339() {
        assert_eq!(format_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_utc(1_700_000_000), "2023-11-14T22:13:20Z");
        assert_eq!(format_utc(86_399), "1970-01-01T23:59:59Z");
    }

    #[test]
    fn a_clean_plan_serializes_without_reproduce() {
        let json = serde_json::to_string(&plan()).expect("json");
        assert!(!json.contains("reproduce"));
    }
}
