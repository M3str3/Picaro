//! `plan` module: loading, parsing and validation of the YAML.
//!
//! Responsibilities:
//! - `schema`: `serde` structs modeling the YAML document (schema 6).
//! - `validate`: semantic validation after parsing.
//! - `steps`: resolution of the flat `runtime:` list into concrete steps.
//! - `build_args`: `$arg.N$` placeholder substitution from CLI args.
//! - `load_plan`: single entry point that reads a file, resolves build
//!   arguments, deserializes it and validates it, returning a ready-to-use
//!   [`Plan`].

pub mod build_args;
pub mod format;
pub mod schema;
pub mod steps;
pub mod validate;

use std::collections::BTreeMap;
use std::path::Path;

use serde_yml::{Mapping, Value};

use crate::error::{PackerError, Result};

pub use schema::Plan;

/// Reads `path`, resolves `$arg.N$` placeholders, deserializes the YAML and
/// validates the resulting plan.
///
/// `build_args` maps the CLI arguments (positional indices and `name=value`
/// pairs, see [`build_args::parse`]) to the values substituted into the YAML.
/// Each stage (read, parse, substitute, validate) returns a typed error so the
/// user gets a clear message without the program panicking.
pub fn load_plan(path: &Path, build_args: &BTreeMap<String, String>) -> Result<Plan> {
    let raw = std::fs::read_to_string(path).map_err(|source| PackerError::ReadPlan {
        path: path.to_path_buf(),
        source,
    })?;

    load_plan_str(&raw, path, build_args)
}

/// Loads an in-memory YAML document through the same path as [`load_plan`].
///
/// `picaro pack` composes a plan from flags, serializes it and feeds it back
/// through this function, so the generated document gets exactly the same
/// placeholders, format detection and validation as a hand-written one. `path`
/// is only used in error messages and names the file the document would live in.
pub fn load_plan_str(
    raw: &str,
    path: &Path,
    build_args: &BTreeMap<String, String>,
) -> Result<Plan> {
    let mut plan = parse_and_substitute(raw, build_args, path)?;
    // `format: auto` is resolved before validation: the validator and the step
    // resolver need a concrete format.
    format::resolve(&mut plan)?;

    validate::validate(&plan)?;

    Ok(plan)
}

/// Parses the raw YAML into an untyped [`serde_yml::Value`], substitutes the
/// build arguments, then deserializes the result into a typed [`Plan`].
///
/// Substituting on the untyped value tree (rather than on the raw string) keeps
/// quoting and escaping correct, while typed fields are still fully checked by
/// the later `serde` deserialization.
fn parse_and_substitute(
    raw: &str,
    build_args: &BTreeMap<String, String>,
    path: &Path,
) -> Result<Plan> {
    let mut value: serde_yml::Value =
        serde_yml::from_str(raw).map_err(|source| PackerError::ParsePlan {
            path: path.to_path_buf(),
            source,
        })?;

    // Detection is by content, not by extension: a manifest is a plan with a
    // `reproduce` block, and a schema-3 manifest is lifted best-effort.
    if is_v3_manifest(&value) {
        value = lift_v3_manifest(value);
    }

    build_args::substitute(&mut value, build_args)?;
    normalize_technique_names(&mut value);
    reject_unknown_step_keys(&value)?;

    serde_yml::from_value(value).map_err(|source| PackerError::ParsePlan {
        path: path.to_path_buf(),
        source,
    })
}

/// Whether `value` is a schema-3 manifest (it nests the plan under
/// `resolved_plan`).
fn is_v3_manifest(value: &Value) -> bool {
    value
        .as_mapping()
        .is_some_and(|map| get(map, "resolved_plan").is_some())
}

/// Lifts a schema-3 manifest into the schema-4 shape.
///
/// The old document nested the plan under `resolved_plan`; the new one *is*
/// that plan plus a `reproduce` block. The old record never stored payload
/// keys, so the result is `secrets: audit` and a replay is not byte-identical.
/// Everything the old document did record (resolved polymorphism, icon seed,
/// nonces, hashes) is carried over.
fn lift_v3_manifest(value: Value) -> Value {
    let Some(old) = value.as_mapping() else {
        return value;
    };
    let Some(Value::Mapping(mut root)) = get(old, "resolved_plan").cloned() else {
        return value;
    };

    let mut reproduce = Mapping::new();
    reproduce.insert(string("manifest_schema"), Value::from(3));
    reproduce.insert(
        string("picaro"),
        Value::String("schema-3 manifest".to_string()),
    );
    if let Some(toolchain) = get(old, "toolchain").cloned() {
        reproduce.insert(string("toolchain"), toolchain);
    }

    let seed = get(old, "polymorphism")
        .and_then(Value::as_mapping)
        .and_then(|record| get(record, "seed"))
        .and_then(Value::as_u64);

    let mut entropy = Mapping::new();
    entropy.insert(
        string("seed"),
        Value::String(
            seed.map(|seed| format!("{seed:#x}"))
                .unwrap_or_else(|| "random".to_string()),
        ),
    );
    if let Some(polymorphism) = get(old, "polymorphism").cloned() {
        entropy.insert(string("polymorphism"), polymorphism);
    }
    entropy.insert(
        string("strings"),
        Value::Mapping(Mapping::from_iter([(
            string("strategy"),
            Value::String(strings_strategy(&root)),
        )])),
    );
    if let Some(icon) = get(old, "generated_icon")
        .and_then(Value::as_mapping)
        .and_then(|record| get(record, "seed").cloned())
    {
        entropy.insert(string("icon"), icon);
    }
    reproduce.insert(string("entropy"), Value::Mapping(entropy));
    reproduce.insert(string("secrets"), Value::String("audit".to_string()));

    if let Some(payloads) = lift_payloads(old) {
        reproduce.insert(string("payloads"), Value::Mapping(payloads));
    }
    if let Some(version_info) = get(old, "version_info").cloned() {
        reproduce.insert(string("identity"), version_info);
    }
    if let Some(signature) = get(old, "signature").cloned() {
        reproduce.insert(string("signature"), signature);
    }
    if let Some(predecessor) = lift_predecessor(old) {
        reproduce.insert(string("predecessor"), Value::Mapping(predecessor));
    }
    if let Some(hash) = get(old, "plan_sha256").cloned() {
        // The old hash was over the plan only; keep it under the deprecated
        // alias rather than claiming it is the new effective hash.
        reproduce.insert(string("plan_sha256"), hash);
    }

    root.insert(string("reproduce"), Value::Mapping(reproduce));

    // The v3 codegen profile was drawn from this seed directly. Pin it as a
    // literal so the lifted plan resolves the same profile again.
    if let Some(seed) = seed {
        pin_polymorphism_seed(&mut root, seed);
    }

    Value::Mapping(root)
}

/// `build.payloads` pins from the old per-step records.
fn lift_payloads(old: &Mapping) -> Option<Mapping> {
    let steps = get(old, "steps")?.as_sequence()?;
    let mut payloads = Mapping::new();
    for step in steps {
        let Some(step) = step.as_mapping() else {
            continue;
        };
        let Some(name) = get(step, "payload").and_then(Value::as_str) else {
            continue;
        };
        let mut record = Mapping::new();
        for field in ["payload_sha256", "payload_size", "nonce"] {
            if let Some(value) = get(step, field).cloned() {
                reproduce_field(&mut record, field, value);
            }
        }
        payloads
            .entry(Value::String(name.to_string()))
            .or_insert(Value::Mapping(record));
    }
    (!payloads.is_empty()).then_some(payloads)
}

/// Maps the v3 field names to their schema-4 names.
fn reproduce_field(record: &mut Mapping, field: &str, value: Value) {
    let name = match field {
        "payload_sha256" | "sha256" => "sha256",
        "payload_size" | "size" => "size",
        other => other,
    };
    record.insert(string(name), value);
}

/// The old artifact record, mapped to `predecessor`.
fn lift_predecessor(old: &Mapping) -> Option<Mapping> {
    let artifact = get(old, "artifact")?.clone();
    let artifact_sha256 = get(old, "artifact_sha256").cloned().unwrap_or(Value::Null);
    let mut predecessor = Mapping::new();
    predecessor.insert(string("built_at"), Value::String("unknown".to_string()));
    predecessor.insert(string("artifact"), artifact);
    predecessor.insert(string("artifact_sha256"), artifact_sha256.clone());
    // v3 hashed the file that was written; before signing that is the same
    // bytes, and with a signature it is the closest value the old document has.
    predecessor.insert(string("unsigned_sha256"), artifact_sha256);
    Some(predecessor)
}

/// The declared strings strategy in the old resolved plan, defaulting to xor.
fn strings_strategy(root: &Mapping) -> String {
    get(root, "build")
        .and_then(Value::as_mapping)
        .and_then(|build| get(build, "stub"))
        .and_then(Value::as_mapping)
        .and_then(|stub| get(stub, "strings"))
        .and_then(Value::as_mapping)
        .and_then(|strings| get(strings, "strategy"))
        .and_then(Value::as_str)
        .unwrap_or("xor")
        .to_string()
}

/// Forces `build.polymorphism.seed` to `literal:<seed>`.
fn pin_polymorphism_seed(root: &mut Mapping, seed: u64) {
    let build = root
        .entry(string("build"))
        .or_insert_with(|| Value::Mapping(Mapping::new()));
    let Some(build) = build.as_mapping_mut() else {
        return;
    };
    let polymorphism = build
        .entry(string("polymorphism"))
        .or_insert_with(|| Value::Mapping(Mapping::new()));
    if let Some(polymorphism) = polymorphism.as_mapping_mut() {
        polymorphism.insert(string("seed"), Value::String(format!("literal:{seed:#x}")));
    }
}

/// Borrows `key` from a YAML mapping.
fn get<'a>(map: &'a Mapping, key: &str) -> Option<&'a Value> {
    map.get(Value::String(key.to_string()))
}

/// A YAML string key.
fn string(key: &str) -> Value {
    Value::String(key.to_string())
}

/// Rewrites every `runtime[].technique` to the registry's canonical spelling.
///
/// The match ignores case and underscores, so `ReflectiveLoading`,
/// `Reflective_Loading` and `reflectiveloading` all resolve to
/// `reflective_loading`. An unknown name is left untouched and fails later in
/// `serde` with the usual "unknown variant" error.
fn normalize_technique_names(value: &mut serde_yml::Value) {
    let Some(steps) = value
        .get_mut("runtime")
        .and_then(serde_yml::Value::as_sequence_mut)
    else {
        return;
    };
    for step in steps {
        let Some(name) = step.get_mut("technique") else {
            continue;
        };
        let replacement = match name.as_str() {
            Some(raw) => crate::techniques::canonical_name(raw)
                .filter(|canonical| *canonical != raw)
                .map(str::to_string),
            None => None,
        };
        if let Some(canonical) = replacement {
            *name = serde_yml::Value::String(canonical);
        }
    }
}

/// The keys a `runtime` entry may carry: the technique tag, its nested
/// `params`, and the loader's orchestration fields.
const STEP_KEYS: &[&str] = &["technique", "params", "on_success", "on_fail", "delay_ms"];

/// Rejects any key in a `runtime` entry that is not one of [`STEP_KEYS`].
///
/// [`crate::techniques::RuntimeStep`] flattens the technique enum and
/// [`crate::plan::schema::StepControl`], and `serde` cannot deny unknown fields
/// on a flattened struct, so without this pass a typo such as `on_fial` (or a
/// schema-3-style flat `target:`) is silently dropped and the default applies.
/// The nested `params` are left to the technique: every technique `Params`
/// denies unknown fields on its own.
fn reject_unknown_step_keys(value: &Value) -> Result<()> {
    let Some(steps) = value
        .as_mapping()
        .and_then(|plan| get(plan, "runtime"))
        .and_then(Value::as_sequence)
    else {
        // A missing or ill-typed `runtime` is reported by the typed parse.
        return Ok(());
    };

    for (index, step) in steps.iter().enumerate() {
        let Some(step) = step.as_mapping() else {
            // A non-mapping entry is reported by the typed parse.
            continue;
        };
        let unknown = step
            .keys()
            .find(|key| !key.as_str().is_some_and(|key| STEP_KEYS.contains(&key)));
        if let Some(unknown) = unknown {
            let unknown = unknown
                .as_str()
                .map_or_else(|| format!("{unknown:?}"), str::to_string);
            return Err(PackerError::Validation(format!(
                "runtime step {} has unknown key '{unknown}': allowed keys are {}",
                index + 1,
                STEP_KEYS.join(", ")
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// A valid schema-6 YAML whose `process_hollowing.target` is a `$arg.0$` token.
    const ARGS_YAML: &str = r#"
schema: 6
name: args-test
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
  - technique: process_hollowing
    params:
      target: "$arg.0$"
"#;

    fn write_temp(name: &str, contents: &str) -> PathBuf {
        let dir = std::env::temp_dir().join("picaro_plan_tests");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        std::fs::write(&path, contents).unwrap();
        path
    }

    #[test]
    fn load_plan_substitutes_build_args() {
        let path = write_temp("build_args.yaml", ARGS_YAML);
        let args = build_args::parse(&["C:\\Windows\\System32\\notepad.exe".to_string()]);

        let plan = load_plan(&path, &args).expect("load with build args");

        match &plan.runtime[0].technique {
            crate::techniques::TechniqueKind::ProcessHollowing { params } => {
                assert_eq!(params.target, r"C:\Windows\System32\notepad.exe");
            }
            other => panic!("expected process_hollowing, got {other:?}"),
        }
    }

    #[test]
    fn load_plan_substitutes_named_build_args() {
        let yaml = ARGS_YAML.replace("$arg.0$", "$arg.target$");
        let path = write_temp("named_args.yaml", &yaml);
        let args = build_args::parse(&["target=C:\\Windows\\System32\\notepad.exe".to_string()]);

        let plan = load_plan(&path, &args).expect("load with a named build arg");

        match &plan.runtime[0].technique {
            crate::techniques::TechniqueKind::ProcessHollowing { params } => {
                assert_eq!(params.target, r"C:\Windows\System32\notepad.exe");
            }
            other => panic!("expected process_hollowing, got {other:?}"),
        }
    }

    #[test]
    fn load_plan_accepts_a_json_document_by_content() {
        let json = r#"
{
  "schema": 6,
  "name": "json-plan",
  "build": {
    "payloads": { "implant": { "source": "./payload.exe", "format": "pe" } },
    "output": { "path": "./dist/out.exe", "arch": "x64", "strip": true, "trim_paths": "all" }
  },
  "runtime": [ { "technique": "reflective_loading" } ],
  "reproduce": { "seed": 42 }
}
"#;
        let path = write_temp("json-plan.json", json);
        let plan = load_plan(&path, &BTreeMap::new()).expect("JSON is valid YAML");
        assert_eq!(
            plan.reproduce
                .as_ref()
                .and_then(|record| record.seed.as_deref()),
            Some("42")
        );
    }

    #[test]
    fn load_plan_lifts_a_schema_3_manifest() {
        let manifest = serde_json::json!({
            "manifest_schema": 3,
            "name": "old",
            "artifact": "dist/out.exe",
            "artifact_sha256": "cc",
            "plan_sha256": "dd",
            "toolchain": { "rustc": "rustc 1.0", "target": "x86_64-pc-windows-msvc" },
            "polymorphism": {
                "mode": "full",
                "seed": 123,
                "codegen_units": 1,
                "opt_level": "z",
                "lto": "off",
                "inline_threshold": null,
                "mir_opt_level": null,
                "randomize_layout": false,
                "layout_seed": 0
            },
            "generated_icon": { "seed": 99 },
            "resolved_plan": {
                "schema": 6,
                "name": "old",
                "build": {
                    "payloads": { "implant": { "source": "./payload.exe", "format": "pe" } },
                    "output": { "path": "./dist/out.exe", "arch": "x64", "strip": true, "trim_paths": "all" }
                },
                "runtime": [ { "technique": "reflective_loading" } ]
            },
            "steps": [
                {
                    "index": 0,
                    "label": "reflective_loading 'implant'",
                    "technique": "reflective_loading",
                    "payload": "implant",
                    "payload_sha256": "aa",
                    "payload_size": 12,
                    "nonce": "bb"
                }
            ]
        });
        let path = write_temp("v3.manifest.json", &manifest.to_string());

        let plan = load_plan(&path, &BTreeMap::new()).expect("a v3 manifest lifts");
        let record = plan.reproduce.expect("the record was lifted");
        assert_eq!(record.manifest_schema, 3);
        assert_eq!(record.secrets, crate::plan::schema::SecretsPolicy::Audit);
        assert_eq!(record.entropy.seed, "0x7b");
        assert_eq!(record.entropy.icon, Some(99));
        assert_eq!(
            record
                .payloads
                .get("implant")
                .and_then(|payload| payload.nonce.as_deref()),
            Some("bb")
        );
        let planted = record.payloads.get("implant").expect("payload record");
        assert_eq!(planted.sha256.as_deref(), Some("aa"));
        assert_eq!(planted.size, Some(12));
        assert_eq!(
            record
                .predecessor
                .as_ref()
                .map(|predecessor| predecessor.unsigned_sha256.as_str()),
            Some("cc")
        );
        assert_eq!(
            plan.build
                .polymorphism
                .as_ref()
                .and_then(|block| block.seed),
            Some(crate::engine::polymorphism::SeedSource::Literal(123))
        );
    }

    #[test]
    fn a_plain_plan_has_no_reproduce_block() {
        let yaml = ARGS_YAML.replace("$arg.0$", "notepad.exe");
        let path = write_temp("plain.yaml", &yaml);
        let plan = load_plan(&path, &BTreeMap::new()).expect("plain plan");
        assert!(plan.reproduce.is_none());
    }
}
