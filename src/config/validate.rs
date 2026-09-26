//! Semantic validation of the already-deserialized configuration.
//!
//! Unlike parsing (which validates structure and types), here we check
//! business rules that cannot be expressed naturally with `serde`: empty
//! values, invalid combinations, supported architectures, etc.

use crate::engine::syscalls::SyscallsConfig;
use crate::error::{PackerError, Result};
use crate::techniques::{category_of, Category, RuntimeStep};

use super::schema::{Config, StubConfig};

/// Checks the business invariants of a [`Config`].
///
/// The schema version is already validated during `Deserialize`, so here we
/// focus on semantic rules.
pub fn validate(config: &Config) -> Result<()> {
    if config.name.trim().is_empty() {
        return Err(PackerError::Validation(
            "'name' must not be empty".to_string(),
        ));
    }

    if config.build.payload.source.trim().is_empty() {
        return Err(PackerError::Validation(
            "'build.payload.source' must not be empty".to_string(),
        ));
    }

    if config.build.output.path.as_os_str().is_empty() {
        return Err(PackerError::Validation(
            "'build.output.path' must not be empty".to_string(),
        ));
    }

    validate_runtime(&config.runtime)?;
    validate_conflicts(&config.runtime)?;
    validate_sleep_obfuscation(&config.runtime)?;
    validate_stub(&config.build.stub)?;

    Ok(())
}

/// Validates the stub's syscall layer.
///
/// `build.stub` itself may be empty (builtin stub, default syscall mode); an
/// unknown `syscalls.mode` or `syscalls.resolver` is a clear error.
fn validate_stub(stub: &StubConfig) -> Result<()> {
    SyscallsConfig::from_yaml(stub.syscalls.as_ref())?;
    Ok(())
}

/// Validates the sleep-obfuscation parameters.
///
/// Only the ekko variant and the `[payload]` region list are implemented in
/// this phase; the other values parse fine but are rejected here with a
/// pointer to the missing phase.
fn validate_sleep_obfuscation(runtime: &[RuntimeStep]) -> Result<()> {
    for step in runtime {
        let RuntimeStep::SleepObfuscation(params) = step else {
            continue;
        };

        if params.variant != crate::techniques::sleep_obfuscation::Variant::Ekko {
            return Err(PackerError::Validation(format!(
                "sleep_obfuscation: variant '{}' is not implemented yet; phase 6 ships 'ekko' only",
                params.variant.label()
            )));
        }

        let only_payload = params.encrypt_regions.len() == 1
            && params.encrypt_regions[0]
                == crate::techniques::sleep_obfuscation::EncryptRegion::Payload;
        if !only_payload {
            return Err(PackerError::Validation(
                "sleep_obfuscation: only encrypt_regions: [payload] is implemented in this phase; 'stack' and 'all' need a stack-safe ROP chain (future phase)".to_string(),
            ));
        }

        if params.sleep_ms > u32::MAX as u64 {
            return Err(PackerError::Validation(format!(
                "sleep_obfuscation: sleep_ms {} exceeds the maximum of {}",
                params.sleep_ms,
                u32::MAX
            )));
        }
    }
    Ok(())
}

/// Enforces declared incompatibilities between techniques.
///
/// With the category model, two Execution techniques are already rejected by
/// [`validate_runtime`]; this check remains for non-category conflicts (e.g.
/// two Preparation techniques that cannot coexist).
fn validate_conflicts(runtime: &[RuntimeStep]) -> Result<()> {
    let active: Vec<&str> = runtime.iter().map(|step| step.name()).collect();
    for def in crate::techniques::all() {
        for conflict in def.conflicts {
            if active.contains(&def.name) && active.contains(conflict) {
                return Err(PackerError::Validation(format!(
                    "techniques '{0}' and '{1}' cannot be used together",
                    def.name, conflict
                )));
            }
        }
    }
    Ok(())
}

/// Validates the technique runtime's category model.
///
/// The runtime is `0..N` Preparation techniques followed by exactly one
/// Execution technique. Preparation techniques run first (they only modify
/// process state); the single Execution technique runs the payload last.
fn validate_runtime(runtime: &[RuntimeStep]) -> Result<()> {
    // Exactly one Execution technique.
    let execution: Vec<&str> = runtime
        .iter()
        .filter(|step| category_of(step.name()) == Some(Category::Execution))
        .map(|step| step.name())
        .collect();

    if execution.len() != 1 {
        let found = if execution.is_empty() {
            "none".to_string()
        } else {
            execution.join(", ")
        };
        return Err(PackerError::Validation(format!(
            "Pipeline must declare exactly one Execution technique.\nFound {}: {}.",
            execution.len(),
            found
        )));
    }

    // Every Preparation technique must come before the Execution technique.
    let mut seen_execution = false;
    for step in runtime {
        match category_of(step.name()) {
            Some(Category::Execution) => seen_execution = true,
            Some(Category::Preparation) if seen_execution => {
                return Err(PackerError::Validation(format!(
                    "Preparation technique '{}' appears after the Execution technique. Move it before.",
                    step.name()
                )));
            }
            _ => {}
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A full valid config without a runtime (runtime tests append their own).
    const NO_RUNTIME: &str = r#"
schema: 2
name: pipeline-test
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
"#;

    /// A full valid config with a single Execution technique, used by the
    /// source/output regression tests.
    const VALID: &str = r#"
schema: 2
name: source-test
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

    /// YAML fragment with a single Execution technique.
    const EXECUTION_YAML: &str = r#"
runtime:
  - technique: reflective_loading
"#;

    /// YAML fragment with a single Preparation technique.
    const PREPARATION_YAML: &str = r#"
runtime:
  - technique: patch_amsi
"#;

    /// YAML fragment with two Execution techniques.
    const TWO_EXECUTION_YAML: &str = r#"
runtime:
  - technique: process_hollowing
  - technique: reflective_loading
"#;

    /// YAML fragment with Preparation after Execution.
    const PREP_AFTER_EXEC_YAML: &str = r#"
runtime:
  - technique: reflective_loading
  - technique: patch_amsi
"#;

    /// YAML fragment with Preparation before Execution.
    const PREP_BEFORE_EXEC_YAML: &str = r#"
runtime:
  - technique: patch_amsi
  - technique: reflective_loading
"#;

    fn parse(yaml: &str) -> Config {
        serde_yml::from_str(yaml).expect("valid YAML")
    }

    fn with_runtime(runtime_yaml: &str) -> Config {
        parse(&(NO_RUNTIME.to_string() + runtime_yaml))
    }

    #[test]
    fn rejects_zero_execution_techniques() {
        let config = with_runtime(PREPARATION_YAML);
        let err = validate(&config).expect_err("zero execution techniques must fail");
        assert!(
            err.to_string()
                .contains("Pipeline must declare exactly one Execution technique."),
            "unclear error: {err}"
        );
    }

    #[test]
    fn rejects_two_execution_techniques() {
        let config = with_runtime(TWO_EXECUTION_YAML);
        let err = validate(&config).expect_err("two execution techniques must fail");
        let msg = err.to_string();
        assert!(
            msg.contains("Pipeline must declare exactly one Execution technique."),
            "unclear error: {msg}"
        );
        assert!(msg.contains("process_hollowing"), "msg: {msg}");
        assert!(msg.contains("reflective_loading"), "msg: {msg}");
    }

    #[test]
    fn rejects_preparation_after_execution() {
        let config = with_runtime(PREP_AFTER_EXEC_YAML);
        let err = validate(&config).expect_err("preparation after execution must fail");
        let msg = err.to_string();
        assert!(
            msg.contains(
                "Preparation technique 'patch_amsi' appears after the Execution technique."
            ),
            "unclear error: {msg}"
        );
    }

    #[test]
    fn accepts_preparation_before_execution() {
        let config = with_runtime(PREP_BEFORE_EXEC_YAML);
        validate(&config).expect("preparation before execution must be valid");
    }

    #[test]
    fn accepts_single_execution() {
        let config = with_runtime(EXECUTION_YAML);
        validate(&config).expect("a single execution technique must be valid");
    }

    // --- sleep_obfuscation specifics ---

    /// YAML fragment with a sleep_obfuscation + execution pipeline.
    const SLEEP_YAML: &str = r#"
runtime:
  - technique: sleep_obfuscation
    variant: ekko
    sleep_ms: 5000
    encrypt_regions: [payload]
  - technique: reflective_loading
"#;

    #[test]
    fn accepts_ekko_with_payload_regions() {
        validate(&with_runtime(SLEEP_YAML)).expect("ekko + [payload] must be valid");
    }

    #[test]
    fn accepts_sleep_obfuscation_defaults() {
        let yaml = r#"
runtime:
  - technique: sleep_obfuscation
  - technique: reflective_loading
"#;
        validate(&with_runtime(yaml)).expect("defaults must be valid");
    }

    #[test]
    fn rejects_unimplemented_variants() {
        for variant in ["foliage", "cronos"] {
            let yaml = SLEEP_YAML.replace("variant: ekko", &format!("variant: {variant}"));
            let err = validate(&with_runtime(&yaml)).expect_err("unimplemented variant must fail");
            let msg = err.to_string();
            assert!(
                msg.contains(variant) && msg.contains("not implemented"),
                "unclear error: {msg}"
            );
        }
    }

    #[test]
    fn rejects_unimplemented_region_lists() {
        for regions in ["[payload, stack]", "all", "[stack]"] {
            let yaml = SLEEP_YAML.replace(
                "encrypt_regions: [payload]",
                &format!("encrypt_regions: {regions}"),
            );
            let err = validate(&with_runtime(&yaml)).expect_err("unimplemented regions must fail");
            assert!(
                err.to_string().contains("encrypt_regions"),
                "unclear error: {err}"
            );
        }
    }

    #[test]
    fn rejects_oversized_sleep() {
        let yaml = SLEEP_YAML.replace("sleep_ms: 5000", "sleep_ms: 4294967296");
        let err = validate(&with_runtime(&yaml)).expect_err("an oversized sleep must fail");
        assert!(err.to_string().contains("sleep_ms"), "unclear error: {err}");
    }

    // --- stub block ---

    #[test]
    fn accepts_stub_with_only_syscalls() {
        let yaml = VALID.replace(
            "  output:\n",
            "  stub:\n    syscalls:\n      mode: indirect\n  output:\n",
        );
        validate(&parse(&yaml)).expect("syscalls-only stub must be valid");
    }

    #[test]
    fn accepts_an_empty_stub_block() {
        let yaml = VALID.replace("  output:\n", "  stub: {}\n  output:\n");
        validate(&parse(&yaml)).expect("an empty stub means the builtin stub");
    }

    #[test]
    fn rejects_unknown_syscalls_mode() {
        let yaml = VALID.replace(
            "  output:\n",
            "  stub:\n    syscalls:\n      mode: warp\n  output:\n",
        );
        let err = validate(&parse(&yaml)).expect_err("an unknown mode must fail");
        assert!(
            err.to_string().contains("build.stub.syscalls.mode"),
            "unclear error: {err}"
        );
    }

    #[test]
    fn rejects_unknown_syscalls_resolver() {
        let yaml = VALID.replace(
            "  output:\n",
            "  stub:\n    syscalls:\n      resolver: tartarus_gate\n  output:\n",
        );
        let err = validate(&parse(&yaml)).expect_err("an unknown resolver must fail");
        assert!(
            err.to_string().contains("build.stub.syscalls.resolver"),
            "unclear error: {err}"
        );
    }

    // --- source/output checks (regression) ---

    #[test]
    fn rejects_empty_source() {
        let yaml = VALID.replace("    source: ./payload.exe\n", "    source: \"\"\n");
        let err = validate(&parse(&yaml)).expect_err("an empty source must fail");
        assert!(
            err.to_string().contains("build.payload.source"),
            "err: {err}"
        );
    }

    #[test]
    fn accepts_a_url_source() {
        let yaml = VALID.replace(
            "    source: ./payload.exe\n",
            "    source: https://example.com/p.exe\n",
        );
        validate(&parse(&yaml)).expect("a url source must be valid");
    }

    #[test]
    fn rejects_empty_output_path() {
        let yaml = VALID.replace("    path: ./dist/out.exe\n", "    path: \"\"\n");
        let err = validate(&parse(&yaml)).expect_err("an empty output path must fail");
        assert!(err.to_string().contains("build.output.path"), "err: {err}");
    }
}
