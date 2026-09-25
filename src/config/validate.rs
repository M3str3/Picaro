//! Semantic validation of the already-deserialized configuration.
//!
//! Unlike parsing (which validates structure and types), here we check
//! business rules that cannot be expressed naturally with `serde`: empty
//! values, invalid combinations, supported architectures, etc. This module
//! will grow in later phases.

use crate::error::{PackerError, Result};
use crate::techniques::{category_of, Category, PipelineStep};

use super::schema::Config;

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

    match (config.input.path.as_ref(), config.input.url.as_ref()) {
        (Some(path), None) => {
            if path.as_os_str().is_empty() {
                return Err(PackerError::Validation(
                    "'input.path' must not be empty".to_string(),
                ));
            }
        }
        (None, Some(url)) => {
            if url.trim().is_empty() {
                return Err(PackerError::Validation(
                    "'input.url' must not be empty".to_string(),
                ));
            }
            if !(url.starts_with("http://") || url.starts_with("https://")) {
                return Err(PackerError::Validation(format!(
                    "'input.url' must use http or https (got '{url}')"
                )));
            }
        }
        _ => {
            return Err(PackerError::Validation(
                "'input' must set exactly one of 'path' or 'url'".to_string(),
            ));
        }
    }

    if config.output.path.as_os_str().is_empty() {
        return Err(PackerError::Validation(
            "'output.path' must not be empty".to_string(),
        ));
    }

    validate_pipeline(&config.pipeline)?;
    validate_conflicts(&config.pipeline)?;

    Ok(())
}

/// Enforces declared incompatibilities between techniques.
///
/// With the category model, two Execution techniques are already rejected by
/// [`validate_pipeline`]; this check remains for non-category conflicts (e.g.
/// two Preparation techniques that cannot coexist).
fn validate_conflicts(pipeline: &[PipelineStep]) -> Result<()> {
    let active: Vec<&str> = pipeline.iter().map(|step| step.name()).collect();
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

/// Validates the technique pipeline's category model.
///
/// The pipeline is `0..N` Preparation techniques followed by exactly one
/// Execution technique. Preparation techniques run first (they only modify
/// process state); the single Execution technique runs the payload last.
fn validate_pipeline(pipeline: &[PipelineStep]) -> Result<()> {
    // Exactly one Execution technique.
    let execution: Vec<&str> = pipeline
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
    for step in pipeline {
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

    /// A full valid config without a pipeline (pipeline tests append their own).
    const NO_PIPELINE: &str = r#"
schema: 1
name: pipeline-test
input:
  path: ./payload.exe
payload:
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
    /// input/output regression tests.
    const VALID: &str = r#"
schema: 1
name: input-test
input:
  path: ./payload.exe
payload:
  crypto:
    algo: xchacha20poly1305
    key: random
pipeline:
  - technique: reflective_loading
output:
  path: ./dist/out.exe
  arch: x64
  strip: true
  trim_paths: all
"#;

    /// YAML fragment with a single Execution technique.
    const EXECUTION_YAML: &str = r#"
pipeline:
  - technique: reflective_loading
"#;

    /// YAML fragment with a single Preparation technique.
    const PREPARATION_YAML: &str = r#"
pipeline:
  - technique: patch_amsi
"#;

    /// YAML fragment with two Execution techniques.
    const TWO_EXECUTION_YAML: &str = r#"
pipeline:
  - technique: process_hollowing
  - technique: reflective_loading
"#;

    /// YAML fragment with Preparation after Execution.
    const PREP_AFTER_EXEC_YAML: &str = r#"
pipeline:
  - technique: reflective_loading
  - technique: patch_amsi
"#;

    /// YAML fragment with Preparation before Execution.
    const PREP_BEFORE_EXEC_YAML: &str = r#"
pipeline:
  - technique: patch_amsi
  - technique: reflective_loading
"#;

    fn parse(yaml: &str) -> Config {
        serde_yml::from_str(yaml).expect("valid YAML")
    }

    fn with_pipeline(pipeline_yaml: &str) -> Config {
        parse(&(NO_PIPELINE.to_string() + pipeline_yaml))
    }

    #[test]
    fn rejects_zero_execution_techniques() {
        let config = with_pipeline(PREPARATION_YAML);
        let err = validate(&config).expect_err("zero execution techniques must fail");
        assert!(
            err.to_string()
                .contains("Pipeline must declare exactly one Execution technique."),
            "unclear error: {err}"
        );
    }

    #[test]
    fn rejects_two_execution_techniques() {
        let config = with_pipeline(TWO_EXECUTION_YAML);
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
        let config = with_pipeline(PREP_AFTER_EXEC_YAML);
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
        let config = with_pipeline(PREP_BEFORE_EXEC_YAML);
        validate(&config).expect("preparation before execution must be valid");
    }

    #[test]
    fn accepts_single_execution() {
        let config = with_pipeline(EXECUTION_YAML);
        validate(&config).expect("a single execution technique must be valid");
    }

    // --- input/output checks (regression) ---

    #[test]
    fn rejects_both_path_and_url() {
        let yaml = VALID.replace(
            "input:\n  path: ./payload.exe\n",
            "input:\n  path: ./payload.exe\n  url: https://example.com/p.exe\n",
        );
        let err = validate(&parse(&yaml)).expect_err("both path and url must fail");
        assert!(err.to_string().contains("exactly one"), "err: {err}");
    }

    #[test]
    fn rejects_neither_path_nor_url() {
        let yaml = VALID.replace("input:\n  path: ./payload.exe\n", "input: {}\n");
        let err = validate(&parse(&yaml)).expect_err("missing input source must fail");
        assert!(err.to_string().contains("exactly one"), "err: {err}");
    }

    #[test]
    fn rejects_non_http_url_scheme() {
        let yaml = VALID.replace(
            "input:\n  path: ./payload.exe\n",
            "input:\n  url: ftp://example.com/p.exe\n",
        );
        let err = validate(&parse(&yaml)).expect_err("ftp scheme must fail");
        assert!(err.to_string().contains("http"), "err: {err}");
    }

    #[test]
    fn accepts_http_url() {
        let yaml = VALID.replace(
            "input:\n  path: ./payload.exe\n",
            "input:\n  url: https://example.com/p.exe\n",
        );
        validate(&parse(&yaml)).expect("https url must be valid");
    }
}
