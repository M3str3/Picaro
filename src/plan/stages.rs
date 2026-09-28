//! Resolution of the plan's stages (schema 5).
//!
//! A schema-4 document — or a schema-5 document without `stages` — is the
//! *single-payload shorthand*: it is normalized here to one `technique` stage
//! built from `build.payload` + `runtime`. That keeps the single-payload build
//! path byte-for-byte identical to before, while a plan with several payloads
//! is expressed as an explicit `stages:` list.
//!
//! A stage is an action: `technique` (run an embedded payload with a technique
//! pipeline), `exec` (launch a command / living-off-the-land binary) or `sleep`.

use crate::error::{PackerError, Result};
use crate::techniques::RuntimeStep;

use super::schema::{
    PayloadPlan, Plan, StageAction, StageFailure, StageOutcome, StagePlan, WindowMode,
};

/// A resolved `exec` stage's parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecPlan {
    /// The process to launch (a bare name is resolved against `System32`).
    pub binary: String,
    /// Arguments passed to `binary`.
    pub args: Vec<String>,
    /// Wait for the child and capture its exit code.
    pub wait: bool,
    /// Window visibility.
    pub window: WindowMode,
    /// Seconds to wait before terminating the child (0 = no limit).
    pub timeout_s: u64,
}

/// One stage, resolved from the plan (owning its payload and pipeline).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stage {
    /// Position in the chain (0-based).
    pub index: usize,
    /// Human label (the stage's `name`, or `<action><index>`).
    pub label: String,
    /// What the stage does.
    pub action: StageAction,
    /// `technique`: the payload to run.
    pub payload: Option<PayloadPlan>,
    /// `technique`: the preparation + execution pipeline.
    pub runtime: Vec<RuntimeStep>,
    /// `exec`: the process to launch.
    pub exec: Option<ExecPlan>,
    /// `sleep`: milliseconds to wait.
    pub sleep_ms: u64,
    /// What to do when the stage completes.
    pub on_success: StageOutcome,
    /// What to do when the stage fails.
    pub on_fail: StageFailure,
    /// Delay before starting the stage.
    pub delay_ms: u64,
}

/// Resolves the plan into its ordered stages.
///
/// Returns an error when the plan declares neither `build.payload` nor a
/// non-empty `stages:` list, so a build never silently packs nothing.
pub fn resolve(plan: &Plan) -> Result<Vec<Stage>> {
    if !plan.stages.is_empty() {
        return Ok(plan
            .stages
            .iter()
            .enumerate()
            .map(|(index, stage)| from_explicit(index, stage))
            .collect());
    }

    let payload = single_payload(plan)?.clone();
    Ok(vec![Stage {
        index: 0,
        label: "technique0".to_string(),
        action: StageAction::Technique,
        payload: Some(payload),
        runtime: plan.runtime.clone(),
        exec: None,
        sleep_ms: 0,
        on_success: StageOutcome::Continue,
        on_fail: StageFailure::Stop,
        delay_ms: 0,
    }])
}

/// The legacy single-payload block, as a `Result` (it is optional in the
/// schema, so a stages-only plan has none).
pub fn single_payload(plan: &Plan) -> Result<&PayloadPlan> {
    plan.build.payload.as_ref().ok_or_else(|| {
        PackerError::Validation(
            "the plan declares no 'build.payload': give a single payload or a non-empty \
             'stages:' list"
                .to_string(),
        )
    })
}

/// Whether the plan uses the explicit multi-stage shape.
pub fn is_multistage(plan: &Plan) -> bool {
    !plan.stages.is_empty()
}

fn from_explicit(index: usize, stage: &StagePlan) -> Stage {
    Stage {
        index,
        label: stage.label(index),
        action: stage.action,
        payload: stage.payload.clone(),
        runtime: stage.runtime.clone(),
        exec: stage.binary.as_ref().map(|binary| ExecPlan {
            binary: binary.clone(),
            args: stage.args.clone(),
            wait: stage.wait,
            window: stage.window,
            timeout_s: stage.timeout_s,
        }),
        sleep_ms: stage.sleep_ms,
        on_success: stage.on_success,
        on_fail: stage.on_fail,
        delay_ms: stage.delay_ms,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(yaml: &str) -> Plan {
        serde_yml::from_str(yaml).expect("valid YAML")
    }

    const LEGACY: &str = r#"
schema: 4
name: legacy
build:
  payload:
    source: ./p.exe
    crypto:
      algo: xchacha20poly1305
      key: random
  output:
    path: ./dist/o.exe
    arch: x64
    strip: true
    trim_paths: all
runtime:
  - technique: patch_amsi
  - technique: reflective_loading
"#;

    const STAGED: &str = r#"
schema: 5
name: staged
build:
  output:
    path: ./dist/o.exe
    arch: x64
    strip: true
    trim_paths: all
stages:
  - action: technique
    payload:
      source: ./a.bin
      format: shellcode
      crypto: { algo: xchacha20poly1305, key: random }
    runtime:
      - technique: reflective_loading
  - action: exec
    binary: certutil.exe
    args: ["-f"]
    wait: false
  - action: sleep
    sleep_ms: 500
"#;

    #[test]
    fn a_legacy_plan_resolves_to_one_technique_stage() {
        let plan = parse(LEGACY);
        let stages = resolve(&plan).expect("resolve");
        assert_eq!(stages.len(), 1);
        assert_eq!(stages[0].action, StageAction::Technique);
        assert_eq!(stages[0].runtime.len(), 2);
        assert_eq!(stages[0].payload.as_ref().unwrap().source, "./p.exe");
    }

    #[test]
    fn an_explicit_stage_list_is_preserved_in_order() {
        let plan = parse(STAGED);
        let stages = resolve(&plan).expect("resolve");
        assert_eq!(stages.len(), 3);
        assert_eq!(stages[0].action, StageAction::Technique);
        assert_eq!(stages[1].action, StageAction::Exec);
        let exec = stages[1].exec.as_ref().unwrap();
        assert_eq!(exec.binary, "certutil.exe");
        assert!(!exec.wait);
        assert_eq!(stages[2].action, StageAction::Sleep);
        assert_eq!(stages[2].sleep_ms, 500);
    }

    #[test]
    fn a_plan_with_no_payload_and_no_stages_is_an_error() {
        let yaml = "schema: 5\nname: empty\nbuild:\n  output: { path: ./o.exe, arch: x64, strip: true, trim_paths: all }\n";
        let plan = parse(yaml);
        assert!(resolve(&plan).is_err());
    }
}
