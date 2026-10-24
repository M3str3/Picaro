//! Resolution of the plan's flat `runtime:` list into concrete steps.
//!
//! A schema-6 document has one ordered list of technique steps. Each step names
//! a technique and passes it its `params`; the loader orchestrates the chain from
//! the steps' [`StepControl`] fields. There are no nested pipelines and no
//! "stages": the lego is the step.
//!
//! Resolution turns the declared steps into [`ResolvedStep`]s, which pins down
//! the one thing a step cannot know by itself: for an Execution technique, which
//! payload it loads (`params.payload`, or the only payload when the plan declares
//! one) and under which crypto config.

use crate::error::{PackerError, Result};
use crate::techniques::{Category, RuntimeStep, TechniqueKind};

use super::schema::{CryptoPlan, PayloadPlan, Plan, StepControl};

/// One payload a step will load, with its resolved crypto configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPayload {
    /// Name of the payload in `build.payloads`.
    pub name: String,
    /// The payload's declared source, format, args and pin.
    pub plan: PayloadPlan,
    /// The crypto to use: the payload's own block, or `build.crypto`.
    pub crypto: CryptoPlan,
}

/// One runtime step, resolved against `build.payloads`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedStep {
    /// Position in the runtime list (0-based).
    pub index: usize,
    /// Human label (the technique name, plus the payload name for an Execution
    /// step).
    pub label: String,
    /// The technique call and its parameters.
    pub technique: TechniqueKind,
    /// The payload the step loads, for an Execution technique.
    pub payload: Option<ResolvedPayload>,
    /// How the loader reacts to this step's result.
    pub control: StepControl,
}

impl ResolvedStep {
    /// Whether the step runs a payload (an Execution technique).
    pub fn is_execution(&self) -> bool {
        self.technique.category() == Category::Execution
    }
}

/// Resolves the plan into its ordered steps.
///
/// Fails when `runtime` is empty (a build would run nothing) or when an
/// Execution step cannot be matched to a payload (no `build.payloads`, an unknown
/// name, or an ambiguous one that forgot `params.payload`).
pub fn resolve(plan: &Plan) -> Result<Vec<ResolvedStep>> {
    if plan.runtime.is_empty() {
        return Err(PackerError::Validation(
            "'runtime' must declare at least one step".to_string(),
        ));
    }

    plan.runtime
        .iter()
        .enumerate()
        .map(|(index, step)| resolve_step(plan, index, step))
        .collect()
}

/// Resolves one declared step.
fn resolve_step(plan: &Plan, index: usize, step: &RuntimeStep) -> Result<ResolvedStep> {
    let payload = match step.category() {
        Category::Execution => Some(resolve_payload(plan, index, step)?),
        Category::Preparation => resolve_preparation_asset(plan, index, step)?,
        Category::Control => None,
    };
    let label = match &payload {
        Some(payload) => format!("{} '{}'", step.name(), payload.name),
        None => step.name().to_string(),
    };
    Ok(ResolvedStep {
        index,
        label,
        technique: step.technique.clone(),
        payload,
        control: step.control,
    })
}

/// Resolves the payload an Execution step loads.
///
/// A single declared payload is implicit; with two or more the step must name
/// one through `params.payload`. The crypto config comes from the payload's own
/// block, falling back to `build.crypto`.
fn resolve_payload(plan: &Plan, index: usize, step: &RuntimeStep) -> Result<ResolvedPayload> {
    let (name, payload) = match step.technique.payload_name() {
        Some(name) => return resolve_named_payload(plan, index, step, name),
        None => match plan.build.payloads.len() {
            0 => {
                return Err(PackerError::Validation(format!(
                    "step {index} ('{}') runs a payload but 'build.payloads' is empty: declare \
                     one, or drop the execution technique",
                    step.name()
                )));
            }
            1 => {
                let (name, payload) = plan.build.payloads.iter().next().ok_or_else(|| {
                    PackerError::Validation("'build.payloads' is empty".to_string())
                })?;
                (name.clone(), payload)
            }
            count => {
                return Err(PackerError::Validation(format!(
                    "step {index} ('{}') must name a payload via 'params.payload' because \
                     'build.payloads' declares {count} payloads{}",
                    step.name(),
                    available_payloads(plan)
                )));
            }
        },
    };

    // Defaults to `xchacha20poly1305` + a random key when neither the payload nor
    // `build.crypto` configures it, so a plan needs no crypto block at all.
    let crypto = payload
        .crypto
        .clone()
        .or_else(|| plan.build.crypto.clone())
        .unwrap_or_default();

    Ok(ResolvedPayload {
        name,
        plan: payload.clone(),
        crypto,
    })
}

/// Resolves a Preparation step's embedded asset, if it carries one.
///
/// Today there are two: the `bouncer` decoy (`on_reject.action: decoy`) and the
/// `drop` file. Both are inert `format: plain` payloads the stub writes to disk;
/// the asset is embedded and encrypted exactly like an Execution payload, so it
/// reuses [`resolve_named_payload`].
fn resolve_preparation_asset(
    plan: &Plan,
    index: usize,
    step: &RuntimeStep,
) -> Result<Option<ResolvedPayload>> {
    let name = match &step.technique {
        TechniqueKind::Bouncer { params } if params.is_decoy() => params
            .decoy()
            .and_then(|decoy| decoy.payload.as_deref())
            .ok_or_else(|| {
                PackerError::Validation(format!(
                    "step {index} ('{}') is 'bouncer' with `on_reject.action: decoy` but no \
                     `params.on_reject.decoy.payload`: name a `format: plain` payload to write",
                    step.name()
                ))
            })?,
        TechniqueKind::Drop { params } => params.payload.as_deref().ok_or_else(|| {
            PackerError::Validation(format!(
                "step {index} ('{}') is 'drop' but no `params.payload`: name a \
                 `format: plain` payload to write",
                step.name()
            ))
        })?,
        _ => return Ok(None),
    };
    Ok(Some(resolve_named_payload(plan, index, step, name)?))
}

/// Resolves a payload by explicit name (the Execution `params.payload` path and
/// the `bouncer` decoy asset).
fn resolve_named_payload(
    plan: &Plan,
    index: usize,
    step: &RuntimeStep,
    name: &str,
) -> Result<ResolvedPayload> {
    let payload = plan.build.payloads.get(name).ok_or_else(|| {
        PackerError::Validation(format!(
            "step {index} ('{}') references payload '{name}', which is not declared in \
             'build.payloads'{}",
            step.name(),
            available_payloads(plan)
        ))
    })?;
    let crypto = payload
        .crypto
        .clone()
        .or_else(|| plan.build.crypto.clone())
        .unwrap_or_default();
    Ok(ResolvedPayload {
        name: name.to_string(),
        plan: payload.clone(),
        crypto,
    })
}

/// ` (available: a, b, c)` for the payload-resolution error messages.
fn available_payloads(plan: &Plan) -> String {
    if plan.build.payloads.is_empty() {
        return String::new();
    }
    let names: Vec<&str> = plan.build.payloads.keys().map(String::as_str).collect();
    format!(" (available: {})", names.join(", "))
}

/// Known living-off-the-land binaries (LOLBAS), matched by file stem.
///
/// The list is advisory only: a `living_off_the_land` step whose `binary` is
/// outside it still works, it just draws a build warning. A signed Microsoft
/// binary is the usual choice for proxy execution (T1218) or download (T1105).
const LOLBINS: &[&str] = &[
    "at",
    "atbroker",
    "bitsadmin",
    "certutil",
    "cmd",
    "cmstp",
    "conhost",
    "cscript",
    "curl",
    "dfshim",
    "expand",
    "extrac32",
    "finger",
    "forfiles",
    "gpscript",
    "ieexec",
    "installutil",
    "makecab",
    "mavinject",
    "msbuild",
    "msconfig",
    "msdt",
    "mshta",
    "msiexec",
    "netsh",
    "odbcconf",
    "pcalua",
    "pnputil",
    "powershell",
    "presentationhost",
    "print",
    "pwsh",
    "reg",
    "regasm",
    "regsvr32",
    "replace",
    "rundll32",
    "runonce",
    "schtasks",
    "ssh",
    "syncappv",
    "tar",
    "utilman",
    "verclsid",
    "wmic",
    "wscript",
    "wsl",
    "xcopy",
    "xwizard",
];

/// Whether `name` is a known living-off-the-land binary (by file stem).
pub fn is_known_lolbin(name: &str) -> bool {
    let file = name.rsplit(['\\', '/']).next().unwrap_or(name);
    let stem = file
        .strip_suffix(".exe")
        .or_else(|| file.strip_suffix(".EXE"))
        .unwrap_or(file);
    LOLBINS.iter().any(|known| known.eq_ignore_ascii_case(stem))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(yaml: &str) -> Plan {
        serde_yml::from_str(yaml).expect("valid YAML")
    }

    const SINGLE: &str = r#"
schema: 6
name: single
build:
  crypto: { algo: xchacha20poly1305, key: random }
  payloads:
    implant: { source: ./implant.exe, format: pe }
  output:
    path: ./dist/o.exe
    arch: x64
    strip: true
    trim_paths: all
runtime:
  - technique: patch_amsi
  - technique: reflective_loading
"#;

    const TWO_PAYLOADS: &str = r#"
schema: 6
name: two
build:
  crypto: { algo: xchacha20poly1305, key: random }
  payloads:
    dropper: { source: ./a.bin, format: shellcode }
    implant: { source: ./b.exe, format: pe }
  output:
    path: ./dist/o.exe
    arch: x64
    strip: true
    trim_paths: all
runtime:
  - technique: reflective_loading
    params: { payload: dropper }
  - technique: sleep
    params: { ms: 10 }
  - technique: process_hollowing
    params: { payload: implant, target: "C:\\Windows\\System32\\svchost.exe" }
"#;

    #[test]
    fn a_single_payload_is_implicit_for_the_execution_step() {
        let plan = parse(SINGLE);
        let steps = resolve(&plan).expect("resolve");
        assert_eq!(steps.len(), 2);
        assert!(!steps[0].is_execution());
        assert!(steps[1].is_execution());
        let payload = steps[1].payload.as_ref().expect("execution payload");
        assert_eq!(payload.name, "implant");
        assert_eq!(
            payload.crypto.algo,
            crate::plan::schema::CryptoAlgorithm::XChaCha20Poly1305
        );
    }

    #[test]
    fn a_named_payload_is_selected_per_step() {
        let plan = parse(TWO_PAYLOADS);
        let steps = resolve(&plan).expect("resolve");
        assert_eq!(steps.len(), 3);
        assert_eq!(steps[0].payload.as_ref().expect("p0").name, "dropper");
        assert!(steps[1].payload.is_none());
        assert_eq!(steps[2].payload.as_ref().expect("p2").name, "implant");
    }

    #[test]
    fn an_unknown_payload_name_is_an_error() {
        let yaml = SINGLE.replace(
            "technique: reflective_loading",
            "technique: reflective_loading\n    params: { payload: nope }",
        );
        let plan = parse(&yaml);
        let err = resolve(&plan).expect_err("unknown payload");
        assert!(err.to_string().contains("nope"), "unclear: {err}");
    }

    #[test]
    fn an_ambiguous_payload_without_a_name_is_an_error() {
        let yaml = TWO_PAYLOADS.replace("params: { payload: implant, target", "params: { target");
        let plan = parse(&yaml);
        let err = resolve(&plan).expect_err("ambiguous payload");
        assert!(err.to_string().contains("params.payload"), "unclear: {err}");
    }

    #[test]
    fn an_execution_step_without_any_payload_is_an_error() {
        let yaml = SINGLE.replace(
            "  payloads:\n    implant: { source: ./implant.exe, format: pe }\n",
            "",
        );
        let plan = parse(&yaml);
        let err = resolve(&plan).expect_err("no payloads");
        assert!(err.to_string().contains("build.payloads"), "unclear: {err}");
    }

    #[test]
    fn an_empty_runtime_is_an_error() {
        let empty = "schema: 6\nname: e\nbuild:\n  output: { path: ./o.exe, arch: x64, strip: true, trim_paths: all }\n";
        let plan = parse(empty);
        assert!(resolve(&plan).is_err());
    }

    #[test]
    fn a_payload_crypto_overrides_the_build_default() {
        let yaml = SINGLE.replace(
            "implant: { source: ./implant.exe, format: pe }",
            "implant:\n      source: ./implant.exe\n      format: pe\n      crypto: { algo: xchacha20poly1305, key: random }",
        );
        let plan = parse(&yaml);
        let steps = resolve(&plan).expect("resolve");
        assert!(steps[1]
            .payload
            .as_ref()
            .expect("payload")
            .plan
            .crypto
            .is_some());
    }

    #[test]
    fn a_payload_without_crypto_falls_back_to_the_default() {
        let yaml = SINGLE.replace("  crypto: { algo: xchacha20poly1305, key: random }\n", "");
        let plan = parse(&yaml);
        let steps = resolve(&plan).expect("resolve with the default crypto");
        let crypto = &steps[1].payload.as_ref().expect("payload").crypto;
        assert_eq!(
            crypto.algo,
            crate::plan::schema::CryptoAlgorithm::XChaCha20Poly1305
        );
        assert_eq!(crypto.key, crate::plan::schema::KeySource::Random);
    }

    #[test]
    fn known_lolbins_are_recognized_by_stem() {
        assert!(is_known_lolbin("certutil.exe"));
        assert!(is_known_lolbin(r"C:\Windows\System32\RUNDLL32.exe"));
        assert!(is_known_lolbin("cmd"));
        assert!(!is_known_lolbin("my_implant.exe"));
    }
}
