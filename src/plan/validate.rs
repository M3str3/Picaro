//! Semantic validation of the already-deserialized plan.
//!
//! Unlike parsing (which validates structure and types), here we check
//! business rules that cannot be expressed naturally with `serde`: empty
//! values, invalid combinations, supported architectures, etc.

use crate::engine::api_resolution::{ApiResolutionConfig, ApiResolutionMode, Unmatched};
use crate::engine::obfuscation::StringsConfig;
use crate::engine::syscalls::{SyscallsConfig, SyscallsMode};
use crate::error::{PackerError, Result};
use crate::techniques::{category_of, Capability, Category, RuntimeStep};

use super::schema::{Arch, PayloadFormat, Plan, StageAction, StubPlan};
use super::stages::{self, Stage};

/// Checks the business invariants of a [`Plan`].
///
/// The schema version is already validated during `Deserialize`, so here we
/// focus on semantic rules.
pub fn validate(plan: &Plan) -> Result<()> {
    if plan.name.trim().is_empty() {
        return Err(PackerError::Validation(
            "'name' must not be empty".to_string(),
        ));
    }

    if plan.build.output.path.as_os_str().is_empty() {
        return Err(PackerError::Validation(
            "'build.output.path' must not be empty".to_string(),
        ));
    }

    validate_sign(plan)?;
    validate_stub(&plan.build.stub)?;
    validate_syscalls_arch(plan)?;

    // Resolve the plan into stages (a single-payload document becomes one
    // `technique` stage), then check every stage and the chain between them.
    let stages = stages::resolve(plan)?;
    validate_chain(&stages)?;

    for stage in &stages {
        match stage.action {
            StageAction::Technique => {
                let Some(payload) = &stage.payload else {
                    return Err(PackerError::Validation(format!(
                        "stage '{}': a 'technique' stage needs a 'payload' block",
                        stage.label
                    )));
                };
                if payload.source.trim().is_empty() {
                    return Err(PackerError::Validation(
                        "'build.payload.source' must not be empty".to_string(),
                    ));
                }
                validate_payload_format(payload, &stage.runtime)?;
                validate_payload_sha256(payload)?;
                validate_runtime(&stage.runtime)?;
                validate_conflicts(&stage.runtime)?;
                validate_sleep_obfuscation(&stage.runtime)?;
                validate_capabilities(plan, &stage.runtime)?;
                validate_hollowing_target(plan, &stage.runtime)?;
            }
            StageAction::Exec => validate_exec(stage)?,
            StageAction::Sleep => {}
        }
    }

    validate_api_resolution(plan, &stages)?;

    Ok(())
}

/// Chain-level rules across the resolved stages.
///
/// The important one is the *terminal-stage* rule: `reflective_loading` of a PE
/// executable and `dotnet_hosting` hand the whole process to the payload (a
/// normal `mainCRTStartup` calls `ExitProcess`), so a stage that uses them can
/// only be the last one — otherwise the following stages would never run.
fn validate_chain(stages: &[Stage]) -> Result<()> {
    for (index, stage) in stages.iter().enumerate() {
        if index + 1 == stages.len() {
            break;
        }
        if let Some(technique) = terminal_technique(stage) {
            return Err(PackerError::Validation(format!(
                "stage '{}' runs '{technique}', which does not return control to the loader, so the
                 later stage(s) would never run. Move it to the end of 'stages:', or use
                 'process_hollowing' (a separate process) or address it as a cooperative payload.",
                stage.label
            )));
        }
    }
    Ok(())
}

/// The execution technique that makes a stage terminal, if any.
///
/// `reflective_loading` is terminal only for a PE *executable* (`format: pe`): a
/// reflectively loaded DLL returns (its entry point is `DllMain`), and raw
/// shellcode returns if it is cooperative. `dotnet_hosting` hosts the CLR in the
/// stub's process, so a managed `Main` that exits ends the process.
fn terminal_technique(stage: &Stage) -> Option<&'static str> {
    let execution = stage
        .runtime
        .iter()
        .find(|step| category_of(step.name()) == Some(Category::Execution))?;
    match execution.name() {
        "dotnet_hosting" => Some("dotnet_hosting"),
        "reflective_loading" => {
            let format = stage
                .payload
                .as_ref()
                .map_or(PayloadFormat::Pe, |payload| payload.format);
            (format == PayloadFormat::Pe).then_some("reflective_loading (a PE executable)")
        }
        _ => None,
    }
}

/// Validates an `exec` stage: it needs a `binary` and carries no payload or
/// runtime.
fn validate_exec(stage: &Stage) -> Result<()> {
    let Some(exec) = &stage.exec else {
        return Err(PackerError::Validation(format!(
            "stage '{}': action 'exec' needs a 'binary'",
            stage.label
        )));
    };
    if exec.binary.trim().is_empty() {
        return Err(PackerError::Validation(format!(
            "stage '{}': 'binary' must not be empty",
            stage.label
        )));
    }
    if !stage.runtime.is_empty() {
        return Err(PackerError::Validation(format!(
            "stage '{}': an 'exec' stage must not declare a 'runtime' (techniques run in a
             'technique' stage)",
            stage.label
        )));
    }
    if stage.payload.is_some() {
        return Err(PackerError::Validation(format!(
            "stage '{}': an 'exec' stage must not declare a 'payload'",
            stage.label
        )));
    }
    Ok(())
}

/// Non-fatal advisories produced by validation.
///
/// These do not reject a plan (unlike [`validate`]); the build prints them as
/// warnings. Today they cover a `bouncer` gate with no check declared (a no-op,
/// almost certainly not intended), the debug build, whose whole point is to
/// trade evasion for observability and whose artifact is therefore never for
/// delivery, and `api_resolution.unmatched: abort`, a strict allowlist that
/// fails the load on the first import outside the catalogue.
pub fn advisories(plan: &Plan) -> Vec<String> {
    let mut warnings = Vec::new();
    // Flatten every stage's pipeline (a single-payload plan resolves to one
    // stage, so this is exactly the old `plan.runtime`).
    let resolved = stages::resolve(plan).unwrap_or_default();
    let runtimes: Vec<RuntimeStep> = resolved
        .iter()
        .flat_map(|stage| stage.runtime.iter().cloned())
        .collect();
    for step in &runtimes {
        if let RuntimeStep::Bouncer { params } = step {
            if params.is_noop() {
                warnings.push(
                    "bouncer: no check field is declared, so the technique is a no-op and will \
                     never abort the pipeline"
                        .to_string(),
                );
            }
        }
    }

    // An `exec` stage whose binary is outside the living-off-the-land catalogue
    // still works, but it is worth flagging.
    for stage in &resolved {
        if let Some(exec) = &stage.exec {
            if !stages::is_known_lolbin(&exec.binary) {
                warnings.push(format!(
                    "stage '{}': '{}' is not a known living-off-the-land binary; the exec stage \
                     still runs it, but a signed system binary (certutil, rundll32, ...) is the \
                     usual choice for proxy execution",
                    stage.label, exec.binary
                ));
            }
        }
    }

    if plan.build.stub.debug {
        warnings.push(
            "build.stub.debug is enabled: the artifact prints technique traces and is built \
             without symbol stripping, path trimming or optimization; it is a lab artifact and \
             must not be delivered"
                .to_string(),
        );
        if runtimes
            .iter()
            .any(|step| matches!(step, RuntimeStep::AntiDebug { .. }))
        {
            warnings.push(
                "build.stub.debug is enabled but `anti_debug` is in the pipeline: it may abort \
                 the stub under the very debugger you are using"
                    .to_string(),
            );
        }
    }

    if let Ok(config) = ApiResolutionConfig::from_yaml(plan.build.stub.api_resolution.as_ref()) {
        if config.mode == ApiResolutionMode::Proxy && config.is_noop() {
            warnings.push(
                "build.stub.api_resolution.mode is 'proxy' but no 'apis' are declared, so it is a \
                 no-op"
                    .to_string(),
            );
        }
        if config.mode == ApiResolutionMode::Proxy && config.unmatched == Unmatched::Abort {
            warnings.push(
                "build.stub.api_resolution.unmatched is 'abort': the loader will fail on any \
                 payload import outside the catalogue (a strict allowlist / debugging posture)"
                    .to_string(),
            );
        }
    }
    warnings
}

/// Validates the stub's syscall layer and string obfuscation.
///
/// `build.stub` itself may be empty (builtin stub, default syscall mode,
/// default obfuscation); an unknown `syscalls.mode`/`syscalls.resolver` or
/// `strings.strategy` is a clear error.
fn validate_stub(stub: &StubPlan) -> Result<()> {
    SyscallsConfig::from_yaml(stub.syscalls.as_ref())?;
    StringsConfig::from_yaml(stub.strings.as_ref())?;
    Ok(())
}

/// Validates `build.stub.api_resolution` and its coupling with the syscall layer
/// and the payload format.
///
/// `mode: proxy` is only meaningful when intercepted calls can be re-routed
/// through the syscall layer (so the imports leave the stub's IAT) and when the
/// payload has an import table to rewrite. No separate "an Execution technique is
/// active" check is needed: the pipeline contract already enforces exactly one
/// Execution technique, and both execution techniques resolve imports.
fn validate_api_resolution(plan: &Plan, stages: &[Stage]) -> Result<()> {
    let config = ApiResolutionConfig::from_yaml(plan.build.stub.api_resolution.as_ref())?;
    if config.mode != ApiResolutionMode::Proxy {
        return Ok(());
    }

    // The proxies are functions in the loader image with loader-wide state, so
    // the mode is meaningful for exactly one stage.
    if stages.len() != 1 {
        return Err(PackerError::Validation(
            "build.stub.api_resolution.mode 'proxy' is loader-wide (it rewrites the loader's own
             IAT), so it is not supported with a multi-stage plan: use a single-payload plan"
                .to_string(),
        ));
    }
    let stage = &stages[0];

    let syscalls = SyscallsConfig::from_yaml(plan.build.stub.syscalls.as_ref())?;
    if syscalls.mode != SyscallsMode::Indirect {
        return Err(PackerError::Validation(
            "build.stub.api_resolution.mode 'proxy' requires 'build.stub.syscalls.mode: indirect': \
             the re-routed calls would otherwise fall back to the Win32 APIs and the intercepted \
             imports would reappear in the stub's IAT"
                .to_string(),
        ));
    }

    let format = stage.payload.as_ref().map(|payload| payload.format);
    let Some(format) = format else {
        return Err(PackerError::Validation(
            "build.stub.api_resolution.mode 'proxy' needs a payload with an import table
             (format: pe or dll)"
                .to_string(),
        ));
    };
    if !format.is_pe_image() {
        return Err(PackerError::Validation(format!(
            "build.stub.api_resolution.mode 'proxy' requires a payload with an import table \
             (format: pe or dll), not '{}'",
            format.label()
        )));
    }

    // The generated proxies are ordinary functions in the loader image, with
    // their own data (obfuscated names, the SSN table, the syscall trampoline).
    // A hollowed payload runs in a *different* process, which has none of that,
    // so its IAT there can only point at the real exports: the mode cannot apply.
    // Failing loudly beats silently not proxying. See Phase E in the doc.
    if stage
        .runtime
        .iter()
        .any(|step| step.name() == "process_hollowing")
    {
        return Err(PackerError::Validation(
            "build.stub.api_resolution.mode 'proxy' is not supported with process_hollowing: the \
             proxies live in the loader image, which is not mapped in the target process, so the \
             payload's IAT there can only point at the real exports. Use reflective_loading (the \
             payload runs in the loader's process). See docs/api-resolution.md (Phase E)."
                .to_string(),
        ));
    }

    Ok(())
}

/// Validates `build.payload.format` and its format-specific fields.
///
/// Two rules that `serde` cannot express: `export` only makes sense for a DLL,
/// and `process_hollowing` can only run a PE executable today (it replaces a
/// suspended process's image; a DLL has no process entry point to run and raw
/// shellcode has no image at all). Shellcode and DLL payloads are run in-process
/// by `reflective_loading`.
fn validate_payload_format(
    payload: &crate::plan::schema::PayloadPlan,
    runtime: &[RuntimeStep],
) -> Result<()> {
    if let Some(export) = &payload.export {
        if payload.format != PayloadFormat::Dll {
            return Err(PackerError::Validation(format!(
                "'build.payload.export' only applies to 'format: dll' (this plan declares \
                 format: {})",
                payload.format.label()
            )));
        }
        if export.trim().is_empty() {
            return Err(PackerError::Validation(
                "'build.payload.export' must not be empty".to_string(),
            ));
        }
    }

    // A managed assembly is neither mapped nor hollowed: the stub hosts the CLR
    // and loads the assembly's bytes, which only `dotnet_hosting` does.
    let execution = runtime
        .iter()
        .find(|step| category_of(step.name()) == Some(Category::Execution));
    let hosts_the_clr = execution.is_some_and(|step| step.name() == "dotnet_hosting");
    if payload.format == PayloadFormat::Dotnet && !hosts_the_clr {
        return Err(PackerError::Validation(format!(
            "build.payload.format 'dotnet' needs an execution technique that hosts the CLR: add 'technique: dotnet_hosting' (this plan runs '{}', which does not run a managed assembly)",
            execution.map_or("no execution technique", |step| step.name())
        )));
    }
    if payload.format != PayloadFormat::Dotnet && hosts_the_clr {
        return Err(PackerError::Validation(format!(
            "'technique: dotnet_hosting' needs 'build.payload.format: dotnet' (this plan declares format: {})",
            payload.format.label()
        )));
    }

    if payload.format != PayloadFormat::Pe
        && execution.is_some_and(|step| step.name() == "process_hollowing")
    {
        return Err(PackerError::Validation(format!(
            "build.payload.format '{}' is not supported by process_hollowing yet: it only runs 'format: pe'. Use reflective_loading, which runs pe, dll and shellcode in-process.",
            payload.format.label()
        )));
    }

    Ok(())
}

/// Rejects a `build.payload.sha256` that is not exactly 64 hex characters.
///
/// Catching a malformed pin here gives a clear message instead of a confusing
/// "payload mismatch" at build time.
fn validate_payload_sha256(payload: &crate::plan::schema::PayloadPlan) -> Result<()> {
    let Some(hash) = payload.sha256.as_deref() else {
        return Ok(());
    };
    let hash = hash.trim();
    if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(PackerError::Validation(format!(
            "'build.payload.sha256' must be 64 hex characters (got '{hash}')"
        )));
    }
    Ok(())
}

/// Validates `output.sign`.
///
/// Only the mode-specific requirements are checked here; locating `signtool`
/// and the certificate happens at build time (so the error names what is
/// actually missing on the machine).
fn validate_sign(plan: &Plan) -> Result<()> {
    let Some(sign) = &plan.build.output.sign else {
        return Ok(());
    };
    match sign.mode.as_str() {
        "none" => {}
        "lab" => {}
        "store" => {
            if sign.thumbprint.is_none() && sign.subject.is_none() {
                return Err(PackerError::Validation(
                    "output.sign.mode 'store' needs either 'thumbprint' or 'subject'".to_string(),
                ));
            }
        }
        "file" => {
            if sign.file.is_none() {
                return Err(PackerError::Validation(
                    "output.sign.mode 'file' needs 'file' (a .pfx/.p12 path)".to_string(),
                ));
            }
        }
        other => {
            return Err(PackerError::Validation(format!(
                "invalid output.sign.mode '{other}': expected none, lab, store or file"
            )));
        }
    }
    if let Some(url) = &sign.timestamp_url {
        if !(url.starts_with("http://") || url.starts_with("https://")) {
            return Err(PackerError::Validation(format!(
                "output.sign.timestamp_url '{url}' must be an http(s) URL"
            )));
        }
    }
    Ok(())
}

/// Rejects a technique that has no implementation for the requested architecture.
///
/// Every technique declares the capabilities it needs (`TechniqueDef::requires`).
/// Its architecture capability (`WindowsX64` / `WindowsX86`) must match
/// `build.output.arch`: the stub and the payload share one address space, so an
/// x64-only fragment cannot be linked into an i686 stub (nor the reverse).
fn validate_capabilities(plan: &Plan, runtime: &[RuntimeStep]) -> Result<()> {
    let arch = plan.build.output.arch;
    let required = match arch {
        Arch::X64 => Capability::WindowsX64,
        Arch::X86 => Capability::WindowsX86,
    };
    for step in runtime {
        // An unknown technique name is rejected by `validate_runtime`.
        let Some(def) = crate::techniques::find(step.name()) else {
            continue;
        };
        if !def.requires.contains(&required) {
            return Err(PackerError::Validation(format!(
                "technique '{}' does not support build.output.arch '{}' yet: it requires {}; the \
                 packer can compile an {} stub, but this technique has no {} fragment",
                def.name,
                arch.label(),
                capabilities_label(def.requires),
                arch.label(),
                arch.label()
            )));
        }
    }
    Ok(())
}

/// Rejects a hollowing target whose image cannot run in the stub's process.
///
/// The target must be a process of the stub's own architecture (see
/// `process_hollowing`): an x86 stub cannot hollow a 64-bit `svchost.exe` and
/// vice versa. When the target is a local file the check is exact; a target
/// that does not resolve locally (`$arg.N$`, a remote path, a missing file) is
/// left to run time, where the technique fails with its own error.
///
/// `C:\Windows\System32` is redirected to `SysWOW64` for a 32-bit process, so
/// the path is mapped the way WOW64 would resolve it before the file is read —
/// the default `System32\svchost.exe` is a 64-bit image on a 64-bit host but
/// the x86 stub actually gets the 32-bit one.
fn validate_hollowing_target(plan: &Plan, runtime: &[RuntimeStep]) -> Result<()> {
    let arch = plan.build.output.arch;
    for step in runtime {
        let RuntimeStep::ProcessHollowing { params } = step else {
            continue;
        };
        let Some(path) = wow64_resolve(&params.target, arch) else {
            continue;
        };
        let Ok(bytes) = std::fs::read(&path) else {
            // Not a local file (a runtime argument, a remote path, or a target
            // that only exists on the host): nothing to check here.
            continue;
        };
        let Ok(info) = crate::engine::pe::parse(&bytes) else {
            continue;
        };
        if info.arch() != Some(arch) {
            return Err(PackerError::Validation(format!(
                "process_hollowing target '{}' is a {} image but build.output.arch is '{}': the target must match the stub's architecture ({} resolves to '{}' under WOW64)",
                params.target,
                info.arch().map(|a| a.label()).unwrap_or("non-PE"),
                arch.label(),
                params.target,
                path.display()
            )));
        }
    }
    Ok(())
}

/// Maps a Windows path the way the target process would see it, or `None` when
/// it cannot be a local file (a runtime argument, or not an absolute path).
///
/// Only a 32-bit process is redirected: its `System32` is `SysWOW64`. A 64-bit
/// process sees both directories as they are (`SysWOW64` keeps the 32-bit
/// images), so a 64-bit target path is taken literally — except when the packer
/// itself is a 32-bit process, whose own read of `System32` would be redirected
/// to the 32-bit image: that case asks for the unredirected view through
/// `Sysnative`, the WOW64 alias that only exists for 32-bit callers.
fn wow64_resolve(target: &str, arch: Arch) -> Option<std::path::PathBuf> {
    if target.contains("$arg.") || target.trim().is_empty() {
        return None;
    }
    let (from, to) = match arch {
        Arch::X86 => ("System32", "SysWOW64"),
        Arch::X64 if cfg!(target_arch = "x86") => ("System32", "Sysnative"),
        Arch::X64 => return local_path(target),
    };
    let needle = format!("\\{from}\\");
    let mapped = match target
        .to_ascii_lowercase()
        .find(&needle.to_ascii_lowercase())
    {
        Some(index) => {
            let mut text = target.to_string();
            text.replace_range(index + 1..index + 1 + from.len(), to);
            text
        }
        None => target.to_string(),
    };
    local_path(&mapped)
}

/// The path as a `PathBuf`, or `None` when it cannot be a local file.
fn local_path(target: &str) -> Option<std::path::PathBuf> {
    let path = std::path::PathBuf::from(target);
    if path.is_absolute() {
        Some(path)
    } else {
        None
    }
}

/// Human list of a technique's capabilities (`x64 + administrator rights`).
fn capabilities_label(requires: &[Capability]) -> String {
    requires
        .iter()
        .map(|capability| match capability {
            Capability::WindowsX64 => "x64",
            Capability::WindowsX86 => "x86",
            Capability::KernelAccess => "kernel access",
            Capability::AdminRequired => "administrator rights",
        })
        .collect::<Vec<_>>()
        .join(" + ")
}

/// Rejects an x64-only loader configuration on an x86 build.
///
/// `syscalls.mode: indirect` relies on the x64 `syscall; ret` gadget and an x64
/// `global_asm!` trampoline; x86 has neither (and the WOW64 SSNs differ), so the
/// x86 path is a second implementation, not a flag.
fn validate_syscalls_arch(plan: &Plan) -> Result<()> {
    if plan.build.output.arch != Arch::X86 {
        return Ok(());
    }
    let syscalls = SyscallsConfig::from_yaml(plan.build.stub.syscalls.as_ref())?;
    if syscalls.mode == SyscallsMode::Indirect {
        return Err(PackerError::Validation(
            "build.stub.syscalls.mode 'indirect' is x64-only for now: the trampoline is x64 (x86 \
             has no 'syscall; ret' gadget, and the WOW64 SSNs differ). Use 'mode: none'"
                .to_string(),
        ));
    }
    Ok(())
}

/// Validates the sleep-obfuscation parameters.
///
/// Only the ekko variant and the `[payload]` region list are implemented in
/// this phase; the other values parse fine but are rejected here with a
/// pointer to the missing phase.
fn validate_sleep_obfuscation(runtime: &[RuntimeStep]) -> Result<()> {
    for step in runtime {
        let RuntimeStep::SleepObfuscation { params } = step else {
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

    /// A full valid plan without a runtime (runtime tests append their own).
    const NO_RUNTIME: &str = r#"
schema: 4
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

    /// A full valid plan with a single Execution technique, used by the
    /// source/output regression tests.
    const VALID: &str = r#"
schema: 4
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

    /// YAML fragment with the other Execution technique.
    const HOLLOWING_YAML: &str = r#"
runtime:
  - technique: process_hollowing
"#;

    /// YAML fragment with the one technique that stays x64-only: Ekko works on
    /// the x64 ABI and is not ported (see the x86 plan).
    const X64_ONLY_YAML: &str = r#"
runtime:
  - technique: sleep_obfuscation
  - technique: reflective_loading
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

    fn parse(yaml: &str) -> Plan {
        serde_yml::from_str(yaml).expect("valid YAML")
    }

    fn with_runtime(runtime_yaml: &str) -> Plan {
        parse(&(NO_RUNTIME.to_string() + runtime_yaml))
    }

    /// `NO_RUNTIME` with the requested `arch` and a runtime appended.
    fn with_arch(arch: &str, runtime_yaml: &str) -> Plan {
        let base = NO_RUNTIME.replace("arch: x64", &format!("arch: {arch}"));
        parse(&(base + runtime_yaml))
    }

    /// `NO_RUNTIME` with the requested `arch` and a `build.stub` block inserted
    /// (`stub_yaml` must already be indented to sit under `build:`).
    fn with_stub(arch: &str, stub_yaml: &str) -> Plan {
        let base = NO_RUNTIME
            .replace("arch: x64", &format!("arch: {arch}"))
            .replace("  output:", &format!("  stub:\n{stub_yaml}  output:"));
        parse(&base)
    }

    /// `arch: x86` is accepted by the schema, but a technique with no x86
    /// fragment is rejected with a message that says which one and why.
    #[test]
    fn rejects_a_technique_without_an_x86_fragment() {
        let plan = with_arch("x86", X64_ONLY_YAML);
        let err = validate(&plan).expect_err("sleep_obfuscation is x64-only");
        let msg = err.to_string();
        assert!(msg.contains("sleep_obfuscation"), "unclear: {msg}");
        assert!(msg.contains("'x86'"), "unclear: {msg}");
        assert!(msg.contains("no x86 fragment"), "unclear: {msg}");
    }

    /// The techniques that have an x86 fragment accept `arch: x86`: both
    /// execution techniques and the preparations ported in M3 (`sleep_obfuscation`
    /// stays x64-only, which the test above covers).
    #[test]
    fn accepts_the_x86_capable_techniques_on_x86() {
        validate(&with_arch("x86", EXECUTION_YAML)).expect("x86 reflective plan is valid");
        validate(&with_arch("x86", HOLLOWING_YAML)).expect("x86 hollowing plan is valid");
        for preparation in ["anti_debug", "patch_amsi", "patch_etw", "bouncer"] {
            let yaml = format!(
                "runtime:
  - technique: {preparation}
  - technique: reflective_loading
"
            );
            validate(&with_arch("x86", &yaml))
                .unwrap_or_else(|e| panic!("x86 {preparation} plan is valid: {e}"));
        }
    }

    /// A hollowing target that exists locally must match the stub's
    /// architecture; the committed fixtures stand in for the target image.
    #[test]
    fn rejects_a_hollowing_target_of_the_wrong_architecture() {
        let x64_fixture = format!(
            "{}/tests/fixtures/minimal_x64.exe",
            env!("CARGO_MANIFEST_DIR")
        );
        // YAML single quotes: a Windows path must not be read as escapes.
        let yaml = format!(
            r#"runtime:
  - technique: process_hollowing
    params:
      target: '{x64_fixture}'
"#
        );
        let err = validate(&with_arch("x86", &yaml))
            .expect_err("a 64-bit target cannot be hollowed by an x86 stub");
        let msg = err.to_string();
        assert!(msg.contains("minimal_x64.exe"), "unclear: {msg}");
        assert!(msg.contains("'x86'"), "unclear: {msg}");

        // The matching architecture is accepted, and so is a target that does
        // not exist locally (it is resolved at run time).
        let x86_fixture = format!(
            "{}/tests/fixtures/minimal_x86.exe",
            env!("CARGO_MANIFEST_DIR")
        );
        let yaml = format!(
            r#"runtime:
  - technique: process_hollowing
    params:
      target: '{x86_fixture}'
"#
        );
        validate(&with_arch("x86", &yaml)).expect("an x86 target fits an x86 stub");

        let yaml = "runtime:
  - technique: process_hollowing
    params:
      target: \"$arg.0$\"
";
        validate(&with_arch("x86", yaml)).expect("a runtime target is checked at run time");
    }

    /// `System32` is `SysWOW64` for a 32-bit process (and the reverse for a
    /// 64-bit one), so the target check resolves the path the way WOW64 would.
    /// The `Arch::X64` case depends on the packer's own bitness: a 64-bit packer
    /// reads the real `System32`, a 32-bit one has to ask for `Sysnative`.
    #[test]
    fn wow64_resolve_maps_the_redirected_directories() {
        use super::wow64_resolve;
        let system32 = r"C:\Windows\System32\svchost.exe";
        let syswow64 = r"C:\Windows\SysWOW64\svchost.exe";

        assert_eq!(
            wow64_resolve(system32, Arch::X86)
                .unwrap()
                .to_string_lossy(),
            r"C:\Windows\SysWOW64\svchost.exe"
        );
        // `SysWOW64` keeps the 32-bit images, so a path there is read as written
        // by both a 64-bit and a 32-bit packer.
        assert_eq!(
            wow64_resolve(syswow64, Arch::X64)
                .unwrap()
                .to_string_lossy(),
            syswow64
        );
        let expected = if cfg!(target_arch = "x86") {
            r"C:\Windows\Sysnative\svchost.exe"
        } else {
            system32
        };
        assert_eq!(
            wow64_resolve(system32, Arch::X64)
                .unwrap()
                .to_string_lossy(),
            expected
        );
        assert!(wow64_resolve("$arg.0$", Arch::X86).is_none());
        assert!(wow64_resolve(r"relative\svchost.exe", Arch::X86).is_none());
    }

    #[test]
    fn accepts_the_x64_techniques_on_x64() {
        validate(&with_arch("x64", EXECUTION_YAML)).expect("x64 plan is valid");
    }

    /// `syscalls.mode: indirect` is x64-only: the trampoline is x64 and the WOW64
    /// SSNs differ, so x86 needs a second implementation, not a flag.
    #[test]
    fn rejects_indirect_syscalls_on_x86() {
        let plan = with_stub("x86", "    syscalls:\n      mode: indirect\n");
        let err = validate_syscalls_arch(&plan).expect_err("x86 has no indirect syscalls");
        assert!(err.to_string().contains("indirect"), "unclear: {err}");

        let plan = with_stub("x64", "    syscalls:\n      mode: indirect\n");
        validate_syscalls_arch(&plan).expect("x64 indirect is fine");
    }

    #[test]
    fn rejects_zero_execution_techniques() {
        let plan = with_runtime(PREPARATION_YAML);
        let err = validate(&plan).expect_err("zero execution techniques must fail");
        assert!(
            err.to_string()
                .contains("Pipeline must declare exactly one Execution technique."),
            "unclear error: {err}"
        );
    }

    #[test]
    fn rejects_two_execution_techniques() {
        let plan = with_runtime(TWO_EXECUTION_YAML);
        let err = validate(&plan).expect_err("two execution techniques must fail");
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
        let plan = with_runtime(PREP_AFTER_EXEC_YAML);
        let err = validate(&plan).expect_err("preparation after execution must fail");
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
        let plan = with_runtime(PREP_BEFORE_EXEC_YAML);
        validate(&plan).expect("preparation before execution must be valid");
    }

    #[test]
    fn accepts_single_execution() {
        let plan = with_runtime(EXECUTION_YAML);
        validate(&plan).expect("a single execution technique must be valid");
    }

    // --- payload formats ---

    /// Injects extra `build.payload` lines into [`NO_RUNTIME`], then appends a
    /// runtime fragment.
    fn with_payload(payload_lines: &str, runtime_yaml: &str) -> Plan {
        let yaml = NO_RUNTIME.replace(
            "    source: ./payload.exe\n",
            &format!("    source: ./payload.bin\n{payload_lines}"),
        );
        parse(&(yaml + runtime_yaml))
    }

    #[test]
    fn accepts_shellcode_with_reflective_loading() {
        let plan = with_payload("    format: shellcode\n", EXECUTION_YAML);
        validate(&plan).expect("shellcode + reflective_loading must be valid");
    }

    #[test]
    fn accepts_a_dll_with_an_export() {
        let plan = with_payload("    format: dll\n    export: Run\n", EXECUTION_YAML);
        validate(&plan).expect("dll + export + reflective_loading must be valid");
    }

    #[test]
    fn rejects_shellcode_with_process_hollowing() {
        let plan = with_payload(
            "    format: shellcode\n",
            "runtime:\n  - technique: process_hollowing\n",
        );
        let err = validate(&plan).expect_err("hollowing can only run a PE today");
        let msg = err.to_string();
        assert!(msg.contains("process_hollowing"), "msg: {msg}");
        assert!(msg.contains("shellcode"), "msg: {msg}");
        assert!(msg.contains("reflective_loading"), "msg: {msg}");
    }

    #[test]
    fn rejects_a_dll_with_process_hollowing() {
        let plan = with_payload(
            "    format: dll\n",
            "runtime:\n  - technique: process_hollowing\n",
        );
        let err = validate(&plan).expect_err("hollowing cannot run a DLL");
        assert!(err.to_string().contains("process_hollowing"), "err: {err}");
    }

    #[test]
    fn rejects_an_export_without_the_dll_format() {
        let plan = with_payload("    export: Run\n", EXECUTION_YAML);
        let err = validate(&plan).expect_err("export only applies to dll");
        let msg = err.to_string();
        assert!(msg.contains("build.payload.export"), "msg: {msg}");
        assert!(msg.contains("format: dll"), "msg: {msg}");
    }

    #[test]
    fn rejects_an_empty_dll_export() {
        let plan = with_payload("    format: dll\n    export: \"   \"\n", EXECUTION_YAML);
        let err = validate(&plan).expect_err("an empty export must fail");
        assert!(err.to_string().contains("export"), "err: {err}");
    }

    // --- sleep_obfuscation specifics ---

    /// YAML fragment with a sleep_obfuscation + execution pipeline.
    const SLEEP_YAML: &str = r#"
runtime:
  - technique: sleep_obfuscation
    params:
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

    #[test]
    fn accepts_a_bouncer_as_the_first_preparation() {
        let yaml = r#"
runtime:
  - technique: bouncer
    params:
      hostname: "WORKSTATION-*"
  - technique: reflective_loading
"#;
        validate(&with_runtime(yaml)).expect("bouncer first must be valid");
    }

    // --- bouncer advisories ---

    #[test]
    fn advises_on_a_noop_bouncer() {
        let plan = with_runtime(
            r#"
runtime:
  - technique: bouncer
  - technique: reflective_loading
"#,
        );
        validate(&plan).expect("a no-op bouncer is valid, only advised against");
        let warnings = advisories(&plan);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("bouncer"), "unclear: {warnings:?}");
        assert!(warnings[0].contains("no-op"), "unclear: {warnings:?}");
    }

    #[test]
    fn no_advisory_when_bouncer_declares_a_check() {
        let plan = with_runtime(
            r#"
runtime:
  - technique: bouncer
    params:
      hostname: "WORKSTATION-*"
  - technique: reflective_loading
"#,
        );
        assert!(advisories(&plan).is_empty());
    }

    #[test]
    fn no_advisory_without_a_bouncer() {
        assert!(advisories(&with_runtime(EXECUTION_YAML)).is_empty());
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
    fn accepts_tartarus_gate_resolver() {
        let yaml = VALID.replace(
            "  output:\n",
            "  stub:\n    syscalls:\n      mode: indirect\n      resolver: tartarus_gate\n  output:\n",
        );
        validate(&parse(&yaml)).expect("tartarus_gate must be valid");
    }

    #[test]
    fn accepts_api_hash_resolver() {
        let yaml = VALID.replace(
            "  output:\n",
            "  stub:\n    syscalls:\n      mode: indirect\n      resolver: api_hash\n  output:\n",
        );
        validate(&parse(&yaml)).expect("api_hash must be valid");
    }

    #[test]
    fn rejects_unknown_syscalls_resolver() {
        let yaml = VALID.replace(
            "  output:\n",
            "  stub:\n    syscalls:\n      resolver: halos_gate\n  output:\n",
        );
        let err = validate(&parse(&yaml)).expect_err("an unknown resolver must fail");
        assert!(
            err.to_string().contains("build.stub.syscalls.resolver"),
            "unclear error: {err}"
        );
    }

    // --- api_resolution block ---

    #[test]
    fn accepts_api_resolution_none() {
        let yaml = VALID.replace(
            "  output:\n",
            "  stub:\n    api_resolution:\n      mode: none\n  output:\n",
        );
        validate(&parse(&yaml)).expect("mode none must be valid");
    }

    #[test]
    fn accepts_proxy_with_indirect_syscalls() {
        let yaml = VALID.replace(
            "  output:\n",
            "  stub:\n    syscalls:\n      mode: indirect\n    api_resolution:\n      mode: proxy\n      apis:\n        - \"kernel32!ReadProcessMemory\"\n  output:\n",
        );
        validate(&parse(&yaml)).expect("proxy with indirect syscalls must be valid");
    }

    #[test]
    fn proxy_requires_indirect_syscalls() {
        let yaml = VALID.replace(
            "  output:\n",
            "  stub:\n    api_resolution:\n      mode: proxy\n      apis:\n        - \"kernel32!ReadProcessMemory\"\n  output:\n",
        );
        let err = validate(&parse(&yaml)).expect_err("proxy without indirect syscalls must fail");
        assert!(
            err.to_string().contains("syscalls.mode: indirect"),
            "unclear error: {err}"
        );
    }

    #[test]
    fn proxy_rejects_a_shellcode_payload() {
        let yaml = VALID
            .replace(
                "    source: ./payload.exe\n",
                "    source: ./payload.bin\n    format: shellcode\n",
            )
            .replace(
                "  output:\n",
                "  stub:\n    syscalls:\n      mode: indirect\n    api_resolution:\n      mode: proxy\n      apis:\n        - \"kernel32!ReadProcessMemory\"\n  output:\n",
            );
        let err = validate(&parse(&yaml)).expect_err("proxy with shellcode must fail");
        assert!(
            err.to_string().contains("import table"),
            "unclear error: {err}"
        );
    }

    #[test]
    fn rejects_an_unknown_api_resolution_api() {
        let yaml = VALID.replace(
            "  output:\n",
            "  stub:\n    api_resolution:\n      mode: proxy\n      apis:\n        - \"kernel32!Nope\"\n  output:\n",
        );
        let err = validate(&parse(&yaml)).expect_err("an unknown api must fail");
        assert!(
            err.to_string().contains("api_resolution.apis"),
            "unclear error: {err}"
        );
    }

    #[test]
    fn proxy_rejects_process_hollowing() {
        let yaml = NO_RUNTIME
            .replace(
                "  output:\n",
                "  stub:\n    syscalls:\n      mode: indirect\n    api_resolution:\n      mode: proxy\n      apis:\n        - \"kernel32!ReadProcessMemory\"\n  output:\n",
            )
            .to_string()
            + "runtime:\n  - technique: process_hollowing\n";
        let err = validate(&parse(&yaml)).expect_err("proxy with hollowing must fail");
        assert!(
            err.to_string().contains("process_hollowing"),
            "unclear error: {err}"
        );
    }

    #[test]
    fn advises_on_a_noop_proxy_with_no_apis() {
        let yaml = VALID.replace(
            "  output:\n",
            "  stub:\n    syscalls:\n      mode: indirect\n    api_resolution:\n      mode: proxy\n  output:\n",
        );
        let plan = parse(&yaml);
        validate(&plan).expect("a proxy with no apis is valid, only advised against");
        let warnings = advisories(&plan);
        assert!(
            warnings.iter().any(|w| w.contains("api_resolution")),
            "expected an advisory: {warnings:?}"
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

    #[test]
    fn accepts_x64() {
        validate(&parse(VALID)).expect("x64 must be valid");
    }

    /// `arch: x86` is a valid schema value now; what fails is the technique
    /// capability, not the arch itself (the packer can compile an i686 stub).
    #[test]
    fn x86_parses_and_fails_on_the_capability_check() {
        let yaml = VALID
            .replace(
                "  - technique: reflective_loading\n",
                "  - technique: sleep_obfuscation\n  - technique: reflective_loading\n",
            )
            .replace("    arch: x64\n", "    arch: x86\n");
        let plan = parse(&yaml); // x86 must parse: the enum value is supported
        let msg = validate(&plan)
            .expect_err("sleep_obfuscation has no x86 fragment")
            .to_string();
        assert!(
            msg.contains("technique 'sleep_obfuscation'"),
            "unclear error: {msg}"
        );
        assert!(
            !msg.contains("not integrated"),
            "the architecture is supported now: {msg}"
        );
    }

    #[test]
    fn accepts_a_valid_payload_sha256() {
        let yaml = VALID.replace(
            "    source: ./payload.exe\n",
            "    source: ./payload.exe\n    sha256: \
             e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n",
        );
        validate(&parse(&yaml)).expect("a 64-hex hash must be accepted");
    }

    #[test]
    fn rejects_a_malformed_payload_sha256() {
        let yaml = VALID.replace(
            "    source: ./payload.exe\n",
            "    source: ./payload.exe\n    sha256: deadbeef\n",
        );
        let err = validate(&parse(&yaml)).expect_err("a short hash must be rejected");
        assert!(
            err.to_string().contains("build.payload.sha256"),
            "unclear error: {err}"
        );
    }

    #[test]
    fn requires_a_sha256_longer_than_a_prefix() {
        // 63 hex chars: right alphabet, wrong length.
        let yaml = VALID.replace(
            "    source: ./payload.exe\n",
            "    source: ./payload.exe\n    sha256: \
             e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85\n",
        );
        validate(&parse(&yaml)).expect_err("63 hex characters must be rejected");
    }

    /// `VALID` with `block` appended to the `output` mapping.
    fn with_sign(block: &str) -> Plan {
        let yaml = VALID.replace(
            "    trim_paths: all\n",
            &format!("    trim_paths: all\n{block}"),
        );
        parse(&yaml)
    }

    #[test]
    fn accepts_the_signing_modes() {
        for mode in ["none", "lab"] {
            validate(&with_sign(&format!("    sign:\n      mode: {mode}\n")))
                .unwrap_or_else(|e| panic!("mode {mode} must be valid: {e}"));
        }
        validate(&with_sign(
            "    sign:\n      mode: store\n      thumbprint: DEADBEEF\n",
        ))
        .expect("store with a thumbprint must be valid");
        validate(&with_sign(
            "    sign:\n      mode: file\n      file: ./cert.pfx\n",
        ))
        .expect("file with a path must be valid");
    }

    #[test]
    fn rejects_an_unknown_signing_mode() {
        let err = validate(&with_sign("    sign:\n      mode: bogus\n"))
            .expect_err("an unknown mode must fail");
        assert!(err.to_string().contains("output.sign.mode"), "{err}");
    }

    #[test]
    fn store_signing_needs_a_subject_or_thumbprint() {
        let err = validate(&with_sign("    sign:\n      mode: store\n"))
            .expect_err("store without an identifier must fail");
        assert!(err.to_string().contains("thumbprint"), "{err}");
    }

    #[test]
    fn file_signing_needs_a_path() {
        let err = validate(&with_sign("    sign:\n      mode: file\n"))
            .expect_err("file without a path must fail");
        assert!(err.to_string().contains("file"), "{err}");
    }

    #[test]
    fn rejects_a_non_http_timestamp_url() {
        let err = validate(&with_sign(
            "    sign:\n      mode: lab\n      timestamp_url: ftp://ts.example\n",
        ))
        .expect_err("a non-http timestamp url must fail");
        assert!(err.to_string().contains("timestamp_url"), "{err}");
    }

    const MULTISTAGE: &str = r#"
schema: 5
name: multi
build:
  output: { path: ./o.exe, arch: x64, strip: true, trim_paths: all }
stages:
  - name: a
    action: technique
    payload: { source: ./a.bin, format: shellcode, crypto: { algo: xchacha20poly1305, key: random } }
    runtime: [{ technique: reflective_loading }]
  - name: b
    action: technique
    payload: { source: ./b.bin, format: shellcode, crypto: { algo: xchacha20poly1305, key: random } }
    runtime: [{ technique: reflective_loading }]
"#;

    #[test]
    fn accepts_a_two_shellcode_chain() {
        assert!(validate(&parse(MULTISTAGE)).is_ok());
    }

    #[test]
    fn rejects_a_terminal_stage_before_the_last_one() {
        let yaml = MULTISTAGE.replace("format: shellcode", "format: pe");
        let err = validate(&parse(&yaml)).expect_err("a terminal stage must be rejected");
        assert!(err.to_string().contains("does not return control"), "{err}");
    }

    #[test]
    fn rejects_an_exec_stage_with_a_runtime() {
        let yaml = MULTISTAGE.replace(
            "    action: technique\n    payload: { source: ./b.bin, format: shellcode, crypto: { algo: xchacha20poly1305, key: random } }\n    runtime: [{ technique: reflective_loading }]",
            "    action: exec\n    binary: cmd.exe\n    runtime: [{ technique: reflective_loading }]",
        );
        let err = validate(&parse(&yaml)).expect_err("an exec stage with a runtime must fail");
        assert!(
            err.to_string().contains("must not declare a 'runtime'"),
            "{err}"
        );
    }

    #[test]
    fn rejects_proxy_api_resolution_on_a_multi_stage_plan() {
        let yaml = MULTISTAGE.replace(
            "  output: { path: ./o.exe, arch: x64, strip: true, trim_paths: all }",
            "  output: { path: ./o.exe, arch: x64, strip: true, trim_paths: all }\n  stub:\n    syscalls: { mode: indirect }\n    api_resolution: { mode: proxy, apis: [\"ntdll!NtOpenProcess\"] }",
        );
        let err = validate(&parse(&yaml)).expect_err("proxy on multi-stage must fail");
        assert!(err.to_string().contains("multi-stage"), "{err}");
    }
}
