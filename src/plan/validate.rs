//! Semantic validation of the already-deserialized plan.
//!
//! Unlike parsing (which validates structure and types), here we check business
//! rules that cannot be expressed naturally with `serde`: empty values, invalid
//! combinations, supported architectures, the terminal-step rule, etc. The flat
//! `runtime:` list is resolved first ([`super::steps::resolve`]) so every rule
//! runs against concrete steps, with the payload each Execution step loads
//! pinned down.

use crate::engine::api_resolution::{ApiResolutionConfig, ApiResolutionMode, Unmatched};
use crate::engine::obfuscation::StringsConfig;
use crate::engine::syscalls::{SyscallsConfig, SyscallsMode};
use crate::error::{PackerError, Result};
use crate::techniques::{Capability, Stability, TechniqueKind};

use super::schema::{Arch, DllEntry, OutputKind, PayloadFormat, Plan, StubPlan, Subsystem};
use super::steps::{self, ResolvedPayload, ResolvedStep};

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

    let steps = steps::resolve(plan)?;
    validate_terminal(&steps)?;
    validate_output(plan, &steps)?;

    for step in &steps {
        if let Some(payload) = &step.payload {
            if payload.plan.source.trim().is_empty() {
                return Err(PackerError::Validation(format!(
                    "payload '{}' has an empty 'source'",
                    payload.name
                )));
            }
            validate_payload_format(step, payload)?;
            validate_payload_sha256(payload)?;
        }
        validate_capabilities(plan, step)?;
        validate_sleep_obfuscation(step)?;
        validate_injection_target(plan, step)?;
    }

    validate_api_resolution(plan, &steps)?;

    Ok(())
}

/// The *terminal-step* rule.
///
/// `reflective_loading` of a PE executable and `dotnet_hosting` hand the whole
/// process to the payload (a normal `mainCRTStartup` calls `ExitProcess`), so
/// such a step can only be the last one — otherwise the following steps would
/// never run.
fn validate_terminal(steps: &[ResolvedStep]) -> Result<()> {
    for (position, step) in steps.iter().enumerate() {
        if position + 1 == steps.len() {
            break;
        }
        if let Some(technique) = terminal_technique(step) {
            return Err(PackerError::Validation(format!(
                "step {} ('{}') runs '{technique}', which does not return control to the loader, so \
                 the later step(s) would never run. Move it to the end of 'runtime:', or use \
                 'process_hollowing' (a separate process) or address it as a cooperative payload.",
                step.index, step.label
            )));
        }
    }
    Ok(())
}

/// The execution technique that makes a step terminal, if any.
///
/// `reflective_loading` is terminal only for a PE *executable* (`format: pe`): a
/// reflectively loaded DLL returns (its entry point is `DllMain`), and raw
/// shellcode returns if it is cooperative. `dotnet_hosting` hosts the CLR in the
/// stub's process, so a managed `Main` that exits ends the process.
fn terminal_technique(step: &ResolvedStep) -> Option<&'static str> {
    match &step.technique {
        TechniqueKind::DotnetHosting { .. } => Some("dotnet_hosting"),
        TechniqueKind::ReflectiveLoading { .. } => {
            let format = step
                .payload
                .as_ref()
                .map_or(PayloadFormat::Pe, |payload| payload.plan.format);
            (format == PayloadFormat::Pe).then_some("reflective_loading (a PE executable)")
        }
        _ => None,
    }
}

/// Validates `build.output.kind`/`entry` and their couplings.
///
/// The chain, the techniques and the injected blocks are identical in both
/// modes; what changes is who owns the process. Everything a standalone
/// executable may do that a *host-loaded* DLL may not — kill the process, name
/// itself, carry a process-scoped manifest — is rejected here. See
/// `docs/design/dll-output.md` section 5.
fn validate_output(plan: &Plan, steps: &[ResolvedStep]) -> Result<()> {
    let output = &plan.build.output;

    if output.kind == OutputKind::Exe {
        if output.entry != DllEntry::Auto {
            return Err(PackerError::Validation(format!(
                "build.output.entry is '{}' but build.output.kind is 'exe': the entry only applies \
                 to a DLL; an executable starts at its `main`",
                output.entry.label()
            )));
        }
        return Ok(());
    }

    if output.subsystem == Subsystem::Windows {
        return Err(PackerError::Validation(
            "build.output.subsystem is 'windows' but build.output.kind is 'dll': a DLL has no \
             subsystem — the host process owns its own (and UAC/DPI awareness is per process)"
                .to_string(),
        ));
    }

    if output
        .resources
        .as_ref()
        .is_some_and(|resources| resources.manifest.is_some())
    {
        return Err(PackerError::Validation(
            "build.output.resources.manifest is set but build.output.kind is 'dll': an embedded \
             application manifest is process-scoped (UAC, DPI awareness) and a DLL cannot express \
             it — remove it for a DLL build"
                .to_string(),
        ));
    }

    if plan.build.stub.path.is_some() {
        return Err(PackerError::Validation(
            "build.stub.path is set but build.output.kind is 'dll': the custom-stub contract is a \
             `fn main()`, which a DLL does not have. Use the builtin stub (a `$ENTRY_BLOCK$` \
             contract is a documented extension, not implemented yet)"
                .to_string(),
        ));
    }

    if let DllEntry::Export(name) = &output.entry {
        validate_export_name(name)?;
    }

    for step in steps {
        if matches!(&step.technique, TechniqueKind::SelfDeletion { .. }) {
            return Err(PackerError::Validation(format!(
                "step {} ('{}') is 'self_deletion' and build.output.kind is 'dll': the technique \
                 resolves the *running image* (`GetModuleFileNameW(NULL)`), which in a DLL build is \
                 the host (`java.exe`, `python.exe`, ...) — it would rename or delete the \
                 interpreter. A mapped DLL cannot be deleted while it is loaded anyway",
                step.index, step.label
            )));
        }
        if matches!(&step.technique, TechniqueKind::SleepObfuscation { .. }) {
            return Err(PackerError::Validation(format!(
                "step {} ('{}') is 'sleep_obfuscation' and build.output.kind is 'dll': the technique \
                 encrypts the *running image* (`GetModuleHandleA(NULL)` + `SizeOfImage`), which in a \
                 DLL build is the host's image (`java.exe`, `python.exe`) — the host's other threads \
                 keep running that code. It would also miss the payload, which lives in its own \
                 allocation outside the host image",
                step.index, step.label
            )));
        }
        if let TechniqueKind::Bouncer { params } = &step.technique {
            if params.on_fail == crate::techniques::bouncer::OnFail::Exit {
                return Err(PackerError::Validation(format!(
                    "step {} ('{}') is 'bouncer' with `on_fail: exit` and build.output.kind is \
                     'dll': `std::process::exit` would kill the host process. Use `on_fail: \
                     silent`",
                    step.index, step.label
                )));
            }
        }
    }

    Ok(())
}

/// The plain export a `kind: dll` build declares must be a C identifier and must
/// not collide with the entry points the build itself emits.
fn validate_export_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(PackerError::Validation(
            "build.output.entry declares an empty export name (`export:`) — name the function hosts \
             will call, e.g. `export:Run`"
                .to_string(),
        ));
    }
    let starts_well = name
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_');
    if !starts_well || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(PackerError::Validation(format!(
            "build.output.entry export name '{name}' is not a valid function name; use letters, \
             digits and underscores, starting with a letter or an underscore"
        )));
    }
    if matches!(name, "DllMain" | "JNI_OnLoad") {
        return Err(PackerError::Validation(format!(
            "build.output.entry export name '{name}' collides with an entry point the build already \
             emits; pick another name"
        )));
    }
    Ok(())
}

/// Non-fatal advisories produced by validation.
///
/// These do not reject a plan (unlike [`validate`]); the build prints them as
/// warnings. Today they cover a `bouncer` gate with no check declared (a no-op,
/// almost certainly not intended), a `living_off_the_land` binary outside the
/// proxy-execution catalogue, the debug build, whose whole point is to trade
/// evasion for observability and whose artifact is therefore never for delivery,
/// and `api_resolution.unmatched: abort`, a strict allowlist that fails the load
/// on the first import outside the catalogue.
pub fn advisories(plan: &Plan) -> Vec<String> {
    let mut warnings = Vec::new();
    let steps = steps::resolve(plan).unwrap_or_default();
    let mut has_anti_debug = false;
    // `unhook_ntdll` restores ntdll's `.text` from a clean copy, so a `patch_etw`
    // step before it (which patches `EtwEventWrite`, also in ntdll's `.text`) is
    // silently undone. The order is the fix, so the warning names it.
    let mut patched_ntdll_text = false;

    for step in &steps {
        match &step.technique {
            TechniqueKind::Bouncer { params } if params.is_noop() => {
                warnings.push(
                    "bouncer: no check field is declared, so the technique is a no-op and will \
                     never abort the pipeline"
                        .to_string(),
                );
            }
            TechniqueKind::PatchEtw { .. } => patched_ntdll_text = true,
            TechniqueKind::UnhookNtdll { .. } if patched_ntdll_text => {
                warnings.push(format!(
                    "step {}: 'unhook_ntdll' restores ntdll's .text from disk, which undoes the \
                     'patch_etw' step before it; put 'unhook_ntdll' first",
                    step.index
                ));
            }
            TechniqueKind::LivingOffTheLand { params } => {
                if !steps::is_known_lolbin(&params.binary) {
                    warnings.push(format!(
                        "step {}: '{}' is not a known living-off-the-land binary; the step still \
                         runs it, but a signed system binary (certutil, rundll32, ...) is the \
                         usual choice for proxy execution",
                        step.index, params.binary
                    ));
                }
            }
            TechniqueKind::AntiDebug { .. } => has_anti_debug = true,
            // Stack spoofing rewrites the trampoline the `mode: indirect` layer
            // emits; under `mode: none` that trampoline does not exist, so the
            // technique silently does nothing.
            TechniqueKind::StackSpoofing { .. }
                if SyscallsConfig::from_yaml(plan.build.stub.syscalls.as_ref())
                    .map(|config| config.mode != SyscallsMode::Indirect)
                    .unwrap_or(true) =>
            {
                warnings.push(format!(
                    "step {}: 'stack_spoofing' only affects the indirect syscall layer, but \
                     build.stub.syscalls.mode is not 'indirect' (or the runtime uses no syscalls at \
                     all), so it is a no-op",
                    step.index
                ));
            }
            _ => {}
        }
    }

    // A technique the registry marks as not finished must be visible at build
    // time: the artifact would be missing part of (or all of) the work the plan
    // asks for, and nothing else in the build says so.
    for step in &steps {
        if let Some(def) = crate::techniques::find(step.technique.name()) {
            if def.stability == Stability::Unimplemented {
                warnings.push(format!(
                    "step {}: technique '{}' is marked 'unimplemented' in the registry — its \
                     implementation is not finished, so the artifact will not do everything the \
                     plan asks for",
                    step.index, def.name
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
        if has_anti_debug {
            warnings.push(
                "build.stub.debug is enabled but `anti_debug` is in the runtime: it may abort \
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

    if plan.build.output.kind == OutputKind::Dll {
        warnings.extend(dll_advisories(plan, &steps));
    }
    warnings
}

/// The advisories specific to a host-loaded DLL build.
///
/// None of these are errors: the artifact works, but each one describes a way it
/// is louder than it has to be (`docs/design/dll-output.md` section 5).
fn dll_advisories(plan: &Plan, steps: &[ResolvedStep]) -> Vec<String> {
    let mut warnings = Vec::new();
    let output = &plan.build.output;

    if output.entry == DllEntry::Auto {
        warnings.push(
            "build.output.entry is 'auto': the export table advertises `JNI_OnLoad` next to a plain \
             chain-runner export, which no ordinary DLL does; a host-specific entry is less \
             conspicuous"
                .to_string(),
        );
    }

    if output.sign.is_none() {
        warnings.push(
            "build.output.kind is 'dll' without `build.output.sign`: the host loads the file with \
             the image loader, so it is scanned on load, and an unsigned module inside a signed \
             host process is what an EDR reports first"
                .to_string(),
        );
    }

    if output.arch == Arch::X86 {
        warnings.push(
            "build.output.kind is 'dll' with arch 'x86': the host and the payload must be 32-bit \
             too, the export follows the stdcall four-argument shape (only a caller that declares \
             it is safe), and indirect syscalls stay x64-only"
                .to_string(),
        );
    }

    let extension = output.path.extension().and_then(|ext| ext.to_str());
    if !extension.is_some_and(|ext| ext.eq_ignore_ascii_case("dll")) {
        warnings.push(
            "build.output.kind is 'dll' but the output path does not end in `.dll`: the OS loader \
             and most hosts expect the extension (a different one is a deliberate choice)"
                .to_string(),
        );
    }

    for step in steps {
        if matches!(&step.technique, TechniqueKind::PatchAmsi { .. }) {
            warnings.push(format!(
                "step {}: 'patch_amsi' loads `amsi.dll` when it is not already loaded, and a DLL \
                 host (`java.exe`, `python.exe`) usually has none — the step would bring the \
                 scanner into the process",
                step.index
            ));
        }
    }

    if output.entry.export_name().is_some() {
        for step in steps {
            if let Some(technique) = terminal_technique(step) {
                warnings.push(format!(
                    "step {}: '{technique}' does not return control to the loader, and the DLL's \
                     plain export waits for the chain: the caller's thread is held for the \
                     payload's lifetime (that is what keeps `rundll32` alive)",
                    step.index
                ));
                break;
            }
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
/// payload has an import table to rewrite.
fn validate_api_resolution(plan: &Plan, steps: &[ResolvedStep]) -> Result<()> {
    let config = ApiResolutionConfig::from_yaml(plan.build.stub.api_resolution.as_ref())?;
    if config.mode != ApiResolutionMode::Proxy {
        return Ok(());
    }

    // The proxies are functions in the loader image with loader-wide state, so
    // the mode is meaningful for exactly one payload load.
    let executions: Vec<&ResolvedStep> = steps.iter().filter(|step| step.is_execution()).collect();
    if executions.len() != 1 {
        return Err(PackerError::Validation(
            "build.stub.api_resolution.mode 'proxy' is loader-wide (it rewrites the loader's own \
             IAT), so it is not supported when the runtime loads more than one payload: use a \
             single Execution step"
                .to_string(),
        ));
    }
    let step = executions[0];

    let syscalls = SyscallsConfig::from_yaml(plan.build.stub.syscalls.as_ref())?;
    if syscalls.mode != SyscallsMode::Indirect {
        return Err(PackerError::Validation(
            "build.stub.api_resolution.mode 'proxy' requires 'build.stub.syscalls.mode: indirect': \
             the re-routed calls would otherwise fall back to the Win32 APIs and the intercepted \
             imports would reappear in the stub's IAT"
                .to_string(),
        ));
    }

    let Some(payload) = &step.payload else {
        return Err(PackerError::Validation(
            "build.stub.api_resolution.mode 'proxy' needs a payload with an import table \
             (format: pe or dll)"
                .to_string(),
        ));
    };
    if !payload.plan.format.is_pe_image() {
        return Err(PackerError::Validation(format!(
            "build.stub.api_resolution.mode 'proxy' requires a payload with an import table \
             (format: pe or dll), not '{}'",
            payload.plan.format.label()
        )));
    }

    // The generated proxies are ordinary functions in the loader image, with
    // their own data (obfuscated names, the SSN table, the syscall trampoline).
    // A hollowed payload runs in a *different* process, which has none of that,
    // so its IAT there can only point at the real exports: the mode cannot apply.
    // Failing loudly beats silently not proxying. See Phase E in the doc.
    if matches!(step.technique, TechniqueKind::ProcessHollowing { .. }) {
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

/// Validates a payload's format against the Execution technique that loads it.
///
/// Two rules that `serde` cannot express: `export` only makes sense for a DLL,
/// and `process_hollowing` can only run a PE executable today (it replaces a
/// suspended process's image; a DLL has no process entry point to run and raw
/// shellcode has no image at all). A managed assembly is neither mapped nor
/// hollowed: `dotnet_hosting` hosts the CLR and loads its bytes.
fn validate_payload_format(step: &ResolvedStep, payload: &ResolvedPayload) -> Result<()> {
    let format = payload.plan.format;
    if let Some(export) = &payload.plan.export {
        if format != PayloadFormat::Dll {
            return Err(PackerError::Validation(format!(
                "payload '{}' declares 'export' but its format is '{}': 'export' only applies to \
                 'format: dll'",
                payload.name,
                format.label()
            )));
        }
        if export.trim().is_empty() {
            return Err(PackerError::Validation(format!(
                "payload '{}' has an empty 'export'",
                payload.name
            )));
        }
    }

    let hosts_the_clr = matches!(step.technique, TechniqueKind::DotnetHosting { .. });
    if format == PayloadFormat::Dotnet && !hosts_the_clr {
        return Err(PackerError::Validation(format!(
            "payload '{}' has 'format: dotnet', which needs 'technique: dotnet_hosting' (this step \
             runs '{}', which does not run a managed assembly)",
            payload.name,
            step.technique.name()
        )));
    }
    if format != PayloadFormat::Dotnet && hosts_the_clr {
        return Err(PackerError::Validation(format!(
            "'technique: dotnet_hosting' (step {}) needs 'format: dotnet'; payload '{}' is '{}'",
            step.index,
            payload.name,
            format.label()
        )));
    }

    if format != PayloadFormat::Pe
        && matches!(step.technique, TechniqueKind::ProcessHollowing { .. })
    {
        return Err(PackerError::Validation(format!(
            "payload '{}' has 'format: {}', which is not supported by process_hollowing yet: it \
             only runs 'format: pe'. Use reflective_loading, which runs pe, dll and shellcode \
             in-process.",
            payload.name,
            format.label()
        )));
    }

    if format != PayloadFormat::Pe && matches!(step.technique, TechniqueKind::PeInjection { .. }) {
        return Err(PackerError::Validation(format!(
            "payload '{}' has 'format: {}', which is not supported by pe_injection: it maps a full \
             PE image into the target. Use 'format: pe', or reflective_loading for dll/shellcode \
             in-process.",
            payload.name,
            format.label()
        )));
    }

    // The in-process runners below enter the payload as flat position-
    // independent code: they have no image mapper, so a PE/DLL has no entry
    // point to call and a managed assembly no CRL to host. (A `dotnet` payload
    // without `dotnet_hosting` is rejected above; a `dotnet` payload with one is
    // rejected here because none of the three is `dotnet_hosting`.)
    let shellcode_only = match &step.technique {
        TechniqueKind::ExecutionCallbacks { .. } => Some("execution_callbacks"),
        TechniqueKind::ModuleStomping { .. } => Some("module_stomping"),
        TechniqueKind::EarlyBird { .. } => Some("early_bird"),
        TechniqueKind::Fibers { .. } => Some("fibers"),
        TechniqueKind::ThreadHijacking { .. } => Some("thread_hijacking"),
        _ => None,
    };
    if let Some(technique) = shellcode_only {
        if format != PayloadFormat::Shellcode {
            return Err(PackerError::Validation(format!(
                "payload '{}' has 'format: {}', which is not supported by {technique}: it runs \
                 raw position-independent code ('format: shellcode'). Use reflective_loading for \
                 pe/dll payloads and dotnet_hosting for a managed assembly.",
                payload.name,
                format.label()
            )));
        }
    }

    Ok(())
}

/// Rejects a payload `sha256` that is not exactly 64 hex characters.
///
/// Catching a malformed pin here gives a clear message instead of a confusing
/// "payload mismatch" at build time.
fn validate_payload_sha256(payload: &ResolvedPayload) -> Result<()> {
    let Some(hash) = payload.plan.sha256.as_deref() else {
        return Ok(());
    };
    let hash = hash.trim();
    if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(PackerError::Validation(format!(
            "payload '{}' sha256 must be 64 hex characters (got '{hash}')",
            payload.name
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
fn validate_capabilities(plan: &Plan, step: &ResolvedStep) -> Result<()> {
    let arch = plan.build.output.arch;
    let required = match arch {
        Arch::X64 => Capability::WindowsX64,
        Arch::X86 => Capability::WindowsX86,
    };
    let Some(def) = crate::techniques::find(step.technique.name()) else {
        return Ok(());
    };
    if !def.requires.contains(&required) {
        return Err(PackerError::Validation(format!(
            "step {}: technique '{}' does not support build.output.arch '{}' yet: it requires {}; \
             the packer can compile an {} stub, but this technique has no {} fragment",
            step.index,
            def.name,
            arch.label(),
            capabilities_label(def.requires),
            arch.label(),
            arch.label()
        )));
    }
    Ok(())
}

/// Rejects an injection target whose image cannot run in the stub's process.
///
/// The techniques that spawn their own target (`process_hollowing`,
/// `early_bird`, `pe_injection`) must spawn one of the stub's own architecture:
/// an x86 stub cannot inject into a 64-bit `svchost.exe` and vice versa. When
/// the target is a local file the check is exact; a target that does not resolve
/// locally (`$arg.N$`, a remote path, a missing file) is left to run time, where
/// the technique fails with its own error.
///
/// `C:\Windows\System32` is redirected to `SysWOW64` for a 32-bit process, so
/// the path is mapped the way WOW64 would resolve it before the file is read —
/// the default `System32\svchost.exe` is a 64-bit image on a 64-bit host but
/// the x86 stub actually gets the 32-bit one.
fn validate_injection_target(plan: &Plan, step: &ResolvedStep) -> Result<()> {
    let Some((technique, target)) = injection_target(step) else {
        return Ok(());
    };
    let arch = plan.build.output.arch;
    let Some(path) = wow64_resolve(target, arch) else {
        return Ok(());
    };
    let Ok(bytes) = std::fs::read(&path) else {
        // Not a local file (a runtime argument, a remote path, or a target
        // that only exists on the host): nothing to check here.
        return Ok(());
    };
    let Ok(info) = crate::engine::pe::parse(&bytes) else {
        return Ok(());
    };
    if info.arch() != Some(arch) {
        return Err(PackerError::Validation(format!(
            "{technique} target '{target}' is a {} image but build.output.arch is '{}': the target must match the stub's architecture ({target} resolves to '{}' under WOW64)",
            info.arch().map(|a| a.label()).unwrap_or("non-PE"),
            arch.label(),
            path.display()
        )));
    }
    Ok(())
}

/// The spawn target of a technique that creates its own process, with the
/// technique's name for the diagnostics.
fn injection_target(step: &ResolvedStep) -> Option<(&'static str, &str)> {
    match &step.technique {
        TechniqueKind::ProcessHollowing { params } => Some(("process_hollowing", &params.target)),
        TechniqueKind::EarlyBird { params } => Some(("early_bird", &params.target)),
        TechniqueKind::PeInjection { params } => Some(("pe_injection", &params.target)),
        // The hijack target is an image name of a *running* process (or an
        // explicit pid), so the architecture check only applies when it names a
        // local file.
        TechniqueKind::ThreadHijacking { params } if params.pid.is_none() => {
            Some(("thread_hijacking", &params.target))
        }
        _ => None,
    }
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
fn validate_sleep_obfuscation(step: &ResolvedStep) -> Result<()> {
    let TechniqueKind::SleepObfuscation { params } = &step.technique else {
        return Ok(());
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
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(yaml: &str) -> Plan {
        serde_yml::from_str(yaml).expect("valid YAML")
    }

    /// A minimal valid plan, with optional extra `build` / `output` blocks.
    fn plan_yaml(build_extra: &str, out_extra: &str, runtime: &str) -> String {
        format!(
            "schema: 6\nname: t\nbuild:\n  crypto: {{ algo: xchacha20poly1305, key: random }}\n  payloads:\n    p: {{ source: ./p.exe, format: pe }}\n{build_extra}  output:\n    path: ./dist/o.exe\n    arch: x64\n    strip: true\n    trim_paths: all\n{out_extra}runtime:\n{runtime}"
        )
    }

    /// A minimal valid plan with the given runtime body and one payload.
    fn with_runtime(runtime: &str) -> String {
        plan_yaml("", "", runtime)
    }

    fn with_stub(stub: &str) -> String {
        plan_yaml(
            &format!("  stub:\n{stub}\n"),
            "",
            "  - technique: reflective_loading\n",
        )
    }

    fn with_sign(sign: &str) -> String {
        plan_yaml(
            "",
            &format!("    sign:\n{sign}\n"),
            "  - technique: reflective_loading\n",
        )
    }

    #[test]
    fn accepts_a_minimal_plan() {
        let plan = parse(&with_runtime("  - technique: reflective_loading\n"));
        validate(&plan).expect("valid");
    }

    #[test]
    fn rejects_an_empty_name() {
        let yaml =
            with_runtime("  - technique: reflective_loading\n").replace("name: t", "name: ' '");
        assert!(validate(&parse(&yaml)).is_err());
    }

    #[test]
    fn rejects_an_empty_output_path() {
        let yaml = with_runtime("  - technique: reflective_loading\n").replace("./dist/o.exe", "");
        assert!(validate(&parse(&yaml)).is_err());
    }

    #[test]
    fn accepts_two_execution_techniques_as_separate_steps() {
        // In the flat model two execution techniques are separate steps with
        // their own payloads, so they do not conflict.
        let plan = parse(
            "schema: 6\nname: t\nbuild:\n  crypto: { algo: xchacha20poly1305, key: random }\n  payloads:\n    a: { source: ./a.bin, format: shellcode }\n    b: { source: ./b.exe, format: pe }\n  output: { path: ./dist/o.exe, arch: x64, strip: true, trim_paths: all }\nruntime:\n  - technique: reflective_loading\n    params: { payload: a }\n  - technique: process_hollowing\n    params: { payload: b, target: \"C:\\\\x.exe\" }\n",
        );
        validate(&plan).expect("valid");
    }

    #[test]
    fn accepts_a_preparation_then_an_execution() {
        let plan = parse(&with_runtime(
            "  - technique: patch_amsi\n  - technique: reflective_loading\n",
        ));
        validate(&plan).expect("valid");
    }

    #[test]
    fn accepts_several_execution_steps() {
        let plan = parse(
            "schema: 6\nname: t\nbuild:\n  crypto: { algo: xchacha20poly1305, key: random }\n  payloads:\n    a: { source: ./a.bin, format: shellcode }\n    b: { source: ./b.exe, format: pe }\n  output: { path: ./dist/o.exe, arch: x64, strip: true, trim_paths: all }\nruntime:\n  - technique: reflective_loading\n    params: { payload: a }\n  - technique: sleep\n    params: { ms: 5 }\n  - technique: process_hollowing\n    params: { payload: b, target: \"C:\\\\x.exe\" }\n",
        );
        validate(&plan).expect("valid");
    }

    #[test]
    fn rejects_a_terminal_step_before_the_last_one() {
        let plan = parse(
            "schema: 6\nname: t\nbuild:\n  crypto: { algo: xchacha20poly1305, key: random }\n  payloads:\n    a: { source: ./a.bin, format: shellcode }\n    b: { source: ./b.exe, format: pe }\n  output: { path: ./dist/o.exe, arch: x64, strip: true, trim_paths: all }\nruntime:\n  - technique: reflective_loading\n    params: { payload: b }\n  - technique: reflective_loading\n    params: { payload: a }\n",
        );
        let err = validate(&plan).expect_err("terminal not last");
        assert!(
            err.to_string().contains("terminal") || err.to_string().contains("later"),
            "unclear: {err}"
        );
    }

    #[test]
    fn accepts_a_terminal_step_at_the_end() {
        let plan = parse(
            "schema: 6\nname: t\nbuild:\n  crypto: { algo: xchacha20poly1305, key: random }\n  payloads:\n    a: { source: ./a.bin, format: shellcode }\n    b: { source: ./b.exe, format: pe }\n  output: { path: ./dist/o.exe, arch: x64, strip: true, trim_paths: all }\nruntime:\n  - technique: reflective_loading\n    params: { payload: a }\n  - technique: reflective_loading\n    params: { payload: b }\n",
        );
        validate(&plan).expect("valid");
    }

    #[test]
    fn rejects_shellcode_with_process_hollowing() {
        let plan = parse(
            "schema: 6\nname: t\nbuild:\n  crypto: { algo: xchacha20poly1305, key: random }\n  payloads:\n    a: { source: ./a.bin, format: shellcode }\n  output: { path: ./dist/o.exe, arch: x64, strip: true, trim_paths: all }\nruntime:\n  - technique: process_hollowing\n    params: { payload: a, target: \"C:\\\\x.exe\" }\n",
        );
        let err = validate(&plan).expect_err("shellcode hollowing");
        assert!(
            err.to_string().contains("process_hollowing"),
            "unclear: {err}"
        );
    }

    #[test]
    fn rejects_a_dll_with_process_hollowing() {
        let plan = parse(
            "schema: 6\nname: t\nbuild:\n  crypto: { algo: xchacha20poly1305, key: random }\n  payloads:\n    a: { source: ./a.dll, format: dll }\n  output: { path: ./dist/o.exe, arch: x64, strip: true, trim_paths: all }\nruntime:\n  - technique: process_hollowing\n    params: { payload: a, target: \"C:\\\\x.exe\" }\n",
        );
        assert!(validate(&plan).is_err());
    }

    /// The three in-process runners execute raw code, so they take shellcode.
    #[test]
    fn accepts_shellcode_with_the_in_process_runners() {
        for technique in ["execution_callbacks", "module_stomping", "fibers"] {
            let plan = parse(&format!(
                "schema: 6\nname: t\nbuild:\n  crypto: {{ algo: xchacha20poly1305, key: random }}\n  payloads:\n    a: {{ source: ./a.bin, format: shellcode }}\n  output: {{ path: ./dist/o.exe, arch: x64, strip: true, trim_paths: all }}\nruntime:\n  - technique: {technique}\n    params: {{ payload: a }}\n"
            ));
            validate(&plan).unwrap_or_else(|e| panic!("{technique}: {e}"));
        }
    }

    #[test]
    fn rejects_a_pe_payload_with_the_in_process_runners() {
        for technique in ["execution_callbacks", "module_stomping", "fibers"] {
            let plan = parse(&format!(
                "schema: 6\nname: t\nbuild:\n  crypto: {{ algo: xchacha20poly1305, key: random }}\n  payloads:\n    a: {{ source: ./a.exe, format: pe }}\n  output: {{ path: ./dist/o.exe, arch: x64, strip: true, trim_paths: all }}\nruntime:\n  - technique: {technique}\n    params: {{ payload: a }}\n"
            ));
            let err = validate(&plan).expect_err("a PE needs an image mapper");
            assert!(err.to_string().contains(technique), "unclear: {err}");
        }
    }

    #[test]
    fn rejects_a_shellcode_payload_with_pe_injection() {
        let plan = parse(
            "schema: 6\nname: t\nbuild:\n  crypto: { algo: xchacha20poly1305, key: random }\n  payloads:\n    a: { source: ./a.bin, format: shellcode }\n  output: { path: ./dist/o.exe, arch: x64, strip: true, trim_paths: all }\nruntime:\n  - technique: pe_injection\n    params: { payload: a, target: \"C:\\\\x.exe\" }\n",
        );
        let err = validate(&plan).expect_err("shellcode has no image to map");
        assert!(err.to_string().contains("pe_injection"), "unclear: {err}");
    }

    #[test]
    fn accepts_a_pe_payload_with_pe_injection() {
        let plan = parse(
            "schema: 6\nname: t\nbuild:\n  crypto: { algo: xchacha20poly1305, key: random }\n  payloads:\n    a: { source: ./a.exe, format: pe }\n  output: { path: ./dist/o.exe, arch: x64, strip: true, trim_paths: all }\nruntime:\n  - technique: pe_injection\n    params: { payload: a, target: \"C:\\\\x.exe\" }\n",
        );
        validate(&plan).expect("pe_injection maps a PE image");
    }

    #[test]
    fn accepts_shellcode_with_early_bird() {
        let plan = parse(
            "schema: 6\nname: t\nbuild:\n  crypto: { algo: xchacha20poly1305, key: random }\n  payloads:\n    a: { source: ./a.bin, format: shellcode }\n  output: { path: ./dist/o.exe, arch: x64, strip: true, trim_paths: all }\nruntime:\n  - technique: early_bird\n    params: { payload: a, target: \"C:\\\\x.exe\" }\n",
        );
        validate(&plan).expect("early_bird runs shellcode");
    }

    #[test]
    fn rejects_a_pe_payload_with_early_bird() {
        let plan = parse(
            "schema: 6\nname: t\nbuild:\n  crypto: { algo: xchacha20poly1305, key: random }\n  payloads:\n    a: { source: ./a.exe, format: pe }\n  output: { path: ./dist/o.exe, arch: x64, strip: true, trim_paths: all }\nruntime:\n  - technique: early_bird\n    params: { payload: a, target: \"C:\\\\x.exe\" }\n",
        );
        let err = validate(&plan).expect_err("early_bird queues raw code");
        assert!(err.to_string().contains("early_bird"), "unclear: {err}");
    }

    /// The architecture check covers every technique that spawns its own target.
    #[test]
    fn rejects_an_early_bird_target_of_the_wrong_architecture() {
        let target = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("minimal_x86.exe");
        if !target.is_file() {
            return;
        }
        let plan = parse(&format!(
            "schema: 6\nname: t\nbuild:\n  crypto: {{ algo: xchacha20poly1305, key: random }}\n  payloads:\n    a: {{ source: ./a.bin, format: shellcode }}\n  output: {{ path: ./dist/o.exe, arch: x64, strip: true, trim_paths: all }}\nruntime:\n  - technique: early_bird\n    params: {{ payload: a, target: '{}' }}\n",
            target.display()
        ));
        let err = validate(&plan).expect_err("wrong-arch target");
        assert!(err.to_string().contains("early_bird"), "unclear: {err}");
        assert!(err.to_string().contains("architecture"), "unclear: {err}");
    }

    #[test]
    fn rejects_a_dll_payload_with_fibers() {
        let plan = parse(
            "schema: 6\nname: t\nbuild:\n  crypto: { algo: xchacha20poly1305, key: random }\n  payloads:\n    a: { source: ./a.dll, format: dll }\n  output: { path: ./dist/o.exe, arch: x64, strip: true, trim_paths: all }\nruntime:\n  - technique: fibers\n    params: { payload: a }\n",
        );
        let err = validate(&plan).expect_err("a DLL needs an image mapper");
        assert!(err.to_string().contains("fibers"), "unclear: {err}");
    }

    #[test]
    fn accepts_a_dll_with_an_export() {
        let plan = parse(
            "schema: 6\nname: t\nbuild:\n  crypto: { algo: xchacha20poly1305, key: random }\n  payloads:\n    a: { source: ./a.dll, format: dll, export: Run }\n  output: { path: ./dist/o.exe, arch: x64, strip: true, trim_paths: all }\nruntime:\n  - technique: reflective_loading\n    params: { payload: a }\n",
        );
        validate(&plan).expect("valid");
    }

    #[test]
    fn rejects_an_export_without_the_dll_format() {
        let plan = parse(
            "schema: 6\nname: t\nbuild:\n  crypto: { algo: xchacha20poly1305, key: random }\n  payloads:\n    a: { source: ./a.exe, format: pe, export: Run }\n  output: { path: ./dist/o.exe, arch: x64, strip: true, trim_paths: all }\nruntime:\n  - technique: reflective_loading\n    params: { payload: a }\n",
        );
        let err = validate(&plan).expect_err("export on pe");
        assert!(err.to_string().contains("export"), "unclear: {err}");
    }

    #[test]
    fn rejects_an_empty_dll_export() {
        let plan = parse(
            "schema: 6\nname: t\nbuild:\n  crypto: { algo: xchacha20poly1305, key: random }\n  payloads:\n    a: { source: ./a.dll, format: dll, export: ' ' }\n  output: { path: ./dist/o.exe, arch: x64, strip: true, trim_paths: all }\nruntime:\n  - technique: reflective_loading\n    params: { payload: a }\n",
        );
        assert!(validate(&plan).is_err());
    }

    #[test]
    fn rejects_a_dotnet_payload_without_the_hosting_technique() {
        let plan = parse(
            "schema: 6\nname: t\nbuild:\n  crypto: { algo: xchacha20poly1305, key: random }\n  payloads:\n    a: { source: ./a.exe, format: dotnet }\n  output: { path: ./dist/o.exe, arch: x64, strip: true, trim_paths: all }\nruntime:\n  - technique: reflective_loading\n    params: { payload: a }\n",
        );
        let err = validate(&plan).expect_err("dotnet without hosting");
        assert!(err.to_string().contains("dotnet_hosting"), "unclear: {err}");
    }

    #[test]
    fn rejects_dotnet_hosting_without_a_dotnet_payload() {
        let plan = parse(
            "schema: 6\nname: t\nbuild:\n  crypto: { algo: xchacha20poly1305, key: random }\n  payloads:\n    a: { source: ./a.exe, format: pe }\n  output: { path: ./dist/o.exe, arch: x64, strip: true, trim_paths: all }\nruntime:\n  - technique: dotnet_hosting\n    params: { payload: a }\n",
        );
        assert!(validate(&plan).is_err());
    }

    #[test]
    fn accepts_a_valid_payload_sha256() {
        let plan = parse(
            "schema: 6\nname: t\nbuild:\n  crypto: { algo: xchacha20poly1305, key: random }\n  payloads:\n    a: { source: ./a.exe, format: pe, sha256: \"0000000000000000000000000000000000000000000000000000000000000000\" }\n  output: { path: ./dist/o.exe, arch: x64, strip: true, trim_paths: all }\nruntime:\n  - technique: reflective_loading\n    params: { payload: a }\n",
        );
        validate(&plan).expect("valid");
    }

    #[test]
    fn rejects_a_malformed_payload_sha256() {
        let plan = parse(
            "schema: 6\nname: t\nbuild:\n  crypto: { algo: xchacha20poly1305, key: random }\n  payloads:\n    a: { source: ./a.exe, format: pe, sha256: \"deadbeef\" }\n  output: { path: ./dist/o.exe, arch: x64, strip: true, trim_paths: all }\nruntime:\n  - technique: reflective_loading\n    params: { payload: a }\n",
        );
        assert!(validate(&plan).is_err());
    }

    // --- capabilities / arch ---

    #[test]
    fn rejects_a_technique_without_an_x86_fragment() {
        let plan = parse(
            "schema: 6\nname: t\nbuild:\n  crypto: { algo: xchacha20poly1305, key: random }\n  payloads:\n    a: { source: ./a.bin, format: shellcode }\n  output: { path: ./dist/o.exe, arch: x86, strip: true, trim_paths: all }\nruntime:\n  - technique: sleep_obfuscation\n  - technique: reflective_loading\n    params: { payload: a }\n",
        );
        let err = validate(&plan).expect_err("x64-only technique on x86");
        assert!(
            err.to_string().contains("sleep_obfuscation"),
            "unclear: {err}"
        );
    }

    #[test]
    fn accepts_the_x86_capable_techniques_on_x86() {
        let plan = parse(
            "schema: 6\nname: t\nbuild:\n  crypto: { algo: xchacha20poly1305, key: random }\n  payloads:\n    a: { source: ./a.bin, format: shellcode }\n  output: { path: ./dist/o.exe, arch: x86, strip: true, trim_paths: all }\nruntime:\n  - technique: patch_amsi\n  - technique: reflective_loading\n    params: { payload: a }\n",
        );
        validate(&plan).expect("valid");
    }

    #[test]
    fn rejects_indirect_syscalls_on_x86() {
        let yaml = plan_yaml(
            "  stub:\n    syscalls: { mode: indirect }\n",
            "",
            "  - technique: reflective_loading\n",
        )
        .replace("arch: x64", "arch: x86");
        let plan = parse(&yaml);
        let err = validate(&plan).expect_err("indirect on x86");
        assert!(err.to_string().contains("x64-only"), "unclear: {err}");
    }

    // --- stub / syscalls / api_resolution ---

    #[test]
    fn accepts_a_stub_with_only_syscalls() {
        let plan = parse(&with_stub("    syscalls: { mode: none }"));
        validate(&plan).expect("valid");
    }

    #[test]
    fn accepts_an_empty_stub_block() {
        let plan = parse(&with_stub("    {}"));
        validate(&plan).expect("valid");
    }

    #[test]
    fn rejects_unknown_syscalls_mode() {
        let plan = parse(&with_stub("    syscalls: { mode: teleport }"));
        assert!(validate(&plan).is_err());
    }

    #[test]
    fn proxy_requires_indirect_syscalls() {
        let plan = parse(&with_stub(
            "    syscalls: { mode: none }\n    api_resolution: { mode: proxy, apis: [\"ntdll!NtReadVirtualMemory\"] }",
        ));
        let err = validate(&plan).expect_err("proxy without indirect");
        assert!(err.to_string().contains("indirect"), "unclear: {err}");
    }

    #[test]
    fn proxy_rejects_a_shellcode_payload() {
        let plan = parse(
            "schema: 6\nname: t\nbuild:\n  crypto: { algo: xchacha20poly1305, key: random }\n  payloads:\n    a: { source: ./a.bin, format: shellcode }\n  stub:\n    syscalls: { mode: indirect }\n    api_resolution: { mode: proxy, apis: [\"ntdll!NtReadVirtualMemory\"] }\n  output: { path: ./dist/o.exe, arch: x64, strip: true, trim_paths: all }\nruntime:\n  - technique: reflective_loading\n    params: { payload: a }\n",
        );
        let err = validate(&plan).expect_err("proxy with shellcode");
        assert!(err.to_string().contains("import table"), "unclear: {err}");
    }

    #[test]
    fn proxy_rejects_process_hollowing() {
        let plan = parse(
            "schema: 6\nname: t\nbuild:\n  crypto: { algo: xchacha20poly1305, key: random }\n  payloads:\n    a: { source: ./a.exe, format: pe }\n  stub:\n    syscalls: { mode: indirect }\n    api_resolution: { mode: proxy, apis: [\"ntdll!NtReadVirtualMemory\"] }\n  output: { path: ./dist/o.exe, arch: x64, strip: true, trim_paths: all }\nruntime:\n  - technique: process_hollowing\n    params: { payload: a, target: \"C:\\\\x.exe\" }\n",
        );
        let err = validate(&plan).expect_err("proxy with hollowing");
        assert!(
            err.to_string().contains("process_hollowing"),
            "unclear: {err}"
        );
    }

    #[test]
    fn proxy_rejects_a_second_payload_load() {
        let plan = parse(
            "schema: 6\nname: t\nbuild:\n  crypto: { algo: xchacha20poly1305, key: random }\n  payloads:\n    a: { source: ./a.dll, format: dll }\n    b: { source: ./b.dll, format: dll }\n  stub:\n    syscalls: { mode: indirect }\n    api_resolution: { mode: proxy, apis: [\"ntdll!NtReadVirtualMemory\"] }\n  output: { path: ./dist/o.exe, arch: x64, strip: true, trim_paths: all }\nruntime:\n  - technique: reflective_loading\n    params: { payload: a }\n  - technique: reflective_loading\n    params: { payload: b }\n",
        );
        let err = validate(&plan).expect_err("proxy with two loads");
        assert!(err.to_string().contains("proxy"), "unclear: {err}");
    }

    // --- sign ---

    #[test]
    fn accepts_the_signing_modes() {
        for sign in [
            "      mode: none",
            "      mode: lab",
            "      mode: lab\n      subject: CN=lab",
        ] {
            validate(&parse(&with_sign(sign))).expect("valid signing");
        }
    }

    #[test]
    fn rejects_an_unknown_signing_mode() {
        assert!(validate(&parse(&with_sign("      mode: wizardry"))).is_err());
    }

    #[test]
    fn store_signing_needs_a_subject_or_thumbprint() {
        assert!(validate(&parse(&with_sign("      mode: store"))).is_err());
    }

    #[test]
    fn file_signing_needs_a_path() {
        assert!(validate(&parse(&with_sign("      mode: file"))).is_err());
    }

    #[test]
    fn rejects_a_non_http_timestamp_url() {
        let yaml = with_sign("      mode: lab\n      timestamp_url: ftp://ts");
        assert!(validate(&parse(&yaml)).is_err());
    }

    // --- hollowing target arch ---

    #[test]
    fn rejects_a_hollowing_target_of_the_wrong_architecture() {
        // The packer runs on x64 in CI; a 32-bit target on an x64 stub is wrong.
        let target = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("minimal_x86.exe");
        if !target.is_file() {
            return;
        }
        let plan = parse(&format!(
            "schema: 6\nname: t\nbuild:\n  crypto: {{ algo: xchacha20poly1305, key: random }}\n  payloads:\n    a: {{ source: ./a.exe, format: pe }}\n  output: {{ path: ./dist/o.exe, arch: x64, strip: true, trim_paths: all }}\nruntime:\n  - technique: process_hollowing\n    params: {{ payload: a, target: '{}' }}\n",
            target.display()
        ));
        let err = validate(&plan).expect_err("wrong-arch target");
        assert!(err.to_string().contains("architecture"), "unclear: {err}");
    }

    #[test]
    fn wow64_resolve_maps_the_redirected_directories() {
        assert_eq!(
            wow64_resolve(r"C:\Windows\System32\svchost.exe", Arch::X86),
            Some(std::path::PathBuf::from(r"C:\Windows\SysWOW64\svchost.exe"))
        );
        assert_eq!(wow64_resolve("relative.exe", Arch::X64), None);
        assert_eq!(wow64_resolve("$arg.0$", Arch::X64), None);
    }

    // --- sleep obfuscation ---

    #[test]
    fn accepts_sleep_obfuscation_defaults() {
        let plan = parse(&with_runtime(
            "  - technique: sleep_obfuscation\n  - technique: reflective_loading\n",
        ));
        validate(&plan).expect("valid");
    }

    #[test]
    fn rejects_unimplemented_variants() {
        let plan = parse(&with_runtime(
            "  - technique: sleep_obfuscation\n    params: { variant: foliage, sleep_ms: 100 }\n  - technique: reflective_loading\n",
        ));
        let err = validate(&plan).expect_err("foliage not implemented");
        assert!(err.to_string().contains("foliage"), "unclear: {err}");
    }

    #[test]
    fn rejects_oversized_sleep() {
        let plan = parse(&with_runtime(
            "  - technique: sleep_obfuscation\n    params: { sleep_ms: 5000000000 }\n  - technique: reflective_loading\n",
        ));
        assert!(validate(&plan).is_err());
    }

    // --- bouncer advisories ---

    /// The `unimplemented` state must surface as a build warning.
    ///
    /// The registry owns which techniques carry it, so the test follows the
    /// registry instead of naming one: when the state is used, the advisory has
    /// to fire; when nothing is marked, there is nothing to warn about.
    #[test]
    fn advises_on_an_unimplemented_technique() {
        let marked: Vec<&str> = crate::techniques::all()
            .iter()
            .filter(|def| def.stability == Stability::Unimplemented)
            .map(|def| def.name)
            .collect();

        for name in marked {
            let plan = parse(&with_runtime(&format!("  - technique: {name}\n")));
            let warnings = advisories(&plan);
            assert!(
                warnings
                    .iter()
                    .any(|w| w.contains(name) && w.contains("unimplemented")),
                "{name}: expected an 'unimplemented' advisory, got {warnings:?}"
            );
        }
    }

    #[test]
    fn advises_on_a_noop_bouncer() {
        let plan = parse(&with_runtime(
            "  - technique: bouncer\n  - technique: reflective_loading\n",
        ));
        let warnings = advisories(&plan);
        assert!(
            warnings.iter().any(|w| w.contains("no-op")),
            "expected a no-op advisory: {warnings:?}"
        );
    }

    #[test]
    fn no_advisory_when_bouncer_declares_a_check() {
        let plan = parse(&with_runtime(
            "  - technique: bouncer\n    params: { min_ram_mb: 512 }\n  - technique: reflective_loading\n",
        ));
        let warnings = advisories(&plan);
        assert!(
            !warnings.iter().any(|w| w.contains("no-op")),
            "unexpected advisory: {warnings:?}"
        );
    }

    #[test]
    fn advises_on_an_unknown_lolbin() {
        let plan = parse(&with_runtime(
            "  - technique: living_off_the_land\n    params: { binary: my_implant.exe }\n",
        ));
        let warnings = advisories(&plan);
        assert!(
            warnings.iter().any(|w| w.contains("living-off-the-land")),
            "expected a LOLBin advisory: {warnings:?}"
        );
    }

    #[test]
    fn no_lolbin_advisory_for_a_known_binary() {
        let plan = parse(&with_runtime(
            "  - technique: living_off_the_land\n    params: { binary: certutil.exe }\n",
        ));
        let warnings = advisories(&plan);
        assert!(
            !warnings.iter().any(|w| w.contains("living-off-the-land")),
            "unexpected advisory: {warnings:?}"
        );
    }

    #[test]
    fn advices_on_a_debug_build() {
        let plan = parse(&with_stub("    debug: true"));
        let warnings = advisories(&plan);
        assert!(
            warnings.iter().any(|w| w.contains("debug")),
            "expected a debug advisory: {warnings:?}"
        );
    }

    // --- host-loaded DLL output (`build.output.kind: dll`) --------------------

    /// A `kind: dll` plan; `output_extra` is inserted right after `path`/`kind`.
    fn with_dll(output_extra: &str, runtime: &str) -> String {
        format!(
            "schema: 6\nname: t\nbuild:\n  crypto: {{ algo: xchacha20poly1305, key: random }}\n  payloads:\n    p: {{ source: ./p.exe, format: pe }}\n  output:\n    path: ./dist/o.dll\n    kind: dll\n{output_extra}runtime:\n{runtime}"
        )
    }

    fn dll_runtime() -> &'static str {
        "  - technique: reflective_loading\n"
    }

    #[test]
    fn accepts_a_dll_with_a_plain_export() {
        let plan = parse(&with_dll("    entry: export:Run\n", dll_runtime()));
        validate(&plan).expect("valid");
    }

    #[test]
    fn accepts_the_default_dll_entry() {
        let plan = parse(&with_dll("", dll_runtime()));
        assert_eq!(plan.build.output.entry, DllEntry::Auto);
        assert_eq!(plan.build.output.kind, OutputKind::Dll);
        validate(&plan).expect("valid");
    }

    #[test]
    fn rejects_an_export_name_that_is_not_an_identifier() {
        let plan = parse(&with_dll("    entry: export:my-run\n", dll_runtime()));
        let err = validate(&plan).expect_err("expected a validation error");
        assert!(
            err.to_string().contains("not a valid function name"),
            "unclear error: {err}"
        );
    }

    #[test]
    fn rejects_an_empty_export_name() {
        let plan = parse(&with_dll("    entry: \"export:\"\n", dll_runtime()));
        let err = validate(&plan).expect_err("expected a validation error");
        assert!(
            err.to_string().contains("empty export name"),
            "unclear error: {err}"
        );
    }

    #[test]
    fn rejects_an_export_name_that_collides_with_a_builtin_entry() {
        let plan = parse(&with_dll("    entry: export:DllMain\n", dll_runtime()));
        let err = validate(&plan).expect_err("expected a validation error");
        assert!(err.to_string().contains("collides"), "unclear error: {err}");
    }

    #[test]
    fn rejects_a_windows_subsystem_with_a_dll() {
        let plan = parse(&with_dll("    subsystem: windows\n", dll_runtime()));
        let err = validate(&plan).expect_err("expected a validation error");
        assert!(
            err.to_string().contains("subsystem"),
            "unclear error: {err}"
        );
    }

    #[test]
    fn rejects_the_application_manifest_with_a_dll() {
        let plan = parse(&with_dll(
            "    resources:\n      manifest: {}\n",
            dll_runtime(),
        ));
        let err = validate(&plan).expect_err("expected a validation error");
        assert!(
            err.to_string().contains("process-scoped"),
            "unclear error: {err}"
        );
    }

    #[test]
    fn rejects_a_custom_stub_with_a_dll() {
        let yaml = "schema: 6\nname: t\nbuild:\n  crypto: { algo: xchacha20poly1305, key: random }\n  payloads:\n    p: { source: ./p.exe, format: pe }\n  stub:\n    path: ./s.rs\n  output:\n    path: ./dist/o.dll\n    kind: dll\nruntime:\n  - technique: reflective_loading\n";
        let plan = parse(yaml);
        let err = validate(&plan).expect_err("expected a validation error");
        assert!(
            err.to_string().contains("stub.path"),
            "unclear error: {err}"
        );
    }

    #[test]
    fn rejects_self_deletion_with_a_dll() {
        let plan = parse(&with_dll(
            "",
            "  - technique: self_deletion\n  - technique: reflective_loading\n",
        ));
        let err = validate(&plan).expect_err("expected a validation error");
        assert!(
            err.to_string().contains("self_deletion"),
            "unclear error: {err}"
        );
    }

    #[test]
    fn rejects_sleep_obfuscation_with_a_dll() {
        let plan = parse(&with_dll(
            "",
            "  - technique: sleep_obfuscation\n    params: { sleep_ms: 10 }\n  - technique: reflective_loading\n",
        ));
        let err = validate(&plan).expect_err("expected a validation error");
        assert!(
            err.to_string().contains("encrypts the *running image*"),
            "unclear error: {err}"
        );
    }

    #[test]
    fn rejects_bouncer_exit_with_a_dll() {
        let plan = parse(&with_dll(
            "",
            "  - technique: bouncer\n    params: { hostname: host, on_fail: exit }\n  - technique: reflective_loading\n",
        ));
        let err = validate(&plan).expect_err("expected a validation error");
        assert!(
            err.to_string().contains("kill the host"),
            "unclear error: {err}"
        );
    }

    #[test]
    fn rejects_an_entry_declared_on_an_executable() {
        let plan = parse(&plan_yaml("", "    entry: export:Run\n", dll_runtime()));
        let err = validate(&plan).expect_err("expected a validation error");
        assert!(
            err.to_string().contains("only applies to a DLL"),
            "unclear error: {err}"
        );
    }

    #[test]
    fn advises_on_an_auto_entry_and_an_unsigned_dll() {
        let plan = parse(&with_dll("", dll_runtime()));
        let warnings = advisories(&plan);
        assert!(
            warnings.iter().any(|w| w.contains("entry is 'auto'")),
            "expected an entry advisory: {warnings:?}"
        );
        assert!(
            warnings.iter().any(|w| w.contains("build.output.sign")),
            "expected a signing advisory: {warnings:?}"
        );
    }

    #[test]
    fn a_host_specific_signed_dll_has_no_dll_advisory() {
        let plan = parse(&with_dll(
            "    entry: export:Run\n    sign: { mode: lab }\n",
            dll_runtime(),
        ));
        let warnings = advisories(&plan);
        assert!(
            !warnings
                .iter()
                .any(|w| w.contains("entry is 'auto'") || w.contains("build.output.sign")),
            "unexpected advisory: {warnings:?}"
        );
    }

    #[test]
    fn advises_on_patch_amsi_in_a_dll_build() {
        let plan = parse(&with_dll(
            "    entry: export:Run\n    sign: { mode: lab }\n",
            "  - technique: patch_amsi\n  - technique: reflective_loading\n",
        ));
        let warnings = advisories(&plan);
        assert!(
            warnings.iter().any(|w| w.contains("patch_amsi")),
            "expected an AMSI advisory: {warnings:?}"
        );
    }

    #[test]
    fn advises_on_a_32_bit_dll() {
        let plan = parse(&with_dll(
            "    entry: export:Run\n    arch: x86\n    sign: { mode: lab }\n",
            dll_runtime(),
        ));
        let warnings = advisories(&plan);
        assert!(
            warnings.iter().any(|w| w.contains("32-bit")),
            "expected an x86 advisory: {warnings:?}"
        );
    }

    #[test]
    fn advises_on_a_dll_path_without_the_extension() {
        let yaml = "schema: 6\nname: t\nbuild:\n  crypto: { algo: xchacha20poly1305, key: random }\n  payloads:\n    p: { source: ./p.exe, format: pe }\n  output:\n    path: ./dist/o.bin\n    kind: dll\n    entry: export:Run\n    sign: { mode: lab }\nruntime:\n  - technique: reflective_loading\n";
        let plan = parse(yaml);
        let warnings = advisories(&plan);
        assert!(
            warnings.iter().any(|w| w.contains("`.dll`")),
            "expected an extension advisory: {warnings:?}"
        );
    }
}
