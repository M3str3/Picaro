//! Semantic validation of the already-deserialized configuration.
//!
//! Unlike parsing (which validates structure and types), here we check
//! business rules that cannot be expressed naturally with `serde`: empty
//! values, invalid combinations, supported architectures, etc.

use crate::engine::obfuscation::StringsConfig;
use crate::engine::syscalls::SyscallsConfig;
use crate::error::{PackerError, Result};
use crate::techniques::{category_of, Category, RuntimeStep};

use super::schema::{Arch, Config, PayloadFormat, StubConfig};

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

    validate_arch(config)?;
    validate_payload_format(config)?;
    validate_payload_sha256(config)?;
    validate_sign(config)?;
    validate_runtime(&config.runtime)?;
    validate_conflicts(&config.runtime)?;
    validate_sleep_obfuscation(&config.runtime)?;
    validate_stub(&config.build.stub)?;

    Ok(())
}

/// Non-fatal advisories produced by validation.
///
/// These do not reject a config (unlike [`validate`]); the build prints them as
/// warnings. Today they cover a `bouncer` gate with no check declared (a no-op,
/// almost certainly not intended) and the debug build, whose whole point is to
/// trade evasion for observability and whose artifact is therefore never for
/// delivery.
pub fn advisories(config: &Config) -> Vec<String> {
    let mut warnings = Vec::new();
    for step in &config.runtime {
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

    if config.build.stub.debug {
        warnings.push(
            "build.stub.debug is enabled: the artifact prints technique traces and is built \
             without symbol stripping, path trimming or optimization; it is a lab artifact and \
             must not be delivered"
                .to_string(),
        );
        if config
            .runtime
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
    warnings
}

/// Validates the stub's syscall layer and string obfuscation.
///
/// `build.stub` itself may be empty (builtin stub, default syscall mode,
/// default obfuscation); an unknown `syscalls.mode`/`syscalls.resolver` or
/// `strings.strategy` is a clear error.
fn validate_stub(stub: &StubConfig) -> Result<()> {
    SyscallsConfig::from_yaml(stub.syscalls.as_ref())?;
    StringsConfig::from_yaml(stub.strings.as_ref())?;
    Ok(())
}

/// Validates `build.payload.format` and its format-specific fields.
///
/// Two rules that `serde` cannot express: `export` only makes sense for a DLL,
/// and `process_hollowing` can only run a PE executable today (it replaces a
/// suspended process's image; a DLL has no process entry point to run and raw
/// shellcode has no image at all). Shellcode and DLL payloads are run in-process
/// by `reflective_loading`.
fn validate_payload_format(config: &Config) -> Result<()> {
    let payload = &config.build.payload;

    if let Some(export) = &payload.export {
        if payload.format != PayloadFormat::Dll {
            return Err(PackerError::Validation(format!(
                "'build.payload.export' only applies to 'format: dll' (this config declares \
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

    if payload.format != PayloadFormat::Pe {
        let execution = config
            .runtime
            .iter()
            .find(|step| category_of(step.name()) == Some(Category::Execution));
        if execution.is_some_and(|step| step.name() == "process_hollowing") {
            return Err(PackerError::Validation(format!(
                "build.payload.format '{}' is not supported by process_hollowing yet: it only runs \
                 'format: pe'. Use reflective_loading, which runs pe, dll and shellcode in-process.",
                payload.format.label()
            )));
        }
    }

    Ok(())
}

/// Rejects a `build.payload.sha256` that is not exactly 64 hex characters.
///
/// Catching a malformed pin here gives a clear message instead of a confusing
/// "payload mismatch" at build time.
fn validate_payload_sha256(config: &Config) -> Result<()> {
    let Some(hash) = config.build.payload.sha256.as_deref() else {
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
fn validate_sign(config: &Config) -> Result<()> {
    let Some(sign) = &config.build.output.sign else {
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

/// Rejects an architecture the stub toolchain cannot produce yet.
///
/// `x86` is a recognized value (the enum documents it for completeness), but the
/// stub is only generated for x64. Accepting it would silently emit an x64
/// binary from a config that asked for x86, so it fails loudly instead.
/// Integrating x86 is more work than the enum value suggests: a second target, a
/// 32-bit stub variant, and a per-architecture fragment for every technique.
fn validate_arch(config: &Config) -> Result<()> {
    if config.build.output.arch == Arch::X86 {
        return Err(PackerError::Validation(
            "build.output.arch: 'x86' is not integrated yet; the stub toolchain only targets \
             x86_64 today. Adding x86 means a 32-bit stub variant plus a per-architecture fragment \
             for every technique, so it is more work than the enum value suggests. Use 'x64'."
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

    /// A full valid config without a runtime (runtime tests append their own).
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

    /// A full valid config with a single Execution technique, used by the
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

    // --- payload formats ---

    /// Injects extra `build.payload` lines into [`NO_RUNTIME`], then appends a
    /// runtime fragment.
    fn with_payload(payload_lines: &str, runtime_yaml: &str) -> Config {
        let yaml = NO_RUNTIME.replace(
            "    source: ./payload.exe\n",
            &format!("    source: ./payload.bin\n{payload_lines}"),
        );
        parse(&(yaml + runtime_yaml))
    }

    #[test]
    fn accepts_shellcode_with_reflective_loading() {
        let config = with_payload("    format: shellcode\n", EXECUTION_YAML);
        validate(&config).expect("shellcode + reflective_loading must be valid");
    }

    #[test]
    fn accepts_a_dll_with_an_export() {
        let config = with_payload("    format: dll\n    export: Run\n", EXECUTION_YAML);
        validate(&config).expect("dll + export + reflective_loading must be valid");
    }

    #[test]
    fn rejects_shellcode_with_process_hollowing() {
        let config = with_payload(
            "    format: shellcode\n",
            "runtime:\n  - technique: process_hollowing\n",
        );
        let err = validate(&config).expect_err("hollowing can only run a PE today");
        let msg = err.to_string();
        assert!(msg.contains("process_hollowing"), "msg: {msg}");
        assert!(msg.contains("shellcode"), "msg: {msg}");
        assert!(msg.contains("reflective_loading"), "msg: {msg}");
    }

    #[test]
    fn rejects_a_dll_with_process_hollowing() {
        let config = with_payload(
            "    format: dll\n",
            "runtime:\n  - technique: process_hollowing\n",
        );
        let err = validate(&config).expect_err("hollowing cannot run a DLL");
        assert!(err.to_string().contains("process_hollowing"), "err: {err}");
    }

    #[test]
    fn rejects_an_export_without_the_dll_format() {
        let config = with_payload("    export: Run\n", EXECUTION_YAML);
        let err = validate(&config).expect_err("export only applies to dll");
        let msg = err.to_string();
        assert!(msg.contains("build.payload.export"), "msg: {msg}");
        assert!(msg.contains("format: dll"), "msg: {msg}");
    }

    #[test]
    fn rejects_an_empty_dll_export() {
        let config = with_payload("    format: dll\n    export: \"   \"\n", EXECUTION_YAML);
        let err = validate(&config).expect_err("an empty export must fail");
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
        let config = with_runtime(
            r#"
runtime:
  - technique: bouncer
  - technique: reflective_loading
"#,
        );
        validate(&config).expect("a no-op bouncer is valid, only advised against");
        let warnings = advisories(&config);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("bouncer"), "unclear: {warnings:?}");
        assert!(warnings[0].contains("no-op"), "unclear: {warnings:?}");
    }

    #[test]
    fn no_advisory_when_bouncer_declares_a_check() {
        let config = with_runtime(
            r#"
runtime:
  - technique: bouncer
    params:
      hostname: "WORKSTATION-*"
  - technique: reflective_loading
"#,
        );
        assert!(advisories(&config).is_empty());
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

    #[test]
    fn rejects_x86_until_it_is_integrated() {
        let yaml = VALID.replace("    arch: x64\n", "    arch: x86\n");
        let err = validate(&parse(&yaml)).expect_err("x86 must be rejected");
        let msg = err.to_string();
        assert!(msg.contains("build.output.arch"), "unclear error: {msg}");
        assert!(msg.contains("x86"), "unclear error: {msg}");
        assert!(msg.contains("not integrated"), "unclear error: {msg}");
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
    fn with_sign(block: &str) -> Config {
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
}
