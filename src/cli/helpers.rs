use super::*;

/// Resolves and validates a build without encrypting, compiling or writing.
///
/// `build --dry-run` / `pack --dry-run` is a pre-flight check: it loads every
/// payload (fetching a URL as a real build would), verifies each `sha256` when
/// pinned, validates the PEs and prints the resolved plan. Nothing is written, so
/// it is safe to run before committing to a build.
pub(super) fn dry_run(
    plan: &plan::Plan,
    plan_path: &Path,
    ui: &Palette,
    entropy: &BuildEntropy,
    heading: &BuildHeading,
    written_plan: Option<&Path>,
    extra_warnings: &[String],
) -> Result<()> {
    let mut deferred_warnings = extra_warnings.to_vec();
    // Show the package the build would produce, not the raw plan path.
    let mut effective_plan = plan.clone();
    let (package_dir, artifact_path) = package_paths(&plan.name, &plan.build.output.path);
    effective_plan.build.output.path = artifact_path;
    let plan = &effective_plan;
    anstream::println!("{}", ui.command_line(&heading.command, &heading.target));
    anstream::println!();
    print_plan(plan, plan_path, ui);
    anstream::println!("{}", ui.field("package", ui.target(package_dir.display())));
    anstream::println!();

    // Resource building is cheap and validates the icon/versions, so a dry run
    // can check it without touching the compiled stub.
    let resources = resolve_resources(plan, entropy);

    let steps = plan::steps::resolve(plan)?;
    let staged_payloads = stager_sources(&steps);
    for step in &steps {
        let Some(payload) = &step.payload else {
            anstream::println!(
                "{}",
                ui.detail(
                    &format!("step {}", step.index),
                    ui.dim(format!(
                        "{} {}",
                        step.technique.name(),
                        step.technique.category().label()
                    ))
                )
            );
            continue;
        };
        // A strictly staged payload is fetched at run time, so there are no bytes
        // to read or validate here (the build skips it too). A staged payload with
        // an embedded fallback is read like any embedded one.
        if staged_payloads.get(&payload.name) == Some(&steps::PayloadSource::Staged) {
            anstream::println!(
                "{}",
                ui.done(
                    &format!("step {} {}", step.index, ui.brand(step.technique.name())),
                    dotted(
                        ui,
                        &[ui.brand("staged"), ui.dim(payload.plan.format.label())]
                    )
                )
            );
            continue;
        }
        let bytes = load_source(&payload.plan.source)?;
        verify_payload_hash(&bytes, payload.plan.sha256.as_deref())?;
        let summary = inspect_payload(payload.plan.format, &bytes, plan.build.output.arch)?;
        for warning in payload_advisories(step, &summary) {
            deferred_warnings.push(warning);
        }
        let mut parts = vec![
            ui.target(describe_source(&payload.plan.source)),
            ui.dim(summary.label),
            human_size(bytes.len()),
        ];
        if let Some(export) = &payload.plan.export {
            parts.push(ui.dim(format!("export {export}")));
        }
        if staged_payloads.get(&payload.name) == Some(&steps::PayloadSource::StagedWithFallback) {
            parts.push(ui.brand("staged fallback"));
        }
        if payload.plan.sha256.is_some() {
            parts.push(ui.ok("sha256 verified"));
        }
        anstream::println!(
            "{}",
            ui.done(
                &format!("step {} {}", step.index, ui.brand(step.technique.name())),
                dotted(ui, &parts)
            )
        );
    }

    if plan.build.output.subsystem == Subsystem::Windows {
        anstream::println!("{}", ui.detail("subsystem", ui.dim("windows")));
    }
    if let Some(resources) = &resources {
        let blob = engine::resources::build(resources, 0)?;
        if !blob.is_empty() {
            anstream::println!(
                "{}",
                ui.detail("resources", ui.dim(format!("{} B", blob.len())))
            );
        }
    }

    // Signing is validated without signing: the configured inputs are checked
    // (a missing .pfx fails without needing a tool) and a backend is located
    // (the certificate itself is resolved at build time).
    let sign = resolve_sign(plan, resources.as_ref());
    if let Some(sign) = &sign {
        if sign.mode != "none" {
            if let Some(file) = &sign.file {
                if !file.is_file() {
                    return Err(error::PackerError::Validation(format!(
                        "output.sign.file '{}' does not exist",
                        file.display()
                    )));
                }
            }
            let signer = engine::signing::locate_signer(sign)?;
            anstream::println!("{}", ui.detail("sign", ui.dim(sign_label(sign))));
            anstream::println!(
                "{}",
                ui.detail(signer.label, ui.dim(signer.path.display().to_string()))
            );
        }
    }

    anstream::println!();
    match written_plan {
        Some(path) => anstream::println!(
            "{}",
            ui.warn(format!(
                "dry run: nothing was encrypted or compiled; the plan is at {}",
                path.display()
            ))
        ),
        None => anstream::println!(
            "{}",
            ui.warn("dry run: nothing was encrypted, compiled or written")
        ),
    }

    if !deferred_warnings.is_empty() {
        anstream::eprintln!();
        let width = ui::term_width();
        for warning in &deferred_warnings {
            for line in ui.warn_lines(warning, width) {
                anstream::eprintln!("{line}");
            }
        }
    }
    Ok(())
}

/// The input payload after format-specific validation.
pub(super) struct PayloadSummary {
    /// Human label for the build log (`x64 PE`, `x64 DLL`, `shellcode`).
    pub(super) label: &'static str,
    /// Parsed PE info for the PE-backed formats; `None` for shellcode.
    pub(super) pe: Option<pe::PeInfo>,
}

/// Parses and validates the payload according to its `format` and the requested
/// `arch`.
///
/// `pe`/`dll` must be a well-formed PE of the matching kind **and** the matching
/// architecture: the stub and the payload share one address space, so a 32-bit
/// payload cannot run in a 64-bit stub and vice versa. `shellcode` has no
/// headers to check, only that it is not empty, so it follows
/// `build.output.arch`. The checks run at build time so a mismatched plan fails
/// before anything is encrypted or compiled.
pub(super) fn inspect_payload(
    format: PayloadFormat,
    data: &[u8],
    arch: Arch,
) -> Result<PayloadSummary> {
    match format {
        PayloadFormat::Auto => Err(error::PackerError::Validation(
            "the payload format is still 'auto': it is resolved from the source when the plan is \
             loaded, so a plan built in memory must resolve it first"
                .to_string(),
        )),
        PayloadFormat::Shellcode => {
            if data.is_empty() {
                return Err(error::PackerError::Validation(
                    "the shellcode payload is empty".to_string(),
                ));
            }
            Ok(PayloadSummary {
                label: "shellcode",
                pe: None,
            })
        }
        PayloadFormat::Powershell => {
            if data.is_empty() {
                return Err(error::PackerError::Validation(
                    "the PowerShell payload is empty".to_string(),
                ));
            }
            if std::str::from_utf8(data).is_err() {
                return Err(error::PackerError::Validation(
                    "the PowerShell payload is not valid UTF-8 text (a .ps1/.psm1 is text; \
                     check the payload source)"
                        .to_string(),
                ));
            }
            Ok(PayloadSummary {
                label: "PowerShell script",
                pe: None,
            })
        }
        PayloadFormat::Plain => {
            // Opaque data with no execution semantics: the packer embeds and
            // encrypts it as-is and a technique (the `bouncer` decoy) writes it
            // back out. There is nothing to validate beyond "not empty".
            if data.is_empty() {
                return Err(error::PackerError::Validation(
                    "the 'plain' payload is empty".to_string(),
                ));
            }
            Ok(PayloadSummary {
                label: "plain",
                pe: None,
            })
        }
        PayloadFormat::Dotnet => {
            let info = pe::parse(data)?;
            let Some(clr) = info.com else {
                return Err(error::PackerError::Validation(
                    "a payload has 'format: dotnet' but no CLR header (data directory 14 is empty): it is a native image, so use 'format: pe'"
                        .to_string(),
                ));
            };
            // A managed assembly is portable when it is IL-only: the CLR of the
            // stub's bitness runs it. `32BITREQUIRED` pins it to a 32-bit
            // runtime, and a mixed-mode (non-IL-only) assembly to its own
            // machine.
            let portable = clr.is_il_only() && !clr.requires_32bit();
            let arch_ok = if portable {
                true
            } else if clr.requires_32bit() {
                arch == Arch::X86
            } else {
                info.arch() == Some(arch)
            };
            if !arch_ok {
                let requirement = if clr.requires_32bit() {
                    "a 32-bit runtime (COMIMAGE_FLAGS_32BITREQUIRED)"
                } else {
                    "the matching architecture (it is not IL-only)"
                };
                return Err(error::PackerError::Validation(format!(
                    "build.output.arch is '{}' but the .NET payload requires {requirement}: a managed assembly runs on the CLR of the stub's bitness",
                    arch.label()
                )));
            }
            Ok(PayloadSummary {
                label: match info.arch() {
                    Some(Arch::X64) => "x64 .NET assembly",
                    Some(Arch::X86) => "x86 .NET assembly",
                    None => ".NET assembly",
                },
                pe: Some(info),
            })
        }

        PayloadFormat::Pe | PayloadFormat::Dll => {
            let info = pe::parse(data)?;
            if info.is_dotnet() {
                return Err(error::PackerError::Validation(
                    "a payload is a .NET assembly (it has a CLR header): a managed image is not mapped as native code; use 'format: dotnet' with 'technique: dotnet_hosting', which hosts the CLR and loads the assembly from memory"
                        .to_string(),
                ));
            }
            let payload_arch = info.arch().ok_or_else(|| {
                error::PackerError::Validation(format!(
                    "unsupported PE machine 0x{:04x}: picaro packs x86 (PE32) and x64 (PE32+) images",
                    info.machine
                ))
            })?;

            if payload_arch != arch {
                return Err(error::PackerError::Validation(format!(
                    "build.output.arch is '{}' but the payload is an {} PE (machine 0x{:04x}): the \
                     stub and the payload must share an architecture",
                    arch.label(),
                    payload_arch.label(),
                    info.machine
                )));
            }
            let is_dll = pe::is_dll(info.characteristics);
            match format {
                PayloadFormat::Dll if !is_dll => {
                    return Err(error::PackerError::Validation(
                        "a payload has 'format: dll' but is an executable \
                         (IMAGE_FILE_DLL is not set)"
                            .to_string(),
                    ));
                }
                PayloadFormat::Pe if is_dll => {
                    return Err(error::PackerError::Validation(
                        "a payload has 'format: pe' but is a DLL; use 'format: dll'".to_string(),
                    ));
                }
                _ => {}
            }
            Ok(PayloadSummary {
                label: match (payload_arch, is_dll) {
                    (Arch::X64, false) => "x64 PE",
                    (Arch::X64, true) => "x64 DLL",
                    (Arch::X86, false) => "x86 PE",
                    (Arch::X86, true) => "x86 DLL",
                },
                pe: Some(info),
            })
        }
    }
}

/// Build-time advisories about an execution step's payload, from facts the
/// parser already extracted.
///
/// `reflective_loading` maps the payload into the *stub's* process and can only
/// move an image that carries base relocations: a `/FIXED` payload runs only if
/// its preferred base happens to be free, and the load fails there instead of
/// running with stale absolute addresses. That is a legitimate build (the base
/// may well be free), so this is a warning, not an error.
pub(super) fn payload_advisories(step: &ResolvedStep, summary: &PayloadSummary) -> Vec<String> {
    let mut warnings = Vec::new();
    if let TechniqueKind::ReflectiveLoading { params } = &step.technique {
        if params.erase_header {
            warnings.push(format!(
                "step {} ('{}'): params.erase_header is on; a payload whose startup code reads \
                 its own PE header (the MSVC CRT, self-inspection) can break. Test this payload \
                 with erase_header: false first",
                step.index, step.label,
            ));
        }
        if let Some(pe) = &summary.pe {
            if !pe.has_relocations {
                warnings.push(format!(
                    "step {} ('{}'): the {} payload has no base relocations (data directory 5 is \
                     empty), so it can only be mapped at its preferred base 0x{:x}; the load fails \
                     if that base is taken. Rebuild the payload without /FIXED",
                    step.index, step.label, summary.label, pe.image_base,
                ));
            }
            if let Some(template) = pe.tls_template_size {
                if template > 0 {
                    warnings.push(format!(
                        "step {} ('{}'): the {} payload carries {} bytes of static TLS data (its PE \
                         has a TLS template), which reflective_loading does not provision: any \
                         thread-local read or write stays on _tls_index 0 and aliases the host's \
                         TLS block instead of the payload's own",
                        step.index, step.label, summary.label, template,
                    ));
                }
            }
        }
    }
    warnings
}

/// Fails when the payload does not match its `sha256`.
///
/// The comparison is case-insensitive hex; the format is already validated in
/// `plan::validate`, so a mismatch here means the payload changed.
pub(super) fn verify_payload_hash(payload: &[u8], expected: Option<&str>) -> Result<()> {
    let Some(expected) = expected else {
        return Ok(());
    };
    let expected = expected.trim();
    let actual = engine::hash::sha256_hex(payload);
    if !actual.eq_ignore_ascii_case(expected) {
        return Err(error::PackerError::Validation(format!(
            "payload sha256 mismatch: plan expects {expected}, payload is {actual}"
        )));
    }
    Ok(())
}

/// Fails when a payload does not match the SHA-256 pinned by a replay record.
///
/// Relocating a payload with `--payload name=path` is allowed, but the new
/// bytes still have to match: the pin is the point of the pin.
pub(super) fn verify_reproduced_payload(
    name: &str,
    payload: &[u8],
    recorded: Option<&PayloadReproduction>,
) -> Result<()> {
    let Some(expected) = recorded.and_then(|record| record.sha256.as_deref()) else {
        return Ok(());
    };
    let actual = engine::hash::sha256_hex(payload);
    if !actual.eq_ignore_ascii_case(expected.trim()) {
        return Err(error::PackerError::Validation(format!(
            "payload '{name}' does not match the manifest pin (expected {}, got {actual}); \
             use `--payload {name}=<path>` with the original bytes",
            expected.trim()
        )));
    }
    Ok(())
}

/// The key for one payload: a plan literal, a key file, or a derivation from
/// the build entropy.
pub(super) fn key_for_payload(
    source: &KeySource,
    entropy: &BuildEntropy,
    tag: &str,
) -> Result<[u8; crypto::KEY_LEN]> {
    match source {
        KeySource::Literal(key) => Ok(*key),
        KeySource::File(path) => read_key_file(path),
        KeySource::Random => {
            Ok(entropy.derive_tagged_bytes::<{ crypto::KEY_LEN }>(Domain::PayloadKey, tag))
        }
    }
}

/// Reads a 32-byte key from `path`, raw or as 64 hex characters.
pub(super) fn read_key_file(path: &Path) -> Result<[u8; crypto::KEY_LEN]> {
    let bytes = std::fs::read(path).map_err(|source| error::PackerError::ReadInput {
        path: path.to_path_buf(),
        source,
    })?;
    if bytes.len() == crypto::KEY_LEN {
        let mut key = [0u8; crypto::KEY_LEN];
        key.copy_from_slice(&bytes);
        return Ok(key);
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| {
        error::PackerError::Validation(format!(
            "key file '{}' must be 32 raw bytes or 64 hex characters",
            path.display()
        ))
    })?;
    parse_key_hex(text)
}

/// Parses a 64-hex-character payload key.
pub(super) fn parse_key_hex(value: &str) -> Result<[u8; crypto::KEY_LEN]> {
    let bytes = hex::decode(value.trim()).map_err(|e| {
        error::PackerError::Validation(format!("invalid payload key: not hexadecimal ({e})"))
    })?;
    if bytes.len() != crypto::KEY_LEN {
        return Err(error::PackerError::Validation(format!(
            "invalid payload key: expected {} bytes ({} hex chars), got {}",
            crypto::KEY_LEN,
            crypto::KEY_LEN * 2,
            bytes.len()
        )));
    }
    let mut key = [0u8; crypto::KEY_LEN];
    key.copy_from_slice(&bytes);
    Ok(key)
}

/// Parses a 48-hex-character XChaCha20 nonce.
pub(super) fn parse_nonce_hex(value: &str) -> Result<[u8; crypto::NONCE_LEN]> {
    let bytes = hex::decode(value.trim()).map_err(|e| {
        error::PackerError::Validation(format!("invalid payload nonce: not hexadecimal ({e})"))
    })?;
    if bytes.len() != crypto::NONCE_LEN {
        return Err(error::PackerError::Validation(format!(
            "invalid payload nonce: expected {} bytes ({} hex chars), got {}",
            crypto::NONCE_LEN,
            crypto::NONCE_LEN * 2,
            bytes.len()
        )));
    }
    let mut nonce = [0u8; crypto::NONCE_LEN];
    nonce.copy_from_slice(&bytes);
    Ok(nonce)
}

/// Applies `--payload name=path` overrides to the plan copy.
pub(super) fn apply_payload_overrides(
    plan: &mut plan::Plan,
    overrides: &BTreeMap<String, PathBuf>,
) -> Result<()> {
    for (name, path) in overrides {
        let Some(payload) = plan.build.payloads.get_mut(name) else {
            return Err(error::PackerError::Usage(format!(
                "--payload names '{name}', which is not declared in build.payloads"
            )));
        };
        payload.source = path.display().to_string();
    }
    Ok(())
}

/// Fails (`--strict`) when the compiler differs from the recorded toolchain.
pub(super) fn verify_toolchain(plan: &plan::Plan) -> Result<()> {
    let recorded = plan
        .reproduce
        .as_ref()
        .map(|record| record.toolchain.rustc.trim())
        .filter(|recorded| !recorded.is_empty());
    let Some(recorded) = recorded else {
        return Err(error::PackerError::Usage(
            "--strict requires a document with a reproduce.toolchain record".to_string(),
        ));
    };
    let current = compiler::rustc_version()?;
    if current.trim() != recorded {
        return Err(error::PackerError::ToolchainMismatch {
            expected: recorded.to_string(),
            actual: current.trim().to_string(),
        });
    }
    Ok(())
}

/// Compares the new unsigned hash with the one recorded by the replay source.
pub(super) fn verify_predecessor(
    plan: &plan::Plan,
    actual: &str,
    ui: &Palette,
    warnings: &mut Vec<String>,
) -> Result<()> {
    let expected = plan
        .reproduce
        .as_ref()
        .and_then(|record| record.predecessor.as_ref())
        .map(|predecessor| predecessor.unsigned_sha256.trim())
        .filter(|expected| !expected.is_empty());
    let Some(expected) = expected else {
        warnings.push("--verify: the plan records no predecessor, nothing to compare".to_string());
        return Ok(());
    };
    if !expected.eq_ignore_ascii_case(actual) {
        return Err(error::PackerError::VerifyMismatch {
            expected: expected.to_string(),
            actual: actual.to_string(),
        });
    }
    anstream::eprintln!("{}", ui.done("verify", ui.dim(actual.to_string())));
    Ok(())
}
///
/// Dumping what the YAML resolved to makes a build reproducible from the log
/// alone, without opening the plan file.
pub(super) fn print_plan(plan: &plan::Plan, plan_path: &Path, ui: &Palette) {
    anstream::println!("{}", ui.heading("PLAN"));
    anstream::println!("{}", ui.field("name", &plan.name));
    anstream::println!("{}", ui.field("plan", ui.target(plan_path.display())));
    for (name, payload) in &plan.build.payloads {
        anstream::println!(
            "{}",
            ui.field(
                &format!("payload {name}"),
                ui.target(describe_source(&payload.source))
            )
        );
        anstream::println!(
            "{}",
            ui.field(&format!("  {name} args"), payload_args_label(payload))
        );
    }
    anstream::println!(
        "{}",
        ui.field("output", ui.target(plan.build.output.path.display()))
    );
    anstream::println!("{}", ui.field("arch", plan.build.output.arch.label()));
    anstream::println!(
        "{}",
        ui.field("strip", if plan.build.output.strip { "yes" } else { "no" })
    );
    anstream::println!(
        "{}",
        ui.field("trim paths", trim_label(plan.build.output.trim_paths))
    );
    anstream::println!(
        "{}",
        ui.field("subsystem", plan.build.output.subsystem.label())
    );
    anstream::println!("{}", ui.field("stub", stub_label(plan)));
    if plan.build.stub.debug {
        anstream::println!("{}", ui.field("debug", ui.warn("yes")));
    }
    if let Some(resolution) = &plan.build.stub.api_resolution {
        if resolution.mode == "proxy" {
            anstream::println!(
                "{}",
                ui.field("api resolution", api_resolution_label(resolution))
            );
        }
    }
    if let Some(resources) = &plan.build.output.resources {
        anstream::println!("{}", ui.field("resources", resources_label(resources)));
    }
    if let Some(sign) = &plan.build.output.sign {
        // A lab certificate without a subject takes its name from the generated
        // metadata, so the echo says where the name comes from.
        let derived = sign.mode == "lab"
            && sign.subject.is_none()
            && plan
                .build
                .output
                .resources
                .as_ref()
                .and_then(|resources| resources.version_info.as_ref())
                .is_some_and(|info| info.randomize);
        let label = if derived {
            "lab (subject derived from metadata)".to_string()
        } else {
            sign_label(sign)
        };
        anstream::println!("{}", ui.field("sign", label));
    }
    if let Ok(steps) = plan::steps::resolve(plan) {
        anstream::println!("{}", ui.field("runtime", runtime_chain(ui, &steps)));
    }
    anstream::println!("{}", ui.field("schema", plan.schema));
    anstream::println!();
}

/// `patch_amsi → reflective_loading`, step labels in the accent colors.
pub(super) fn runtime_chain(ui: &Palette, steps: &[ResolvedStep]) -> String {
    if steps.is_empty() {
        return ui.dim("no techniques");
    }
    steps
        .iter()
        .map(|step| match step.technique.category() {
            Category::Control => ui.target(step.label.clone()),
            Category::Preparation | Category::Execution => ui.brand(step.label.clone()),
        })
        .collect::<Vec<_>>()
        .join(&format!(" {} ", ui.dim(glyph::ARROW)))
}

/// Joins already-styled fragments with a faint `·` separator.
pub(super) fn dotted(ui: &Palette, parts: &[String]) -> String {
    parts.join(&format!(" {} ", ui.faint(glyph::DOT)))
}

/// Lowercase label for the debug-info path policy.
pub(super) fn trim_label(trim: TrimPaths) -> &'static str {
    match trim {
        TrimPaths::All => "all",
        TrimPaths::None => "none",
        TrimPaths::Relative => "relative",
    }
}

/// Which stub template the build resolved to (plus the syscall mode).
pub(super) fn stub_label(plan: &plan::Plan) -> String {
    match &plan.build.stub.path {
        Some(path) => format!("custom {}", path.display()),
        None => {
            let mode = stub_mode_label(plan);
            format!("builtin (syscalls {mode})")
        }
    }
}

/// Lowercase label of the resolved syscall mode (used by [`stub_label`]).
pub(super) fn stub_mode_label(plan: &plan::Plan) -> &'static str {
    plan.build
        .stub
        .syscalls
        .as_ref()
        .map(|s| match s.mode.as_str() {
            "indirect" => "indirect",
            _ => "none",
        })
        .unwrap_or("none")
}

/// Verifies that the compiled stub does not import any API that
/// `build.stub.api_resolution` routes or forwards (D-21).
///
/// The whole point of the feature is that the intercepted calls leave the IAT; a
/// proxy that imported the very API it intercepts would move the signature from
/// the payload's IAT into the stub's instead of removing it.
///
/// Two kinds of hit are expected and skipped:
///
/// - `Strategy::Handler` entries (D-22): `GetProcAddress` is imported by the
///   loader itself (the import resolver and the syscall resolvers use it), so its
///   presence is not a regression and cannot be told apart from the handler's own
///   dynamic resolver.
/// - An export an active technique's stub fragment references (D-24): the
///   technique needs it (the `bouncer` opens the current process token), so the
///   name is in the stub's IAT whatever the proxies do. The post-build audit
///   cannot tell that import from one a proxy added by mistake; without this
///   exemption `apis: all` makes the two features mutually exclusive.
pub(super) fn verify_no_intercepted_imports(
    artifact: &Path,
    config: &api_resolution::ApiResolutionConfig,
    steps: &[ResolvedStep],
) -> Result<()> {
    if config.mode != api_resolution::ApiResolutionMode::Proxy || config.apis.is_empty() {
        return Ok(());
    }
    let bytes = std::fs::read(artifact)?;
    let audit = audit::pe_info::analyze(&bytes).map_err(|e| {
        error::PackerError::Validation(format!("could not audit the compiled stub: {e}"))
    })?;
    let technique_imports = technique_imported_functions(steps, &config.apis);
    for entry in &config.apis {
        if entry.strategy == api_resolution::Strategy::Handler
            || technique_imports.contains(entry.func)
        {
            continue;
        }
        for dll in &audit.imports {
            let hit = dll
                .functions
                .iter()
                .any(|f| matches!(f, audit::pe_info::ImportItem::Named(n) if n == entry.func));
            if hit {
                return Err(error::PackerError::Validation(format!(
                    "the stub imports '{}' (from '{}') while build.stub.api_resolution proxies it: a \
                     proxy must not import the API it intercepts",
                    entry.func, dll.name
                )));
            }
        }
    }
    Ok(())
}

/// Catalogued exports that an active technique's own stub fragment references.
///
/// A technique that opens a token (`bouncer`) imports the Win32 API directly, so
/// the name lands in the stub's IAT no matter how the proxies are implemented.
/// The audit can only see the IAT, so it must treat those names as expected;
/// matching is per identifier, so `bouncer`'s `OpenProcessToken` does not exempt
/// `OpenProcess`.
pub(super) fn technique_imported_functions(
    steps: &[ResolvedStep],
    entries: &[api_resolution::ApiEntry],
) -> BTreeSet<&'static str> {
    let defs = techniques::all();
    let mut names = BTreeSet::new();
    for step in steps {
        let Some(def) = defs.iter().find(|def| def.name == step.technique.name()) else {
            continue;
        };
        for entry in entries {
            if mentions_identifier(def.stub_fragment, entry.func) {
                names.insert(entry.func);
            }
        }
    }
    names
}

/// Whether `haystack` contains `needle` as a whole ASCII identifier.
pub(super) fn mentions_identifier(haystack: &str, needle: &str) -> bool {
    let is_identifier = |c: char| c.is_ascii_alphanumeric() || c == '_';
    haystack.match_indices(needle).any(|(at, _)| {
        let before = haystack[..at].chars().next_back();
        let after = haystack[at + needle.len()..].chars().next();
        !before.is_some_and(is_identifier) && !after.is_some_and(is_identifier)
    })
}

/// Prepends `#![windows_subsystem = "windows"]` for a GUI build.
///
/// Runs on the rendered source (builtin or custom) so `rustc` links a GUI
/// binary. A source that already sets `windows_subsystem` is left untouched.
pub(super) fn apply_subsystem(source: String, subsystem: Subsystem) -> String {
    if subsystem == Subsystem::Windows && !source.contains("windows_subsystem") {
        let mut out = String::with_capacity(source.len() + 40);
        out.push_str("#![windows_subsystem = \"windows\"]\n");
        out.push_str(&source);
        out
    } else {
        source
    }
}

/// Copies the generated stub source and the encrypted payloads next to the
/// artifact, so the output folder is a complete package and not just the
/// compiled file.
pub(super) fn copy_package_sources(build_dir: &Path, package_dir: &Path) -> Result<()> {
    std::fs::create_dir_all(package_dir)?;

    // A previous, larger run may have left extra blobs behind; drop the old set
    // before copying the new one, so the folder describes exactly this build.
    if let Ok(entries) = std::fs::read_dir(package_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with("payload_") && name.ends_with(".bin") {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }

    let source = build_dir.join("main.rs");
    if source.is_file() {
        std::fs::copy(&source, package_dir.join("main.rs"))?;
    }
    for entry in std::fs::read_dir(build_dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with("payload_") && name.ends_with(".bin") {
            std::fs::copy(entry.path(), package_dir.join(name.as_ref()))?;
        }
    }
    Ok(())
}

/// Copies the generated C# sources of a `psmodule` build into its package.
pub(super) fn copy_psmodule_sources(build_dir: &Path, package_dir: &Path) -> Result<()> {
    std::fs::create_dir_all(package_dir)?;
    for name in ["picaro_module.cs", "picaro_module_xchacha.cs"] {
        let source = build_dir.join(name);
        if source.is_file() {
            std::fs::copy(&source, package_dir.join(name))?;
        }
    }
    Ok(())
}

/// Where the compiled stub is written inside the build directory.
///
/// An executable keeps the fixed `out.exe`, and a shellcode build keeps
/// `out.dll`: its intermediate is never delivered (sRDI converts it in place),
/// so a neutral name leaves no codename in the stage's export directory or PDB.
/// A DLL is named after the artifact the operator asked for: the linker records
/// the link output's name inside the PE (the export directory's `Name` field),
/// so the file should report the name it will be delivered under rather than
/// the build's scratch name.
pub(super) fn intermediate_path(build_dir: &Path, output: &plan::schema::OutputPlan) -> PathBuf {
    match output.kind {
        OutputKind::Exe => build_dir.join("out.exe"),
        OutputKind::Shellcode => build_dir.join("out.dll"),
        // A psmodule build has its own flow (see `build_psmodule`); keeping it
        // in this arm keeps the match total and names the scratch module after
        // the artifact.
        OutputKind::Dll | OutputKind::PsModule => {
            let stem = output
                .path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .unwrap_or("loader");
            build_dir.join(format!("{stem}.dll"))
        }
    }
}

/// First 16 hex digits of a thumbprint, for a compact step line.
pub(super) fn short_thumbprint(thumbprint: &str) -> String {
    thumbprint.chars().take(16).collect()
}

/// Human summary of `output.sign`.
pub(super) fn sign_label(sign: &plan::schema::SignPlan) -> String {
    match sign.mode.as_str() {
        "lab" => format!(
            "lab ({})",
            sign.subject.as_deref().unwrap_or("default subject")
        ),
        "store" => format!(
            "store ({})",
            sign.thumbprint
                .as_deref()
                .or(sign.subject.as_deref())
                .unwrap_or("?")
        ),
        "file" => format!(
            "file ({})",
            sign.file
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_default()
        ),
        other => other.to_string(),
    }
}

/// The `api_resolution` echo: `proxy (5 APIs, unmatched forward)`.
///
/// The count is the *resolved* catalogue size (so `apis: all` reports every
/// entry), not the number of selectors written in the YAML.
pub(super) fn api_resolution_label(yaml: &engine::api_resolution::YamlApiResolutionPlan) -> String {
    let apis = engine::api_resolution::ApiResolutionConfig::from_yaml(Some(yaml))
        .map(|config| config.apis.len())
        .unwrap_or_else(|_| yaml.apis.len());
    format!("proxy ({apis} APIs, unmatched {})", yaml.unmatched)
}

/// Human summary of the configured PE resources (`output.resources`).
pub(super) fn resources_label(resources: &plan::schema::ResourcesPlan) -> String {
    let mut parts = Vec::new();
    if let Some(icon) = &resources.icon {
        parts.push(match icon {
            plan::schema::IconPlan::Random { .. } => "icon random".to_string(),
            plan::schema::IconPlan::Path(path) => format!("icon {}", path.display()),
        });
    }
    if resources.version_info.is_some() {
        parts.push("version info".to_string());
    }
    if let Some(manifest) = &resources.manifest {
        parts.push(format!("manifest ({})", manifest.level.xml_value()));
    }
    if parts.is_empty() {
        "(none)".to_string()
    } else {
        parts.join(", ")
    }
}

/// Resolves `output.resources`, applying random metadata when requested.
///
/// `version_info.randomize` fills the unset fields with generated values, so the
/// artifact carries plausible company/product/version metadata instead of empty
/// strings. The generated company is later reused as the lab certificate
/// subject (see [`resolve_sign`]).
///
/// `icon: random` is given a concrete seed here, so the embedded icon and the
/// seed recorded in the manifest agree.
pub(super) fn resolve_resources(
    plan: &plan::Plan,
    entropy: &BuildEntropy,
) -> Option<plan::schema::ResourcesPlan> {
    let resources = plan.build.output.resources.as_ref()?;
    let mut resolved = resources.clone();
    if let Some(info) = &resolved.version_info {
        // The resolved identity is recorded by value because it is what the
        // artifact embeds; prefer the record over regenerating it (the
        // copyright year would otherwise change across years and break replay).
        let recorded = plan
            .reproduce
            .as_ref()
            .and_then(|record| record.identity.clone());
        resolved.version_info = Some(match recorded {
            Some(identity) => identity,
            None => engine::identity::apply(info, entropy),
        });
    }
    if let Some(icon) = resolved.icon.take() {
        let seed = plan
            .reproduce
            .as_ref()
            .and_then(|record| record.entropy.icon)
            .unwrap_or_else(|| entropy.derive(Domain::Icon));
        resolved.icon = Some(icon.with_seed(seed));
    }
    Some(resolved)
}

/// The seed of a generated icon, for the reproduction record.
pub(super) fn generated_icon(resources: Option<&plan::schema::ResourcesPlan>) -> Option<u64> {
    resources?.icon.as_ref()?.seed()
}

/// A per-build stub marker derived from the master entropy.
///
/// The marker distinguishes two steps that embed one payload; it is part of the
/// generated source, so it must be reproducible. The `stub` module keeps the
/// unseeded helper for tests.
pub(super) fn stub_marker(entropy: &BuildEntropy, tag: &str) -> String {
    let bytes: [u8; 8] = entropy.derive_tagged_bytes(Domain::PayloadKey, tag);
    format!("STUB_MARKER_{}", hex::encode(bytes))
}

/// Resolves `output.sign`, deriving the lab certificate subject from the
/// generated company when one is available and no subject was configured.
pub(super) fn resolve_sign(
    plan: &plan::Plan,
    resources: Option<&plan::schema::ResourcesPlan>,
) -> Option<plan::schema::SignPlan> {
    let sign = plan.build.output.sign.as_ref()?;
    let mut resolved = sign.clone();
    if resolved.mode == "lab" && resolved.subject.is_none() {
        if let Some(company) = resources
            .and_then(|r| r.version_info.as_ref())
            .and_then(|info| info.company.clone())
        {
            resolved.subject = Some(format!("CN={company}"));
        }
    }
    Some(resolved)
}

/// The configured payload source, or a placeholder when empty.
pub(super) fn describe_source(source: &str) -> String {
    if source.trim().is_empty() {
        "(unspecified)".to_string()
    } else {
        source.to_string()
    }
}

/// Lowercase label for the crypto algorithm, as printed by `build`.
pub(super) fn crypto_label(algo: CryptoAlgorithm) -> &'static str {
    match algo {
        CryptoAlgorithm::XChaCha20Poly1305 => "xchacha20poly1305",
    }
}

/// `(none)` or `N (mode)` for a payload's configured runtime arguments.
pub(super) fn payload_args_label(payload: &PayloadPlan) -> String {
    match &payload.args {
        Some(args) if !args.is_empty() => {
            format!("{} ({})", args.len(), payload.args_mode.label())
        }
        _ => "(none)".to_string(),
    }
}

/// Reads an input payload into memory from its configured source.
///
/// `http://` and `https://` sources are fetched in memory (never written to
/// disk); a `file://` source is read from disk after stripping the scheme; any
/// other value is treated as a local path. `ftp://` is recognized but rejected
/// with a clear message because no FTP client is implemented.
pub(super) fn load_source(source: &str) -> Result<Vec<u8>> {
    if source.starts_with("http://") || source.starts_with("https://") {
        return engine::fetch::fetch_url(source);
    }
    if source.starts_with("ftp://") {
        return Err(error::PackerError::Validation(
            "a payload 'source' uses ftp://, which is not supported; \
             use http(s):// or a local path"
                .to_string(),
        ));
    }
    let path = match source.strip_prefix("file://") {
        Some(rest) => file_url_to_path(rest),
        None => source.to_string(),
    };
    std::fs::read(&path).map_err(|source| error::PackerError::ReadInput {
        path: PathBuf::from(path),
        source,
    })
}

/// Removes `dir` if it exists and recreates it empty.
pub(super) fn prepare_build_dir(dir: &Path) -> Result<()> {
    if dir.exists() {
        std::fs::remove_dir_all(dir)?;
    }
    std::fs::create_dir_all(dir)?;
    Ok(())
}

/// The scratch directory for intermediate artifacts (the ciphertexts, the
/// rendered stub, the compiled `out.exe`).
///
/// Defaults to a unique `build/run-<pid>-<nanos>` directory next to the
/// manifest, so concurrent `picaro build` runs never share — and never wipe —
/// each other's intermediate files. A `--build-name NAME` replaces that unique
/// run label with `NAME` (`build/NAME`), trading isolation for a stable path a
/// debugger can rely on. `PICARO_BUILD_DIR`, when set and non-empty, replaces
/// the `build` base for reproducible single-directory workflows (e.g. the
/// read-only Docker source tree); a `--build-name` stacks on top of it.
pub(super) fn scratch_dir(build_name: Option<&str>) -> Result<PathBuf> {
    let override_dir = std::env::var_os("PICARO_BUILD_DIR").map(PathBuf::from);
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    scratch_dir_for(override_dir, manifest_dir, build_name)
}

/// Testable core of [`scratch_dir`]: resolves the override/manifest base, then
/// applies the `--build-name` (or the unique run label) on top.
pub(super) fn scratch_dir_for(
    override_dir: Option<PathBuf>,
    manifest_dir: &Path,
    build_name: Option<&str>,
) -> Result<PathBuf> {
    if let Some(name) = build_name {
        // A named directory is deliberately *not* unique: the whole point is
        // that `build/<name>/main.rs` is the same path next run. Two concurrent
        // builds that pass the same name share it, which is the caller's call.
        return Ok(scratch_dir_in(override_dir, manifest_dir).join(bare_dir_component(name)?));
    }
    if override_dir
        .as_ref()
        .is_some_and(|dir| !dir.as_os_str().is_empty())
    {
        return Ok(scratch_dir_in(override_dir, manifest_dir));
    }
    Ok(unique_scratch_dir_in(manifest_dir, &run_nonce()))
}

/// Accepts a `--build-name` only when it is a single, ordinary directory name.
///
/// The flag names one folder under the scratch root; it is not a path. Rejecting
/// separators, a drive prefix and `.`/`..` keeps a mistyped name from writing
/// anywhere else on disk.
pub(super) fn bare_dir_component(name: &str) -> Result<&str> {
    let trimmed = name.trim();
    let invalid = trimmed.is_empty()
        || trimmed == "."
        || trimmed == ".."
        || trimmed.contains('/')
        || trimmed.contains('\\')
        || trimmed.contains(':');
    if invalid {
        return Err(error::PackerError::Usage(format!(
            "--build-name must be a single directory name (got {name:?})"
        )));
    }
    Ok(trimmed)
}

/// Resolves [`scratch_dir`] from an explicit `PICARO_BUILD_DIR` value (when set
/// and non-empty) and the manifest directory. Split out so both branches are
/// testable without touching the process environment.
pub(super) fn scratch_dir_in(override_dir: Option<PathBuf>, manifest_dir: &Path) -> PathBuf {
    match override_dir {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => manifest_dir.join("build"),
    }
}

/// A unique scratch directory for one build run, derived from `nonce`.
///
/// Split from [`scratch_dir`] so tests can inject a deterministic nonce.
pub(super) fn unique_scratch_dir_in(manifest_dir: &Path, nonce: &str) -> PathBuf {
    manifest_dir.join("build").join(format!("run-{nonce}"))
}

/// A process- and time-unique label (`<pid>-<nanos>`) for a build run.
pub(super) fn run_nonce() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    format!("{}-{nanos}", std::process::id())
}
