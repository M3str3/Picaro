use super::*;

const PE: &str = "tests/fixtures/minimal_x64.exe";
const PE_X86: &str = "tests/fixtures/minimal_x86.exe";
const DOTNET: &str = "tests/fixtures/managed_anycpu.exe";
const PS1: &str = "examples/payloads/demo_script.ps1";

fn default_args(payload: &str) -> PackArgs {
    PackArgs {
        payload: PathBuf::from(payload),
        exec: None,
        techniques: Vec::new(),
        steps: Vec::new(),
        syscalls: None,
        resolver: None,
        stack_spoofing: None,
        strings: None,
        out: None,
        dir: None,
        build_name: None,
        plan_out: None,
        no_save_plan: false,
        arch: None,
        kind: None,
        entry: None,
        export: None,
        sign: None,
        sign_subject: None,
        sign_thumbprint: None,
        sign_file: None,
        sign_password_env: None,
        timestamp_url: None,
        icon: None,
        strip: None,
        gui: None,
        target: None,
        sleep_ms: None,
        debug: false,
        reflective_loading: false,
        hollow: false,
        patch_amsi: false,
        patch_etw: false,
        erase_header: false,
        unhook: false,
        hide_module: false,
        allow_experimental: false,
    }
}

/// A fresh empty directory for a test's temporary files.
fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("picaro_pack_{}_{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

/// Writes a non-PE blob so the detector picks `shellcode`.
fn shellcode_file(name: &str) -> PathBuf {
    let path = temp_dir(name).join("payload.bin");
    std::fs::write(&path, [0x90u8; 16]).expect("write shellcode");
    path
}

fn names(outcome: &PackOutcome) -> Vec<&str> {
    outcome
        .plan
        .runtime
        .iter()
        .map(|step| step.name())
        .collect()
}

#[test]
fn a_pe_defaults_to_reflective_loading_over_indirect_hells_gate() {
    let outcome = compose(&default_args(PE), &Defaults::default()).expect("compose");
    assert_eq!(outcome.format, PayloadFormat::Pe);
    assert_eq!(outcome.executions, vec!["reflective_loading"]);
    assert_eq!(names(&outcome), vec!["reflective_loading"]);

    let syscalls = outcome
        .plan
        .build
        .stub
        .syscalls
        .as_ref()
        .expect("indirect syscalls by default");
    assert_eq!(syscalls.mode, "indirect");
    assert_eq!(syscalls.resolver, "hells_gate");
    assert_eq!(
        outcome
            .plan
            .build
            .stub
            .strings
            .as_ref()
            .map(|s| &*s.strategy),
        Some("xor")
    );
    assert!(
        outcome
            .warnings
            .iter()
            .any(|warning| warning.contains("experimental")),
        "the reflective default must be announced: {:?}",
        outcome.warnings
    );
}

#[test]
fn a_dotnet_payload_defaults_to_dotnet_hosting() {
    let outcome = compose(&default_args(DOTNET), &Defaults::default()).expect("compose");
    assert_eq!(outcome.format, PayloadFormat::Dotnet);
    assert_eq!(outcome.executions, vec!["dotnet_hosting"]);
}

#[test]
fn a_powershell_payload_defaults_to_powershell_hosting() {
    let outcome = compose(&default_args(PS1), &Defaults::default()).expect("compose");
    assert_eq!(outcome.format, PayloadFormat::Powershell);
    assert_eq!(outcome.executions, vec!["powershell_hosting"]);
}

#[test]
fn shellcode_defaults_to_reflective_loading() {
    let payload = shellcode_file("shellcode-default");
    let outcome = compose(
        &default_args(&payload.display().to_string()),
        &Defaults::default(),
    )
    .expect("compose");
    assert_eq!(outcome.format, PayloadFormat::Shellcode);
    assert_eq!(outcome.executions, vec!["reflective_loading"]);
}

#[test]
fn the_default_layout_is_a_bundle_under_packed() {
    let outcome = compose(&default_args(PE), &Defaults::default()).expect("compose");
    let root = &outcome.bundle.root;
    assert_eq!(root.parent(), Some(Path::new("packed")));
    let name = root
        .file_name()
        .and_then(|name| name.to_str())
        .expect("a bundle name");
    assert!(
        name.starts_with("minimal_x64-") && name.len() > "minimal_x64-".len(),
        "the bundle is named after the plan plus a run label: {name}"
    );
    assert_eq!(outcome.bundle.plan, root.join("plan.yaml"));
    assert_eq!(outcome.bundle.build, root.join("build"));
    assert_eq!(outcome.bundle.artifacts, root.join("artifacts"));
    assert_eq!(
        outcome.bundle.bundled_artifact,
        root.join("dist/minimal_x64.exe")
    );
    // No `--out`: the artifact travels with the bundle.
    assert_eq!(outcome.bundle.artifact, outcome.bundle.bundled_artifact);
    assert_eq!(
        outcome.plan.build.output.path, None,
        "the plan stays portable"
    );
    assert!(outcome.save_plan, "the plan is saved by default");
}

#[test]
fn the_configured_directory_replaces_the_default_root() {
    let defaults = Defaults {
        dir: Some(PathBuf::from("out")),
        ..Defaults::default()
    };
    let outcome = compose(&default_args(PE), &defaults).expect("compose");
    assert_eq!(outcome.bundle.root.parent(), Some(Path::new("out")));
}

#[test]
fn a_cli_directory_wins_over_the_config() {
    let defaults = Defaults {
        dir: Some(PathBuf::from("out")),
        ..Defaults::default()
    };
    let mut args = default_args(PE);
    args.dir = Some(PathBuf::from("cli"));
    let outcome = compose(&args, &defaults).expect("compose");
    assert_eq!(outcome.bundle.root.parent(), Some(Path::new("cli")));
}

#[test]
fn an_explicit_output_file_is_delivered_verbatim_and_still_gets_a_bundle() {
    let mut args = default_args(PE);
    args.out = Some(PathBuf::from("custom/artifact.exe"));
    let outcome = compose(&args, &Defaults::default()).expect("compose");
    assert_eq!(outcome.bundle.root.parent(), Some(Path::new("packed")));
    assert_eq!(
        outcome.bundle.artifact,
        PathBuf::from("custom/artifact.exe")
    );
    assert_eq!(
        outcome.bundle.artifact_name, "artifact.exe",
        "the delivered name drives the manifest and CA names"
    );
    assert_eq!(
        outcome.plan.build.output.path,
        Some(PathBuf::from("custom/artifact.exe")),
        "a saved plan keeps the operator's deliverable"
    );
}

#[test]
fn each_run_gets_its_own_bundle() {
    let first = compose(&default_args(PE), &Defaults::default()).expect("compose");
    let second = compose(&default_args(PE), &Defaults::default()).expect("compose");
    assert_ne!(
        first.bundle.root, second.bundle.root,
        "two runs must not overwrite each other's bundle"
    );
}

#[test]
fn no_save_plan_disables_the_written_document() {
    let mut args = default_args(PE);
    args.no_save_plan = true;
    let outcome = compose(&args, &Defaults::default()).expect("compose");
    assert!(!outcome.save_plan);
}

#[test]
fn plan_out_implies_saving() {
    let defaults = Defaults {
        plan: Some(false),
        ..Defaults::default()
    };
    let mut args = default_args(PE);
    args.plan_out = Some(PathBuf::from("plans/one.yaml"));
    let outcome = compose(&args, &defaults).expect("compose");
    assert!(outcome.save_plan);
    assert_eq!(outcome.plan_out, Some(PathBuf::from("plans/one.yaml")));
    // The extra copy is outside the bundle; the bundled plan is unaffected.
    assert_eq!(
        outcome
            .bundle
            .plan
            .file_name()
            .and_then(|name| name.to_str()),
        Some("plan.yaml")
    );
}

#[test]
fn an_explicit_experimental_technique_needs_the_flag() {
    let mut args = default_args(PE);
    args.exec = Some("reflective_loading".to_string());
    let error = compose(&args, &Defaults::default()).expect_err("gate");
    assert!(
        error.to_string().contains("--allow-experimental"),
        "unclear: {error}"
    );
}

#[test]
fn allow_experimental_accepts_and_announces_the_technique() {
    let mut args = default_args(PE);
    args.exec = Some("reflective_loading".to_string());
    args.allow_experimental = true;
    let outcome = compose(&args, &Defaults::default()).expect("compose");
    assert!(
        outcome
            .warnings
            .iter()
            .any(|warning| warning.contains("--allow-experimental")),
        "the acceptance must be visible: {:?}",
        outcome.warnings
    );
}

#[test]
fn a_stable_technique_needs_no_flag() {
    let mut args = default_args(PE);
    args.exec = Some("process_hollowing".to_string());
    let outcome = compose(&args, &Defaults::default()).expect("compose");
    assert_eq!(outcome.executions, vec!["process_hollowing"]);
}

#[test]
fn a_preparation_shortcut_runs_before_the_execution() {
    let mut args = default_args(PE);
    args.exec = Some("process_hollowing".to_string());
    args.patch_amsi = true;
    args.erase_header = true;
    let outcome = compose(&args, &Defaults::default()).expect("compose");
    assert_eq!(
        names(&outcome),
        vec!["patch_amsi", "erase_pe_header", "process_hollowing"]
    );
}

#[test]
fn a_shortcut_is_inserted_before_an_execution_given_with_technique() {
    let mut args = default_args(PE);
    args.techniques = vec!["process_hollowing".to_string()];
    args.patch_amsi = true;
    let outcome = compose(&args, &Defaults::default()).expect("compose");
    assert_eq!(names(&outcome), vec!["patch_amsi", "process_hollowing"]);
}

#[test]
fn sleep_runs_before_the_execution() {
    let mut args = default_args(PE);
    args.sleep_ms = Some(2500);
    let outcome = compose(&args, &Defaults::default()).expect("compose");
    assert_eq!(names(&outcome), vec!["sleep", "reflective_loading"]);
    let TechniqueKind::Sleep { params } = &outcome.plan.runtime[0].technique else {
        panic!("first step is sleep");
    };
    assert_eq!(params.ms, 2500);
}

#[test]
fn target_reaches_process_hollowing() {
    let mut args = default_args(PE);
    args.hollow = true;
    args.target = Some(r"C:\Windows\System32\notepad.exe".to_string());
    let outcome = compose(&args, &Defaults::default()).expect("compose");
    let TechniqueKind::ProcessHollowing { params } = &outcome.plan.runtime[0].technique else {
        panic!("hollowing step");
    };
    assert_eq!(params.target, r"C:\Windows\System32\notepad.exe");
}

#[test]
fn target_is_rejected_by_an_execution_without_one() {
    let mut args = default_args(PE);
    args.target = Some("x.exe".to_string());
    let error = compose(&args, &Defaults::default()).expect_err("no target");
    assert!(error.to_string().contains("--target"), "unclear: {error}");
}

#[test]
fn exec_and_a_technique_execution_are_mutually_exclusive() {
    let mut args = default_args(PE);
    args.exec = Some("process_hollowing".to_string());
    args.techniques = vec!["pe_injection".to_string()];
    let error = compose(&args, &Defaults::default()).expect_err("ambiguous");
    assert!(
        error.to_string().contains("execution step"),
        "unclear: {error}"
    );
}

#[test]
fn exec_rejects_a_preparation_technique() {
    let mut args = default_args(PE);
    args.exec = Some("patch_amsi".to_string());
    let error = compose(&args, &Defaults::default()).expect_err("wrong category");
    assert!(
        error.to_string().contains("execution technique"),
        "unclear: {error}"
    );
}

#[test]
fn syscalls_none_omits_the_block() {
    let mut args = default_args(PE);
    args.syscalls = Some("none".to_string());
    let outcome = compose(&args, &Defaults::default()).expect("compose");
    assert!(outcome.plan.build.stub.syscalls.is_none());
}

#[test]
fn a_resolver_needs_indirect_syscalls() {
    let mut args = default_args(PE);
    args.syscalls = Some("none".to_string());
    args.resolver = Some("tartarus_gate".to_string());
    let error = compose(&args, &Defaults::default()).expect_err("inconsistent");
    assert!(
        error.to_string().contains("--syscalls indirect"),
        "unclear: {error}"
    );
}

#[test]
fn an_unknown_resolver_is_rejected() {
    let mut args = default_args(PE);
    args.resolver = Some("tatarus_gate".to_string());
    let error = compose(&args, &Defaults::default()).expect_err("typo");
    assert!(
        error.to_string().contains("tartarus_gate"),
        "unclear: {error}"
    );
}

#[test]
fn x86_downgrades_the_implicit_indirect_default() {
    let mut args = default_args(PE_X86);
    args.arch = Some("x86".to_string());
    let outcome = compose(&args, &Defaults::default()).expect("compose");
    assert_eq!(outcome.plan.build.output.arch, Arch::X86);
    assert!(outcome.plan.build.stub.syscalls.is_none());
}

#[test]
fn x86_downgrades_the_indirect_default_from_the_config() {
    let mut args = default_args(PE_X86);
    args.arch = Some("x86".to_string());
    let defaults = Defaults {
        syscalls: Some("indirect".to_string()),
        resolver: Some("hells_gate".to_string()),
        ..Defaults::default()
    };
    let outcome = compose(&args, &defaults).expect("compose");
    assert!(outcome.plan.build.stub.syscalls.is_none());
}

#[test]
fn syscalls_none_ignores_a_leftover_config_resolver() {
    let mut args = default_args(PE);
    args.syscalls = Some("none".to_string());
    let defaults = Defaults {
        resolver: Some("hells_gate".to_string()),
        stack_spoofing: Some(false),
        ..Defaults::default()
    };
    let outcome = compose(&args, &defaults).expect("compose");
    assert!(outcome.plan.build.stub.syscalls.is_none());
}

#[test]
fn an_explicit_indirect_request_on_x86_is_an_error() {
    let mut args = default_args(PE_X86);
    args.arch = Some("x86".to_string());
    args.syscalls = Some("indirect".to_string());
    let error = compose(&args, &Defaults::default()).expect_err("x64 only");
    assert!(error.to_string().contains("x64-only"), "unclear: {error}");
}

#[test]
fn an_explicit_dll_export_is_checked_against_the_table() {
    let exports = vec!["DllMain".to_string(), "Run".to_string()];
    let mut warnings = Vec::new();
    let chosen = resolve_export(
        Some("Run"),
        Path::new("payload.dll"),
        &exports,
        &mut warnings,
    )
    .expect("explicit export");
    assert_eq!(chosen.as_deref(), Some("Run"));

    let error = resolve_export(
        Some("Nope"),
        Path::new("payload.dll"),
        &exports,
        &mut warnings,
    )
    .expect_err("missing export");
    assert!(error.to_string().contains("available"), "unclear: {error}");
    assert!(error.to_string().contains("DllMain"), "unclear: {error}");
}

#[test]
fn the_only_callable_dll_export_is_selected() {
    let exports = vec!["DllMain".to_string(), "DllRegisterServer".to_string()];
    let mut warnings = Vec::new();
    let chosen =
        choose_dll_export(Path::new("payload.dll"), &exports, &mut warnings).expect("choice");
    assert_eq!(chosen.as_deref(), Some("DllRegisterServer"));
    assert!(
        warnings
            .iter()
            .any(|warning| warning.contains("DllRegisterServer")),
        "the selected export must be announced: {warnings:?}"
    );
}

#[test]
fn several_callable_dll_exports_ask_for_a_choice() {
    let exports = vec![
        "DllMain".to_string(),
        "Run".to_string(),
        "Encrypt".to_string(),
    ];
    let mut warnings = Vec::new();
    let error = choose_dll_export(Path::new("payload.dll"), &exports, &mut warnings)
        .expect_err("ambiguous");
    assert!(error.to_string().contains("--export"), "unclear: {error}");
    assert!(
        error.to_string().contains("Encrypt, Run"),
        "unclear: {error}"
    );
}

#[test]
fn a_dll_with_only_dllmain_explains_the_dead_end() {
    let exports = vec!["DllMain".to_string()];
    let mut warnings = Vec::new();
    let error = choose_dll_export(Path::new("payload.dll"), &exports, &mut warnings)
        .expect_err("no callable export");
    assert!(
        error.to_string().contains("no callable export"),
        "unclear: {error}"
    );
}

#[test]
fn dll_entry_exports_are_not_callable() {
    assert!(is_dll_entry_export("DllMain"));
    assert!(is_dll_entry_export("DllMain@12"));
    assert!(is_dll_entry_export("_DllMainCRTStartup@12"));
    assert!(!is_dll_entry_export("DllRegisterServer"));
}

#[test]
fn a_dll_output_accepts_an_entry() {
    let mut args = default_args(PE);
    args.kind = Some("dll".to_string());
    args.entry = Some("export:Run".to_string());
    let outcome = compose(&args, &Defaults::default()).expect("compose");
    assert_eq!(outcome.plan.build.output.kind, OutputKind::Dll);
    assert_eq!(
        outcome.plan.build.output.entry,
        DllEntry::Export("Run".to_string())
    );
    assert!(
        outcome.bundle.bundled_artifact.ends_with("minimal_x64.dll"),
        "a DLL build delivers a .dll: {:?}",
        outcome.bundle.bundled_artifact
    );
}

#[test]
fn a_psmodule_output_needs_the_import_step() {
    let mut args = default_args(PS1);
    args.kind = Some("psmodule".to_string());
    let error = compose(&args, &Defaults::default()).expect_err("missing import step");
    assert!(
        error.to_string().contains("import_powermodule"),
        "unclear: {error}"
    );
}

#[test]
fn export_is_only_for_dll_payloads() {
    let mut args = default_args(PE);
    args.export = Some("Run".to_string());
    let error = compose(&args, &Defaults::default()).expect_err("not a dll");
    assert!(error.to_string().contains("--export"), "unclear: {error}");
}

#[test]
fn signing_needs_a_mode_and_its_inputs() {
    let mut args = default_args(PE);
    args.sign_subject = Some("CN=lab".to_string());
    let error = compose(&args, &Defaults::default()).expect_err("no mode");
    assert!(error.to_string().contains("--sign"), "unclear: {error}");

    let mut store = default_args(PE);
    store.sign = Some("store".to_string());
    let error = compose(&store, &Defaults::default()).expect_err("no identity");
    assert!(
        error.to_string().contains("--sign-thumbprint"),
        "unclear: {error}"
    );

    let mut file = default_args(PE);
    file.sign = Some("file".to_string());
    let error = compose(&file, &Defaults::default()).expect_err("no file");
    assert!(
        error.to_string().contains("--sign-file"),
        "unclear: {error}"
    );
}

#[test]
fn output_options_reach_the_plan() {
    let mut args = default_args(PE);
    args.debug = true;
    args.strip = Some(false);
    args.gui = Some(true);
    args.icon = Some("random".to_string());
    let outcome = compose(&args, &Defaults::default()).expect("compose");
    assert!(outcome.plan.build.stub.debug);
    assert!(!outcome.plan.build.output.strip);
    assert_eq!(outcome.plan.build.output.subsystem, Subsystem::Windows);
    assert_eq!(
        outcome
            .plan
            .build
            .output
            .resources
            .as_ref()
            .and_then(|resources| resources.icon.as_ref()),
        Some(&IconPlan::Random { seed: None })
    );
}

#[test]
fn a_lab_signature_reaches_the_plan() {
    let mut args = default_args(PE);
    args.sign = Some("lab".to_string());
    let outcome = compose(&args, &Defaults::default()).expect("compose");
    let sign = outcome.plan.build.output.sign.as_ref().expect("sign block");
    assert_eq!(sign.mode, "lab");
}

#[test]
fn a_step_document_is_parsed_and_ordered_first() {
    let dir = temp_dir("step-doc");
    let path = dir.join("etw.yaml");
    std::fs::write(&path, "technique: patch_etw\nparams:\n  full: false\n").expect("write step");

    let mut args = default_args(PE);
    args.steps = vec![path];
    args.patch_amsi = true;
    let outcome = compose(&args, &Defaults::default()).expect("compose");
    assert_eq!(
        names(&outcome),
        vec!["patch_etw", "patch_amsi", "reflective_loading"]
    );
    let TechniqueKind::PatchEtw { params } = &outcome.plan.runtime[0].technique else {
        panic!("first step is patch_etw");
    };
    assert!(!params.full);
}

#[test]
fn config_is_read_from_the_given_file() {
    let dir = temp_dir("config");
    let path = dir.join("picaro.config.yaml");
    std::fs::write(
        &path,
        "pack:\n  dir: out\n  syscalls: none\n  plan: false\n",
    )
    .expect("write config");
    let defaults = load_config(Some(&path)).expect("load config");
    assert_eq!(defaults.dir, Some(PathBuf::from("out")));
    assert_eq!(defaults.syscalls.as_deref(), Some("none"));
    assert_eq!(defaults.plan, Some(false));
}

#[test]
fn an_absent_optional_config_falls_back_to_the_defaults() {
    let defaults =
        load_config_at(Path::new("does/not/exist.yaml"), false).expect("optional lookup");
    assert!(defaults.dir.is_none());
}

#[test]
fn a_missing_explicit_config_is_an_error() {
    let error = load_config(Some(Path::new("does/not/exist.yaml"))).expect_err("missing");
    assert!(error.to_string().contains("config"), "unclear: {error}");
}

#[test]
fn the_generated_plan_round_trips_through_the_loader() {
    let outcome = compose(&default_args(PE), &Defaults::default()).expect("compose");
    let reloaded =
        load_plan_str(&outcome.plan_yaml, &outcome.bundle.plan, &BTreeMap::new()).expect("reload");
    assert_eq!(reloaded, outcome.plan);
    assert!(outcome.plan_yaml.contains("schema: 6"));
}
