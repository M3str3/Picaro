use super::*;
use std::collections::BTreeMap;
use std::io::Cursor;

use crate::plan::load_plan;

/// Joins answer lines the way a terminal would deliver them.
fn script(lines: &[&str]) -> String {
    let mut input = lines.join("\n");
    input.push('\n');
    input
}

/// A unique, empty directory for one test's generated plan.
fn temp_dir(test: &str) -> PathBuf {
    let dir = std::env::temp_dir().join("picaro_wizard_tests").join(test);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

/// Runs a scripted session and returns its written plan path and output.
fn session(payload: &str, answers: &[&str], plan_out: Option<&Path>) -> (Option<PathBuf>, String) {
    let mut out = Vec::new();
    let result = match run_with(
        Path::new(payload),
        plan_out,
        &Palette::plain(),
        Cursor::new(script(answers)),
        &mut out,
    ) {
        Ok(result) => result,
        Err(error) => panic!(
            "the scripted session failed: {error}\n--- transcript ---\n{}",
            String::from_utf8_lossy(&out)
        ),
    };
    (
        result,
        String::from_utf8(out).expect("the transcript is utf-8"),
    )
}

#[test]
fn parse_yes_no_accepts_common_spellings() {
    assert_eq!(parse_yes_no("", true), Some(true));
    assert_eq!(parse_yes_no("", false), Some(false));
    assert_eq!(parse_yes_no("Y", false), Some(true));
    assert_eq!(parse_yes_no("no", true), Some(false));
    assert_eq!(parse_yes_no("0", true), Some(false));
    assert_eq!(parse_yes_no("maybe", true), None);
}

#[test]
fn parse_choice_accepts_numbers_and_names() {
    let options = [("xor", "a"), ("stack", "b")];
    assert_eq!(parse_choice("", &options, 1), Some(1));
    assert_eq!(parse_choice("1", &options, 0), Some(0));
    assert_eq!(parse_choice("2", &options, 0), Some(1));
    assert_eq!(parse_choice("STACK", &options, 0), Some(1));
    assert_eq!(parse_choice("3", &options, 0), None);
    assert_eq!(parse_choice("nope", &options, 0), None);
}

#[test]
fn parse_multi_sorts_and_dedups() {
    let options = [("a", ""), ("b", ""), ("c", "")];
    assert_eq!(parse_multi("", &options), Some(vec![]));
    assert_eq!(parse_multi("3,1,1", &options), Some(vec![0, 2]));
    assert_eq!(parse_multi("b c", &options), Some(vec![1, 2]));
    assert_eq!(parse_multi("9", &options), None);
}

#[test]
fn parse_number_stays_within_bounds() {
    assert_eq!(parse_number("", 5, 0, 10), Some(5));
    assert_eq!(parse_number("0", 5, 0, 10), Some(0));
    assert_eq!(parse_number("1_000", 0, 0, 2000), Some(1000));
    assert_eq!(parse_number("11", 5, 0, 10), None);
    assert_eq!(parse_number("abc", 5, 0, 10), None);
}

#[test]
fn split_list_trims_and_drops_empty_items() {
    assert_eq!(split_list(" a , b ,, "), vec!["a", "b"]);
    assert!(split_list("  ").is_empty());
}

#[test]
fn default_name_uses_the_file_stem() {
    assert_eq!(default_name(Path::new("C:\\tmp\\mimikatz.exe")), "mimikatz");
    assert_eq!(default_name(Path::new("payload")), "payload");
}

#[test]
fn payload_format_is_detected_from_content_and_extension() {
    let detect = crate::plan::format::detect;
    assert_eq!(
        detect(Path::new("examples/payloads/hello_world.exe")),
        PayloadFormat::Pe
    );
    assert_eq!(
        detect(Path::new("examples/payloads/demo_shellcode.bin")),
        PayloadFormat::Shellcode
    );
    assert_eq!(
        detect(Path::new("tests/fixtures/managed_anycpu.exe")),
        PayloadFormat::Dotnet
    );
    // A missing file falls back to the extension.
    assert_eq!(detect(Path::new("missing.dll")), PayloadFormat::Dll);
    assert_eq!(detect(Path::new("missing.bin")), PayloadFormat::Shellcode);
    assert_eq!(detect(Path::new("missing.ps1")), PayloadFormat::Powershell);
}

#[test]
fn shellcode_output_is_selectable_and_uses_the_bin_extension() {
    let dir = temp_dir("shellcode_output");
    let plan_path = dir.join("out.yaml");
    let answers = [
        "demo",
        "",
        "",
        "shellcode", // payload
        "",
        "", // strings, syscalls
        "add a step",
        "reflective_loading",
        "done",
        "",
        "",
        "", // output
        "", // review -> build now
    ];

    let (written, _) = session("payload.exe", &answers, Some(&plan_path));
    assert_eq!(written.as_deref(), Some(plan_path.as_path()));

    let plan = load_plan(&plan_path, &BTreeMap::new()).expect("valid plan");
    assert_eq!(plan.build.output.kind, OutputKind::Shellcode);
    assert_eq!(
        plan.build.output.path,
        Some(PathBuf::from("./dist/demo_packed.bin"))
    );
}

/// The default answers (stub, one reflective step, output, build) produce a
/// plan the packer accepts as-is.
#[test]
fn defaults_produce_a_valid_reflective_plan() {
    let dir = temp_dir("defaults");
    let plan_path = dir.join("out.yaml");
    let answers = [
        "",                   // name
        "",                   // payload args
        "",                   // arch -> x64
        "",                   // output kind -> exe
        "",                   // strings -> xor
        "",                   // syscalls -> none
        "add a step",         // runtime action
        "reflective_loading", // the execution technique
        "done",               // accept the chain
        "",                   // output path
        "",                   // strip
        "",                   // trim paths
        "",                   // review -> build now
    ];

    let (written, transcript) = session("payload.exe", &answers, Some(&plan_path));

    assert_eq!(written.as_deref(), Some(plan_path.as_path()));
    assert!(
        transcript.contains("build interactive"),
        "no echo: {transcript}"
    );

    let plan = load_plan(&plan_path, &BTreeMap::new()).expect("valid plan");
    assert_eq!(plan.name, "payload");
    assert_eq!(plan.build.output.arch, Arch::X64, "the default arch is x64");
    assert_eq!(
        plan.build.output.kind,
        OutputKind::Exe,
        "the default output kind is exe"
    );
    let payload = plan.build.payloads.get("payload").expect("the payload");
    assert_eq!(payload.source, "payload.exe");
    assert!(payload.args.is_none());
    assert!(plan.build.crypto.is_some(), "build.crypto is the default");
    assert_eq!(
        plan.build.output.path,
        Some(PathBuf::from("./dist/payload_packed.exe"))
    );
    assert!(plan.build.output.strip);
    assert_eq!(plan.runtime.len(), 1);
    assert!(
        matches!(
            plan.runtime[0].technique,
            TechniqueKind::ReflectiveLoading { .. }
        ),
        "got {:?}",
        plan.runtime[0]
    );
    // The stub is configured before the runtime; `none` is the default, so
    // no syscall block is written.
    assert!(plan.build.stub.syscalls.is_none());
    assert!(plan.build.stub.strings.is_some());
}

/// The syscall layer is configured before the runtime, and `indirect` asks
/// for the resolver and stack spoofing.
#[test]
fn indirect_syscalls_ask_for_the_resolver_and_stack_spoofing() {
    let dir = temp_dir("indirect");
    let plan_path = dir.join("out.yaml");
    let answers = [
        "",
        "",
        "",
        "",           // payload
        "",           // strings -> xor
        "indirect",   // syscalls
        "halos_gate", // resolver
        "y",          // stack spoofing
        "add a step",
        "reflective_loading",
        "done",
        "",
        "",
        "", // output
        "", // review -> build now
    ];

    let (written, _) = session("payload.exe", &answers, Some(&plan_path));
    assert_eq!(written.as_deref(), Some(plan_path.as_path()));

    let plan = load_plan(&plan_path, &BTreeMap::new()).expect("valid plan");
    let syscalls = plan.build.stub.syscalls.expect("indirect block");
    assert_eq!(syscalls.mode, "indirect");
    assert_eq!(syscalls.resolver, "halos_gate");
    assert!(syscalls.stack_spoofing.is_some());
}

/// The execution techniques the wizard has tailored questions for must
/// honour the answers instead of silently keeping the `params_example`
/// defaults.
#[test]
fn prompts_the_execution_technique_params() {
    // module_stomping: which module to stomp.
    let dir = temp_dir("exec_params_module");
    let plan_path = dir.join("out.yaml");
    let answers = [
        "demo",
        "",
        "",
        "",
        "", // strings -> xor
        "", // syscalls -> none
        "add a step",
        "module_stomping",
        "dbghelp.dll",
        "done",
        "", // output path
        "", // strip
        "", // trim paths
        "", // review -> build now
    ];
    let (written, _) = session("payload.bin", &answers, Some(&plan_path));
    assert_eq!(written.as_deref(), Some(plan_path.as_path()));
    let plan = load_plan(&plan_path, &BTreeMap::new()).expect("valid plan");
    match &plan.runtime[0].technique {
        TechniqueKind::ModuleStomping { params } => {
            assert_eq!(params.module, "dbghelp.dll");
            assert_eq!(params.payload, None);
        }
        other => panic!("expected module_stomping, got {other:?}"),
    }

    // early_bird: the target and the bounded wait.
    let dir = temp_dir("exec_params_early_bird");
    let plan_path = dir.join("out.yaml");
    let answers = [
        "demo",
        "",
        "",
        "",
        "", // strings -> xor
        "", // syscalls -> none
        "add a step",
        "early_bird",
        "C:\\Windows\\System32\\notepad.exe",
        "1500",
        "done",
        "", // output path
        "", // strip
        "", // trim paths
        "", // review -> build now
    ];
    let (written, _) = session("payload.bin", &answers, Some(&plan_path));
    assert_eq!(written.as_deref(), Some(plan_path.as_path()));
    let plan = load_plan(&plan_path, &BTreeMap::new()).expect("valid plan");
    match &plan.runtime[0].technique {
        TechniqueKind::EarlyBird { params } => {
            assert_eq!(params.target, "C:\\Windows\\System32\\notepad.exe");
            assert_eq!(params.wait_ms, 1500);
        }
        other => panic!("expected early_bird, got {other:?}"),
    }
    let payload = plan.build.payloads.get("payload").expect("the payload");
    assert_eq!(payload.format, PayloadFormat::Shellcode);
}

/// `reflective_loading` asks for `patch_exit` when the payload has an import
/// table (PE/DLL), and skips the question for raw shellcode, which `plan::
/// validate` would reject.
#[test]
fn prompts_the_reflective_patch_exit_only_for_a_pe_image() {
    let dir = temp_dir("patch_exit_pe");
    let plan_path = dir.join("out.yaml");
    let answers = [
        "demo",
        "",
        "", // arch
        "", // output kind
        "", // strings
        "", // syscalls
        "add a step",
        "reflective_loading",
        "y", // patch exit
        "done",
        "", // output path
        "", // strip
        "", // trim paths
        "", // review -> build now
    ];
    let (written, _) = session(
        "examples/payloads/hello_world.exe",
        &answers,
        Some(&plan_path),
    );
    assert_eq!(written.as_deref(), Some(plan_path.as_path()));
    let plan = load_plan(&plan_path, &BTreeMap::new()).expect("valid plan");
    match &plan.runtime[0].technique {
        TechniqueKind::ReflectiveLoading { params } => {
            assert!(params.patch_exit, "the answer must reach the plan");
            assert_eq!(params.payload, None);
        }
        other => panic!("expected reflective_loading, got {other:?}"),
    }

    // A shellcode payload is not asked: the script has no answer for it.
    let dir = temp_dir("patch_exit_shellcode");
    let plan_path = dir.join("out.yaml");
    let answers = [
        "demo",
        "",
        "", // arch
        "", // output kind
        "", // strings
        "", // syscalls
        "add a step",
        "reflective_loading",
        "done",
        "", // output path
        "", // strip
        "", // trim paths
        "", // review -> build now
    ];
    let (written, _) = session("payload.bin", &answers, Some(&plan_path));
    assert_eq!(written.as_deref(), Some(plan_path.as_path()));
    let plan = load_plan(&plan_path, &BTreeMap::new()).expect("valid plan");
    match &plan.runtime[0].technique {
        TechniqueKind::ReflectiveLoading { params } => {
            assert!(!params.patch_exit);
        }
        other => panic!("expected reflective_loading, got {other:?}"),
    }
}

/// Every Execution technique must assemble a plan the packer accepts.
///
/// The wizard writes a single payload and never asks for its format, so the
/// assembled plan must use a format the chosen technique runs
/// (`dotnet_hosting` hosts a managed assembly; the in-process shellcode
/// runners execute raw code) and the step's `params_example` must not name
/// a payload the plan does not declare.
#[test]
fn every_execution_technique_assembles_a_valid_plan() {
    use crate::plan::validate;

    for def in execution_defs() {
        let execution = default_step(def).expect("params_example parses");
        let format = def.formats.first().copied().unwrap_or(PayloadFormat::Pe);
        let answers = Answers {
            name: "demo".to_string(),
            payload_args: Vec::new(),
            payload_format: format,
            runtime: vec![execution.clone()],
            strings_strategy: "xor".to_string(),
            syscalls_mode: "none".to_string(),
            syscalls_resolver: "hells_gate".to_string(),
            stack_spoofing: false,
            output_path: "./dist/demo_packed.exe".to_string(),
            output_kind: OutputKind::Exe,
            dll_entry: DllEntry::Auto,
            arch: "x64".to_string(),
            strip: true,
            trim_paths: TrimPaths::All,
        };

        let plan = assemble(Path::new("payload.exe"), &answers);
        let payload = plan.build.payloads.get("payload").expect("the payload");
        assert_eq!(
            payload.format, format,
            "{}: the payload format must be one the technique runs",
            def.name
        );
        validate::validate(&plan).unwrap_or_else(|e| panic!("{}: {e}", def.name));
    }
}

/// The wizard names its payload after the input file, so an Execution
/// technique's `params_example` must not name one: the default step would
/// reference a payload the plan never declares.
fn execution_defs() -> Vec<&'static TechniqueDef> {
    techniques::all()
        .iter()
        .filter(|def| def.category == Category::Execution)
        .filter(|def| def.name != "import_powermodule")
        .collect()
}

#[test]
fn execution_params_examples_do_not_name_a_payload() {
    for def in execution_defs() {
        let step: RuntimeStep =
            serde_yml::from_str(def.params_example).expect("params_example parses");
        assert!(
            step.technique.payload_name().is_none(),
            "{}: params_example names a payload; the wizard's payload is named after the input \
                 file",
            def.name
        );
    }
}

/// A full script exercises the execution choice, a preparation with several
/// follow-ups, the payload args and the syscall default.
#[test]
fn hollowing_with_a_bouncer_keeps_the_pipeline_order() {
    let dir = temp_dir("hollowing");
    let plan_path = dir.join("out.yaml");
    let answers = [
        "demo",              // name
        "a,b",               // payload args
        "2",                 // arch -> x86
        "",                  // output kind -> exe
        "",                  // strings -> xor
        "",                  // syscalls -> none (indirect is x64-only)
        "add a step",        // runtime action
        "bouncer",           // preparation
        "",                  // bouncer on_reject.action -> abort
        "1,10",              // checks: hostname + not_in_vm
        "WORKSTATION-*",     // hostname
        "add a step",        // runtime action
        "process_hollowing", // execution
        "",                  // target -> default
        "done",              // accept the chain
        "",                  // output path
        "",                  // strip
        "",                  // trim paths
        "",                  // review -> build now
    ];

    let (written, _) = session(
        payload_copy(&dir, "mimikatz.exe").as_str(),
        &answers,
        Some(&plan_path),
    );
    assert!(written.is_some());

    let plan = load_plan(&plan_path, &BTreeMap::new()).expect("valid plan");
    assert_eq!(plan.name, "demo");
    assert_eq!(
        plan.build.payloads.get("mimikatz").expect("payload").args,
        Some(vec!["a".to_string(), "b".to_string()])
    );

    assert_eq!(plan.runtime.len(), 2);
    let TechniqueKind::Bouncer { params } = &plan.runtime[0].technique else {
        panic!("expected a bouncer first, got {:?}", plan.runtime[0]);
    };
    assert_eq!(params.on_reject.action, bouncer::RejectAction::Abort);
    assert_eq!(
        params.require,
        vec![bouncer::Requirement::Hostname("WORKSTATION-*".to_string())]
    );
    assert!(params.anti_analysis.hypervisor);

    let TechniqueKind::ProcessHollowing { params } = &plan.runtime[1].technique else {
        panic!(
            "expected process_hollowing second, got {:?}",
            plan.runtime[1]
        );
    };
    assert_eq!(params.target, process_hollowing::default_target());

    // The wizard can produce an x86 plan (`x86` was chosen above), and for
    // x86 it does not offer `syscalls: indirect` at all.
    assert_eq!(plan.build.output.arch, Arch::X86);
    assert!(
        plan.build.stub.syscalls.is_none(),
        "an x86 plan must not select indirect syscalls"
    );
}

/// Copies a real PE next to the generated plan, so format detection reads
/// the file instead of trusting a name that does not exist.
fn payload_copy(dir: &Path, name: &str) -> String {
    let path = dir.join(name);
    std::fs::copy("examples/payloads/test_payload.exe", &path).expect("copy the fixture");
    path.to_str().expect("utf-8 path").to_string()
}

/// A shellcode payload can run several in-process steps: the wizard appends
/// Control and Execution steps in order, and every appended Execution step
/// references the single payload.
#[test]
fn a_multi_step_runtime_appends_steps_in_order() {
    let dir = temp_dir("multistep");
    let plan_path = dir.join("out.yaml");
    let answers = [
        "demo",                // name
        "",                    // payload args
        "",                    // arch -> x64
        "",                    // output kind -> exe
        "",                    // strings -> xor
        "",                    // syscalls -> none
        "add a step",          // runtime action
        "fibers",              // execution (a shellcode runner)
        "add a step",          // runtime action
        "sleep",               // control
        "500",                 // sleep ms
        "add a step",          // runtime action
        "living_off_the_land", // control
        "certutil.exe",        // binary
        "-urlcache,-f",        // args
        "add a step",          // runtime action
        "module_stomping",     // execution (returns for shellcode)
        "dbghelp.dll",         // module
        "done",                // accept the chain
        "",                    // output path
        "",                    // strip
        "",                    // trim paths
        "",                    // review -> build now
    ];

    let (written, _) = session("payload.bin", &answers, Some(&plan_path));
    assert_eq!(written.as_deref(), Some(plan_path.as_path()));

    let plan = load_plan(&plan_path, &BTreeMap::new()).expect("valid plan");
    assert_eq!(plan.runtime.len(), 4);

    let TechniqueKind::Fibers { params } = &plan.runtime[0].technique else {
        panic!("expected fibers first, got {:?}", plan.runtime[0]);
    };
    assert_eq!(params.payload, None);

    let TechniqueKind::Sleep { params } = &plan.runtime[1].technique else {
        panic!("expected sleep second, got {:?}", plan.runtime[1]);
    };
    assert_eq!(params.ms, 500);

    let TechniqueKind::LivingOffTheLand { params } = &plan.runtime[2].technique else {
        panic!(
            "expected living_off_the_land third, got {:?}",
            plan.runtime[2]
        );
    };
    assert_eq!(params.binary, "certutil.exe");
    assert_eq!(params.args, vec!["-urlcache", "-f"]);

    let TechniqueKind::ModuleStomping { params } = &plan.runtime[3].technique else {
        panic!("expected module_stomping fourth, got {:?}", plan.runtime[3]);
    };
    assert_eq!(params.module, "dbghelp.dll");
    assert_eq!(params.payload, None);

    // Every appended step still references the one wizard payload.
    let payload = plan.build.payloads.get("payload").expect("the payload");
    assert_eq!(payload.format, PayloadFormat::Shellcode);
}

/// Steps can be added before a terminal execution; the terminal step stays
/// last.
#[test]
fn steps_can_be_added_before_a_terminal_execution() {
    let dir = temp_dir("terminal");
    let plan_path = dir.join("out.yaml");
    let answers = [
        "",
        "",
        "",
        "", // payload
        "",
        "", // strings, syscalls
        "add a step",
        "patch_amsi",
        "", // also patch AmsiScanString -> default (yes)
        "", // also patch AmsiOpenSession -> default (yes)
        "add a step",
        "reflective_loading",
        "done",
        "",
        "",
        "", // output
        "", // review -> build now
    ];

    let (written, _) = session("payload.exe", &answers, Some(&plan_path));
    assert_eq!(written.as_deref(), Some(plan_path.as_path()));

    let plan = load_plan(&plan_path, &BTreeMap::new()).expect("valid plan");
    assert_eq!(plan.runtime.len(), 2);
    assert!(matches!(
        plan.runtime[0].technique,
        TechniqueKind::PatchAmsi { .. }
    ));
    assert!(matches!(
        plan.runtime[1].technique,
        TechniqueKind::ReflectiveLoading { .. }
    ));
}

/// `kind: dll` turns the wizard into a DLL build: it asks for the entry, the
/// default path carries the `.dll` extension, and the preparations that act
/// on the running image are not offered (a DLL's image is the host's).
#[test]
fn a_dll_build_asks_for_the_entry_and_hides_image_scoped_preparations() {
    let dir = temp_dir("dll");
    let plan_path = dir.join("out.yaml");
    let answers = [
        "demo", // name
        "",     // payload args
        "",     // arch -> x64
        "dll",  // output kind
        "",     // strings
        "",     // syscalls
        "add a step",
        "reflective_loading",
        "done",
        "export", // entry
        "Start",  // export name
        "",       // output path -> default
        "",       // strip
        "",       // trim paths
        "",       // review -> build now
    ];

    let (written, transcript) = session("payload.exe", &answers, Some(&plan_path));
    assert_eq!(written.as_deref(), Some(plan_path.as_path()));

    let plan = load_plan(&plan_path, &BTreeMap::new()).expect("valid plan");
    let output = &plan.build.output;
    assert_eq!(output.kind, OutputKind::Dll);
    assert_eq!(output.entry, DllEntry::Export("Start".to_string()));
    assert_eq!(
        output.path,
        Some(PathBuf::from("./dist/demo_packed.dll")),
        "a DLL build defaults to the `.dll` extension"
    );

    // `self_deletion` and `sleep_obfuscation` rewrite the running image,
    // which in a DLL build is the host, so `plan::validate` rejects them. The
    // runtime editor reports them as unavailable with the reason.
    assert!(
        transcript.contains("self_deletion (mutates the host image in a DLL build)")
            && transcript.contains("sleep_obfuscation (mutates the host image in a DLL build)"),
        "image-scoped preparations must be reported unavailable: {transcript}"
    );
}

/// A DLL build never offers `bouncer`'s exiting rejection (which would kill
/// the host process), so the bouncer question flow is one prompt shorter.
#[test]
fn a_dll_build_never_offers_the_process_killing_bouncer_rejection() {
    use crate::techniques::bouncer;

    let dir = temp_dir("dll_bouncer");
    let plan_path = dir.join("out.yaml");
    let answers = [
        "demo", // name
        "",     // payload args
        "",     // arch -> x64
        "dll",  // output kind
        "",     // strings
        "",     // syscalls
        "add a step",
        "bouncer",
        "1",    // checks: hostname
        "PC-*", // hostname
        "add a step",
        "reflective_loading",
        "done",
        "", // entry -> auto
        "", // output path
        "", // strip
        "", // trim paths
        "", // review -> build now
    ];

    let (written, _) = session("payload.exe", &answers, Some(&plan_path));
    assert_eq!(written.as_deref(), Some(plan_path.as_path()));

    let plan = load_plan(&plan_path, &BTreeMap::new()).expect("valid plan");
    let TechniqueKind::Bouncer { params } = &plan.runtime[0].technique else {
        panic!("expected a bouncer first, got {:?}", plan.runtime[0]);
    };
    assert_eq!(
        params.require,
        vec![bouncer::Requirement::Hostname("PC-*".to_string())]
    );
    assert_eq!(
        params.on_reject.action,
        bouncer::RejectAction::Abort,
        "a DLL build must never select the exiting rejection"
    );
    assert_eq!(plan.build.output.kind, OutputKind::Dll);
}

/// Choosing `edit answers` at the review re-asks the questions with the
/// previous values as defaults, so a single field can be corrected.
#[test]
fn editing_answers_updates_a_single_field() {
    let dir = temp_dir("edit");
    let plan_path = dir.join("out.yaml");
    let answers = [
        "first", // name
        "",      // payload args
        "",      // arch
        "",      // output kind
        "",      // strings
        "",      // syscalls
        "add a step",
        "reflective_loading",
        "done",
        "",       // output path
        "",       // strip
        "",       // trim paths
        "2",      // review -> edit answers
        "second", // name (corrected)
        "",       // payload args
        "",       // arch
        "",       // output kind
        "",       // strings
        "",       // syscalls
        "done",   // keep the previous chain
        "",       // output path
        "",       // strip
        "",       // trim paths
        "",       // review -> build now
    ];

    let (written, _) = session("payload.exe", &answers, Some(&plan_path));
    assert!(written.is_some());

    let plan = load_plan(&plan_path, &BTreeMap::new()).expect("valid plan");
    assert_eq!(plan.name, "second");
}

/// Choosing `quit` at the review leaves the disk untouched.
#[test]
fn quitting_the_review_writes_nothing() {
    let dir = temp_dir("aborted");
    let plan_path = dir.join("out.yaml");
    let answers = [
        "",
        "",
        "",
        "", // payload
        "",
        "", // strings, syscalls
        "add a step",
        "reflective_loading",
        "done",
        "",
        "",
        "",  // output
        "3", // review -> quit
    ];

    let (written, _) = session("payload.exe", &answers, Some(&plan_path));

    assert!(written.is_none());
    assert!(!plan_path.exists(), "the plan must not be written");
}

/// A closed stdin mid-session is an error, not a silent all-defaults build.
#[test]
fn truncated_input_is_an_error() {
    let dir = temp_dir("truncated");
    let plan_path = dir.join("out.yaml");
    let err = run_with(
        Path::new("payload.exe"),
        Some(&plan_path),
        &Palette::plain(),
        Cursor::new(String::new()),
        Vec::new(),
    )
    .expect_err("an empty input must fail");
    assert!(
        err.to_string().contains("input ended"),
        "unclear error: {err}"
    );
}
