//! Tests for vector-exception execution.

use super::{Params, DEF, MESSAGES};
use crate::engine::obfuscation::StringsConfig;
use crate::plan::schema::PayloadFormat;
use crate::techniques::{Capability, Category, RuntimeStep, Stability, TechniqueKind};

/// Every message `render_fragment_for` obfuscates must not survive in the
/// rendered fragment as cleartext.
const MESSAGE_TEXTS: &[&str] = &[
    "the payload is empty",
    "could not allocate the payload region",
    "could not make the payload executable",
    "could not allocate the execution stack",
    "could not register the vectored exception handler",
    "the vectored handler never entered the payload",
    "runs raw shellcode payloads only",
];

/// Formats the technique is rendered for, including the ones the fragment
/// refuses at run time (the guard still has to be valid Rust).
const FORMATS: [PayloadFormat; 4] = [
    PayloadFormat::Shellcode,
    PayloadFormat::Pe,
    PayloadFormat::Dll,
    PayloadFormat::Dotnet,
];

fn fragment() -> String {
    let strings = StringsConfig::from_yaml(None).expect("default strings");
    Params::default().render_fragment_for(&strings, PayloadFormat::Shellcode, None)
}

#[test]
fn parses_params_from_empty_yaml() {
    let step: TechniqueKind =
        serde_yml::from_str("technique: veh_execution\n").expect("veh_execution should parse");
    assert_eq!(
        step,
        TechniqueKind::VehExecution {
            params: Params::default()
        }
    );
}

#[test]
fn parses_a_payload_name() {
    let step: TechniqueKind =
        serde_yml::from_str("technique: veh_execution\nparams:\n  payload: implant\n")
            .expect("veh_execution with a payload should parse");
    match step {
        TechniqueKind::VehExecution { params } => {
            assert_eq!(params.payload.as_deref(), Some("implant"));
        }
        other => panic!("expected veh_execution, got {other:?}"),
    }
}

#[test]
fn def_is_well_formed() {
    assert_eq!(DEF.name, "veh_execution");
    assert_eq!(DEF.category, Category::Execution);
    assert_eq!(DEF.formats, &[PayloadFormat::Shellcode]);
    assert_eq!(DEF.stability, Stability::Experimental);
    assert_eq!(DEF.requires, &[Capability::WindowsX64]);
    assert_eq!(DEF.attck, &["T1106", "T1620"]);
    assert_eq!(
        DEF.syscalls,
        &["NtAllocateVirtualMemory", "NtProtectVirtualMemory"]
    );
    // Through the registry, so the assertion reads a runtime value rather than
    // a compile-time constant.
    let registered = crate::techniques::find("veh_execution").expect("registered");
    assert!(!registered.resolves_imports);
    assert!(!DEF.stub_fragment.is_empty());
    assert!(!DEF.readme.is_empty());
}

#[test]
fn params_example_parses_as_a_runtime_step() {
    let step: RuntimeStep =
        serde_yml::from_str(DEF.params_example).expect("params_example must parse");
    assert_eq!(step.name(), "veh_execution");
}

#[test]
fn the_fragment_defines_the_execution_contract() {
    assert!(
        DEF.stub_fragment
            .contains("pub fn execute_payload(image: &mut [u8]) -> Result<i32, String>"),
        "the generated wrapper calls exactly this signature"
    );
}

#[test]
fn every_placeholder_is_substituted_for_every_format() {
    let strings = StringsConfig::from_yaml(None).expect("default strings");
    for format in FORMATS {
        let rendered = Params::default().render_fragment_for(&strings, format, None);
        assert!(
            !rendered.contains('$'),
            "an unsubstituted placeholder would break the stub ({format:?})"
        );
    }
}

#[test]
fn the_message_table_covers_exactly_the_fragment_placeholders() {
    let rendered = fragment();
    for (placeholder, _) in MESSAGES {
        assert!(
            DEF.stub_fragment.contains(placeholder),
            "{placeholder} is in MESSAGES but no longer in the fragment"
        );
        assert!(
            !rendered.contains(placeholder),
            "{placeholder} was not substituted"
        );
    }
}

#[test]
fn rendered_fragment_hides_every_message() {
    let xor = StringsConfig::from_yaml(None).expect("default strings");
    let stack = StringsConfig {
        strategy: crate::engine::obfuscation::StringStrategy::Stack,
        key: None,
    };

    for strings in [xor, stack] {
        for format in FORMATS {
            let rendered = Params::default().render_fragment_for(&strings, format, None);
            for text in MESSAGE_TEXTS {
                assert!(
                    !rendered.contains(text),
                    "message text leaked in cleartext ({format:?}): {text}"
                );
            }
        }
    }
}

#[test]
fn the_format_guard_marks_shellcode_supported() {
    let strings = StringsConfig::from_yaml(None).expect("default strings");
    let params = Params::default();

    let shellcode = params.render_fragment_for(&strings, PayloadFormat::Shellcode, None);
    assert!(
        shellcode.contains("if !true"),
        "a shellcode payload must pass the format guard"
    );

    let pe = params.render_fragment_for(&strings, PayloadFormat::Pe, None);
    assert!(
        pe.contains("if !false"),
        "a non-shellcode payload must hit the format guard"
    );
    assert!(
        !pe.contains("format is 'pe'"),
        "the guard message must be obfuscated, not inlined"
    );
}

#[test]
fn the_fragment_routes_kernel_memory_calls_through_the_syscall_layer() {
    for forbidden in [
        "VirtualAlloc(",
        "VirtualAllocEx(",
        "VirtualProtect(",
        "VirtualProtectEx(",
        "VirtualFree(",
        "CreateThread(",
        "CreateRemoteThread(",
        "WriteProcessMemory(",
        "ExitProcess(",
    ] {
        assert!(
            !DEF.stub_fragment.contains(forbidden),
            "a stub fragment must not call '{forbidden}' directly"
        );
    }
    assert!(
        DEF.stub_fragment.contains("crate::nt_alloc_vm("),
        "the payload and stack allocations must go through the syscall layer"
    );
    assert!(
        DEF.stub_fragment.contains("crate::nt_protect_vm("),
        "page protection must go through the syscall layer"
    );
}

#[test]
fn the_fragment_raises_a_breakpoint_and_redirects_it() {
    let rendered = fragment();
    assert!(rendered.contains("global_asm!"));
    assert!(rendered.contains("\"int3\""));
    assert!(rendered.contains("AddVectoredExceptionHandler"));
    assert!(rendered.contains("RemoveVectoredExceptionHandler"));
    assert!(rendered.contains("EXCEPTION_CONTINUE_EXECUTION"));
    assert!(
        rendered.contains("context.Rip = entry as u64;"),
        "the handler must redirect the faulting instruction"
    );
    assert!(
        rendered.contains("context.Rsp = new_rsp as u64;"),
        "the payload must run on the dedicated stack"
    );
    assert!(
        rendered.contains("RESUME.store(context.Rip.wrapping_add(1) as usize"),
        "a breakpoint's context points at the int3, so the resume address is +1"
    );
}

#[test]
fn the_payload_runs_on_its_own_stack() {
    let rendered = fragment();
    assert!(rendered.contains("const STACK_BYTES: usize = 64 * 1024;"));
    assert!(rendered.contains("wrapping_add(stack_size)"));
    assert!(
        rendered.contains("wrapping_sub(0x38)"),
        "the call frame needs a return address and 32 bytes of shadow space"
    );
}

#[test]
fn only_the_triggers_own_breakpoint_is_redirected() {
    let rendered = fragment();
    assert!(
        rendered.contains("static TRIGGER: AtomicUsize"),
        "the trigger address must be published"
    );
    let compare = rendered
        .find("(*info.ExceptionRecord).ExceptionAddress as usize != trigger")
        .expect("the handler must compare the faulting address");
    let armed = rendered
        .find("if ARMED.swap(0, Ordering::SeqCst) == 0")
        .expect("the one-shot gate must exist");
    assert!(
        compare < armed,
        "a foreign breakpoint must be rejected before the one-shot gate is consumed"
    );
    assert!(
        rendered.contains("_int3:"),
        "the published address must be the int3 label, not the trigger's entry"
    );
    assert!(rendered.contains("TRIGGER.store("));
}

#[test]
fn fragment_has_no_forbidden_patterns() {
    for forbidden in [
        "anyhow",
        "static mut",
        "println!",
        "unwrap(",
        "expect(",
        "todo!",
        "unimplemented!",
        "panic!",
    ] {
        assert!(
            !DEF.stub_fragment.contains(forbidden),
            "a stub fragment must not contain '{forbidden}'"
        );
    }
}
