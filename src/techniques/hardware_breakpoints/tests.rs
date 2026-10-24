//! Tests for the hardware-breakpoint bypass technique.

use super::{Params, DEF};
use crate::engine::obfuscation::StringsConfig;
use crate::techniques::TechniqueKind;

#[test]
fn parses_params_from_empty_yaml_and_watches_the_load_bearing_exports() {
    let step: TechniqueKind =
        serde_yml::from_str("technique: hardware_breakpoints\n").expect("should parse");
    assert_eq!(
        step,
        TechniqueKind::HardwareBreakpoints {
            params: Params {
                amsi: true,
                scan_string: false,
                open_session: false,
                etw: true,
            }
        }
    );
}

#[test]
fn parses_explicit_watch_flags() {
    let step: TechniqueKind = serde_yml::from_str(
        "technique: hardware_breakpoints\nparams:\n  amsi: false\n  scan_string: true\n  open_session: true\n  etw: false\n",
    )
    .expect("should parse");
    assert_eq!(
        step,
        TechniqueKind::HardwareBreakpoints {
            params: Params {
                amsi: false,
                scan_string: true,
                open_session: true,
                etw: false,
            }
        }
    );
}

#[test]
fn def_is_well_formed() {
    assert_eq!(DEF.name, "hardware_breakpoints");
    assert_eq!(DEF.attck, &["T1562.001", "T1562.006"]);
    assert_eq!(DEF.category, crate::techniques::Category::Preparation);
    assert_eq!(DEF.stability, crate::techniques::Stability::Experimental);
    assert_eq!(DEF.requires, &[crate::techniques::Capability::WindowsX64]);
    assert_eq!(DEF.conflicts, &["patch_amsi", "patch_etw"]);
    assert_eq!(DEF.syscalls, &["NtGetContextThread", "NtSetContextThread"]);
    assert!(DEF.formats.is_empty());
    assert!(!DEF.stub_fragment.is_empty());
    assert!(!DEF.readme.is_empty());
}

#[test]
fn fragment_has_no_forbidden_patterns() {
    for forbidden in [
        "println!",
        "unwrap",
        "expect",
        "todo!",
        "unimplemented!",
        "anyhow",
    ] {
        assert!(
            !DEF.stub_fragment.contains(forbidden),
            "stub_fragment.rs must not contain '{forbidden}'"
        );
    }
}

#[test]
fn render_fragment_obfuscates_literals() {
    let strings = StringsConfig::from_yaml(None).expect("default strings");
    let fragment = Params::default().render_fragment(&strings);

    // The entry point is present, the placeholders are substituted, and the
    // runtime byte literals must not appear in cleartext.
    assert!(fragment.contains("fn hardware_breakpoints"));
    assert!(fragment.contains("const WATCH_AMSI: bool = true;"));
    assert!(fragment.contains("const WATCH_SCAN_STRING: bool = false;"));
    assert!(fragment.contains("const WATCH_OPEN_SESSION: bool = false;"));
    assert!(fragment.contains("const WATCH_ETW: bool = true;"));
    for placeholder in [
        "$AMSI_DLL_DEF$",
        "$AMSI_SCAN_BUFFER_DEF$",
        "$AMSI_SCAN_STRING_DEF$",
        "$AMSI_OPEN_SESSION_DEF$",
        "$NTDLL_DLL_DEF$",
        "$ETW_WRITE_DEF$",
        "$WATCH_AMSI$",
        "$WATCH_SCAN_STRING$",
        "$WATCH_OPEN_SESSION$",
        "$WATCH_ETW$",
        "$MSG_LOAD_FAILED$",
        "$MSG_RESOLVE_FAILED$",
        "$MSG_CONTEXT_READ_FAILED$",
        "$MSG_CONTEXT_ARM_FAILED$",
    ] {
        assert!(
            !fragment.contains(placeholder),
            "placeholder {placeholder} was not substituted"
        );
    }
    assert!(!fragment.contains("b\"amsi.dll"));
    assert!(!fragment.contains("b\"AmsiScanBuffer"));
    assert!(!fragment.contains("b\"AmsiScanString"));
    assert!(!fragment.contains("b\"AmsiOpenSession"));
    assert!(!fragment.contains("b\"ntdll.dll"));
    assert!(!fragment.contains("b\"EtwEventWrite"));
    assert!(fragment.contains("crate::dec_xor"));
    assert!(
        crate::audit::strings::find_sensitive_literals_in_source(&fragment).is_empty(),
        "cleartext sensitive literal in the rendered fragment"
    );
}

#[test]
fn fragment_arms_the_debug_registers_and_returns_clean() {
    // The shape the runtime depends on: an x64 result offset per scan export,
    // the execute-breakpoint enable bits, and a handler that resumes at the
    // caller. A regression here compiles but misbehaves, so pin it.
    let fragment = DEF.stub_fragment;
    assert!(fragment.contains("const AMSI_SCAN_BUFFER_RESULT_OFFSET: usize = 0x30;"));
    assert!(fragment.contains("const AMSI_SCAN_STRING_RESULT_OFFSET: usize = 0x28;"));
    assert!(fragment.contains("EXCEPTION_SINGLE_STEP"));
    assert!(fragment.contains("AddVectoredExceptionHandler"));
    assert!(fragment.contains("dr7 |= 1 << (slot * 2);"));
    assert!(fragment.contains("context.Rip = return_address;"));
    assert!(fragment.contains("EXCEPTION_CONTINUE_EXECUTION"));
    assert!(fragment.contains("crate::nt_get_context_thread"));
    assert!(fragment.contains("crate::nt_set_context_thread"));
}

#[test]
fn selecting_the_optional_amsi_exports_without_the_buffer_scan_is_refused() {
    let strings = StringsConfig::from_yaml(None).expect("default strings");
    let fragment = Params {
        amsi: false,
        scan_string: true,
        open_session: true,
        etw: false,
    }
    .render_fragment(&strings);

    let guard = fragment
        .find("if !WATCH_AMSI && (WATCH_SCAN_STRING || WATCH_OPEN_SESSION)")
        .expect("the impossible combination must be refused");
    let error = fragment[guard..]
        .find("return Err(")
        .expect("the refusal must return an error");
    let resolve = fragment[guard..]
        .find("load_module(")
        .expect("the watch table must still be built");
    assert!(
        error < resolve,
        "the check must run before anything is resolved or armed"
    );
}

#[test]
fn open_session_clears_the_session_pointer_and_the_handler_is_checked() {
    let strings = StringsConfig::from_yaml(None).expect("default strings");
    let fragment = Params {
        amsi: true,
        scan_string: false,
        open_session: true,
        etw: false,
    }
    .render_fragment(&strings);

    assert!(fragment.contains("const AMSI_OPEN_SESSION_SENTINEL: usize = usize::MAX;"));
    assert!(fragment.contains("const AMSI_OPEN_SESSION_SESSION_OFFSET: usize = 0x28;"));
    assert!(fragment.contains("(address, AMSI_OPEN_SESSION_SENTINEL)"));
    assert!(
        fragment.contains("if handler.is_null()"),
        "a missing handler must fail before the debug registers are armed"
    );
    let clear = fragment
        .find("offset == AMSI_OPEN_SESSION_SENTINEL")
        .expect("the handler must special-case the sentinel");
    let resume = fragment
        .find("context.Rip = return_address;")
        .expect("the handler must resume the caller");
    assert!(
        clear < resume,
        "the session must be cleared before resuming"
    );
}

#[test]
fn render_fragment_bakes_in_the_selected_exports() {
    let strings = StringsConfig::from_yaml(None).expect("default strings");
    let fragment = Params {
        amsi: false,
        scan_string: true,
        open_session: true,
        etw: false,
    }
    .render_fragment(&strings);
    assert!(fragment.contains("const WATCH_AMSI: bool = false;"));
    assert!(fragment.contains("const WATCH_SCAN_STRING: bool = true;"));
    assert!(fragment.contains("const WATCH_OPEN_SESSION: bool = true;"));
    assert!(fragment.contains("const WATCH_ETW: bool = false;"));
}
