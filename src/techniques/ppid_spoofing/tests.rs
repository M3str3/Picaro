//! Tests for parent-process spoofing.

use super::{default_parent, Params, DEF};
use crate::engine::obfuscation::{StringStrategy, StringsConfig};
use crate::techniques::{Category, TechniqueKind};

/// Parameters with every placeholder-relevant field populated.
fn populated() -> Params {
    Params {
        binary: "certutil.exe".to_string(),
        args: vec!["-urlcache".to_string(), "-f".to_string()],
        parent: "winlogon.exe".to_string(),
        wait: true,
    }
}

#[test]
fn parses_params_from_empty_yaml() {
    let step: TechniqueKind =
        serde_yml::from_str("technique: ppid_spoofing\n").expect("ppid_spoofing should parse");
    assert_eq!(
        step,
        TechniqueKind::PpidSpoofing {
            params: Params::default()
        }
    );
}

#[test]
fn defaults_the_parent_and_waiting() {
    let params = Params::default();
    assert_eq!(params.parent, default_parent());
    assert!(params.wait);
    assert!(params.binary.is_empty());
}

#[test]
fn parses_a_binary_and_args() {
    let step: TechniqueKind =
        serde_yml::from_str("technique: ppid_spoofing\nparams:\n  binary: certutil.exe\n  args: [\"-urlcache\"]\n  parent: winlogon.exe\n  wait: false\n")
            .expect("ppid_spoofing with parameters should parse");
    match step {
        TechniqueKind::PpidSpoofing { params } => {
            assert_eq!(params.binary, "certutil.exe");
            assert_eq!(params.args, vec!["-urlcache".to_string()]);
            assert_eq!(params.parent, "winlogon.exe");
            assert!(!params.wait);
        }
        other => panic!("expected ppid_spoofing, got {other:?}"),
    }
}

#[test]
fn params_example_parses_as_a_runtime_step() {
    let step: TechniqueKind =
        serde_yml::from_str(DEF.params_example).expect("params_example should parse");
    assert_eq!(step.name(), "ppid_spoofing");
}

#[test]
fn def_is_well_formed() {
    assert_eq!(DEF.name, "ppid_spoofing");
    assert_eq!(DEF.category, Category::Control);
    assert!(!DEF.attck.is_empty());
    assert!(!DEF.requires.is_empty());
    assert!(!DEF.stub_fragment.is_empty());
    assert!(!DEF.readme.is_empty());
    assert!(
        DEF.syscalls.is_empty(),
        "the technique is pure Win32: CreateProcessA is an entry point, not a syscall the stub issues"
    );
}

#[test]
fn def_exposes_the_control_entry_point() {
    assert!(
        DEF.stub_fragment.contains("fn run_exec"),
        "the fragment must define the Control contract"
    );
}

#[test]
fn fragment_uses_the_attribute_list_api() {
    for expected in [
        "InitializeProcThreadAttributeList",
        "UpdateProcThreadAttribute",
        "PROC_THREAD_ATTRIBUTE_PARENT_PROCESS",
        "EXTENDED_STARTUPINFO_PRESENT",
        "CreateProcessA",
    ] {
        assert!(
            DEF.stub_fragment.contains(expected),
            "the fragment is missing {expected}"
        );
    }
}

#[test]
fn fragment_keeps_the_parent_handle_alive_until_createprocess() {
    let fragment = DEF.stub_fragment;
    // The early error paths also close the handle; what matters is that the
    // *last* close comes after the process was created.
    let close = fragment
        .rfind("CloseHandle(parent_handle)")
        .expect("the fragment must close the parent handle");
    let create = fragment
        .find("CreateProcessA(")
        .expect("the fragment must create the process");
    assert!(
        close > create,
        "the parent handle must outlive CreateProcessA: the attribute stores its address"
    );
    assert!(
        fragment.contains("Some(&parent_handle as *const HANDLE"),
        "the attribute value must point at the named handle local"
    );
}

#[test]
fn fragment_leaves_no_panic_paths() {
    for forbidden in [
        "println!",
        "unwrap(",
        "expect(",
        "panic!",
        "todo!",
        "unimplemented!",
        "anyhow",
    ] {
        assert!(
            !DEF.stub_fragment.contains(forbidden),
            "the fragment must not use {forbidden}"
        );
    }
}

#[test]
fn render_fragment_substitutes_every_placeholder() {
    let strings = StringsConfig::from_yaml(None).expect("default strings");
    let fragment = populated().render_fragment(&strings);

    assert!(fragment.contains("fn run_exec"));
    for placeholder in [
        "$BINARY_DEF$",
        "$ARGS_DEF$",
        "$PARENT_DEF$",
        "$WAIT$",
        "$ENV_SYSTEMROOT$",
        "$WINDOWS_FALLBACK$",
        "$SYSTEM32_DIR$",
    ] {
        assert!(
            !fragment.contains(placeholder),
            "placeholder {placeholder} was not substituted"
        );
    }
    assert!(
        !fragment.contains('$'),
        "an unsubstituted placeholder is still in the fragment"
    );
    assert!(fragment.contains("let wait: bool = true;"));
}

#[test]
fn detached_mode_is_rendered() {
    let strings = StringsConfig::from_yaml(None).expect("default strings");
    let fragment = Params {
        wait: false,
        ..populated()
    }
    .render_fragment(&strings);

    assert!(fragment.contains("let wait: bool = false;"));
    assert!(!fragment.contains("$WAIT$"));
}

#[test]
fn render_fragment_obfuscates_the_binary_args_and_parent() {
    let strategies = [
        (
            "xor",
            StringsConfig::from_yaml(None).expect("default strings"),
        ),
        (
            "stack",
            StringsConfig {
                strategy: StringStrategy::Stack,
                key: None,
            },
        ),
    ];

    for (label, strings) in strategies {
        let fragment = populated().render_fragment(&strings);

        for secret in ["certutil.exe", "-urlcache", "winlogon.exe"] {
            assert!(
                !fragment.contains(secret),
                "the {label} strategy leaked '{secret}' in cleartext"
            );
        }
        // The launch's own fixed strings must not survive either: a quoted
        // literal would be the giveaway (the words may appear in comments).
        for literal in ["\"SystemRoot\"", "\"System32\"", "\"C:\\\\Windows\""] {
            assert!(
                !fragment.contains(literal),
                "the {label} strategy leaked the literal {literal}"
            );
        }
    }
}

#[test]
fn the_default_xor_strategy_rebuilds_at_runtime() {
    let strings = StringsConfig::from_yaml(None).expect("default strings");
    let fragment = Params::default().render_fragment(&strings);

    assert!(fragment.contains("crate::dec_xor"));
}

#[test]
fn render_fragment_builds_the_child_command_line() {
    let strings = StringsConfig {
        strategy: StringStrategy::Stack,
        key: None,
    };
    let fragment = populated().render_fragment(&strings);

    // The command line is the resolved binary plus the quoted arguments; the
    // helpers survive the substitution and every piece is rendered.
    assert!(fragment.contains("fn resolve_binary"));
    assert!(fragment.contains("fn quote_arg"));
    assert!(fragment.contains("let mut command = quote_arg(&exe);"));
    for name in [
        "launch_binary_buf",
        "launch_parent_buf",
        "launch_arg_0_buf",
        "launch_arg_1_buf",
    ] {
        assert!(fragment.contains(name), "{name} is missing");
    }

    let no_args = Params {
        args: vec![],
        ..populated()
    }
    .render_fragment(&strings);
    assert!(
        no_args.contains("let args: Vec<String> = vec![];"),
        "an empty argument list must render as an empty vector"
    );
}
