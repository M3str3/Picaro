//! Tests for the ETW patch technique.

use super::{Params, DEF};
use crate::audit::strings::find_sensitive_literals_in_source;
use crate::engine::obfuscation::StringsConfig;
use crate::techniques::{Category, TechniqueKind};

#[test]
fn parses_params_from_empty_yaml_and_enables_every_variant() {
    let step: TechniqueKind =
        serde_yml::from_str("technique: patch_etw\n").expect("patch_etw should parse");
    assert_eq!(
        step,
        TechniqueKind::PatchEtw {
            params: Params {
                full: true,
                ex: true,
                nt_trace: true,
            }
        }
    );
}

#[test]
fn parses_explicit_full_false() {
    let step: TechniqueKind = serde_yml::from_str("technique: patch_etw\nparams:\n  full: false\n")
        .expect("patch_etw should parse");
    assert_eq!(
        step,
        TechniqueKind::PatchEtw {
            params: Params {
                full: false,
                ex: true,
                nt_trace: true,
            }
        }
    );
}

#[test]
fn parses_explicit_ex_and_nt_trace_false() {
    let step: TechniqueKind =
        serde_yml::from_str("technique: patch_etw\nparams:\n  ex: false\n  nt_trace: false\n")
            .expect("patch_etw should parse");
    assert_eq!(
        step,
        TechniqueKind::PatchEtw {
            params: Params {
                full: true,
                ex: false,
                nt_trace: false,
            }
        }
    );
}

#[test]
fn def_is_well_formed() {
    assert_eq!(DEF.name, "patch_etw");
    assert_eq!(DEF.attck, &["T1562.006"]);
    assert_eq!(DEF.category, Category::Preparation);
    assert!(DEF.conflicts.is_empty());
    assert_eq!(DEF.syscalls, &["NtProtectVirtualMemory"]);
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
        "panic!",
    ] {
        assert!(
            !DEF.stub_fragment.contains(forbidden),
            "stub_fragment.rs must not contain '{forbidden}'"
        );
    }
}

#[test]
fn x86_patches_return_with_the_export_argument_bytes() {
    let strings = StringsConfig::from_yaml(None).expect("default strings");
    let fragment = Params::default().render_fragment(&strings);

    // `xor eax, eax; ret imm16` — five bytes, and the `imm16` is the `@N`
    // decoration of the stdcall export. A bare `ret` would leave 20, 32, 40 or
    // 16 bytes on the caller's stack.
    for (name, bytes) in [
        ("ETW_WRITE_PATCH", "[0x33, 0xC0, 0xC2, 0x14, 0x00]"),
        ("ETW_WRITE_FULL_PATCH", "[0x33, 0xC0, 0xC2, 0x20, 0x00]"),
        ("ETW_WRITE_EX_PATCH", "[0x33, 0xC0, 0xC2, 0x28, 0x00]"),
        ("ETW_NT_TRACE_PATCH", "[0x33, 0xC0, 0xC2, 0x10, 0x00]"),
    ] {
        assert!(
            fragment.contains(&format!("const {name}: [u8; 5] = {bytes};")),
            "{name} must be a five-byte ret imm16 patch on x86"
        );
    }
    assert_eq!(
        fragment.matches("#[cfg(target_arch = \"x86\")]").count(),
        4,
        "every export needs its own x86 patch"
    );
}

#[test]
fn x64_patches_stay_three_byte_returns() {
    let strings = StringsConfig::from_yaml(None).expect("default strings");
    let fragment = Params::default().render_fragment(&strings);

    for name in [
        "ETW_WRITE_PATCH",
        "ETW_WRITE_FULL_PATCH",
        "ETW_WRITE_EX_PATCH",
        "ETW_NT_TRACE_PATCH",
    ] {
        assert!(
            fragment.contains(&format!("const {name}: [u8; 3] = [0x33, 0xC0, 0xC3];")),
            "{name} must stay a three-byte `ret` patch on x64"
        );
    }
    assert_eq!(
        fragment.matches("#[cfg(target_arch = \"x86_64\")]").count(),
        4,
        "every export needs its own x64 patch"
    );
}

#[test]
fn each_export_is_patched_with_its_own_bytes() {
    let source = DEF.stub_fragment;

    for (placeholder, patch) in [
        ("$ETW_FUNC_DEF$", "&ETW_WRITE_PATCH"),
        ("$ETW_FULL_FUNC_DEF$", "&ETW_WRITE_FULL_PATCH"),
        ("$ETW_EX_FUNC_DEF$", "&ETW_WRITE_EX_PATCH"),
        ("$ETW_NT_TRACE_FUNC_DEF$", "&ETW_NT_TRACE_PATCH"),
    ] {
        assert!(
            source.contains(&format!("{placeholder}, {patch}")),
            "the {patch} patch must follow {placeholder}"
        );
    }

    // The page protection must follow the bytes actually written: three on x64,
    // five on x86. A global length would under- or over-protect one arch.
    assert!(source.contains("fn patch_export(dll: &str, func: &str, patch: &[u8])"));
    assert!(source.contains("fn patch_optional(dll: &str, func: &str, patch: &[u8])"));
    assert_eq!(source.matches("patch.len()").count(), 2);
    assert!(!source.contains("ETW_PATCH.len()"));
}

#[test]
fn render_fragment_obfuscates_literals_and_enables_every_variant() {
    let strings = StringsConfig::from_yaml(None).expect("default strings");
    let fragment = Params::default().render_fragment(&strings);

    // The entry point is present and every placeholder is substituted.
    assert!(fragment.contains("fn patch_etw"));
    assert!(fragment.contains("const PATCH_FULL: bool = true;"));
    assert!(fragment.contains("const PATCH_EX: bool = true;"));
    assert!(fragment.contains("const PATCH_NT_TRACE: bool = true;"));
    for placeholder in [
        "$ETW_DLL_DEF$",
        "$ETW_FUNC_DEF$",
        "$ETW_FULL_FUNC_DEF$",
        "$ETW_EX_FUNC_DEF$",
        "$ETW_NT_TRACE_FUNC_DEF$",
        "$PATCH_FULL$",
        "$PATCH_EX$",
        "$PATCH_NT_TRACE$",
        "$MSG_LOAD_FAILED$",
        "$MSG_RESOLVE_FAILED$",
        "$MSG_MAKE_WRITABLE_FAILED$",
        "$MSG_RESTORE_PROTECTION_FAILED$",
    ] {
        assert!(
            !fragment.contains(placeholder),
            "placeholder {placeholder} was not substituted"
        );
    }

    // No sensitive literal survives in code (the guardrail ignores comments,
    // which *do* name the functions).
    assert!(
        find_sensitive_literals_in_source(&fragment).is_empty(),
        "cleartext sensitive literal in the rendered fragment"
    );
    assert!(fragment.contains("crate::dec_xor"));
}

#[test]
fn render_fragment_disables_optional_variants_when_requested() {
    let strings = StringsConfig::from_yaml(None).expect("default strings");
    let fragment = Params {
        full: false,
        ex: false,
        nt_trace: false,
    }
    .render_fragment(&strings);
    assert!(fragment.contains("const PATCH_FULL: bool = false;"));
    assert!(fragment.contains("const PATCH_EX: bool = false;"));
    assert!(fragment.contains("const PATCH_NT_TRACE: bool = false;"));
}
