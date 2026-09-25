//! Tests for the process hollowing technique.

use super::{default_target, Params, DEF};
use crate::engine::obfuscation::{StringStrategy, StringsConfig};
use crate::techniques::RuntimeStep;

#[test]
fn parses_params_with_default_target() {
    let step: RuntimeStep = serde_yml::from_str("technique: process_hollowing\n")
        .expect("process_hollowing without target should parse");
    assert_eq!(
        step,
        RuntimeStep::ProcessHollowing(Params {
            target: default_target(),
        })
    );
}

#[test]
fn parses_params_with_explicit_target() {
    let step: RuntimeStep = serde_yml::from_str(
        r#"technique: process_hollowing
target: "C:\\Windows\\System32\\notepad.exe""#,
    )
    .expect("process_hollowing with target should parse");
    assert_eq!(
        step,
        RuntimeStep::ProcessHollowing(Params {
            target: r"C:\Windows\System32\notepad.exe".to_string(),
        })
    );
}

#[test]
fn render_fragment_substitutes_and_obfuscates_target() {
    let params = Params {
        target: r"C:\Windows\System32\svchost.exe".to_string(),
    };
    let strings = StringsConfig {
        strategy: StringStrategy::Xor,
        key: Some([0x5Au8; 32]),
    };
    let fragment = params.render_fragment(&strings);

    // The placeholders must be gone and the runtime byte literals must not
    // appear in cleartext (comments may still mention the names).
    assert!(!fragment.contains("$HOLLOW_TARGET_DEF$"));
    assert!(!fragment.contains("$NTDLL_DEF$"));
    assert!(!fragment.contains("$UNMAP_FUNC_DEF$"));
    assert!(!fragment.contains(r"C:\Windows\System32\svchost.exe"));
    assert!(!fragment.contains("b\"ntdll.dll"));
    assert!(!fragment.contains("b\"NtUnmapViewOfSection"));

    // The fragment must carry the hollowing entry point and the runtime decoder.
    assert!(fragment.contains("fn run_stage_two"));
    assert!(fragment.contains("crate::dec_xor"));
}

#[test]
fn def_is_well_formed() {
    assert_eq!(DEF.name, "process_hollowing");
    assert!(!DEF.stub_fragment.is_empty());
    assert!(!DEF.readme.is_empty());
}
