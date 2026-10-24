//! Tests for the process hollowing technique.

use super::{default_target, Params, DEF};
use crate::engine::obfuscation::{StringStrategy, StringsConfig};
use crate::techniques::TechniqueKind;

#[test]
fn parses_params_with_default_target() {
    let step: TechniqueKind = serde_yml::from_str("technique: process_hollowing\n")
        .expect("process_hollowing without target should parse");
    assert_eq!(
        step,
        TechniqueKind::ProcessHollowing {
            params: Params {
                payload: None,
                target: default_target(),
            }
        }
    );
}

#[test]
fn parses_params_with_explicit_target() {
    let step: TechniqueKind = serde_yml::from_str(
        r#"technique: process_hollowing
params:
  target: "C:\\Windows\\System32\\notepad.exe""#,
    )
    .expect("process_hollowing with target should parse");
    assert_eq!(
        step,
        TechniqueKind::ProcessHollowing {
            params: Params {
                payload: None,
                target: r"C:\Windows\System32\notepad.exe".to_string(),
            }
        }
    );
}

#[test]
fn render_fragment_substitutes_and_obfuscates_target() {
    let params = Params {
        payload: None,
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
    assert!(!fragment.contains("$KERNEL32_DEF$"));
    assert!(!fragment.contains("$LOAD_LIBRARY_DEF$"));
    assert!(!fragment.contains("$NTDLL_DEF$"));
    assert!(!fragment.contains("$UNMAP_FUNC_DEF$"));
    assert!(!fragment.contains(r"C:\Windows\System32\svchost.exe"));
    assert!(!fragment.contains("b\"ntdll.dll"));
    assert!(!fragment.contains("b\"NtUnmapViewOfSection"));
    assert!(!fragment.contains("b\"kernel32.dll"));
    assert!(!fragment.contains("b\"LoadLibraryA"));

    // Neither do the error diagnostics: their text is rebuilt at runtime too,
    // so no message (least of all a technique keyword) reaches the stub.
    assert!(!fragment.contains("$MSG_"));
    assert!(!fragment.contains("unmap failed"));
    assert!(!fragment.contains("entry patch failed"));
    assert!(!fragment.contains("timed out waiting for the target loader to initialize"));
    assert!(!fragment.contains("the target could not allocate a TLS index"));
    assert!(!fragment.contains("the image has no base relocations"));
    assert!(!fragment.contains("inconsistent SizeOfImage"));
    assert!(!fragment.contains("headers out of bounds"));

    // The fragment must carry the hollowing entry point and the runtime decoder.
    assert!(fragment.contains("fn run_stage_two"));
    assert!(fragment.contains("crate::dec_xor"));
}

/// Every diagnostic in the catalogue must be reconstructed at runtime, never
/// stored as a literal. Scanning the code (comments stripped) catches a message
/// that a future edit re-inlines in cleartext — the same failure the audit's
/// `technique names` heuristic reports.
#[test]
fn render_fragment_obfuscates_every_diagnostic() {
    let strings = StringsConfig {
        strategy: StringStrategy::Xor,
        key: Some([0x11u8; 32]),
    };
    let fragment = Params::default().render_fragment(&strings);
    let code = crate::audit::strings::strip_comments(&fragment);

    assert!(
        !code.contains("$MSG_"),
        "an unsubstituted message placeholder survived"
    );
    for (_, text) in super::MESSAGES {
        assert!(
            !code.contains(*text),
            "diagnostic leaked in cleartext: {text:?}"
        );
    }
}

#[test]
fn render_fragment_refuses_relocation_free_images_off_base() {
    let strings = StringsConfig {
        strategy: StringStrategy::Xor,
        key: Some([0x22u8; 32]),
    };
    let fragment = Params::default().render_fragment(&strings);
    let code = crate::audit::strings::strip_comments(&fragment);

    // An image with no relocation table cannot be rebased, so the grace path
    // must be an error, not `Ok(())`.
    let check = code
        .find("if pe.reloc_size == 0 {")
        .expect("the relocation-free guard must be present");
    let after = &code[check..];
    let body = &after[..after.find('}').expect("the guard must have a body")];
    assert!(
        body.contains("return Err("),
        "a relocation-free image that moved must be a clean error, not a success: {body}"
    );
    assert!(
        !body.contains("return Ok(())"),
        "a relocation-free image that moved must not report success: {body}"
    );
}

#[test]
fn render_fragment_guards_the_write_path() {
    let strings = StringsConfig {
        strategy: StringStrategy::Xor,
        key: Some([0x33u8; 32]),
    };
    let fragment = Params::default().render_fragment(&strings);
    let code = crate::audit::strings::strip_comments(&fragment);

    // Headers are validated in the parser and re-checked with `get` before the
    // write; the section end is a checked add and the destination RVA is
    // clamped to `SizeOfImage`.
    assert!(code.contains("size_of_headers as usize > image.len()"));
    assert!(code.contains(".get(..pe.size_of_headers as usize)"));
    assert!(code.contains(".checked_add(length)"));
    assert!(code.contains("pe.size_of_image.saturating_sub(sec.virtual_address)"));
    // The DLL name tail is not indexed blindly.
    assert!(code.contains(".get(name_off..)"));
    // A 32-bit stub patches 4-byte IAT slots; a 64-bit one patches 8.
    assert!(code.contains("write_u32(image, offset, address as u32)"));
    assert!(code.contains("write_u64(image, offset, address)"));
    // A remote `LoadLibraryA` thread's exit status is inspected (NULL = failed).
    assert!(code.contains("info.exit_status == 0"));
}

#[test]
fn def_is_well_formed() {
    assert_eq!(DEF.name, "process_hollowing");
    assert!(!DEF.stub_fragment.is_empty());
    assert!(!DEF.readme.is_empty());
}
