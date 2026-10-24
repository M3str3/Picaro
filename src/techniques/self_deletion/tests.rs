//! Tests for self-deletion.

use super::{default_mode, Mode, Params, DEF, MESSAGES};
use crate::engine::obfuscation::StringsConfig;
use crate::techniques::{Category, TechniqueKind};

/// Renders the fragment with the default (obfuscating) string strategy.
fn render(params: &Params) -> String {
    let strings = StringsConfig::from_yaml(None).expect("default strings");
    params.render_fragment(&strings)
}

#[test]
fn parses_params_from_empty_yaml() {
    let step: TechniqueKind =
        serde_yml::from_str("technique: self_deletion\n").expect("self_deletion should parse");
    assert_eq!(
        step,
        TechniqueKind::SelfDeletion {
            params: Params::default()
        }
    );
}

#[test]
fn defaults_to_the_rename_variant() {
    assert_eq!(default_mode(), Mode::RenameAds);
    assert_eq!(Params::default().mode, Mode::RenameAds);
    assert!(Params::default().stream.is_none());
}

#[test]
fn parses_the_helper_mode_and_a_stream_name() {
    let step: TechniqueKind = serde_yml::from_str(
        "technique: self_deletion\nparams:\n  mode: helper\n  stream: \":custom\"\n",
    )
    .expect("self_deletion with params should parse");
    match step {
        TechniqueKind::SelfDeletion { params } => {
            assert_eq!(params.mode, Mode::Helper);
            assert_eq!(params.stream.as_deref(), Some(":custom"));
        }
        other => panic!("expected self_deletion, got {other:?}"),
    }
}

#[test]
fn def_is_well_formed() {
    assert_eq!(DEF.name, "self_deletion");
    assert_eq!(DEF.category, Category::Preparation);
    assert_eq!(DEF.attck, ["T1070.004"]);
    assert!(!DEF.requires.is_empty());
    assert!(!DEF.stub_fragment.is_empty());
    assert!(!DEF.readme.is_empty());
}

#[test]
fn def_exposes_the_preparation_contract() {
    assert!(
        DEF.stub_fragment
            .contains("pub fn self_deletion() -> Result<bool, String>"),
        "the fragment must define the Preparation contract"
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
fn the_mode_selects_the_variant() {
    let rename = render(&Params {
        mode: Mode::RenameAds,
        stream: None,
    });
    assert!(
        rename.contains("if true"),
        "the default must be the rename variant"
    );
    assert!(rename.contains("FILE_RENAME_INFORMATION_CLASS"));

    let helper = render(&Params {
        mode: Mode::Helper,
        stream: None,
    });
    assert!(
        helper.contains("if false"),
        "the helper variant must be selectable"
    );
    assert!(helper.contains("CreateProcessA"));
}

#[test]
fn the_rename_information_layout_covers_both_architectures() {
    // `FILE_RENAME_INFO` is pointer-sized: the length field sits at 8 on x86
    // and 16 on x64, and the UTF-16 name starts at 12 and 20 respectively. The
    // fragment must pick between them instead of hard-coding the x64 numbers.
    let fragment = DEF.stub_fragment.replace("\r\n", "\n");
    assert!(
        fragment.contains("fn rename_info_layout(is_x86: bool) -> (usize, usize)"),
        "the layout must be a pure, argument-driven helper"
    );
    assert!(
        fragment.contains("(12, 8)"),
        "the x86 header is 12 bytes and its length field starts at 8"
    );
    assert!(
        fragment.contains("(20, 16)"),
        "the x64 header is 20 bytes and its length field starts at 16"
    );
    assert!(
        fragment.contains("rename_info_layout(cfg!(target_arch = \"x86\"))"),
        "the layout must follow the architecture the stub is compiled for"
    );
}

#[test]
fn the_fragment_writes_the_structure_at_the_arch_specific_offsets() {
    let fragment = render(&Params::default());
    assert!(
        fragment.contains(
            "let (header, length_offset) = rename_info_layout(cfg!(target_arch = \"x86\"));"
        ),
        "the header size and the length offset must come from the layout helper"
    );
    assert!(
        fragment.contains("info[length_offset..length_offset + 4]"),
        "FileNameLength must be written at the architecture's offset"
    );
    assert!(
        fragment.contains("let at = header + index * 2;"),
        "the name must follow the architecture's header"
    );
    assert!(
        !fragment.contains("RENAME_INFO_HEADER"),
        "the hard-coded x64 header must be gone"
    );
}

#[test]
fn the_stream_name_never_appears_in_cleartext() {
    let params = Params {
        mode: Mode::RenameAds,
        stream: Some(":unique_stream_marker".to_string()),
    };
    let fragment = render(&params);
    assert!(
        !fragment.contains(&params.stream()),
        "the stream name must be rebuilt from obfuscated bytes"
    );
    assert!(
        !fragment.contains(":unique_stream_marker"),
        "no fragment of the stream name may appear"
    );
}

#[test]
fn the_stream_name_is_validated_before_the_rename() {
    let fragment = render(&Params::default());
    assert!(
        fragment.contains("fn stream_name_is_valid(stream: &str) -> bool"),
        "the fragment must validate the configured stream name"
    );
    assert!(
        fragment.contains("if !stream_name_is_valid(&stream)"),
        "the rename must reject an invalid stream before it touches the file"
    );
    assert!(
        fragment.contains("stream.is_empty()"),
        "an empty stream name must be rejected"
    );
    assert!(
        fragment.contains("stream.starts_with(':')"),
        "a stream name must start with ':'"
    );
    assert!(
        fragment.contains(r"stream.contains('\\')"),
        "a stream name must not contain a backslash"
    );
    assert!(
        fragment.contains("stream.contains('/')"),
        "a stream name must not contain a forward slash"
    );
    assert!(
        !fragment.contains("$MSG_INVALID_STREAM$"),
        "the rejection diagnostic must be rebuilt at run time"
    );
    let check = fragment
        .find("if !stream_name_is_valid(&stream)")
        .expect("the validation must be present");
    let open = fragment
        .find("let handle = open_image(path)?")
        .expect("the rename must open the image");
    assert!(
        check < open,
        "an invalid stream must be rejected before the file is opened"
    );
}

#[test]
fn the_invalid_stream_diagnostic_is_registered_and_obfuscated() {
    let text = MESSAGES
        .iter()
        .find_map(|(placeholder, text)| (*placeholder == "$MSG_INVALID_STREAM$").then_some(*text))
        .expect("the invalid-stream diagnostic must be registered");
    let fragment = render(&Params::default());
    assert!(
        DEF.stub_fragment.contains("$MSG_INVALID_STREAM$"),
        "the fragment must use the registered diagnostic"
    );
    assert!(
        !DEF.stub_fragment.contains(text),
        "the diagnostic must not be a cleartext literal in the fragment"
    );
    assert!(
        !fragment.contains(text),
        "the diagnostic must be rebuilt from obfuscated bytes"
    );
}

#[test]
fn an_unset_stream_name_is_random_per_build() {
    let first = Params::default().stream();
    let second = Params::default().stream();
    assert!(
        first.starts_with(':'),
        "an alternate data stream name starts with ':'"
    );
    assert_ne!(
        first, second,
        "a constant stream name would be a signature shared by every artifact"
    );
}

#[test]
fn the_helper_command_line_is_never_in_cleartext() {
    let fragment = render(&Params {
        mode: Mode::Helper,
        stream: None,
    });
    for literal in ["cmd.exe", "ping -n 3", "del /f /q"] {
        assert!(
            !fragment.contains(literal),
            "the helper's '{literal}' must be rebuilt from obfuscated bytes"
        );
    }
}

#[test]
fn the_image_is_opened_for_a_metadata_change() {
    let fragment = render(&Params::default());
    assert!(
        fragment.contains("DELETE.0 | SYNCHRONIZE"),
        "the rename needs a handle with delete access that can be waited on"
    );
    assert!(
        fragment.contains("FILE_SHARE_READ"),
        "the share mode has to be the one a mapped image tolerates"
    );
    assert!(
        fragment.contains("OPEN_EXISTING"),
        "the file must already exist; this technique never creates one"
    );
}

#[test]
fn the_path_is_read_not_embedded() {
    let fragment = render(&Params::default());
    assert!(
        fragment.contains("GetModuleFileNameW"),
        "the running image's path must be read at run time"
    );
}

#[test]
fn the_fragment_uses_the_syscall_layer() {
    let fragment = render(&Params::default());
    assert!(
        fragment.contains("crate::nt_set_info_file"),
        "the file-information call must go through the syscall layer"
    );
    assert!(
        !fragment.contains("SetFileInformationByHandle") && !fragment.contains("DeleteFileW"),
        "kernel-facing calls must go through the nt_* helpers"
    );
}

#[test]
fn the_chain_continues_after_the_deletion() {
    let fragment = render(&Params::default()).replace("\r\n", "\n");
    assert!(
        fragment.trim_end().ends_with("Ok(true)\n}"),
        "a successful deletion must not abort the pipeline (last statement): {fragment}"
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
