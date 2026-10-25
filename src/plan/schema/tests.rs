use super::*;

use crate::techniques::process_hollowing::{default_target, Params};
use crate::techniques::TechniqueKind;

/// Minimal valid YAML used as a base in all tests.
const VALID_YAML: &str = r#"
schema: 6
name: mimikatz-basic

build:
  crypto:
    algo: xchacha20poly1305
    key: random
  payloads:
    mimikatz:
      source: ./mimikatz.exe

  output:
    path: ./dist/mimikatz_packed.exe
    arch: x64
    strip: true
    trim_paths: all

runtime:
  - technique: process_hollowing
    params:
      target: "C:\\Windows\\System32\\svchost.exe"
"#;

#[test]
fn parses_valid_plan() {
    let plan: Plan = serde_yml::from_str(VALID_YAML).expect("the example YAML should parse");

    assert_eq!(plan.schema, 6);
    assert_eq!(plan.name, "mimikatz-basic");
    let payload = plan.build.payloads.get("mimikatz").expect("the payload");
    assert_eq!(payload.source, "./mimikatz.exe");
    // An omitted `format` is `auto`; `load_plan` resolves it against the
    // source before validation.
    assert_eq!(payload.format, PayloadFormat::Auto);
    let crypto = plan.build.crypto.as_ref().expect("build.crypto");
    assert_eq!(crypto.algo, CryptoAlgorithm::XChaCha20Poly1305);
    assert_eq!(crypto.key, KeySource::Random);
    assert_eq!(plan.build.stub.path, None);
    assert_eq!(plan.build.stub.syscalls, None);
    assert_eq!(plan.build.stub.api_resolution, None);
    assert_eq!(plan.build.stub.strings, None);
    assert_eq!(
        plan.runtime[0].technique,
        TechniqueKind::ProcessHollowing {
            params: Params {
                payload: None,
                target: r"C:\Windows\System32\svchost.exe".to_string(),
            }
        }
    );
    assert_eq!(
        plan.build.output.path,
        PathBuf::from("./dist/mimikatz_packed.exe")
    );
    assert_eq!(plan.build.output.arch, Arch::X64);
    assert!(plan.build.output.strip);
    assert_eq!(plan.build.output.trim_paths, TrimPaths::All);
}

#[test]
fn parses_a_generated_icon() {
    let yaml = VALID_YAML.replace(
        "  output:\n",
        "  output:\n    resources:\n      icon: random\n",
    );
    let plan: Plan = serde_yml::from_str(&yaml).expect("icon: random should parse");
    let icon = plan
        .build
        .output
        .resources
        .expect("resources")
        .icon
        .expect("icon");
    assert_eq!(icon, IconPlan::Random { seed: None });
    assert_eq!(icon.seed(), None);
}

#[test]
fn parses_an_icon_path() {
    let yaml = VALID_YAML.replace(
        "  output:\n",
        "  output:\n    resources:\n      icon: ./app.ico\n",
    );
    let plan: Plan = serde_yml::from_str(&yaml).expect("an icon path should parse");
    let icon = plan
        .build
        .output
        .resources
        .expect("resources")
        .icon
        .expect("icon");
    assert_eq!(icon, IconPlan::Path(PathBuf::from("./app.ico")));
}

#[test]
fn an_icon_round_trips_as_a_string() {
    assert_eq!(String::from(IconPlan::Random { seed: Some(7) }), "random");
    assert_eq!(
        String::from(IconPlan::Path(PathBuf::from("./app.ico"))),
        "./app.ico"
    );
}

#[test]
fn with_seed_only_fills_an_unresolved_generated_icon() {
    assert_eq!(
        IconPlan::Random { seed: None }.with_seed(9),
        IconPlan::Random { seed: Some(9) }
    );
    assert_eq!(
        IconPlan::Random { seed: Some(1) }.with_seed(9),
        IconPlan::Random { seed: Some(1) }
    );
    assert_eq!(
        IconPlan::Path(PathBuf::from("a.ico")).with_seed(9),
        IconPlan::Path(PathBuf::from("a.ico"))
    );
}

#[test]
fn rejects_an_empty_icon_value() {
    assert!(serde_yml::from_str::<IconPlan>("").is_err());
}

#[test]
fn parses_stub_strings_block() {
    let yaml = VALID_YAML.replace(
        "  output:\n",
        "  stub:\n    strings:\n      strategy: stack\n      key: random\n\n  output:\n",
    );
    let plan: Plan = serde_yml::from_str(&yaml).expect("stub strings block should parse");
    let strings = plan.build.stub.strings.expect("strings should be present");
    assert_eq!(strings.strategy, "stack");
    assert_eq!(strings.key, "random");
}

#[test]
fn parses_stub_strings_and_syscalls_together() {
    let yaml = VALID_YAML.replace(
            "  output:\n",
            "  stub:\n    syscalls:\n      mode: indirect\n    strings:\n      strategy: xor\n\n  output:\n",
        );
    let plan: Plan = serde_yml::from_str(&yaml).expect("stub block should parse");
    assert_eq!(plan.build.stub.syscalls.expect("syscalls").mode, "indirect");
    assert_eq!(plan.build.stub.strings.expect("strings").strategy, "xor");
}

#[test]
fn strings_block_is_optional() {
    let plan: Plan = serde_yml::from_str(VALID_YAML).expect("valid YAML should parse");
    assert_eq!(plan.build.stub.strings, None);
}

#[test]
fn parses_stub_api_resolution_block() {
    let yaml = VALID_YAML.replace(
            "  output:\n",
            "  stub:\n    api_resolution:\n      mode: proxy\n      apis:\n        - \"kernel32!ReadProcessMemory\"\n      unmatched: abort\n\n  output:\n",
        );
    let plan: Plan = serde_yml::from_str(&yaml).expect("api_resolution block should parse");
    let api = plan
        .build
        .stub
        .api_resolution
        .expect("api_resolution should be present");
    assert_eq!(api.mode, "proxy");
    assert_eq!(api.unmatched, "abort");
    assert_eq!(api.apis, vec!["kernel32!ReadProcessMemory".to_string()]);
}

#[test]
fn rejects_strings_block_at_build_level() {
    // Schema 2's `build.strings` is no longer a valid sibling of `payloads`.
    let yaml = VALID_YAML.replace(
        "  output:\n",
        "  strings:\n    strategy: xor\n\n  output:\n",
    );
    assert!(
        serde_yml::from_str::<Plan>(&yaml).is_err(),
        "build.strings should be rejected (deny_unknown_fields)"
    );
}

#[test]
fn stub_block_is_optional_and_defaults_to_builtin() {
    let plan: Plan = serde_yml::from_str(VALID_YAML).expect("valid YAML should parse");
    assert_eq!(plan.build.stub, StubPlan::default());
}

#[test]
fn parses_stub_path_block() {
    let yaml = VALID_YAML.replace(
        "  output:\n",
        "  stub:\n    path: ./my_stub.rs\n\n  output:\n",
    );
    let plan: Plan = serde_yml::from_str(&yaml).expect("stub block should parse");
    assert_eq!(plan.build.stub.path, Some(PathBuf::from("./my_stub.rs")));
}

#[test]
fn stub_path_null_means_builtin() {
    let yaml = VALID_YAML.replace("  output:\n", "  stub:\n    path: null\n\n  output:\n");
    let plan: Plan = serde_yml::from_str(&yaml).expect("null path should parse");
    assert_eq!(plan.build.stub.path, None);
}

#[test]
fn parses_stub_syscalls_block() {
    let yaml = VALID_YAML.replace(
        "  output:\n",
        "  stub:\n    syscalls:\n      mode: indirect\n\n  output:\n",
    );
    let plan: Plan = serde_yml::from_str(&yaml).expect("syscalls block should parse");
    assert_eq!(plan.build.stub.path, None);
    let syscalls = plan
        .build
        .stub
        .syscalls
        .expect("syscalls should be present");
    assert_eq!(syscalls.mode, "indirect");
    assert_eq!(syscalls.resolver, "hells_gate");
}

#[test]
fn stub_syscalls_defaults_mode_and_resolver() {
    let yaml = VALID_YAML.replace("  output:\n", "  stub:\n    syscalls: {}\n\n  output:\n");
    let plan: Plan = serde_yml::from_str(&yaml).expect("empty syscalls should parse");
    let syscalls = plan
        .build
        .stub
        .syscalls
        .expect("syscalls should be present");
    assert_eq!(syscalls.mode, "none");
    assert_eq!(syscalls.resolver, "hells_gate");
}

#[test]
fn parses_url_source() {
    let yaml = VALID_YAML.replace(
        "      source: ./mimikatz.exe\n",
        "      source: https://example.com/mimikatz.exe\n",
    );
    let plan: Plan = serde_yml::from_str(&yaml).expect("a url source should parse");

    assert_eq!(
        plan.build.payloads.get("mimikatz").expect("payload").source,
        "https://example.com/mimikatz.exe"
    );
}

#[test]
fn process_hollowing_defaults_target() {
    let yaml = VALID_YAML.replace(
            "  - technique: process_hollowing\n    params:\n      target: \"C:\\\\Windows\\\\System32\\\\svchost.exe\"\n",
            "  - technique: process_hollowing\n",
        );
    let plan: Plan =
        serde_yml::from_str(&yaml).expect("process_hollowing without target should parse");
    assert_eq!(
        plan.runtime[0].technique,
        TechniqueKind::ProcessHollowing {
            params: Params {
                payload: None,
                target: default_target(),
            }
        }
    );
}

#[test]
fn payload_args_default_to_join() {
    let plan: Plan = serde_yml::from_str(VALID_YAML).expect("valid YAML should parse");
    let payload = plan.build.payloads.get("mimikatz").expect("payload");
    assert_eq!(payload.args, None);
    assert_eq!(payload.args_mode, ArgsMode::Join);
}

/// Locks in the documented migration hazard: unknown keys inside a runtime
/// entry are dropped, so a plan migrated from schema 3 that leaves its
/// parameters flat parses and silently falls back to the defaults.
#[test]
fn a_flat_param_is_dropped_and_the_default_applies() {
    let yaml = VALID_YAML.replace(
        "    params:\n      target: \"C:\\\\Windows\\\\System32\\\\svchost.exe\"\n",
        "    target: \"C:\\\\Windows\\\\System32\\\\notepad.exe\"\n",
    );
    let plan: Plan = serde_yml::from_str(&yaml).expect("a flat param still parses");
    assert_eq!(
        plan.runtime[0].technique,
        TechniqueKind::ProcessHollowing {
            params: Params {
                payload: None,
                target: default_target(),
            }
        },
        "the flat target must be dropped in favour of the default"
    );
}

#[test]
fn payload_args_and_override_mode_parse() {
    let yaml = VALID_YAML.replace(
            "      source: ./mimikatz.exe\n",
            "      source: ./mimikatz.exe\n      args: [\"privilege::debug\", \"log\", \"C:\\\\temp\\\\out.log\"]\n      args_mode: override\n",
        );
    let plan: Plan = serde_yml::from_str(&yaml).expect("args should parse");
    let payload = plan.build.payloads.get("mimikatz").expect("payload");
    assert_eq!(
        payload.args,
        Some(vec![
            "privilege::debug".to_string(),
            "log".to_string(),
            r"C:\temp\out.log".to_string(),
        ])
    );
    assert_eq!(payload.args_mode, ArgsMode::Override);
}

#[test]
fn empty_payload_args_are_valid() {
    let yaml = VALID_YAML.replace(
        "      source: ./mimikatz.exe\n",
        "      source: ./mimikatz.exe\n      args: []\n",
    );
    let plan: Plan = serde_yml::from_str(&yaml).expect("empty args should parse");
    let payload = plan.build.payloads.get("mimikatz").expect("payload");
    assert_eq!(payload.args, Some(vec![]));
    assert_eq!(payload.args_mode, ArgsMode::Join);
}

#[test]
fn payload_args_keep_special_characters() {
    let yaml = VALID_YAML.replace(
            "      source: ./mimikatz.exe\n",
            "      source: ./mimikatz.exe\n      args: ['hello world', 'say \"hi\"', 'C:\\Program Files\\x']\n",
        );
    let plan: Plan = serde_yml::from_str(&yaml).expect("special args should parse");
    assert_eq!(
        plan.build.payloads.get("mimikatz").expect("payload").args,
        Some(vec![
            "hello world".to_string(),
            "say \"hi\"".to_string(),
            r"C:\Program Files\x".to_string(),
        ])
    );
}

#[test]
fn rejects_unknown_args_mode() {
    let yaml = VALID_YAML.replace(
        "      source: ./mimikatz.exe\n",
        "      source: ./mimikatz.exe\n      args_mode: prepend\n",
    );
    assert!(
        serde_yml::from_str::<Plan>(&yaml).is_err(),
        "an unknown args_mode should fail"
    );
}

#[test]
fn payload_format_defaults_to_auto() {
    let plan: Plan = serde_yml::from_str(VALID_YAML).expect("valid YAML should parse");
    let payload = plan.build.payloads.get("mimikatz").expect("payload");
    assert_eq!(payload.format, PayloadFormat::Auto);
    assert_eq!(payload.export, None);
}

#[test]
fn parses_shellcode_format() {
    let yaml = VALID_YAML.replace(
        "      source: ./mimikatz.exe\n",
        "      source: ./beacon.bin\n      format: shellcode\n",
    );
    let plan: Plan = serde_yml::from_str(&yaml).expect("shellcode format should parse");
    let payload = plan.build.payloads.get("mimikatz").expect("payload");
    assert_eq!(payload.format, PayloadFormat::Shellcode);
    assert!(!payload.format.is_pe_image());
}

#[test]
fn parses_powershell_format() {
    let yaml = VALID_YAML.replace(
        "      source: ./mimikatz.exe\n",
        "      source: ./PowerUp.ps1\n      format: powershell\n",
    );
    let plan: Plan = serde_yml::from_str(&yaml).expect("powershell format should parse");
    let payload = plan.build.payloads.get("mimikatz").expect("payload");
    assert_eq!(payload.format, PayloadFormat::Powershell);
    assert_eq!(payload.format.label(), "powershell");
    assert!(!payload.format.is_pe_image());
}

#[test]
fn parses_dll_format_with_export() {
    let yaml = VALID_YAML.replace(
        "      source: ./mimikatz.exe\n",
        "      source: ./payload.dll\n      format: dll\n      export: Run\n",
    );
    let plan: Plan = serde_yml::from_str(&yaml).expect("dll format should parse");
    let payload = plan.build.payloads.get("mimikatz").expect("payload");
    assert_eq!(payload.format, PayloadFormat::Dll);
    assert_eq!(payload.export.as_deref(), Some("Run"));
    assert!(payload.format.is_pe_image());
}

#[test]
fn output_kind_defaults_to_an_executable() {
    let plan: Plan = serde_yml::from_str(VALID_YAML).expect("valid YAML should parse");
    assert_eq!(plan.build.output.kind, OutputKind::Exe);
    assert_eq!(plan.build.output.entry, DllEntry::Auto);
    assert!(plan.build.output.kind.is_exe());
    assert_eq!(plan.build.output.kind.label(), "exe");
}

#[test]
fn parses_a_dll_output_with_a_plain_export() {
    let yaml = VALID_YAML.replace(
        "    path: ./dist/mimikatz_packed.exe\n",
        "    path: ./dist/loader.dll\n    kind: dll\n    entry: export:Run\n",
    );
    let plan: Plan = serde_yml::from_str(&yaml).expect("a dll output should parse");
    assert_eq!(plan.build.output.kind, OutputKind::Dll);
    assert_eq!(plan.build.output.entry, DllEntry::Export("Run".to_string()));
    assert_eq!(plan.build.output.entry.label(), "export:Run");
    assert_eq!(plan.build.output.entry.export_name(), Some("Run"));
    assert!(!plan.build.output.entry.exports_jni_on_load());
}

#[test]
fn parses_the_jni_entry() {
    let yaml = VALID_YAML.replace(
        "    path: ./dist/mimikatz_packed.exe\n",
        "    path: ./dist/loader.dll\n    kind: dll\n    entry: jni_on_load\n",
    );
    let plan: Plan = serde_yml::from_str(&yaml).expect("a jni entry should parse");
    assert_eq!(plan.build.output.entry, DllEntry::JniOnLoad);
    assert!(plan.build.output.entry.exports_jni_on_load());
    assert_eq!(plan.build.output.entry.export_name(), None);
}

#[test]
fn console_defaults_to_parent() {
    let plan: Plan = serde_yml::from_str(VALID_YAML).expect("valid YAML should parse");
    assert_eq!(plan.build.output.console, ConsoleMode::Parent);
}

#[test]
fn parses_console_modes() {
    for (mode, expected) in [("parent", ConsoleMode::Parent), ("none", ConsoleMode::None)] {
        let yaml = VALID_YAML.replace(
            "    path: ./dist/mimikatz_packed.exe\n",
            &format!("    path: ./dist/loader.dll\n    kind: dll\n    console: {mode}\n"),
        );
        let plan: Plan = serde_yml::from_str(&yaml).expect("a console mode should parse");
        assert_eq!(plan.build.output.console, expected, "mode: {mode}");
    }
}

#[test]
fn console_parent_is_not_serialized() {
    let parent = VALID_YAML.replace(
        "    path: ./dist/mimikatz_packed.exe\n",
        "    path: ./dist/loader.dll\n    kind: dll\n    console: parent\n",
    );
    let plan: Plan = serde_yml::from_str(&parent).expect("parent should parse");
    let rendered = serde_yml::to_string(&plan).expect("serialize");
    assert!(
        !rendered.contains("console:"),
        "the default console mode should be skipped: {rendered}"
    );

    let none = VALID_YAML.replace(
        "    path: ./dist/mimikatz_packed.exe\n",
        "    path: ./dist/loader.dll\n    kind: dll\n    console: none\n",
    );
    let plan: Plan = serde_yml::from_str(&none).expect("none should parse");
    let rendered = serde_yml::to_string(&plan).expect("serialize");
    assert!(
        rendered.contains("console: none"),
        "a non-default console mode should serialize: {rendered}"
    );
}

#[test]
fn the_default_output_kind_and_entry_are_not_serialized() {
    let plan: Plan = serde_yml::from_str(VALID_YAML).expect("valid YAML should parse");
    let yaml = serde_yml::to_string(&plan).expect("serialize");
    assert!(
        !yaml.contains("kind:"),
        "the default kind should be skipped: {yaml}"
    );
    assert!(
        !yaml.contains("entry:"),
        "the default entry should be skipped: {yaml}"
    );
}

#[test]
fn a_dll_output_round_trips_through_yaml() {
    let yaml = VALID_YAML.replace(
        "    path: ./dist/mimikatz_packed.exe\n",
        "    path: ./dist/loader.dll\n    kind: dll\n    entry: export:Run\n",
    );
    let plan: Plan = serde_yml::from_str(&yaml).expect("a dll output should parse");
    let rendered = serde_yml::to_string(&plan).expect("serialize");
    let again: Plan = serde_yml::from_str(&rendered).expect("a rendered plan should parse");
    assert_eq!(again.build.output.kind, OutputKind::Dll);
    assert_eq!(
        again.build.output.entry,
        DllEntry::Export("Run".to_string())
    );
}

#[test]
fn a_shellcode_output_round_trips_through_yaml() {
    let yaml = VALID_YAML.replace(
        "    path: ./dist/mimikatz_packed.exe\n",
        "    path: ./dist/loader.bin\n    kind: shellcode\n    entry: export:Run\n",
    );
    let plan: Plan = serde_yml::from_str(&yaml).expect("a shellcode output should parse");
    assert_eq!(plan.build.output.kind, OutputKind::Shellcode);
    assert_eq!(plan.build.output.kind.label(), "shellcode");
    assert!(!plan.build.output.kind.is_exe());
    let rendered = serde_yml::to_string(&plan).expect("serialize");
    let again: Plan = serde_yml::from_str(&rendered).expect("a rendered plan should parse");
    assert_eq!(again.build.output.kind, OutputKind::Shellcode);
}

#[test]
fn rejects_an_unknown_dll_entry() {
    let yaml = VALID_YAML.replace(
        "    path: ./dist/mimikatz_packed.exe\n",
        "    path: ./dist/loader.dll\n    kind: dll\n    entry: now\n",
    );
    assert!(
        serde_yml::from_str::<Plan>(&yaml).is_err(),
        "an unknown entry should fail"
    );
}

#[test]
fn rejects_unknown_payload_format() {
    let yaml = VALID_YAML.replace(
        "      source: ./mimikatz.exe\n",
        "      source: ./beacon.bin\n      format: vbs\n",
    );
    assert!(
        serde_yml::from_str::<Plan>(&yaml).is_err(),
        "an unknown payload format should fail"
    );
}

#[test]
fn rejects_invalid_target_type() {
    let yaml = VALID_YAML.replace(
        "      target: \"C:\\\\Windows\\\\System32\\\\svchost.exe\"\n",
        "      target: 123\n",
    );
    assert!(
        serde_yml::from_str::<Plan>(&yaml).is_err(),
        "a non-string target should fail"
    );
}

#[test]
fn rejects_retired_schema_versions_with_a_migration_message() {
    for version in [1, 2, 3, 4, 5] {
        let yaml = VALID_YAML.replace("schema: 6", &format!("schema: {version}"));
        let err =
            serde_yml::from_str::<Plan>(&yaml).expect_err("a retired schema version must fail");
        assert!(
            err.to_string().contains("not supported"),
            "schema {version}: unclear error: {err}"
        );
    }
}

#[test]
fn rejects_a_retired_schema_with_a_migration_hint() {
    let yaml = VALID_YAML.replace("schema: 6", "schema: 4");
    let err = serde_yml::from_str::<Plan>(&yaml).expect_err("schema 4 should fail");
    let msg = err.to_string();
    assert!(msg.contains("not supported"), "unclear message: {msg}");
    assert!(
        msg.contains("build.payloads"),
        "missing migration hint: {msg}"
    );
    assert!(
        msg.contains("living_off_the_land"),
        "missing migration hint: {msg}"
    );
}

#[test]
fn accepts_only_the_current_schema() {
    let plan: Plan = serde_yml::from_str(VALID_YAML).expect("schema 6 parses");
    assert_eq!(plan.schema, SUPPORTED_SCHEMA);
}

#[test]
fn rejects_schema_1_keys() {
    let yaml = r#"
schema: 1
name: old
input:
  path: ./p.exe
payload:
  crypto:
    algo: xchacha20poly1305
    key: random
output:
  path: ./dist/o.exe
  arch: x64
  strip: true
  trim_paths: all
"#;
    let err = serde_yml::from_str::<Plan>(yaml).expect_err("schema 1 should fail");
    assert!(
        err.to_string().contains("not supported"),
        "unclear error: {err}"
    );
}

#[test]
fn rejects_unknown_technique() {
    let yaml = VALID_YAML.replace("process_hollowing", "indirect_syscalls");
    assert!(
        serde_yml::from_str::<Plan>(&yaml).is_err(),
        "an unknown technique should fail"
    );
}

#[test]
fn rejects_typo_in_field_name() {
    let yaml = VALID_YAML.replace("name: mimikatz-basic", "naem: mimikatz-basic");
    assert!(
        serde_yml::from_str::<Plan>(&yaml).is_err(),
        "a typo in a key should fail (deny_unknown_fields)"
    );
}

#[test]
fn rejects_legacy_top_level_input_block() {
    let yaml = VALID_YAML.replace(
        "build:\n  crypto:\n",
        "input:\n  path: ./mimikatz.exe\nbuild:\n  crypto:\n",
    );
    assert!(
        serde_yml::from_str::<Plan>(&yaml).is_err(),
        "the schema-1 `input` block should fail (deny_unknown_fields)"
    );
}

#[test]
fn allows_empty_runtime() {
    let yaml = VALID_YAML.replace(
            "runtime:\n  - technique: process_hollowing\n    params:\n      target: \"C:\\\\Windows\\\\System32\\\\svchost.exe\"\n",
            "",
        );
    let plan: Plan = serde_yml::from_str(&yaml).expect("an empty runtime should be valid");
    assert!(plan.runtime.is_empty());
}

#[test]
fn key_sources_parse_random_literal_and_file() {
    assert_eq!(KeySource::default(), KeySource::Random);
    assert_eq!(
        "random".parse::<KeySource>().expect("random"),
        KeySource::Random
    );

    let hex = "11".repeat(32);
    assert_eq!(
        format!("literal:{hex}")
            .parse::<KeySource>()
            .expect("literal"),
        KeySource::Literal([0x11; 32])
    );
    assert_eq!(
        "file:./key.bin".parse::<KeySource>().expect("file"),
        KeySource::File(PathBuf::from("./key.bin"))
    );
}

#[test]
fn key_sources_reject_bad_literals() {
    assert!("literal:zz".parse::<KeySource>().is_err(), "non-hex");
    assert!(
        format!("literal:{}", "00".repeat(32))
            .parse::<KeySource>()
            .is_err(),
        "all-zero"
    );
    assert!("literal:0011".parse::<KeySource>().is_err(), "wrong length");
    assert!("nope".parse::<KeySource>().is_err(), "unknown source");
}

#[test]
fn a_key_source_round_trips_as_a_string() {
    let key = KeySource::Literal([0x22; 32]);
    let text = String::from(key.clone());
    assert_eq!(text.parse::<KeySource>().expect("reparse"), key);
    assert_eq!(String::from(KeySource::Random), "random");
}

#[test]
fn reproduce_is_optional_and_accepts_the_shorthand_seed() {
    let plan: Plan = serde_yml::from_str(VALID_YAML).expect("no reproduce block");
    assert!(plan.reproduce.is_none());

    let yaml = format!("{VALID_YAML}\nreproduce:\n  seed: 42\n");
    let plan: Plan = serde_yml::from_str(&yaml).expect("a shorthand seed");
    assert_eq!(
        plan.reproduce
            .as_ref()
            .and_then(|record| record.seed.as_deref()),
        Some("42")
    );
}

#[test]
fn a_literal_crypto_key_parses_from_yaml() {
    let yaml = VALID_YAML.replace("key: random", &format!("key: literal:{}", "33".repeat(32)));
    let plan: Plan = serde_yml::from_str(&yaml).expect("a literal key parses");
    assert_eq!(
        plan.build.crypto.expect("crypto").key,
        KeySource::Literal([0x33; 32])
    );
}
