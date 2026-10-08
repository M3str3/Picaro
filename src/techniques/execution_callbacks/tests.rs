//! Tests for callback execution.

use super::{Params, DEF, MESSAGES};
use crate::engine::obfuscation::StringsConfig;
use crate::plan::schema::PayloadFormat;
use crate::techniques::{Capability, Category, RuntimeStep, Stability, TechniqueKind};

/// The rendered fragment for the default strings configuration.
fn fragment() -> String {
    let strings = StringsConfig::from_yaml(None).expect("default strings");
    Params::default().render_fragment_for(&strings, PayloadFormat::Shellcode, None)
}

/// Every double-quoted literal of the rendered fragment, ignoring comments.
fn string_literals(rendered: &str) -> Vec<String> {
    rendered
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .flat_map(|line| {
            line.split('"')
                .skip(1)
                .step_by(2)
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .collect()
}

#[test]
fn parses_params_from_empty_yaml() {
    let step: TechniqueKind = serde_yml::from_str("technique: execution_callbacks\n")
        .expect("execution_callbacks should parse");
    assert_eq!(
        step,
        TechniqueKind::ExecutionCallbacks {
            params: Params::default()
        }
    );
}

#[test]
fn parses_a_payload_name() {
    let step: TechniqueKind =
        serde_yml::from_str("technique: execution_callbacks\nparams:\n  payload: implant\n")
            .expect("execution_callbacks with a payload should parse");
    match step {
        TechniqueKind::ExecutionCallbacks { params } => {
            assert_eq!(params.payload.as_deref(), Some("implant"));
        }
        other => panic!("expected execution_callbacks, got {other:?}"),
    }
}

#[test]
fn def_is_well_formed() {
    assert_eq!(DEF.name, "execution_callbacks");
    assert_eq!(DEF.category, Category::Execution);
    assert!(!DEF.attck.is_empty());
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
fn render_fragment_for_returns_the_fragment() {
    let strings = StringsConfig::from_yaml(None).expect("default strings");
    let fragment = Params::default().render_fragment_for(&strings, PayloadFormat::Shellcode, None);
    assert!(fragment.contains("fn execute_payload"));
}

#[test]
fn def_is_a_stable_windows_technique() {
    assert_eq!(DEF.stability, Stability::Stable);
    assert!(DEF.requires.contains(&Capability::WindowsX64));
    assert!(DEF.requires.contains(&Capability::WindowsX86));
    assert!(DEF.conflicts.is_empty());
}

#[test]
fn def_claims_native_api_and_reflective_loading_not_process_injection() {
    // Research summary (see the README's Metadata section): MITRE documents
    // "running shellcode through the callback function" under T1106, and the
    // payload is executed from an in-process allocation (T1620). T1055, the
    // skeleton's placeholder, is about injecting into *another* process.
    assert_eq!(DEF.attck, &["T1106", "T1620"]);
}

// --- placeholder substitution ---

#[test]
fn every_placeholder_is_substituted() {
    let rendered = fragment();
    assert!(
        !rendered.contains('$'),
        "a $PLACEHOLDER$ survived rendering: {}",
        rendered
            .lines()
            .filter(|line| line.contains('$'))
            .collect::<Vec<_>>()
            .join(" | ")
    );
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
    assert_ne!(rendered, DEF.stub_fragment, "nothing was substituted");
}

#[test]
fn the_rendered_fragment_resolves_the_callback_dynamically() {
    let rendered = fragment();
    assert!(
        rendered.contains("CString::new("),
        "the library/entry names must be rebuilt at runtime"
    );
    assert!(rendered.contains("LoadLibraryA"));
    assert!(rendered.contains("GetProcAddress"));
}

// --- string obfuscation ---

#[test]
fn no_runtime_literal_leaks_in_cleartext() {
    // Only double-quoted literals matter: a comment or a type name may mention
    // the API (the CI leak check strips comments too), while anything the stub
    // can *say* at run time must be rebuilt from obfuscated bytes.
    let literals = string_literals(&fragment());
    assert!(!literals.is_empty(), "the helper found no literal at all");
    for (placeholder, text) in MESSAGES {
        for literal in &literals {
            assert!(
                !literal.contains(text),
                "the diagnostic for {placeholder} leaked in cleartext: {literal}"
            );
        }
    }
    for plaintext in ["crypt32", "CertEnumSystemStoreLocation"] {
        for literal in &literals {
            assert!(
                !literal.contains(plaintext),
                "'{plaintext}' must be rebuilt at runtime, not embedded: {literal}"
            );
        }
    }
}

// --- fragment contract ---

#[test]
fn the_fragment_keeps_the_execution_contract() {
    let rendered = fragment();
    assert!(
        rendered.contains("pub fn execute_payload(image: &mut [u8]) -> Result<i32, String>"),
        "the stub wrapper calls execute_payload(image) unqualified"
    );
}

#[test]
fn kernel_facing_calls_go_through_the_nt_helpers() {
    let rendered = fragment();
    assert!(rendered.contains("crate::nt_alloc_vm("));
    assert!(rendered.contains("crate::nt_protect_vm("));
    for win32 in [
        "VirtualAllocEx",
        "VirtualProtectEx",
        "VirtualAlloc(",
        "VirtualProtect(",
    ] {
        assert!(
            !rendered.contains(win32),
            "{win32} must only appear in the syscall layer's mode-none helpers"
        );
    }
}

#[test]
fn the_declared_syscalls_cover_the_helpers_the_fragment_calls() {
    let step = RuntimeStep::new(TechniqueKind::ExecutionCallbacks {
        params: Params::default(),
    });
    let required = crate::engine::syscalls::required(&[step]);
    assert!(
        required.contains(&"NtAllocateVirtualMemory"),
        "the fragment calls nt_alloc_vm but DEF.syscalls does not list it: {required:?}"
    );
    assert!(
        required.contains(&"NtProtectVirtualMemory"),
        "the fragment calls nt_protect_vm but DEF.syscalls does not list it: {required:?}"
    );
}

#[test]
fn the_fragment_never_writes_its_own_strings() {
    let rendered = fragment();
    for banned in [
        "println!",
        "unwrap(",
        "expect(",
        "todo!",
        "unimplemented!",
        "panic!",
        "anyhow",
        "{{",
    ] {
        assert!(
            !rendered.contains(banned),
            "'{banned}' is not allowed in a stub fragment"
        );
    }
}

#[test]
fn the_payload_is_entered_from_the_callback() {
    let rendered = fragment();
    // The API is entered with the module's callback and an obfuscated context;
    // the callback stores the payload's exit code for the loader.
    assert!(rendered.contains("unsafe extern \"system\" fn callback("));
    assert!(rendered.contains("(context.entry)()"));
    assert!(rendered.contains("exit_code"));
    // The enumeration is asked to stop after the payload, so the loader keeps
    // control and the steps after this one can run.
    assert!(rendered.contains("// FALSE: stop enumerating"));
}

#[test]
fn the_runtime_guard_rejects_a_pe_payload() {
    let rendered = fragment();
    assert!(rendered.contains("fn is_pe_image("));
    assert!(
        rendered.contains("is_pe_image(image)"),
        "execute_payload must check the payload before making it executable"
    );
}

#[test]
fn the_fragment_is_format_independent() {
    // The registry passes the payload's format to every Execution technique.
    // This technique renders the same fragment for all of them and reports a
    // PE/dll/dotnet payload at run time (see the README); the build-time rule
    // belongs to plan::validate.
    let strings = StringsConfig::from_yaml(None).expect("default strings");
    let shellcode = Params::default().render_fragment_for(&strings, PayloadFormat::Shellcode, None);
    let pe = Params::default().render_fragment_for(&strings, PayloadFormat::Pe, None);
    assert_eq!(shellcode, pe);
}
