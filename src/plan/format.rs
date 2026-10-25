//! Payload format resolution (`format: auto`).
//!
//! A plan may leave `build.payloads.<name>.format` unset; the default is
//! [`PayloadFormat::Auto`]. Before validation, [`resolve`] reads each local
//! source and replaces `auto` with a concrete format:
//!
//! - a PE image is `pe`, unless its file header marks a DLL (or its name ends
//!   in `.dll`) → `dll`, or it carries a CLR header → `dotnet`;
//! - a `.ps1`/`.psm1` is `powershell`;
//! - anything else is raw `shellcode`.
//!
//! A remote source cannot be sniffed at plan-load time, so `auto` requires an
//! explicit format there.

use std::path::{Path, PathBuf};

use crate::error::{PackerError, Result};
use crate::paths::file_url_to_path;

use super::schema::{PayloadFormat, Plan};

/// Resolves every `format: auto` payload in `plan`.
///
/// Called by [`super::load_plan`] before semantic validation, so the validator,
/// the step resolver and the technique fragment selection all see a concrete
/// format.
pub fn resolve(plan: &mut Plan) -> Result<()> {
    for (name, payload) in &mut plan.build.payloads {
        if payload.format != PayloadFormat::Auto {
            continue;
        }
        let Some(path) = local_path(&payload.source) else {
            return Err(PackerError::Validation(format!(
                "payload '{name}': format 'auto' cannot read a remote source; set `format` to \
                 'exe', 'dll', 'shellcode', 'dotnet' or 'powershell'"
            )));
        };
        payload.format = detect(&path);
    }
    Ok(())
}

/// Detects a payload's format from its bytes, falling back to the extension when
/// the file cannot be read (a missing source, or a test plan parsed without the
/// payload next to it).
pub fn detect(path: &Path) -> PayloadFormat {
    if let Ok(bytes) = std::fs::read(path) {
        if bytes.starts_with(b"MZ") {
            return match crate::engine::pe::parse(&bytes) {
                Ok(info) if info.is_dotnet() => PayloadFormat::Dotnet,
                Ok(info)
                    if crate::engine::pe::is_dll(info.characteristics)
                        || has_dll_extension(path) =>
                {
                    PayloadFormat::Dll
                }
                _ => PayloadFormat::Pe,
            };
        }
        return if is_script_extension(path) {
            PayloadFormat::Powershell
        } else {
            PayloadFormat::Shellcode
        };
    }
    format_from_extension(path)
}

/// Whether the extension names a DLL.
fn has_dll_extension(path: &Path) -> bool {
    matches!(
        path.extension()
            .and_then(|extension| extension.to_str())
            .map(str::to_ascii_lowercase)
            .as_deref(),
        Some("dll")
    )
}

/// Whether the extension names a PowerShell script.
fn is_script_extension(path: &Path) -> bool {
    matches!(
        path.extension()
            .and_then(|extension| extension.to_str())
            .map(str::to_ascii_lowercase)
            .as_deref(),
        Some("ps1" | "psm1")
    )
}

/// Extension fallback when the payload cannot be read.
///
/// Only two extensions are conclusive: `.dll` (the name says the image is a
/// library) and the PowerShell script extensions. Everything else stays
/// `shellcode`, because an unreadable file has no PE structure to confirm it is
/// an executable.
fn format_from_extension(path: &Path) -> PayloadFormat {
    if has_dll_extension(path) {
        return PayloadFormat::Dll;
    }
    if is_script_extension(path) {
        return PayloadFormat::Powershell;
    }
    PayloadFormat::Shellcode
}

/// The local path a payload source names, or `None` for a remote URL.
fn local_path(source: &str) -> Option<PathBuf> {
    let lower = source.to_ascii_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") || lower.starts_with("ftp://")
    {
        return None;
    }
    if let Some(rest) = source.strip_prefix("file://") {
        return Some(PathBuf::from(file_url_to_path(rest)));
    }
    Some(PathBuf::from(source))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_a_pe_executable() {
        assert_eq!(
            detect(Path::new("examples/payloads/hello_world.exe")),
            PayloadFormat::Pe
        );
    }

    #[test]
    fn detects_raw_shellcode() {
        assert_eq!(
            detect(Path::new("examples/payloads/demo_shellcode.bin")),
            PayloadFormat::Shellcode
        );
    }

    #[test]
    fn detects_a_dotnet_assembly() {
        assert_eq!(
            detect(Path::new("tests/fixtures/managed_anycpu.exe")),
            PayloadFormat::Dotnet
        );
    }

    #[test]
    fn a_missing_file_falls_back_to_the_extension() {
        assert_eq!(detect(Path::new("missing.dll")), PayloadFormat::Dll);
        assert_eq!(detect(Path::new("missing.bin")), PayloadFormat::Shellcode);
        assert_eq!(detect(Path::new("missing.ps1")), PayloadFormat::Powershell);
        assert_eq!(detect(Path::new("missing.exe")), PayloadFormat::Shellcode);
    }

    #[test]
    fn a_pe_named_dll_is_a_dll_even_without_the_file_header_flag() {
        let source = Path::new("examples/payloads/hello_world.exe");
        let bytes = std::fs::read(source).expect("fixture");
        let path =
            std::env::temp_dir().join(format!("picaro-format-{}-library.dll", std::process::id()));
        std::fs::write(&path, &bytes).expect("temp payload");
        let format = detect(&path);
        let _ = std::fs::remove_file(&path);
        assert_eq!(format, PayloadFormat::Dll);
    }

    #[test]
    fn resolve_replaces_auto_with_the_detected_format() {
        let yaml = r#"
schema: 6
name: auto-test
build:
  payloads:
    implant:
      source: examples/payloads/hello_world.exe
  output:
    path: ./dist/auto.exe
runtime:
  - technique: reflective_loading
"#;
        let mut plan: Plan = serde_yml::from_str(yaml).expect("valid plan");
        assert_eq!(plan.build.payloads["implant"].format, PayloadFormat::Auto);
        resolve(&mut plan).expect("resolve");
        assert_eq!(plan.build.payloads["implant"].format, PayloadFormat::Pe);
    }

    #[test]
    fn resolve_rejects_a_remote_auto_source() {
        let yaml = r#"
schema: 6
name: auto-url
build:
  payloads:
    implant:
      source: "https://example.invalid/payload.bin"
  output:
    path: ./dist/auto.exe
runtime:
  - technique: reflective_loading
"#;
        let mut plan: Plan = serde_yml::from_str(yaml).expect("valid plan");
        let error = resolve(&mut plan).expect_err("a URL cannot be sniffed");
        assert!(error.to_string().contains("cannot read a remote source"));
    }

    #[test]
    fn exe_is_an_alias_for_pe() {
        let yaml = r#"
schema: 6
name: alias
build:
  payloads:
    implant:
      source: ./payload.exe
      format: exe
  output:
    path: ./dist/alias.exe
runtime:
  - technique: reflective_loading
"#;
        let plan: Plan = serde_yml::from_str(yaml).expect("valid plan");
        assert_eq!(plan.build.payloads["implant"].format, PayloadFormat::Pe);
    }
}
