//! Live test for the `advapi32!DuplicateTokenEx` proxy (`docs/bugs.md` #3).
//!
//! The wrapper carries the requested impersonation level in the
//! `OBJECT_ATTRIBUTES`/`SECURITY_QUALITY_OF_SERVICE` pair passed to
//! `NtDuplicateToken`; without it the duplicate keeps the source token's level.
//! This test packs
//! the `token_probe` fixture with indirect syscalls and the API-resolution
//! proxy, runs the artifact and checks the level the kernel reports for the
//! duplicate.
//!
//! It compiles and runs a loader, so it is not part of the inert suite: the
//! whole file disappears without `--features live-tests`, and the test is
//! `#[ignore]`d even then. Run it by hand on the isolated lab host, after
//! `cargo build`:
//!
//! ```text
//! cargo test --features live-tests -- --ignored
//! ```

#![cfg(feature = "live-tests")]

use std::path::{Path, PathBuf};
use std::process::Command;

/// A fresh, uniquely named scratch directory for one test.
fn scratch(label: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let dir = std::env::temp_dir().join(format!("picaro_token_proxy_{label}_{nanos}"));
    std::fs::create_dir_all(&dir).expect("scratch directory");
    dir
}

/// Compiles the probe fixture with a single `rustc`.
fn build_probe(dir: &Path) -> PathBuf {
    let source = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("token_probe.rs");
    let exe = dir.join("token_probe.exe");
    let status = Command::new("rustc")
        .arg(&source)
        .args(["-O", "-C", "strip=symbols", "-o"])
        .arg(&exe)
        .status()
        .expect("run rustc to build the token probe");
    assert!(status.success(), "the token probe did not compile");
    exe
}

/// Writes the plan that packs `payload` with indirect syscalls and the token
/// proxies, under `reflective_loading`.
fn write_plan(dir: &Path, payload: &Path, out: &Path) -> PathBuf {
    let payload = payload.display().to_string().replace('\\', "/");
    let out = out.display().to_string().replace('\\', "/");
    let yaml = format!(
        r#"schema: 6
name: token-proxy
build:
  payloads:
    probe:
      source: "{payload}"
      format: pe
  stub:
    syscalls:
      mode: indirect
      resolver: hells_gate
    api_resolution:
      mode: proxy
      apis:
        - "advapi32!OpenProcessToken"
        - "advapi32!DuplicateTokenEx"
      unmatched: forward
  output:
    path: "{out}"
runtime:
  - technique: reflective_loading
"#
    );
    let path = dir.join("plan.yaml");
    std::fs::write(&path, yaml).expect("write plan");
    path
}

#[test]
#[ignore = "live: compiles and runs a stub; lab host only"]
fn duplicate_token_ex_proxy_applies_security_impersonation() {
    if !cfg!(windows) {
        return;
    }

    let dir = scratch("level");
    let probe = build_probe(&dir);
    let out = dir.join("out.exe");
    let plan = write_plan(&dir, &probe, &out);
    // `output.path` is the exact delivered path; the bundle under `packed/`
    // keeps the canonical copy and the provenance.
    let artifact = out.clone();
    let plan_arg = plan.to_string_lossy().into_owned();

    let build = Command::new(env!("CARGO_BIN_EXE_picaro"))
        .args(["build", &plan_arg])
        .output()
        .expect("run picaro build");
    assert!(
        build.status.success(),
        "build failed: {}",
        String::from_utf8_lossy(&build.stderr)
    );

    let run = Command::new(&artifact)
        .output()
        .expect("run the packed exe");
    let stdout = String::from_utf8_lossy(&run.stdout);
    assert!(
        stdout.contains("TOKEN level=2"),
        "DuplicateTokenEx did not apply SecurityImpersonation: {stdout}"
    );
}
