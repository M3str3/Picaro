//! Integration tests for the `batesian` CLI.

use std::process::Command;
use std::sync::Mutex;

/// Serializes the e2e `batesian build` tests: they share the repo's `build/`
/// directory (wiped by each build), so two of them must not run concurrently.
static BUILD_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn techniques_list_lists_all_techniques() {
    let output = Command::new(env!("CARGO_BIN_EXE_batesian"))
        .args(["techniques", "list"])
        .output()
        .expect("run batesian techniques list");

    assert!(output.status.success(), "list must exit 0");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("process_hollowing"),
        "list output: {stdout}"
    );
    assert!(
        stdout.contains("reflective_loading"),
        "list output: {stdout}"
    );
}

#[test]
fn techniques_show_prints_readme() {
    let output = Command::new(env!("CARGO_BIN_EXE_batesian"))
        .args(["techniques", "show", "process_hollowing"])
        .output()
        .expect("run batesian techniques show");

    assert!(output.status.success(), "show must exit 0");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("# Process hollowing"),
        "show output: {stdout}"
    );
}

/// End-to-end: `batesian build` with a Preparation + Execution pipeline
/// produces a PE. Marked `#[ignore]` because it compiles the stub (needs
/// `rustc` + the compiled dependencies).
#[test]
#[ignore = "requires rustc and the compiled dependencies"]
fn build_with_amsi_patch_produces_pe() {
    let _guard = BUILD_LOCK.lock().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_batesian"))
        .args(["build", "examples/configs/test-amsi-patch.yaml"])
        .output()
        .expect("run batesian build");
    assert!(
        output.status.success(),
        "build failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let bytes = std::fs::read("dist/test_amsi_patch.exe").expect("read output");
    assert_eq!(&bytes[..2], b"MZ", "output must be a PE");
}

/// End-to-end: a Preparation-after-Execution pipeline fails validation with a
/// clear error. Marked `#[ignore]` to keep the fast suite hermetic (this one
/// needs no `rustc`, but it is grouped with the other e2e build checks).
#[test]
#[ignore = "requires rustc and the compiled dependencies"]
fn build_with_invalid_order_fails() {
    let output = Command::new(env!("CARGO_BIN_EXE_batesian"))
        .args(["build", "examples/configs/test-invalid-order.yaml"])
        .output()
        .expect("run batesian build");
    assert!(!output.status.success(), "invalid order must fail");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("appears after the Execution technique"),
        "unclear error: {stderr}"
    );
}

/// The banner (and its tagline) is printed before every subcommand.
#[test]
fn banner_is_printed_by_default() {
    let output = Command::new(env!("CARGO_BIN_EXE_batesian"))
        .args(["techniques", "list"])
        .output()
        .expect("run batesian techniques list");

    assert!(output.status.success(), "list must exit 0");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("mimicry-based packer"),
        "banner missing: {stdout}"
    );
}

/// `--quiet` suppresses the banner but keeps the command output.
#[test]
fn quiet_flag_hides_the_banner() {
    let output = Command::new(env!("CARGO_BIN_EXE_batesian"))
        .args(["--quiet", "techniques", "list"])
        .output()
        .expect("run batesian --quiet techniques list");

    assert!(output.status.success(), "list must exit 0");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("mimicry-based packer"),
        "banner not suppressed: {stdout}"
    );
    assert!(
        stdout.contains("process_hollowing"),
        "output missing: {stdout}"
    );
}

/// End-to-end: `batesian build` with a custom loader stub produces a PE.
/// Marked `#[ignore]` because it compiles the stub.
#[test]
#[ignore = "requires rustc and the compiled dependencies"]
fn build_with_custom_stub_produces_pe() {
    let _guard = BUILD_LOCK.lock().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_batesian"))
        .args(["build", "examples/configs/test-custom-stub.yaml"])
        .output()
        .expect("run batesian build");
    assert!(
        output.status.success(),
        "build failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let bytes = std::fs::read("dist/test_custom_stub.exe").expect("read output");
    assert_eq!(&bytes[..2], b"MZ", "output must be a PE");
}
