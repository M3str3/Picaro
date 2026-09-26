//! Integration tests for the `batesian` CLI.

use std::path::{Path, PathBuf};
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

/// End-to-end: a `bouncer` Preparation + `reflective_loading` pipeline compiles
/// to a PE. Marked `#[ignore]` because it compiles the stub.
#[test]
#[ignore = "requires rustc and the compiled dependencies"]
fn build_with_bouncer_produces_pe() {
    let _guard = BUILD_LOCK.lock().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_batesian"))
        .args(["build", "examples/configs/test-bouncer.yaml"])
        .output()
        .expect("run batesian build");
    assert!(
        output.status.success(),
        "build failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let bytes = std::fs::read("dist/test_bouncer.exe").expect("read output");
    assert_eq!(&bytes[..2], b"MZ", "output must be a PE");
}

/// End-to-end (Windows): the `bouncer` gate rejects a host whose name does not
/// match and lets a matching host run the payload.
///
/// The payload prints `PAYLOAD_MARKER_7f3a9c2e` to stdout, so the presence or
/// absence of that line tells whether the gate worked. Marked `#[ignore]`
/// because it compiles two stubs and needs a Windows host.
#[test]
#[ignore = "requires rustc, the compiled dependencies and a Windows host"]
fn bouncer_gate_blocks_and_allows_on_windows() {
    if !cfg!(windows) {
        return;
    }
    let _guard = BUILD_LOCK.lock().unwrap();

    // Build the config and run the packed binary, returning its stdout.
    let run = |config: &str, exe: &str| -> String {
        let build = Command::new(env!("CARGO_BIN_EXE_batesian"))
            .args(["build", config])
            .output()
            .expect("run batesian build");
        assert!(
            build.status.success(),
            "build {config} failed: {}",
            String::from_utf8_lossy(&build.stderr)
        );
        let packed = Command::new(exe).output().expect("run the packed exe");
        String::from_utf8_lossy(&packed.stdout).into_owned()
    };

    const MARKER: &str = "PAYLOAD_MARKER_7f3a9c2e";

    let miss = run(
        "examples/configs/test-bouncer-miss.yaml",
        "dist/test_bouncer_miss.exe",
    );
    assert!(
        !miss.contains(MARKER),
        "the payload ran even though the host name did not match: {miss}"
    );

    let hit = run(
        "examples/configs/test-bouncer.yaml",
        "dist/test_bouncer.exe",
    );
    assert!(
        hit.contains(MARKER),
        "the payload did not run on a matching host: {hit}"
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

/// `build interactive` reads its answers from stdin. Declining the final
/// confirmation must write nothing and exit cleanly — no `rustc` needed, so the
/// test runs in the fast suite.
#[test]
fn build_interactive_declines_without_writing() {
    use std::io::Write;
    use std::process::Stdio;

    let config_out = std::env::temp_dir().join("batesian_wizard_cli_decline.yaml");
    let _ = std::fs::remove_file(&config_out);

    let mut child = Command::new(env!("CARGO_BIN_EXE_batesian"))
        .args(["build", "interactive", "examples/payloads/test_payload.exe"])
        .arg("--config-out")
        .arg(&config_out)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn batesian build interactive");

    // Nine blank answers walk the menus with their defaults; the tenth declines
    // the write, so the wizard stops before compiling anything.
    let mut stdin = child.stdin.take().expect("stdin is piped");
    stdin.write_all(&b"\n".repeat(9)).expect("write answers");
    stdin.write_all(b"n\n").expect("write the decline");
    drop(stdin);

    let output = child.wait_with_output().expect("wait for batesian");
    assert!(
        output.status.success(),
        "wizard failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !config_out.exists(),
        "the declined config must not be written"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("build interactive"),
        "no command echo: {stdout}"
    );
}

// --- payload runtime arguments ---

/// Compiles `examples/payloads/test_args_payload.rs` and returns the exe path.
fn build_args_payload() -> PathBuf {
    let src = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("examples")
        .join("payloads")
        .join("test_args_payload.rs");
    let out =
        std::env::temp_dir().join(format!("batesian_args_payload_{}.exe", std::process::id()));
    let status = Command::new("rustc")
        .arg(&src)
        .arg("-O")
        .arg("-C")
        .arg("strip=symbols")
        .arg("-o")
        .arg(&out)
        .status()
        .expect("run rustc to build the args test payload");
    assert!(status.success(), "rustc failed to build the test payload");
    out
}

/// Packs `payload` with reflective loading, `args` and `mode`, and returns the
/// packed exe path (relative to the crate root, where `cargo test` runs).
fn pack_args_payload(name: &str, payload: &Path, args: &[&str], mode: &str) -> PathBuf {
    let yaml_args = args
        .iter()
        .map(|arg| format!("      - \"{arg}\"\n"))
        .collect::<String>();
    let source = payload.display().to_string().replace('\\', "/");
    let config = format!(
        r#"schema: 4
name: {name}
build:
  payload:
    source: "{source}"
    args:
{yaml_args}    args_mode: {mode}
    crypto:
      algo: xchacha20poly1305
      key: random
  output:
    path: ./dist/{name}.exe
    arch: x64
    strip: true
    trim_paths: all
runtime:
  - technique: reflective_loading
"#
    );

    let config_path = std::env::temp_dir().join(format!("batesian_args_{name}.yaml"));
    std::fs::write(&config_path, config).expect("write the temp config");

    let output = Command::new(env!("CARGO_BIN_EXE_batesian"))
        .args(["build", config_path.to_str().expect("utf-8 config path")])
        .output()
        .expect("run batesian build");
    assert!(
        output.status.success(),
        "build failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    PathBuf::from(format!("dist/{name}.exe"))
}

/// Extracts the payload's `argv` from its `ARGS_BEGIN`/`ARGS_END` stdout block.
fn payload_argv(stdout: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(stdout);
    let mut argv = Vec::new();
    let mut inside = false;
    for line in text.lines() {
        match line {
            "ARGS_BEGIN" => inside = true,
            "ARGS_END" => break,
            _ if inside => argv.push(line.to_string()),
            _ => {}
        }
    }
    assert!(!argv.is_empty(), "the payload printed no argv:\n{text}");
    argv
}

/// Runs the packed binary with `args` and returns its parsed payload `argv`.
fn run_packed(exe: &Path, args: &[&str]) -> Vec<String> {
    let output = Command::new(exe)
        .args(args)
        .output()
        .expect("run the packed binary");
    assert!(
        output.status.success(),
        "packed run failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    payload_argv(&output.stdout)
}

/// End-to-end: with `args_mode: join`, the payload receives the YAML args
/// followed by the runtime args. `argv[0]` is the executable name.
/// `#[ignore]`: needs `rustc` and the compiled dependencies.
#[test]
#[ignore = "requires rustc and the compiled dependencies"]
fn payload_receives_yaml_then_runtime_args() {
    let _guard = BUILD_LOCK.lock().unwrap();
    let payload = build_args_payload();
    let exe = pack_args_payload("test_args_join", &payload, &["yaml-a", "yaml-b"], "join");

    let argv = run_packed(&exe, &["runtime-c", "runtime-d"]);
    assert_eq!(argv.len(), 5, "argv: {argv:?}");
    assert_eq!(&argv[1..], &["yaml-a", "yaml-b", "runtime-c", "runtime-d"]);

    // With no runtime args the payload still gets the YAML ones.
    let argv = run_packed(&exe, &[]);
    assert_eq!(&argv[1..], &["yaml-a", "yaml-b"]);
}

/// End-to-end: with `args_mode: override`, the runtime args replace the YAML
/// ones when present, and the YAML args are used when there are none.
#[test]
#[ignore = "requires rustc and the compiled dependencies"]
fn payload_override_mode_prefers_runtime_args() {
    let _guard = BUILD_LOCK.lock().unwrap();
    let payload = build_args_payload();
    let exe = pack_args_payload(
        "test_args_override",
        &payload,
        &["yaml-a", "yaml-b"],
        "override",
    );

    let argv = run_packed(&exe, &["runtime-c"]);
    assert_eq!(&argv[1..], &["runtime-c"]);

    let argv = run_packed(&exe, &[]);
    assert_eq!(&argv[1..], &["yaml-a", "yaml-b"]);
}
