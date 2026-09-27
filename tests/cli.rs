//! Integration tests for the `picaro` CLI.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;

/// Serializes the e2e `picaro build` tests: they share the repo's `build/`
/// directory (wiped by each build), so two of them must not run concurrently.
static BUILD_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn techniques_list_lists_all_techniques() {
    let output = Command::new(env!("CARGO_BIN_EXE_picaro"))
        .args(["techniques", "list"])
        .output()
        .expect("run picaro techniques list");

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
    let output = Command::new(env!("CARGO_BIN_EXE_picaro"))
        .args(["techniques", "show", "process_hollowing"])
        .output()
        .expect("run picaro techniques show");

    assert!(output.status.success(), "show must exit 0");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("# Process hollowing"),
        "show output: {stdout}"
    );
}

/// End-to-end: `picaro build` with a Preparation + Execution pipeline
/// produces a PE. Marked `#[ignore]` because it compiles the stub (needs
/// `rustc` + the compiled dependencies).
#[test]
#[ignore = "requires rustc and the compiled dependencies"]
fn build_with_amsi_patch_produces_pe() {
    let _guard = BUILD_LOCK.lock().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_picaro"))
        .args(["build", "tests/plans/amsi-patch.yaml"])
        .output()
        .expect("run picaro build");
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
    let output = Command::new(env!("CARGO_BIN_EXE_picaro"))
        .args(["build", "tests/plans/invalid-order.yaml"])
        .output()
        .expect("run picaro build");
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
    let output = Command::new(env!("CARGO_BIN_EXE_picaro"))
        .args(["techniques", "list"])
        .output()
        .expect("run picaro techniques list");

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
    let output = Command::new(env!("CARGO_BIN_EXE_picaro"))
        .args(["--quiet", "techniques", "list"])
        .output()
        .expect("run picaro --quiet techniques list");

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
    let output = Command::new(env!("CARGO_BIN_EXE_picaro"))
        .args(["build", "tests/plans/bouncer.yaml"])
        .output()
        .expect("run picaro build");
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

    // Build the plan and run the packed binary, returning its stdout.
    let run = |plan: &str, exe: &str| -> String {
        let build = Command::new(env!("CARGO_BIN_EXE_picaro"))
            .args(["build", plan])
            .output()
            .expect("run picaro build");
        assert!(
            build.status.success(),
            "build {plan} failed: {}",
            String::from_utf8_lossy(&build.stderr)
        );
        let packed = Command::new(exe).output().expect("run the packed exe");
        String::from_utf8_lossy(&packed.stdout).into_owned()
    };

    const MARKER: &str = "PAYLOAD_MARKER_7f3a9c2e";

    let miss = run(
        "tests/plans/bouncer-miss.yaml",
        "dist/test_bouncer_miss.exe",
    );
    assert!(
        !miss.contains(MARKER),
        "the payload ran even though the host name did not match: {miss}"
    );

    let hit = run("tests/plans/bouncer.yaml", "dist/test_bouncer.exe");
    assert!(
        hit.contains(MARKER),
        "the payload did not run on a matching host: {hit}"
    );
}

/// End-to-end: `picaro build` with a custom loader stub produces a PE.
/// Marked `#[ignore]` because it compiles the stub.
#[test]
#[ignore = "requires rustc and the compiled dependencies"]
fn build_with_custom_stub_produces_pe() {
    let _guard = BUILD_LOCK.lock().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_picaro"))
        .args(["build", "examples/plans/custom-stub.yaml"])
        .output()
        .expect("run picaro build");
    assert!(
        output.status.success(),
        "build failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let bytes = std::fs::read("dist/test_custom_stub.exe").expect("read output");
    assert_eq!(&bytes[..2], b"MZ", "output must be a PE");
}

/// `build interactive` reads its answers from stdin. Choosing `quit` at the
/// review screen must write nothing and exit cleanly — no `rustc` needed, so
/// the test runs in the fast suite.
#[test]
fn build_interactive_quit_writes_nothing() {
    use std::io::Write;
    use std::process::Stdio;

    let plan_out = std::env::temp_dir().join("picaro_wizard_cli_quit.yaml");
    let _ = std::fs::remove_file(&plan_out);

    let mut child = Command::new(env!("CARGO_BIN_EXE_picaro"))
        .args(["build", "interactive", "examples/payloads/test_payload.exe"])
        .arg("--plan-out")
        .arg(&plan_out)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn picaro build interactive");

    // Nine blank answers walk the first pass with their defaults; `3` quits the
    // review screen, so the wizard stops before writing (or compiling) anything.
    let mut stdin = child.stdin.take().expect("stdin is piped");
    stdin.write_all(&b"\n".repeat(9)).expect("write answers");
    stdin.write_all(b"3\n").expect("write the quit choice");
    drop(stdin);

    let output = child.wait_with_output().expect("wait for picaro");
    assert!(
        output.status.success(),
        "wizard failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!plan_out.exists(), "the quit plan must not be written");
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
    let out = std::env::temp_dir().join(format!("picaro_args_payload_{}.exe", std::process::id()));
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
    let plan = format!(
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

    let plan_path = std::env::temp_dir().join(format!("picaro_args_{name}.yaml"));
    std::fs::write(&plan_path, plan).expect("write the temp plan");

    let output = Command::new(env!("CARGO_BIN_EXE_picaro"))
        .args(["build", plan_path.to_str().expect("utf-8 plan path")])
        .output()
        .expect("run picaro build");
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

// --- audit --json / --baseline ---

/// A checked-in x64 PE used by the hermetic audit tests.
const AUDIT_FIXTURE: &str = "tests/fixtures/minimal_x64.exe";

/// Runs `picaro` with `args` and returns the output.
fn picaro(args: &[&std::ffi::OsStr]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_picaro"))
        .args(args)
        .output()
        .expect("run picaro")
}

/// `audit --json` emits a JSON report whose top level is the report itself.
#[test]
fn audit_json_emits_a_machine_readable_report() {
    let out = picaro(&[
        "--quiet".as_ref(),
        "audit".as_ref(),
        AUDIT_FIXTURE.as_ref(),
        "--json".as_ref(),
    ]);
    assert!(
        out.status.success(),
        "audit --json failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let report: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("stdout must be valid JSON");
    assert_eq!(report["report_schema"], 1, "report: {report}");
    assert!(
        report["sections"].as_array().is_some_and(|s| !s.is_empty()),
        "the report must list sections"
    );
    assert!(
        report.get("baseline").is_none(),
        "no baseline was given, so none must be emitted"
    );
}

/// `audit` writes its JSON to a file and compares a later run against it: the
/// same binary is clean, a forced entropy jump exits 3.
#[test]
fn audit_baseline_gates_a_regression() {
    let json = picaro(&[
        "--quiet".as_ref(),
        "audit".as_ref(),
        AUDIT_FIXTURE.as_ref(),
        "--json".as_ref(),
    ]);
    assert!(json.status.success());

    let baseline = std::env::temp_dir().join("picaro_cli_baseline.json");
    std::fs::write(&baseline, &json.stdout).expect("write the baseline");

    // The same binary must not regress against its own report.
    let clean = picaro(&[
        "--quiet".as_ref(),
        "audit".as_ref(),
        AUDIT_FIXTURE.as_ref(),
        "--baseline".as_ref(),
        baseline.as_os_str(),
    ]);
    assert!(
        clean.status.success(),
        "a self-baseline must pass: {}",
        String::from_utf8_lossy(&clean.stdout)
    );
    assert!(String::from_utf8_lossy(&clean.stdout).contains("no regressions"));

    // Fake an entropy regression in the baseline, then it must fail with exit 3.
    let mut report: serde_json::Value = serde_json::from_slice(&json.stdout).expect("valid JSON");
    report["sections"][0]["entropy"] = serde_json::json!(0.0);
    std::fs::write(&baseline, serde_json::to_vec(&report).unwrap()).expect("rewrite baseline");

    let regressed = picaro(&[
        "--quiet".as_ref(),
        "audit".as_ref(),
        AUDIT_FIXTURE.as_ref(),
        "--baseline".as_ref(),
        baseline.as_os_str(),
    ]);
    assert_eq!(
        regressed.status.code(),
        Some(3),
        "a regression must exit 3: {}",
        String::from_utf8_lossy(&regressed.stdout)
    );
    assert!(String::from_utf8_lossy(&regressed.stdout).contains("regression"));
}

// --- build --dry-run / build.payload.sha256 ---

/// A minimal build plan (reflective loading, builtin stub) for `out`.
fn minimal_build_plan(out: &Path, sha256: Option<&str>) -> String {
    let sha_line = match sha256 {
        Some(hash) => format!("    sha256: \"{hash}\"\n"),
        None => String::new(),
    };
    let out = out.display().to_string().replace('\\', "/");
    format!(
        r#"schema: 4
name: cli-dry-run
build:
  payload:
    source: examples/payloads/test_payload.exe
{sha_line}    crypto:
      algo: xchacha20poly1305
      key: random
  output:
    path: "{out}"
    arch: x64
    strip: true
    trim_paths: all
runtime:
  - technique: reflective_loading
"#
    )
}

fn write_temp_plan(name: &str, body: &str) -> PathBuf {
    let path = std::env::temp_dir().join(name);
    std::fs::write(&path, body).expect("write the temp plan");
    path
}

/// `build --dry-run` validates the plan and payload but writes nothing — and
/// therefore needs no `rustc`, so it runs in the fast suite.
#[test]
fn build_dry_run_validates_without_writing() {
    let out = std::env::temp_dir().join("picaro_dry_run_out.exe");
    let manifest = std::env::temp_dir().join("picaro_dry_run_out.manifest.json");
    let _ = std::fs::remove_file(&out);
    let _ = std::fs::remove_file(&manifest);

    let plan = write_temp_plan("picaro_dry_run.yaml", &minimal_build_plan(&out, None));
    let output = picaro(&[
        "--quiet".as_ref(),
        "build".as_ref(),
        plan.as_os_str(),
        "--dry-run".as_ref(),
    ]);

    assert!(
        output.status.success(),
        "dry run failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("dry run"));
    assert!(!out.exists(), "a dry run must not write the artifact");
    assert!(!manifest.exists(), "a dry run must not write a manifest");
}

/// A `build.payload.sha256` that does not match the payload aborts the build
/// with a clear message, before anything is compiled.
#[test]
fn build_rejects_a_payload_sha256_mismatch() {
    let out = std::env::temp_dir().join("picaro_sha_out.exe");
    let wrong = "0".repeat(64);
    let plan = write_temp_plan(
        "picaro_sha_mismatch.yaml",
        &minimal_build_plan(&out, Some(&wrong)),
    );

    let output = picaro(&["--quiet".as_ref(), "build".as_ref(), plan.as_os_str()]);
    assert!(!output.status.success(), "a mismatch must fail");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("sha256 mismatch"),
        "unclear error: {stderr}"
    );
    assert!(!out.exists(), "nothing must be written on a mismatch");
}

// --- output.resources (icon / version info / manifest) ---

/// `build --dry-run` validates the resources (icon parsing, version strings and
/// manifest) without compiling, so it runs in the fast suite.
#[test]
fn build_dry_run_validates_resources() {
    let output = picaro(&[
        "--quiet".as_ref(),
        "build".as_ref(),
        "tests/plans/resources.yaml".as_ref(),
        "--dry-run".as_ref(),
    ]);
    assert!(
        output.status.success(),
        "resource dry run failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("icon"), "resources not shown: {stdout}");
    assert!(
        stdout.contains("resources"),
        "resources not shown: {stdout}"
    );
}

/// End-to-end: a plan with icon + version info + manifest embeds a `.rsrc`
/// section, which `audit --json` reports. Marked `#[ignore]` (compiles a stub).
#[test]
#[ignore = "requires rustc and the compiled dependencies"]
fn build_with_resources_embeds_a_resource_section() {
    let _guard = BUILD_LOCK.lock().unwrap();
    let build = picaro(&["build".as_ref(), "tests/plans/resources.yaml".as_ref()]);
    assert!(
        build.status.success(),
        "build failed: {}",
        String::from_utf8_lossy(&build.stderr)
    );

    let audit = picaro(&[
        "--quiet".as_ref(),
        "audit".as_ref(),
        "dist/test_resources.exe".as_ref(),
        "--json".as_ref(),
    ]);
    assert!(audit.status.success(), "audit failed");
    let report: serde_json::Value = serde_json::from_slice(&audit.stdout).expect("valid JSON");
    assert_eq!(
        report["has_manifest"], true,
        "no manifest resource: {report}"
    );
    assert_eq!(
        report["has_manifest"], true,
        "no manifest resource: {report}"
    );
    assert!(
        report["sections"]
            .as_array()
            .is_some_and(|s| s.iter().any(|s| s["name"] == ".rsrc")),
        "no .rsrc section: {report}"
    );
}

// --- output.sign / output.subsystem ---

/// A `sign.file` that does not exist is caught by `--dry-run` (no `signtool`
/// needed for this path, so the test is hermetic).
#[test]
fn build_dry_run_rejects_a_missing_signing_file() {
    let out = std::env::temp_dir().join("picaro_sign_out.exe");
    let yaml = minimal_build_plan(&out, None).replace(
        "    trim_paths: all\n",
        "    trim_paths: all\n    sign:\n      mode: file\n      file: ./does-not-exist.pfx\n",
    );
    let plan = write_temp_plan("picaro_sign_missing.yaml", &yaml);

    let output = picaro(&[
        "--quiet".as_ref(),
        "build".as_ref(),
        plan.as_os_str(),
        "--dry-run".as_ref(),
    ]);
    assert!(!output.status.success(), "a missing .pfx must fail");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("does not exist"), "unclear error: {stderr}");
}

/// An unknown `sign.mode` is rejected before anything runs.
#[test]
fn build_rejects_an_unknown_signing_mode() {
    let out = std::env::temp_dir().join("picaro_sign_mode_out.exe");
    let yaml = minimal_build_plan(&out, None).replace(
        "    trim_paths: all\n",
        "    trim_paths: all\n    sign:\n      mode: bogus\n",
    );
    let plan = write_temp_plan("picaro_sign_mode.yaml", &yaml);

    let output = picaro(&[
        "--quiet".as_ref(),
        "build".as_ref(),
        plan.as_os_str(),
        "--dry-run".as_ref(),
    ]);
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("output.sign.mode"),
        "unclear error: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// `version_info.randomize` is resolved during `--dry-run` (no `rustc` or
/// `signtool` needed), so the generated metadata is exercised hermetically.
#[test]
fn build_dry_run_resolves_randomized_metadata() {
    let out = std::env::temp_dir().join("picaro_random_out.exe");
    let yaml = minimal_build_plan(&out, None).replace(
        "    trim_paths: all\n",
        "    trim_paths: all\n    resources:\n      version_info:\n        randomize: true\n",
    );
    let plan = write_temp_plan("picaro_random.yaml", &yaml);

    let output = picaro(&[
        "--quiet".as_ref(),
        "build".as_ref(),
        plan.as_os_str(),
        "--dry-run".as_ref(),
    ]);
    assert!(
        output.status.success(),
        "randomized dry run failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("resources"));
}
