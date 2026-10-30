//! Live reproduction contract tests.
//!
//! These compile a stub and run the packer, so they are **not** part of the
//! inert suite: the whole file disappears without `--features live-tests`, and
//! every test is `#[ignore]`d even then. Run them by hand on the isolated lab
//! host, after `cargo build`:
//!
//! ```text
//! cargo build
//! cargo test --features live-tests -- --ignored
//! ```
//!
//! The first test is the definition of done for `docs/design/reproduction.md`:
//! the same effective inputs must produce the same unsigned artifact.

#![cfg(feature = "live-tests")]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const PAYLOAD: &str = "examples/payloads/hello_world.exe";

/// A fresh, uniquely named scratch directory for one test.
fn scratch(label: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let dir = std::env::temp_dir().join(format!("picaro_repro_{label}_{nanos}"));
    std::fs::create_dir_all(&dir).expect("scratch directory");
    dir
}

/// Writes a minimal plan that packs `PAYLOAD` with `reflective_loading`.
fn write_plan(dir: &Path) -> PathBuf {
    let payload = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(PAYLOAD)
        .display()
        .to_string()
        .replace('\\', "/");
    let out = dir.join("out.exe").display().to_string().replace('\\', "/");
    let yaml = format!(
        r#"schema: 6
name: live-repro
build:
  payloads:
    implant:
      source: "{payload}"
      format: pe
  output:
    path: "{out}"
    arch: x64
    strip: true
    trim_paths: all
runtime:
  - technique: reflective_loading
"#
    );
    let path = dir.join("plan.yaml");
    std::fs::write(&path, yaml).expect("write plan");
    path
}

/// Runs `picaro build` with `args` and returns the process output.
fn build(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_picaro"))
        .arg("build")
        .args(args)
        .output()
        .expect("run picaro")
}

/// The `unsigned_sha256` recorded by a manifest.
fn unsigned_hash(manifest: &Path) -> String {
    let text = std::fs::read_to_string(manifest).expect("read manifest");
    let value: serde_json::Value = serde_json::from_str(&text).expect("manifest JSON");
    value["reproduce"]["predecessor"]["unsigned_sha256"]
        .as_str()
        .expect("unsigned hash")
        .to_string()
}

/// `packed/live-repro-<run>/`: the bundle a test's build wrote.
fn bundle(run: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("packed")
        .join(format!("live-repro-{run}"))
}

/// The manifest a build writes for `artifact`: it lives in the bundle's
/// `artifacts/`, named after the delivered artifact. A replay writes the
/// `*.replay.json` variant so it never overwrites the recipe it was fed.
fn manifest(run: &str, artifact: &Path, replay: bool) -> PathBuf {
    let stem = artifact.file_stem().expect("stem").to_string_lossy();
    let suffix = if replay { ".replay" } else { "" };
    bundle(run)
        .join("artifacts")
        .join(format!("{stem}.manifest{suffix}.json"))
}

/// Runs a build that must succeed.
fn build_ok(args: &[&str]) {
    let output = build(args);
    assert!(
        output.status.success(),
        "build failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
#[ignore = "live: compiles and runs a stub; lab host only"]
fn the_same_seed_produces_the_same_unsigned_artifact() {
    let dir = scratch("same_seed");
    let plan = write_plan(&dir);
    let out = dir.join("out.exe");
    let plan_arg = plan.to_string_lossy().into_owned();
    let out_arg = out.to_string_lossy().into_owned();

    build_ok(&[
        &plan_arg,
        "--seed",
        "0x1234",
        "--out",
        &out_arg,
        "--build-name",
        "same-seed-a",
    ]);
    let first_hash = unsigned_hash(&manifest("same-seed-a", &out, false));
    // A *different* bundle path must not reach the artifact: the run label is
    // remapped away during compilation (see `stub_dir_remap`).
    build_ok(&[
        &plan_arg,
        "--seed",
        "0x1234",
        "--out",
        &out_arg,
        "--build-name",
        "same-seed-b",
    ]);
    let second_hash = unsigned_hash(&manifest("same-seed-b", &out, false));

    assert_eq!(
        first_hash, second_hash,
        "same seed must reproduce the bytes"
    );
}

#[test]
#[ignore = "live: compiles and runs a stub; lab host only"]
fn a_different_seed_changes_the_artifact() {
    let dir = scratch("different_seed");
    let plan = write_plan(&dir);
    let out = dir.join("out.exe");
    let plan_arg = plan.to_string_lossy().into_owned();
    let out_arg = out.to_string_lossy().into_owned();

    build_ok(&[
        &plan_arg,
        "--seed",
        "1",
        "--out",
        &out_arg,
        "--build-name",
        "different-seed",
    ]);
    let first_hash = unsigned_hash(&manifest("different-seed", &out, false));
    build_ok(&[
        &plan_arg,
        "--seed",
        "2",
        "--out",
        &out_arg,
        "--build-name",
        "different-seed",
    ]);
    let second_hash = unsigned_hash(&manifest("different-seed", &out, false));

    assert_ne!(
        first_hash, second_hash,
        "polymorphism and the payload cipher must still differ per seed"
    );
}

#[test]
#[ignore = "live: compiles and runs a stub; lab host only"]
fn replaying_a_manifest_reproduces_the_unsigned_artifact() {
    let dir = scratch("replay");
    let plan = write_plan(&dir);
    let out = dir.join("out.exe");
    let replay_out = dir.join("replay.exe");
    let plan_arg = plan.to_string_lossy().into_owned();
    let out_arg = out.to_string_lossy().into_owned();
    let replay_out_arg = replay_out.to_string_lossy().into_owned();

    build_ok(&[
        &plan_arg,
        "--seed",
        "0xabcd",
        "--out",
        &out_arg,
        "--build-name",
        "replay-source",
    ]);
    let recipe = manifest("replay-source", &out, false);
    let expected = unsigned_hash(&recipe);

    build_ok(&[
        &recipe.to_string_lossy(),
        "--verify",
        "--out",
        &replay_out_arg,
        "--build-name",
        "replay-copy",
    ]);
    let actual = unsigned_hash(&manifest("replay-copy", &replay_out, true));

    assert_eq!(
        expected, actual,
        "a replay must reproduce the unsigned bytes"
    );
}

#[test]
#[ignore = "live: compiles and runs a stub; lab host only"]
fn a_corrupted_payload_fails_on_the_pin() {
    let dir = scratch("corrupt");
    let plan = write_plan(&dir);
    let out = dir.join("out.exe");
    let plan_arg = plan.to_string_lossy().into_owned();
    let out_arg = out.to_string_lossy().into_owned();

    build_ok(&[
        &plan_arg,
        "--seed",
        "7",
        "--out",
        &out_arg,
        "--build-name",
        "corrupt",
    ]);
    let manifest = manifest("corrupt", &out, false);

    let mut bytes = std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join(PAYLOAD))
        .expect("read fixture payload");
    let last = bytes.len() - 1;
    bytes[last] ^= 0xFF;
    let corrupt = dir.join("corrupt.exe");
    std::fs::write(&corrupt, bytes).expect("write corrupt payload");
    let corrupt_arg = format!("implant={}", corrupt.display());

    let output = build(&[
        &manifest.to_string_lossy(),
        "--payload",
        &corrupt_arg,
        "--out",
        &out_arg,
    ]);
    assert!(!output.status.success(), "a corrupted payload must fail");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("does not match the manifest pin"),
        "unexpected error: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
#[ignore = "live: compiles and runs a stub; lab host only"]
fn strict_with_a_doctored_toolchain_exits_five() {
    let dir = scratch("strict");
    let plan = write_plan(&dir);
    let out = dir.join("out.exe");
    let plan_arg = plan.to_string_lossy().into_owned();
    let out_arg = out.to_string_lossy().into_owned();

    build_ok(&[
        &plan_arg,
        "--seed",
        "7",
        "--out",
        &out_arg,
        "--build-name",
        "strict",
    ]);
    let manifest = manifest("strict", &out, false);
    let text = std::fs::read_to_string(&manifest).expect("read manifest");
    let mut value: serde_json::Value = serde_json::from_str(&text).expect("manifest JSON");
    value["reproduce"]["toolchain"]["rustc"] =
        serde_json::Value::String("rustc 0.0.0 (doctored)".to_string());
    let doctored = dir.join("doctored.manifest.json");
    std::fs::write(
        &doctored,
        serde_json::to_string_pretty(&value).expect("json"),
    )
    .expect("write doctored manifest");

    let output = build(&[&doctored.to_string_lossy(), "--strict", "--out", &out_arg]);
    assert_eq!(
        output.status.code(),
        Some(5),
        "--strict must exit 5: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
