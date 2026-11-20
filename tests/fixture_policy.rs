//! Fixture policy for `examples/payloads`.
//!
//! The directory mixes binaries that are part of the repository with binaries
//! that only exist after a build script runs, and that mix is what makes a
//! fresh clone fail: a tracked `.exe` has to survive `*.exe` in `.gitignore`,
//! and a file a script produces has to be documented as generated. These tests
//! are the inert guard for both halves — they only read files.

use std::path::PathBuf;

/// Every binary kept in the repository. `test_payload.rs` compiles to two
/// architectures, so the pair is listed separately.
const COMMITTED_BINARIES: &[&str] = &[
    "demo_shellcode.bin",
    "msgbox.exe",
    "test_payload.exe",
    "test_payload_x86.exe",
];

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn payloads() -> PathBuf {
    repo().join("examples/payloads")
}

fn gitignore() -> String {
    std::fs::read_to_string(repo().join(".gitignore")).expect("read .gitignore")
}

fn payload_readme() -> String {
    std::fs::read_to_string(payloads().join("README.md")).expect("read examples/payloads/README.md")
}

/// Quoted string literals of a script: `"src/file.rs"` and `"out.exe"`. The
/// scripts only ever quote paths and cmdlet arguments, so this is enough to see
/// what each one compiles and what it writes.
fn quoted_tokens(script: &str) -> Vec<String> {
    script
        .split('"')
        .skip(1)
        .step_by(2)
        .map(str::to_string)
        .collect()
}

fn build_scripts() -> Vec<PathBuf> {
    let mut scripts: Vec<PathBuf> = std::fs::read_dir(payloads())
        .expect("read examples/payloads")
        .map(|entry| entry.expect("directory entry").path())
        .filter(|path| {
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default();
            name.starts_with("build_") && name.ends_with(".ps1")
        })
        .collect();
    scripts.sort();
    scripts
}

#[test]
fn every_committed_binary_is_an_explicit_gitignore_exception() {
    let gitignore = gitignore();
    for name in COMMITTED_BINARIES {
        assert!(
            payloads().join(name).is_file(),
            "{name} is supposed to be committed but is missing from the working tree"
        );
        let exception = format!("!examples/payloads/{name}");
        assert!(
            gitignore.lines().any(|line| line.trim() == exception),
            ".gitignore has no `{exception}` line, so `git add` would skip a tracked fixture"
        );
    }
}

#[test]
fn every_build_script_points_at_a_source_that_exists() {
    let scripts = build_scripts();
    assert!(
        !scripts.is_empty(),
        "no build script found under examples/payloads"
    );
    for script in scripts {
        let name = script
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_string();
        let tokens = quoted_tokens(&std::fs::read_to_string(&script).expect("read build script"));
        let sources: Vec<&String> = tokens
            .iter()
            .filter(|token| token.ends_with(".rs"))
            .collect();
        assert!(
            !sources.is_empty(),
            "{name} names no `.rs` source to compile"
        );
        for source in sources {
            assert!(
                payloads().join(source).is_file(),
                "{name} compiles {source}, which does not exist"
            );
        }
    }
}

#[test]
fn every_built_binary_is_either_committed_or_documented_as_generated() {
    let gitignore = gitignore();
    let readme = payload_readme();
    for script in build_scripts() {
        let name = script
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_string();
        let tokens = quoted_tokens(&std::fs::read_to_string(&script).expect("read build script"));
        let outputs: Vec<&String> = tokens
            .iter()
            .filter(|token| token.ends_with(".exe"))
            .collect();
        assert!(!outputs.is_empty(), "{name} writes no `.exe`");
        for output in outputs {
            let exception = format!("!examples/payloads/{output}");
            let committed = gitignore.lines().any(|line| line.trim() == exception);
            if committed {
                assert!(
                    payloads().join(output.as_str()).is_file(),
                    "{name} output {output} is excepted in .gitignore but absent"
                );
            } else {
                assert!(
                    readme.contains(output.as_str()),
                    "{name} produces {output}; the payload README must say it is generated"
                );
            }
        }
    }
}
