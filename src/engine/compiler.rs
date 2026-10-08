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
//! Size therefore comes from `opt-level="z"` (optimize for size, not speed),
//! `codegen-units=1`, and `strip=symbols`: the stub is a small shim, so speed
//! is irrelevant next to a smaller artifact.
//!
//! `build.output` reaches this module as [`CompileOptions`]: `strip` maps to
//! `-C strip=...` and `trim_paths` to `--remap-path-prefix`, so both actually
//! shape the final binary instead of being display-only configuration.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;

use super::{BuildError, Result};
use crate::plan::schema::{Arch, OutputKind};

/// `rustc` executable names (Windows and Unix).
const RUSTC_NAMES: &[&str] = &["rustc.exe", "rustc"];

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

/// The `rustc` target triple the stub is compiled for, for a given architecture.
///
/// On Windows the host's environment (MSVC or GNU) picks the ABI; off Windows
/// the stub is always cross-compiled with the GNU ABI, which is what the Docker
/// image provides.
pub fn stub_target(arch: Arch) -> &'static str {
    match (ON_WINDOWS, cfg!(target_env = "msvc"), arch) {
        (true, true, Arch::X64) => "x86_64-pc-windows-msvc",
        (true, true, Arch::X86) => "i686-pc-windows-msvc",
        (true, false, Arch::X64) => "x86_64-pc-windows-gnu",
        (true, false, Arch::X86) => "i686-pc-windows-gnu",
        (false, _, Arch::X64) => "x86_64-pc-windows-gnu",
        (false, _, Arch::X86) => "i686-pc-windows-gnu",
    }
}

/// The triple `rustc` targets by default on this host (empty off Windows: there
/// the stub is always cross-compiled).
fn host_target() -> &'static str {
    if !ON_WINDOWS {
        return "";
    }
    match (cfg!(target_env = "msvc"), cfg!(target_arch = "x86_64")) {
        (true, true) => "x86_64-pc-windows-msvc",
        (true, false) => "i686-pc-windows-msvc",
        (false, true) => "x86_64-pc-windows-gnu",
        (false, false) => "i686-pc-windows-gnu",
    }
}

/// Whether the requested stub target is the host's own target: no `--target`
/// flag, and the stub's dependencies live in the host's `deps` directory.
fn is_native_target(arch: Arch) -> bool {
    ON_WINDOWS && stub_target(arch) == host_target()
}

/// The `rustc --version` line of the compiler the stub is built with.
///
/// Recorded in the build manifest so an artifact can be traced back to the
/// exact toolchain that produced it.
pub fn rustc_version() -> Result<String> {
    let rustc = find_rustc()?;
    let out = Command::new(&rustc)
        .arg("--version")
        .output()
        .map_err(|e| {
            BuildError::RustcVersion(format!("could not run '{}': {e}", rustc.display()))
        })?;
    if !out.status.success() {
        return Err(BuildError::RustcVersion(format!(
            "'{}' --version exited with {}",
            rustc.display(),
            out.status
        )));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Locates every dependency required to compile the stub for `arch`.
pub fn locate_stub_deps(arch: Arch) -> Result<StubDeps> {
    let native = is_native_target(arch);
    let deps_dir = if native {
        find_deps_dir_in(&target_dir())?
    } else {
        find_target_deps_dir(stub_target(arch))?
    };
    // Cross-compiling needs the host's `deps` directory too: the `windows-rs`
    // proc-macros are host binaries, not target artifacts.
    let host_deps_dir = if native {
        deps_dir.clone()
    } else {
        find_host_deps_dir()?
    };
    Ok(StubDeps {
        chacha_rlib: find_rlib(&deps_dir, "chacha20poly1305")?,
        hex_rlib: find_rlib(&deps_dir, "hex")?,
        windows_rlib: find_rlib(&deps_dir, "windows")?,
        thiserror_rlib: find_rlib(&deps_dir, "thiserror")?,
        windows_import_lib_dir: find_windows_import_lib_dir(arch)?,
        deps_dir,
        host_deps_dir,
    })
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

/// Finds the target's `deps` directory (`target/<triple>/{debug,release}/deps`),
/// reporting a clear error when the target has not been built.
fn find_target_deps_dir(triple: &str) -> Result<PathBuf> {
    let triple_dir = target_dir().join(triple);
    if triple_dir.is_dir() {
        if let Ok(deps) = find_deps_dir_in(&triple_dir) {
            return Ok(deps);
        }
    }
    Err(BuildError::MissingTarget {
        target: triple.to_string(),
    })
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
/// per-architecture `windows_*` crate: `windows_x86_64_msvc` / `windows_i686_msvc`
/// on Windows and their `_gnu` counterparts when cross-compiling from Linux. The
/// version is read from `Cargo.lock` so it matches exactly the one `windows`
/// uses.
fn find_windows_import_lib_dir(arch: Arch) -> Result<PathBuf> {
    let crate_name = windows_import_crate(arch);
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

/// The `windows` per-architecture import-lib crate name for a target.
fn windows_import_crate(arch: Arch) -> &'static str {
    match (ON_WINDOWS && cfg!(target_env = "msvc"), arch) {
        (true, Arch::X64) => "windows_x86_64_msvc",
        (true, Arch::X86) => "windows_i686_msvc",
        (false, Arch::X64) => "windows_x86_64_gnu",
        (false, Arch::X86) => "windows_i686_gnu",
    }
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

/// Reads the resolved version of a `windows_*` per-architecture crate from
/// `Cargo.lock`.
///
/// `windows` links against the import library provided by the per-arch crate
/// that its `windows-targets` dependency pulls in. The lock file can hold
/// several versions at once (e.g. `windows-sys 0.48` pulls
/// `windows-targets 0.48` while `windows` uses `windows-targets 0.52`), so we
/// resolve the chain `windows` → `windows-targets` → per-arch crate instead of
/// trusting the first matching entry, which need not match.
fn windows_crate_version(crate_name: &str) -> Result<String> {
    let lock_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.lock");
    let content = std::fs::read_to_string(&lock_path).map_err(|e| {
        BuildError::WindowsImportLibNotFound(format!(
            "could not read '{}': {e}",
            lock_path.display()
        ))
    })?;
    windows_crate_version_in(&content, crate_name)
}

/// Resolves the per-arch `windows_*` version from a `Cargo.lock` document.
fn windows_crate_version_in(lock: &str, crate_name: &str) -> Result<String> {
    let targets_version = dependency_version(lock, "windows", "windows-targets")?;
    dependency_version(
        lock,
        &format!("windows-targets {targets_version}"),
        crate_name,
    )
}

/// The version of `dep` that the package `spec` lists in its dependencies.
///
/// `spec` is either a bare crate name (`windows`) or a disambiguated
/// `"name version"` pair when the lock has several versions of the same crate.
fn dependency_version(lock: &str, spec: &str, dep: &str) -> Result<String> {
    let block = package_block(lock, spec)?;
    let marker = "dependencies = [";
    let start = block.find(marker).ok_or_else(|| {
        BuildError::WindowsImportLibNotFound(format!(
            "'{spec}' has no dependencies list in Cargo.lock"
        ))
    })? + marker.len();
    let end = block[start..].find(']').ok_or_else(|| {
        BuildError::WindowsImportLibNotFound(format!(
            "malformed dependencies list for '{spec}' in Cargo.lock"
        ))
    })? + start;

    for line in block[start..end].lines() {
        let entry = line.trim().trim_matches(',').trim().trim_matches('"');
        // `windows-targets` is listed with a version when several exist (the
        // only case we need to disambiguate); a bare name is left to the caller
        // to never hit.
        if let Some(version) = entry.strip_prefix(&format!("{dep} ")) {
            return Ok(version.trim_matches('"').to_string());
        }
    }

    Err(BuildError::WindowsImportLibNotFound(format!(
        "'{dep}' is not a dependency of '{spec}' in Cargo.lock"
    )))
}

/// The text of one `[[package]]` block for `spec` (`"name"` or `"name version"`).
fn package_block<'a>(lock: &'a str, spec: &str) -> Result<&'a str> {
    let (name, wanted_version) = match spec.split_once(' ') {
        Some((name, version)) => (name, Some(version)),
        None => (spec, None),
    };

    let mut offset = 0;
    while let Some(relative) = lock[offset..].find("[[package]]") {
        let start = offset + relative;
        let end = lock[start..]
            .find("\n[[package]]")
            .map(|next| start + next)
            .unwrap_or(lock.len());
        let block = &lock[start..end];
        if package_field(block, "name") == Some(name)
            && wanted_version.is_none_or(|version| package_field(block, "version") == Some(version))
        {
            return Ok(block);
        }
        offset = end;
    }

    Err(BuildError::WindowsImportLibNotFound(format!(
        "'{spec}' was not found in Cargo.lock"
    )))
}

/// The string value of a `key = "value"` field inside a package block.
fn package_field<'a>(block: &'a str, key: &str) -> Option<&'a str> {
    let marker = format!("{key} = \"");
    let start = block.find(&marker)? + marker.len();
    let end = block[start..].find('"')? + start;
    Some(&block[start..end])
}

/// How the compiled stub is finalized, resolved from `build.output`.
///
/// The compiler is the only place that can actually apply these, so the values
/// are threaded down from the plan instead of being display-only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompileOptions {
    /// Strip symbols and debug info (`-C strip=symbols`) when true.
    pub strip: bool,
    /// How build-time paths embedded in the binary are rewritten.
    pub trim_paths: PathTrim,
    /// Build the stub as a debug artifact (`build.stub.debug`): no symbols are
    /// stripped, the debug info is kept, the optimization level drops to 0 and
    /// path remapping is skipped, so a debugger can open the generated source.
    pub debug: bool,
    /// Architecture the stub is compiled for: selects the `rustc` target and the
    /// matching dependency set (`build.output.arch`).
    pub arch: Arch,
    /// What the artifact is: a binary or a host-loaded DLL
    /// (`build.output.kind`).
    pub kind: OutputKind,
}

impl Default for CompileOptions {
    /// Strip symbols and trim every path (the previous hardcoded behaviour).
    fn default() -> Self {
        Self {
            strip: true,
            trim_paths: PathTrim::All,
            debug: false,
            arch: Arch::X64,
            kind: OutputKind::Exe,
        }
    }
}

/// Build-time path rewriting applied with `--remap-path-prefix`.
///
/// Rust bakes absolute source paths into panic locations and debug info, which
/// leaks the operator's profile and build layout into the packed binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathTrim {
    /// Leave paths untouched.
    None,
    /// Make the project's own paths relative (remap the manifest dir to `.`).
    Relative,
    /// Also scrub the Cargo home, so no path under the user profile survives.
    All,
}

/// The replacement every remapped prefix is rewritten to.
const REMAP_TO: &str = ".";

/// The `-C strip=...` value for the requested output.
fn strip_flag(strip: bool) -> &'static str {
    if strip {
        "strip=symbols"
    } else {
        "strip=none"
    }
}

/// The `-C panic=...` strategy for the requested output.
///
/// A DLL runs inside a host process, so a panic must unwind into the entry
/// block's `catch_unwind` instead of taking `java.exe`/`python.exe` down with
/// it. An executable keeps `abort`: nothing catches a panic there, and the
/// unwinding machinery is weight — and `panic` strings — the artifact does not
/// need.
fn panic_flag(kind: OutputKind) -> &'static str {
    match kind {
        OutputKind::Dll => "panic=unwind",
        OutputKind::Exe => "panic=abort",
    }
}

/// A valid `rustc` crate name derived from the output file's stem.
///
/// Without `--crate-name` the crate is named after the generated source
/// (`main`), which is what ends up in panic locations and symbol paths. A DLL
/// should report the name it is delivered under.
fn crate_name(output: &Path) -> String {
    let stem = output
        .file_stem()
        .and_then(OsStr::to_str)
        .unwrap_or("loader");
    let mut name: String = stem
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if name.is_empty() || name.starts_with(|c: char| c.is_ascii_digit()) {
        name.insert(0, '_');
    }
    name
}

/// Appends one `--remap-path-prefix=<from>=<to>` pair to `flags`.
fn push_remap(from: &Path, to: &str, flags: &mut Vec<String>) {
    flags.push("--remap-path-prefix".to_string());
    flags.push(format!("{}={to}", from.display()));
}

/// Builds the flags that shape the final binary.
///
/// Split out from [`compile_stub`] so the mapping from [`CompileOptions`] to
/// `rustc` flags is unit-testable without invoking the compiler. `cargo_home`
/// is only needed for [`PathTrim::All`], hence optional.
///
/// A debug build deliberately drops the hardening: `opt-level=0` keeps every
/// line of the generated stub mapped to its instructions, `debuginfo=2` keeps
/// line tables and variable names, `strip=none` keeps the symbols, and the path
/// remapping is skipped so a debugger can resolve the source files. All of that
/// is what makes the artifact debuggable, and all of it costs evasion — hence
/// `build.stub.debug` is for the lab, never for delivery.
///
/// A release build trades speed for size: `opt-level="z"` (the smallest code),
/// `debug-assertions=off` and `overflow-checks=off` drop the assertion and
/// overflow machinery, and `strip`/`trim_paths` remove symbols and leak-proof
/// the paths.
fn hardening_flags(
    options: CompileOptions,
    manifest_dir: &Path,
    cargo_home: Option<&Path>,
) -> Vec<String> {
    let mut flags = Vec::new();
    if options.debug {
        flags.extend(["-C".to_string(), "opt-level=0".to_string()]);
        flags.extend(["-C".to_string(), "debuginfo=2".to_string()]);
        flags.extend(["-C".to_string(), "debug-assertions=on".to_string()]);
        flags.extend(["-C".to_string(), "overflow-checks=on".to_string()]);
        flags.extend(["-C".to_string(), strip_flag(false).to_string()]);
        return flags;
    }

    flags.extend(["-C".to_string(), "opt-level=z".to_string()]);
    flags.extend(["-C".to_string(), "debug-assertions=off".to_string()]);
    flags.extend(["-C".to_string(), "overflow-checks=off".to_string()]);
    flags.extend(["-C".to_string(), strip_flag(options.strip).to_string()]);
    match options.trim_paths {
        PathTrim::None => {}
        PathTrim::Relative => push_remap(manifest_dir, REMAP_TO, &mut flags),
        PathTrim::All => {
            push_remap(manifest_dir, REMAP_TO, &mut flags);
            if let Some(home) = cargo_home {
                push_remap(home, REMAP_TO, &mut flags);
            }
        }
    }
    flags
}

/// Compiles the generated stub into a final binary.
pub fn compile_stub(
    stub_rs: &Path,
    output: &Path,
    deps: &StubDeps,
    options: CompileOptions,
) -> Result<()> {
    let rustc = find_rustc()?;
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let home = cargo_home().ok();

    let mut cmd = Command::new(rustc);
    if !is_native_target(options.arch) {
        cmd.arg("--target").arg(stub_target(options.arch));
    }
    if options.kind == OutputKind::Dll {
        // A library the host loads with the normal image loader. The crate name
        // follows the output's stem so the artifact does not report the build's
        // internal file name; the linker takes the export directory's `Name`
        // from the link output itself.
        cmd.arg("--crate-type").arg("cdylib");
        cmd.arg("--crate-name").arg(crate_name(output));
    }
    cmd.arg(stub_rs)
        .arg("--edition")
        .arg("2021")
        .args(hardening_flags(options, manifest_dir, home.as_deref()))
        .arg("-C")
        .arg(panic_flag(options.kind))
        .arg("-C")
        .arg("codegen-units=1")
        .arg("-C")
        .arg("target-feature=+crt-static")
        .arg("-L")
        .arg(format!("dependency={}", deps.deps_dir.display()));
    if deps.host_deps_dir != deps.deps_dir {
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

    verify_pe_magic(output)?;
    verify_output_kind(output, options.kind)
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

/// Verifies that the compiled image is the kind `build.output.kind` asked for.
///
/// `rustc` links a `cdylib` from any source, including one whose entry points
/// were never exported (a name typo, a missing `#[no_mangle]`); the result is a
/// DLL no host can start, and nothing else in the build would notice.
/// `IMAGE_FILE_DLL` is the header bit that tells the two apart. An executable is
/// checked too: it catches an entry block that was rendered for a DLL into a
/// binary build.
fn verify_output_kind(path: &Path, kind: OutputKind) -> Result<()> {
    let bytes = std::fs::read(path)?;
    let info = crate::engine::pe::parse(&bytes).map_err(|e| {
        BuildError::CompilationFailed(format!(
            "the compiled stub '{}' is not a valid PE: {e}",
            path.display()
        ))
    })?;
    let is_dll = crate::engine::pe::is_dll(info.characteristics);
    match (kind, is_dll) {
        (OutputKind::Dll, false) => Err(BuildError::CompilationFailed(format!(
            "'{}' was built as a DLL (build.output.kind: dll) but the compiled image is an \
             executable: no export was linked",
            path.display()
        ))),
        (OutputKind::Exe, true) => Err(BuildError::CompilationFailed(format!(
            "'{}' was built as an executable but the compiled image is a DLL",
            path.display()
        ))),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::plan::schema::PayloadFormat;
    use crate::techniques::{RuntimeStep, TechniqueKind};

    #[test]
    fn find_executable_in_empty_path_is_none() {
        assert!(find_executable_in_path(OsStr::new(""), RUSTC_NAMES).is_none());
    }

    #[test]
    fn a_dll_build_unwinds_and_an_executable_aborts() {
        assert_eq!(panic_flag(OutputKind::Dll), "panic=unwind");
        assert_eq!(panic_flag(OutputKind::Exe), "panic=abort");
    }

    #[test]
    fn the_crate_name_follows_the_output_stem() {
        assert_eq!(crate_name(Path::new("picaro.dll")), "picaro");
        assert_eq!(crate_name(Path::new("/tmp/loader-x64.dll")), "loader_x64");
        // A Rust crate name may not start with a digit, and an empty stem needs
        // some name at all.
        assert_eq!(crate_name(Path::new("2fast.dll")), "_2fast");
        assert_eq!(crate_name(Path::new("")), "loader");
    }

    /// The stub target follows the requested architecture (and the host ABI on
    /// Windows); off Windows it is always the GNU cross target.
    #[test]
    fn stub_target_follows_the_arch() {
        let x64 = stub_target(Arch::X64);
        let x86 = stub_target(Arch::X86);
        assert!(x64.starts_with("x86_64-pc-windows-"), "x64: {x64}");
        assert!(x86.starts_with("i686-pc-windows-"), "x86: {x86}");
        assert_ne!(x64, x86);
    }

    /// The `windows` import-lib crate name is per architecture: `windows_i686_*`
    /// for x86, `windows_x86_64_*` for x64.
    #[test]
    fn windows_import_crate_is_per_arch() {
        assert!(windows_import_crate(Arch::X64).starts_with("windows_x86_64_"));
        assert!(windows_import_crate(Arch::X86).starts_with("windows_i686_"));
    }

    #[test]
    fn rustc_missing_produces_clear_error() {
        let err = find_rustc_in(OsStr::new("")).expect_err("an empty PATH should fail");
        let msg = err.to_string();
        assert!(msg.contains("rustc"), "unclear error message: {msg}");
    }

    #[test]
    fn rustc_version_reports_a_toolchain() {
        // `cargo test` cannot run without rustc, so this is not an extra
        // requirement; the manifest needs the same call to succeed.
        let version = rustc_version().expect("rustc --version should work");
        assert!(version.starts_with("rustc "), "unexpected: {version}");
    }

    /// `find_deps_dir_in` must locate `debug/deps` when the three rlibs are
    /// present under a given target directory.
    #[test]
    fn finds_deps_dir_under_debug() {
        let tmp = std::env::temp_dir().join(format!("picaro_deps_{}", std::process::id()));
        let deps = tmp.join("debug").join("deps");
        std::fs::create_dir_all(&deps).unwrap();
        for crate_name in ["chacha20poly1305", "hex", "windows"] {
            std::fs::write(deps.join(format!("lib{crate_name}-deadbeef.rlib")), b"").unwrap();
        }

        let found = find_deps_dir_in(&tmp).expect("should locate debug/deps");
        assert!(found.ends_with("debug/deps"));

        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// The per-arch crate version must be resolved through `windows`'s own
    /// `windows-targets` dependency, not the first `windows_x86_64_*` entry — a
    /// second `windows-targets` (e.g. from `windows-sys 0.48`) must not win.
    #[test]
    fn windows_crate_version_follows_the_windows_dependency_chain() {
        let lock = "\
[[package]]
name = \"windows\"
version = \"0.58.0\"
dependencies = [
 \"windows-core\",
 \"windows-targets 0.52.6\",
]

[[package]]
name = \"windows-targets\"
version = \"0.48.5\"
dependencies = [
 \"windows_x86_64_msvc 0.48.5\",
]

[[package]]
name = \"windows-targets\"
version = \"0.52.6\"
dependencies = [
 \"windows_x86_64_msvc 0.52.6\",
]
";

        let version = windows_crate_version_in(lock, "windows_x86_64_msvc")
            .expect("should resolve through windows -> windows-targets");
        assert_eq!(version, "0.52.6");
    }

    /// Extracts the `FROM=TO` pairs following each `--remap-path-prefix` flag.
    fn remaps(flags: &[String]) -> Vec<&str> {
        flags
            .iter()
            .enumerate()
            .filter(|(_, f)| f.as_str() == "--remap-path-prefix")
            .filter_map(|(i, _)| flags.get(i + 1).map(String::as_str))
            .collect()
    }

    #[test]
    fn strip_flag_follows_the_option() {
        let manifest = Path::new("/proj");
        let stripped = hardening_flags(
            CompileOptions {
                strip: true,
                trim_paths: PathTrim::None,
                debug: false,
                arch: Arch::X64,
                kind: OutputKind::Exe,
            },
            manifest,
            None,
        );
        assert!(stripped.contains(&"strip=symbols".to_string()));

        let kept = hardening_flags(
            CompileOptions {
                strip: false,
                trim_paths: PathTrim::None,
                debug: false,
                arch: Arch::X64,
                kind: OutputKind::Exe,
            },
            manifest,
            None,
        );
        assert!(kept.contains(&"strip=none".to_string()));
        assert!(!kept.contains(&"strip=symbols".to_string()));
    }

    #[test]
    fn trim_paths_none_emits_no_remap() {
        let flags = hardening_flags(
            CompileOptions {
                strip: true,
                trim_paths: PathTrim::None,
                debug: false,
                arch: Arch::X64,
                kind: OutputKind::Exe,
            },
            Path::new("/proj"),
            Some(Path::new("/home/dev")),
        );
        assert!(remaps(&flags).is_empty(), "flags: {flags:?}");
    }

    #[test]
    fn trim_paths_relative_remaps_only_the_manifest_dir() {
        let flags = hardening_flags(
            CompileOptions {
                strip: true,
                trim_paths: PathTrim::Relative,
                debug: false,
                arch: Arch::X64,
                kind: OutputKind::Exe,
            },
            Path::new("/proj"),
            Some(Path::new("/home/dev")),
        );
        assert_eq!(remaps(&flags), vec!["/proj=."]);
    }

    #[test]
    fn trim_paths_all_also_scrubs_the_cargo_home() {
        let flags = hardening_flags(
            CompileOptions {
                strip: true,
                trim_paths: PathTrim::All,
                debug: false,
                arch: Arch::X64,
                kind: OutputKind::Exe,
            },
            Path::new("/proj"),
            Some(Path::new("/home/dev/.cargo")),
        );
        assert_eq!(remaps(&flags), vec!["/proj=.", "/home/dev/.cargo=."]);
    }

    #[test]
    fn trim_paths_all_tolerates_a_missing_cargo_home() {
        let flags = hardening_flags(
            CompileOptions {
                strip: true,
                trim_paths: PathTrim::All,
                debug: false,
                arch: Arch::X64,
                kind: OutputKind::Exe,
            },
            Path::new("/proj"),
            None,
        );
        assert_eq!(remaps(&flags), vec!["/proj=."]);
    }

    /// A debug build keeps the symbols, the debug info and the real source
    /// paths, and drops the optimizer: that is the whole point of the mode.
    #[test]
    fn debug_flags_drop_the_hardening() {
        let flags = hardening_flags(
            CompileOptions {
                strip: true,
                trim_paths: PathTrim::All,
                debug: true,
                arch: Arch::X64,
                kind: OutputKind::Exe,
            },
            Path::new("/proj"),
            Some(Path::new("/home/dev/.cargo")),
        );
        assert!(flags.contains(&"opt-level=0".to_string()));
        assert!(flags.contains(&"debuginfo=2".to_string()));
        assert!(flags.contains(&"strip=none".to_string()));
        assert!(flags.contains(&"debug-assertions=on".to_string()));
        assert!(flags.contains(&"overflow-checks=on".to_string()));
        assert!(!flags.contains(&"strip=symbols".to_string()));
        assert!(!flags.contains(&"-O".to_string()));
        // Paths are kept so a debugger can open the generated stub.
        assert!(remaps(&flags).is_empty(), "flags: {flags:?}");
    }

    /// A release build optimizes for size: the smallest opt level and no
    /// assertion/overflow machinery. `codegen-units=1` (set in `compile_stub`)
    /// and `strip=symbols` finish the job.
    #[test]
    fn release_build_optimizes_for_size() {
        let flags = hardening_flags(
            CompileOptions {
                strip: true,
                trim_paths: PathTrim::None,
                debug: false,
                arch: Arch::X64,
                kind: OutputKind::Exe,
            },
            Path::new("/proj"),
            None,
        );
        assert!(
            flags.contains(&"opt-level=z".to_string()),
            "flags: {flags:?}"
        );
        assert!(flags.contains(&"debug-assertions=off".to_string()));
        assert!(flags.contains(&"overflow-checks=off".to_string()));
        assert!(flags.contains(&"strip=symbols".to_string()));
        assert!(!flags.contains(&"-O".to_string()));
        assert!(!flags.contains(&"opt-level=0".to_string()));
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

        let build_dir = std::env::temp_dir().join(format!("picaro_it_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&build_dir);
        std::fs::create_dir_all(&build_dir).unwrap();

        std::fs::write(build_dir.join("payload.bin"), &encrypted.ciphertext).unwrap();

        let tpl_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("templates")
            .join("stub")
            .join("main.rs.tpl");
        let template = std::fs::read_to_string(tpl_path).unwrap();
        let pipeline = vec![RuntimeStep::new(TechniqueKind::ProcessHollowing {
            params: crate::techniques::process_hollowing::Params {
                payload: None,
                target: r"C:\Windows\System32\svchost.exe".to_string(),
            },
        })];
        let params = crate::engine::steps::test_params(
            &pipeline,
            &encrypted,
            "payload.bin",
            PayloadFormat::Pe,
            None,
            false,
        );
        let strings = crate::engine::obfuscation::StringsConfig::from_yaml(None).unwrap();
        let syscalls = crate::engine::syscalls::SyscallsConfig::default();
        let stub_src = crate::engine::steps::render_builtin(
            &template,
            &params,
            &strings,
            &syscalls,
            &crate::engine::api_resolution::ApiResolutionConfig::default(),
        )
        .unwrap();
        let stub_path = build_dir.join("main.rs");
        std::fs::write(&stub_path, stub_src).unwrap();

        let deps = locate_stub_deps(Arch::X64).unwrap();
        let out = build_dir.join("out.exe");
        compile_stub(&stub_path, &out, &deps, CompileOptions::default()).unwrap();

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

        let build_dir = std::env::temp_dir().join(format!("picaro_str_{}", std::process::id()));
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

        let deps = locate_stub_deps(Arch::X64).unwrap();

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
            let pipeline = vec![RuntimeStep::new(TechniqueKind::ProcessHollowing {
                params: crate::techniques::process_hollowing::Params {
                    payload: None,
                    target: target.clone(),
                },
            })];
            let params = crate::engine::steps::test_params(
                &pipeline,
                &encrypted,
                "payload.bin",
                PayloadFormat::Pe,
                None,
                false,
            );
            let stub_src = crate::engine::steps::render_builtin(
                &template,
                &params,
                &strings,
                &crate::engine::syscalls::SyscallsConfig::default(),
                &crate::engine::api_resolution::ApiResolutionConfig::default(),
            )
            .unwrap();
            let stub_path = build_dir.join(format!("main_{name}.rs"));
            std::fs::write(&stub_path, stub_src).unwrap();

            let out = build_dir.join(format!("out_{name}.exe"));
            compile_stub(&stub_path, &out, &deps, CompileOptions::default()).unwrap();

            let binary = std::fs::read(&out).unwrap();
            assert!(
                !binary.windows(target.len()).any(|w| w == target.as_bytes()),
                "{name}: hollowing target leaked into the binary"
            );
        }

        let _ = std::fs::remove_dir_all(&build_dir);
    }

    /// Compiles a stub for each registered technique and asserts that no
    /// sensitive string literal (AMSI/ETW/DLL names, paths, technique keywords)
    /// appears in cleartext in the resulting PE's code/data sections.
    ///
    /// This is the safety net that stops a new technique fragment from
    /// introducing a cleartext literal. Marked `#[ignore]` because it compiles
    /// one stub per technique. Run it with `cargo test -- --ignored`.
    #[test]
    #[ignore = "requires rustc and the compiled dependencies"]
    fn no_sensitive_literals_in_generated_stubs() {
        use crate::audit::{pe_info, strings};
        use crate::techniques::{Category, RuntimeStep};

        let plaintext: Vec<u8> = (0..1024u32).map(|i| (i % 251) as u8).collect();
        let key = crate::engine::crypto::generate_key();
        let encrypted = crate::engine::crypto::encrypt_payload(&plaintext, &key).unwrap();

        let build_dir = std::env::temp_dir().join(format!("picaro_leak_{}", std::process::id()));
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

        let deps = locate_stub_deps(Arch::X64).unwrap();
        let strings = crate::engine::obfuscation::StringsConfig::from_yaml(None).unwrap();

        for def in crate::techniques::all() {
            let step: RuntimeStep = serde_yml::from_str(def.params_example)
                .unwrap_or_else(|e| panic!("{} params_example does not parse: {e}", def.name));

            // A Preparation technique needs an Execution technique so the stub
            // compiles; `reflective_loading` is used as the filler.
            let pipeline = if def.category == Category::Preparation {
                let execution: RuntimeStep =
                    serde_yml::from_str("technique: reflective_loading\n").unwrap();
                vec![step, execution]
            } else {
                vec![step]
            };

            let params = crate::engine::steps::test_params(
                &pipeline,
                &encrypted,
                "payload.bin",
                PayloadFormat::Pe,
                None,
                false,
            );
            let stub_src = crate::engine::steps::render_builtin(
                &template,
                &params,
                &strings,
                &crate::engine::syscalls::SyscallsConfig::default(),
                &crate::engine::api_resolution::ApiResolutionConfig::default(),
            )
            .unwrap();
            let stub_path = build_dir.join(format!("main_{}.rs", def.name));
            std::fs::write(&stub_path, &stub_src).unwrap();

            let out = build_dir.join(format!("out_{}.exe", def.name));
            compile_stub(&stub_path, &out, &deps, CompileOptions::default()).unwrap();

            let binary = std::fs::read(&out).unwrap();
            let pe = pe_info::analyze(&binary).unwrap();
            let code = pe_info::code_data(&binary, &pe.sections, &pe.import_text_ranges);
            // A hit in the binary alone is not proof of a leak: the `windows`
            // crate graph embeds `ntdll.dll` (via `windows-result`'s
            // `hresult.rs`) and the import table carries every imported DLL
            // name, none of which the packer controls. Only a literal that is
            // *also* present in the generated stub source — which is entirely
            // ours — is a real fragment leak.
            let in_source = strings::find_sensitive_literals_in_source(&stub_src);
            let leaked: Vec<String> = strings::find_sensitive_literals(&code)
                .into_iter()
                .filter(|lit| in_source.contains(lit))
                .collect();
            assert!(
                leaked.is_empty(),
                "technique '{}' leaks sensitive literals into the generated stub: {:?}. Route them through StringsConfig.",
                def.name,
                leaked
            );
        }

        let _ = std::fs::remove_dir_all(&build_dir);
    }

    /// Compiles `examples/stubs/minimal.rs` (a custom loader stub) and checks
    /// it produces a PE. Marked `#[ignore]` because it needs `rustc` and the
    /// compiled dependencies.
    #[test]
    #[ignore = "requires rustc and the compiled dependencies"]
    fn custom_stub_compiles_to_pe() {
        let template = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("examples")
                .join("stubs")
                .join("minimal.rs"),
        )
        .unwrap();

        let params = crate::engine::steps::test_params(
            &[],
            &crate::engine::crypto::EncryptedPayload {
                nonce: [0u8; 24],
                key: [0u8; 32],
                ciphertext: vec![0xAA, 0xBB, 0xCC, 0xDD],
                plaintext_len: 4,
            },
            "payload.bin",
            PayloadFormat::Pe,
            None,
            false,
        );
        let strings = crate::engine::obfuscation::StringsConfig::from_yaml(None).unwrap();
        let rendered = crate::engine::steps::render_custom(
            &template,
            &params,
            &strings,
            &crate::engine::syscalls::SyscallsConfig::default(),
            &crate::engine::api_resolution::ApiResolutionConfig::default(),
        )
        .unwrap();
        assert!(rendered.warnings.is_empty(), "no techniques declared");

        let build_dir = std::env::temp_dir().join(format!("picaro_custom_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&build_dir);
        std::fs::create_dir_all(&build_dir).unwrap();
        let stub_path = build_dir.join("main.rs");
        std::fs::write(&stub_path, &rendered.source).unwrap();

        let deps = locate_stub_deps(Arch::X64).unwrap();
        let out = build_dir.join("out.exe");
        compile_stub(&stub_path, &out, &deps, CompileOptions::default()).unwrap();

        let bytes = std::fs::read(&out).unwrap();
        assert_eq!(&bytes[..2], b"MZ", "custom stub must compile to a PE");

        let _ = std::fs::remove_dir_all(&build_dir);
    }

    // --- indirect syscalls (phase 6a) ---

    /// Builds a process-hollowing stub with the given syscall plan, writing
    /// `payload.bin` and the rendered stub into `build_dir`. Returns the path
    /// of the compiled exe. `payload` is the plaintext to pack.
    fn build_hollowing_exe(
        build_dir: &Path,
        name: &str,
        syscalls: &crate::engine::syscalls::SyscallsConfig,
        payload: &[u8],
    ) -> PathBuf {
        let key = crate::engine::crypto::generate_key();
        let encrypted = crate::engine::crypto::encrypt_payload(payload, &key).unwrap();
        std::fs::write(build_dir.join("payload.bin"), &encrypted.ciphertext).unwrap();

        let template = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("templates")
                .join("stub")
                .join("main.rs.tpl"),
        )
        .unwrap();
        let pipeline = vec![RuntimeStep::new(TechniqueKind::ProcessHollowing {
            params: crate::techniques::process_hollowing::Params {
                payload: None,
                target: r"C:\Windows\System32\svchost.exe".to_string(),
            },
        })];
        let params = crate::engine::steps::test_params(
            &pipeline,
            &encrypted,
            "payload.bin",
            PayloadFormat::Pe,
            None,
            false,
        );
        let strings = crate::engine::obfuscation::StringsConfig::from_yaml(None).unwrap();
        let stub_src = crate::engine::steps::render_builtin(
            &template,
            &params,
            &strings,
            syscalls,
            &crate::engine::api_resolution::ApiResolutionConfig::default(),
        )
        .unwrap();
        let stub_path = build_dir.join(format!("main_{name}.rs"));
        std::fs::write(&stub_path, stub_src).unwrap();

        let deps = locate_stub_deps(Arch::X64).unwrap();
        let out = build_dir.join(format!("out_{name}.exe"));
        compile_stub(&stub_path, &out, &deps, CompileOptions::default()).unwrap();
        out
    }

    /// Builds the hollowing stub in both syscall modes and asserts the IAT
    /// effect of `mode: indirect`: the four suspicious Win32 imports
    /// (VirtualAllocEx, WriteProcessMemory, ReadProcessMemory, ResumeThread)
    /// disappear, the NT names never appear in cleartext, and the output is
    /// still a PE. Marked `#[ignore]` because it compiles two stubs.
    #[test]
    #[ignore = "requires rustc and the compiled dependencies"]
    fn indirect_syscalls_remove_the_suspicious_imports() {
        use crate::audit::pe_info::{self, ImportItem};

        let build_dir =
            std::env::temp_dir().join(format!("picaro_syscalls_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&build_dir);
        std::fs::create_dir_all(&build_dir).unwrap();

        // This test only inspects the compiled binary, so the payload content
        // is irrelevant.
        let plaintext: Vec<u8> = (0..1024u32).map(|i| (i % 251) as u8).collect();

        let modes = [
            ("none", crate::engine::syscalls::SyscallsConfig::default()),
            (
                "indirect",
                crate::engine::syscalls::SyscallsConfig {
                    mode: crate::engine::syscalls::SyscallsMode::Indirect,
                    resolver: crate::engine::syscalls::Resolver::HellsGate,
                },
            ),
        ];

        for (name, syscalls) in modes {
            let out = build_hollowing_exe(&build_dir, name, &syscalls, &plaintext);
            let binary = std::fs::read(&out).unwrap();
            assert_eq!(&binary[..2], b"MZ", "{name}: the stub must compile to a PE");

            let pe = pe_info::analyze(&binary).unwrap();
            let imported: Vec<String> = pe
                .imports
                .iter()
                .flat_map(|d| &d.functions)
                .filter_map(|f| match f {
                    ImportItem::Named(n) => Some(n.clone()),
                    ImportItem::Ordinal(_) => None,
                })
                .collect();

            const SUSPICIOUS: &[&str] = &[
                "VirtualAllocEx",
                "WriteProcessMemory",
                "ReadProcessMemory",
                "ResumeThread",
            ];

            if name == "indirect" {
                for s in SUSPICIOUS {
                    assert!(
                        !imported.iter().any(|n| n == s),
                        "indirect mode must not import {s}"
                    );
                }
                // The NT names must not appear anywhere in the binary.
                for nt in [
                    "NtAllocateVirtualMemory",
                    "NtWriteVirtualMemory",
                    "NtReadVirtualMemory",
                    "NtResumeThread",
                    "NtUnmapViewOfSection",
                ] {
                    assert!(
                        !binary.windows(nt.len()).any(|w| w == nt.as_bytes()),
                        "indirect mode leaked cleartext {nt}"
                    );
                }
                // The userland APIs the stub still uses stay imported.
                for kept in ["CreateProcessA", "LoadLibraryA", "GetProcAddress"] {
                    assert!(
                        imported.iter().any(|n| n == kept),
                        "indirect mode should still import {kept}"
                    );
                }
            } else {
                for s in SUSPICIOUS {
                    assert!(
                        imported.iter().any(|n| n == s),
                        "none mode must keep importing {s} (baseline)"
                    );
                }
            }
        }

        let _ = std::fs::remove_dir_all(&build_dir);
    }

    /// Builds the hollowing stub with `resolver: tartarus_gate` and asserts it
    /// compiles to a PE and leaks no NT names in cleartext. Marked `#[ignore]`
    /// because it compiles a stub.
    #[test]
    #[ignore = "requires rustc and the compiled dependencies"]
    fn tartarus_gate_stub_compiles_to_pe() {
        let build_dir =
            std::env::temp_dir().join(format!("picaro_tartarus_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&build_dir);
        std::fs::create_dir_all(&build_dir).unwrap();

        let plaintext: Vec<u8> = (0..1024u32).map(|i| (i % 251) as u8).collect();
        let syscalls = crate::engine::syscalls::SyscallsConfig {
            mode: crate::engine::syscalls::SyscallsMode::Indirect,
            resolver: crate::engine::syscalls::Resolver::TartarusGate,
        };
        let out = build_hollowing_exe(&build_dir, "tartarus", &syscalls, &plaintext);

        let binary = std::fs::read(&out).unwrap();
        assert_eq!(
            &binary[..2],
            b"MZ",
            "the tartarus stub must compile to a PE"
        );
        for nt in [
            "NtAllocateVirtualMemory",
            "NtWriteVirtualMemory",
            "NtReadVirtualMemory",
            "NtResumeThread",
            "NtUnmapViewOfSection",
            "NtProtectVirtualMemory",
            "NtSuspendThread",
        ] {
            assert!(
                !binary.windows(nt.len()).any(|w| w == nt.as_bytes()),
                "tartarus mode leaked cleartext {nt}"
            );
        }

        let _ = std::fs::remove_dir_all(&build_dir);
    }

    /// Builds the hollowing stub with `resolver: api_hash` and asserts it
    /// compiles to a PE, leaks no NT names in cleartext, and emits no
    /// `GetProcAddress`-based resolution. Marked `#[ignore]` because it
    /// compiles a stub.
    #[test]
    #[ignore = "requires rustc and the compiled dependencies"]
    fn api_hash_stub_compiles_to_pe() {
        let build_dir =
            std::env::temp_dir().join(format!("picaro_api_hash_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&build_dir);
        std::fs::create_dir_all(&build_dir).unwrap();

        let plaintext: Vec<u8> = (0..1024u32).map(|i| (i % 251) as u8).collect();
        let syscalls = crate::engine::syscalls::SyscallsConfig {
            mode: crate::engine::syscalls::SyscallsMode::Indirect,
            resolver: crate::engine::syscalls::Resolver::ApiHash,
        };
        let out = build_hollowing_exe(&build_dir, "api_hash", &syscalls, &plaintext);

        let binary = std::fs::read(&out).unwrap();
        assert_eq!(
            &binary[..2],
            b"MZ",
            "the api_hash stub must compile to a PE"
        );
        for nt in [
            "NtAllocateVirtualMemory",
            "NtWriteVirtualMemory",
            "NtReadVirtualMemory",
            "NtResumeThread",
            "NtUnmapViewOfSection",
            "NtProtectVirtualMemory",
            "NtSuspendThread",
        ] {
            assert!(
                !binary.windows(nt.len()).any(|w| w == nt.as_bytes()),
                "api_hash mode leaked cleartext {nt}"
            );
        }

        let _ = std::fs::remove_dir_all(&build_dir);
    }

    /// Builds the hollowing stub with `mode: indirect` and runs the resulting
    /// binary on a Windows host.
    ///
    /// The stub exits `1` only when its own error path fires (decryption,
    /// syscall resolution, or a failed nt_* call); so the assertion is that it
    /// does NOT exit `1`. Any other outcome is accepted: the stub may relay the
    /// hollowed process's exit code (process hollowing can crash the payload on
    /// hardened hosts; that is a separate, pre-existing limitation and the
    /// stub's syscall calls all returned success before the hand-off). The test
    /// does not rely on the payload's output, which it prints to stdout.
    ///
    /// Marked `#[ignore]`; it only does something on a Windows host.
    #[test]
    #[ignore = "requires rustc, compiled deps and a Windows host with a desktop"]
    fn indirect_syscalls_binary_runs_on_windows() {
        if !cfg!(windows) {
            return;
        }

        let build_dir = std::env::temp_dir().join(format!("picaro_run_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&build_dir);
        std::fs::create_dir_all(&build_dir).unwrap();

        let syscalls = crate::engine::syscalls::SyscallsConfig {
            mode: crate::engine::syscalls::SyscallsMode::Indirect,
            resolver: crate::engine::syscalls::Resolver::HellsGate,
        };
        // The real test payload (it prints a fixed marker), not the synthetic
        // bytes the compile-only tests use: this test actually runs the stub,
        // which parses and executes the payload.
        let payload = std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("examples")
                .join("payloads")
                .join("test_payload.exe"),
        )
        .unwrap();
        let out = build_hollowing_exe(&build_dir, "run", &syscalls, &payload);

        let mut child = std::process::Command::new(&out)
            .spawn()
            .expect("the exe must start");
        // Give the stub time to decrypt, resolve SSNs and hollow svchost.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    assert_ne!(
                        status.code(),
                        Some(1),
                        "the stub failed through its own error path (syscall layer)"
                    );
                    break;
                }
                Ok(None) if std::time::Instant::now() >= deadline => {
                    // Still alive: the stub is waiting on the hollowed process.
                    let _ = child.kill();
                    break;
                }
                Ok(None) => std::thread::sleep(std::time::Duration::from_millis(200)),
                Err(e) => panic!("could not check the packed exe: {e}"),
            }
        }

        let _ = std::fs::remove_dir_all(&build_dir);
    }

    /// Renders a custom stub template with a fresh key and a small payload.
    ///
    /// The pipeline only drives the shared blocks (args/imports/syscalls); a
    /// custom template that ignores `$STEP_MODULES$` never pulls in a technique
    /// fragment, which is what lets the x86 toolchain be tested while every
    /// fragment is still x64-only.
    fn render_custom(template: &str, pipeline: &[crate::techniques::RuntimeStep]) -> String {
        let plaintext: Vec<u8> = (0..64u32).map(|i| i as u8).collect();
        let key = crate::engine::crypto::generate_key();
        let encrypted = crate::engine::crypto::encrypt_payload(&plaintext, &key).unwrap();
        let params = crate::engine::steps::test_params(
            pipeline,
            &encrypted,
            "payload.bin",
            PayloadFormat::Pe,
            None,
            false,
        );
        crate::engine::steps::render_custom(
            template,
            &params,
            &crate::engine::obfuscation::StringsConfig::from_yaml(None).unwrap(),
            &crate::engine::syscalls::SyscallsConfig::default(),
            &crate::engine::api_resolution::ApiResolutionConfig::default(),
        )
        .unwrap()
        .source
    }

    /// Renders the builtin stub template for a pipeline, returning the source and
    /// the ciphertext to write as `payload.bin` next to it (the builtin template
    /// `include_bytes!`s the payload).
    fn render_builtin(pipeline: &[crate::techniques::RuntimeStep]) -> (String, Vec<u8>) {
        let template = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("templates")
                .join("stub")
                .join("main.rs.tpl"),
        )
        .unwrap();

        let plaintext: Vec<u8> = (0..256u32).map(|i| i as u8).collect();
        let key = crate::engine::crypto::generate_key();
        let encrypted = crate::engine::crypto::encrypt_payload(&plaintext, &key).unwrap();
        let params = crate::engine::steps::test_params(
            pipeline,
            &encrypted,
            "payload.bin",
            PayloadFormat::Pe,
            None,
            false,
        );
        let source = crate::engine::steps::render_builtin(
            &template,
            &params,
            &crate::engine::obfuscation::StringsConfig::from_yaml(None).unwrap(),
            &crate::engine::syscalls::SyscallsConfig::default(),
            &crate::engine::api_resolution::ApiResolutionConfig::default(),
        )
        .unwrap();
        (source, encrypted.ciphertext)
    }

    /// Compiles `source` for i686 (writing `payload.bin` when the template needs
    /// it) and returns the parsed artifact.
    fn compile_i686(source: &str, payload: Option<&[u8]>, name: &str) -> crate::engine::pe::PeInfo {
        let build_dir =
            std::env::temp_dir().join(format!("picaro_i686_{name}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&build_dir);
        std::fs::create_dir_all(&build_dir).unwrap();

        if let Some(bytes) = payload {
            std::fs::write(build_dir.join("payload.bin"), bytes).unwrap();
        }
        let stub_path = build_dir.join("main.rs");
        std::fs::write(&stub_path, source).unwrap();

        let deps = locate_stub_deps(Arch::X86).unwrap();
        let out = build_dir.join("out.exe");
        compile_stub(
            &stub_path,
            &out,
            &deps,
            CompileOptions {
                arch: Arch::X86,
                ..CompileOptions::default()
            },
        )
        .unwrap();

        let bytes = std::fs::read(&out).unwrap();
        let info = crate::engine::pe::parse(&bytes).unwrap();
        let _ = std::fs::remove_dir_all(&build_dir);
        info
    }

    /// M0: picaro compiles a valid **i686** stub. The custom template ignores the
    /// technique blocks, so this exercises the toolchain (target selection, i686
    /// dependency set, `windows_i686_*` import lib, `--target` on a Windows host)
    /// while every technique fragment is still x64-only.
    ///
    /// Marked `#[ignore]` because it needs `rustc` and the workspace built for
    /// the i686 target: `cargo build --target i686-pc-windows-msvc` (or
    /// `i686-pc-windows-gnu` off Windows).
    #[test]
    #[ignore = "requires rustc and the workspace built for the i686 target"]
    fn compiles_an_i686_stub() {
        let template = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("examples")
                .join("stubs")
                .join("minimal.rs"),
        )
        .unwrap();
        let source = render_custom(&template, &[]);

        let info = compile_i686(&source, None, "minimal");
        assert_eq!(info.machine, crate::engine::pe::IMAGE_FILE_MACHINE_I386);
        assert_eq!(info.arch(), Some(Arch::X86));
    }

    /// M0: the shared blocks (payload arguments and the import resolver) compile
    /// for i686, including their x86 branches (`fs:[0x30]`, the 32-bit PEB
    /// offsets, 4-byte thunks and `IMAGE_ORDINAL_FLAG32`).
    ///
    /// The pipeline is only there to make the renderer emit `$ARGS_BLOCK$` /
    /// `$IMPORTS_BLOCK$`; the template ignores `$STEP_MODULES$`, so no x64
    /// technique fragment is linked in.
    #[test]
    #[ignore = "requires rustc and the workspace built for the i686 target"]
    fn compiles_the_shared_blocks_for_i686() {
        const TEMPLATE: &str = r#"
// The builtin template provides `dec_xor`; a custom stub that pulls in the
// obfuscated blocks has to provide it too.
#[inline(never)]
#[allow(dead_code)]
fn dec_xor(bytes: &[u8], key: &[u8; 32]) -> Vec<u8> {
    let mut out = bytes.to_vec();
    for (i, b) in out.iter_mut().enumerate() {
        *b ^= key[i % 32];
    }
    out
}

fn main() {}

$SYSCALLS_BLOCK$
$ARGS_BLOCK$
$IMPORTS_BLOCK$
"#;

        let pipeline = vec![RuntimeStep::new(TechniqueKind::ReflectiveLoading {
            params: crate::techniques::reflective_loading::Params::default(),
        })];
        let source = render_custom(TEMPLATE, &pipeline);
        assert!(source.contains("fs:[0x30]"), "the x86 PEB read is missing");
        assert!(
            source.contains("IMAGE_ORDINAL_FLAG32"),
            "the PE32 ordinal flag is missing"
        );

        let info = compile_i686(&source, None, "shared_blocks");
        assert_eq!(info.machine, crate::engine::pe::IMAGE_FILE_MACHINE_I386);
    }

    /// M1: the reflective-loading fragment compiles for i686 — the PE32 mapper,
    /// the hand-defined 32-bit `IMAGE_TLS_DIRECTORY` and the x86 entry call.
    #[test]
    #[ignore = "requires rustc and the workspace built for the i686 target"]
    fn compiles_a_reflective_stub_for_i686() {
        let pipeline = vec![RuntimeStep::new(TechniqueKind::ReflectiveLoading {
            params: crate::techniques::reflective_loading::Params::default(),
        })];
        let (source, ciphertext) = render_builtin(&pipeline);

        let info = compile_i686(&source, Some(&ciphertext), "reflective");
        assert_eq!(info.machine, crate::engine::pe::IMAGE_FILE_MACHINE_I386);
        assert_eq!(info.arch(), Some(Arch::X86));
    }

    /// M2: the process-hollowing fragment compiles for i686 — PE32 parsing,
    /// `CONTEXT32`, the `fs:[0x2C]` TLS array and the 32-bit `THREAD_BASIC_INFORMATION`.
    #[test]
    #[ignore = "requires rustc and the workspace built for the i686 target"]
    fn compiles_a_hollowing_stub_for_i686() {
        let pipeline = vec![RuntimeStep::new(TechniqueKind::ProcessHollowing {
            params: crate::techniques::process_hollowing::Params::default(),
        })];
        let (source, ciphertext) = render_builtin(&pipeline);

        let info = compile_i686(&source, Some(&ciphertext), "hollowing");
        assert_eq!(info.machine, crate::engine::pe::IMAGE_FILE_MACHINE_I386);
        assert_eq!(info.arch(), Some(Arch::X86));
    }

    /// M3: every x86-capable Preparation compiles for i686 next to an execution
    /// technique — `anti_debug`'s x86 debug-register `CONTEXT`, the arch-neutral
    /// AMSI/ETW patches and the `bouncer`'s Win32 checks.
    #[test]
    #[ignore = "requires rustc and the workspace built for the i686 target"]
    fn compiles_the_x86_preparations_for_i686() {
        use crate::techniques::{anti_debug, bouncer, patch_amsi, patch_etw, reflective_loading};
        let pipeline = vec![
            RuntimeStep::new(TechniqueKind::AntiDebug {
                params: anti_debug::Params::default(),
            }),
            RuntimeStep::new(TechniqueKind::PatchAmsi {
                params: patch_amsi::Params::default(),
            }),
            RuntimeStep::new(TechniqueKind::PatchEtw {
                params: patch_etw::Params::default(),
            }),
            RuntimeStep::new(TechniqueKind::Bouncer {
                params: bouncer::Params {
                    hostname: Some("WORKSTATION-*".to_string()),
                    not_in_vm: Some(true),
                    min_ram_mb: Some(2048),
                    ..bouncer::Params::default()
                },
            }),
            RuntimeStep::new(TechniqueKind::ReflectiveLoading {
                params: reflective_loading::Params::default(),
            }),
        ];
        let (source, ciphertext) = render_builtin(&pipeline);

        let info = compile_i686(&source, Some(&ciphertext), "preparations");
        assert_eq!(info.machine, crate::engine::pe::IMAGE_FILE_MACHINE_I386);
        assert_eq!(info.arch(), Some(Arch::X86));
    }

    /// M5: the `dotnet_hosting` fragment compiles for i686 — the COM vtable
    /// calls, the 16-byte `VARIANT` layout and the x86 `Invoke_3` ABI (the
    /// variant passed by value, not by reference as on x64).
    #[test]
    #[ignore = "requires rustc and the workspace built for the i686 target"]
    fn compiles_a_dotnet_hosting_stub_for_i686() {
        let pipeline = vec![RuntimeStep::new(TechniqueKind::DotnetHosting {
            params: crate::techniques::dotnet_hosting::Params::default(),
        })];
        let (source, ciphertext) = render_builtin(&pipeline);

        let info = compile_i686(&source, Some(&ciphertext), "dotnet_hosting");
        assert_eq!(info.machine, crate::engine::pe::IMAGE_FILE_MACHINE_I386);
        assert_eq!(info.arch(), Some(Arch::X86));
    }
}
