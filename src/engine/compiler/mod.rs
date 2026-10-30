//! Compilation of the generated stub with `rustc`.
//!
//! On Windows the stub is compiled natively: `rustc` targets the host and the
//! dependencies are read from `target/{debug,release}/deps/`. On Linux/WSL the
//! stub is cross-compiled to `x86_64-pc-windows-gnu`: the dependencies come from
//! `target/x86_64-pc-windows-gnu/{debug,release}/deps/`, the host `deps` dir
//! provides the `windows-rs` proc-macros, and the GNU import library is passed
//! via `-L native`.
//!
//! Note: `-C lto=fat` (and, with the precompiled `.rlib`s cargo produces,
//! likely `thin` too) fails because those `.rlib` files do not carry bitcode
//! (`.llvmbc`), so `lto` with `--extern` cannot be used. The `lto` pool is
//! therefore `[off]` by default. Size comes from `opt-level="z"`,
//! `codegen-units=1` and `strip=symbols`: the stub is a small shim, so speed is
//! irrelevant next to a smaller artifact. `build.polymorphism` may vary
//! `opt-level`/`codegen-units` per build (see `super::polymorphism`).
//!
//! `build.output` reaches this module as [`CompileOptions`]: `strip` maps to
//! `-C strip=...` and `trim_paths` to `--remap-path-prefix`, so both actually
//! shape the final binary instead of being display-only configuration.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;

use super::polymorphism::CodegenProfile;
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

/// Whether the stub target links with MSVC's `link.exe`.
fn target_is_msvc(arch: Arch) -> bool {
    stub_target(arch).ends_with("-msvc")
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
pub(crate) fn cargo_home() -> Result<PathBuf> {
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
    /// Strip symbols and debug info (`-C strip=symbols`, plus `/DEBUG:NONE` on
    /// MSVC so the linker emits no debug directory) when true.
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
    /// Seeded codegen profile (`build.polymorphism`): `-C codegen-units`,
    /// `-C opt-level`, `-C lto`, `-C llvm-args=--inline-threshold` and
    /// `-Z randomize-layout`/`-Z layout-seed`. [`CodegenProfile::default`] is
    /// exactly the previous hardcoded release flags.
    pub codegen: CodegenProfile,
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
            codegen: CodegenProfile::default(),
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
/// block's `catch_unwind` instead of taking the host down with it. Shellcode is
/// the same DLL, mapped reflectively into a host, so it keeps the same
/// strategy. An executable keeps `abort`: nothing catches a panic there, and the
/// unwinding machinery is weight — and `panic` strings — the artifact does not
/// need.
fn panic_flag(kind: OutputKind) -> &'static str {
    match kind {
        // A psmodule build compiles C#, not a Rust stub; the value is unused.
        // Shellcode aborts like an executable: there is no host loader to
        // protect, and `panic=unwind` pulls std's panic thread-locals into the
        // stub, which gives the mapped image static TLS that sRDI cannot
        // provision safely (see vendor/srdi/ShellcodeRDI.c, STEP 10b).
        OutputKind::Dll | OutputKind::PsModule => "panic=unwind",
        OutputKind::Exe | OutputKind::Shellcode => "panic=abort",
    }
}

/// Whether this output kind is compiled as a `cdylib`.
///
/// Both a host-loaded DLL and the shellcode that wraps one are built as a
/// library: shellcode is the DLL plus a reflective loader, not a separate
/// compile shape.
fn compiles_as_dll(kind: OutputKind) -> bool {
    matches!(kind, OutputKind::Dll | OutputKind::Shellcode)
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

    flags.extend([
        "-C".to_string(),
        format!("opt-level={}", options.codegen.opt_level.flag()),
    ]);
    flags.extend(["-C".to_string(), "debug-assertions=off".to_string()]);
    flags.extend(["-C".to_string(), "overflow-checks=off".to_string()]);
    if let Some(lto) = options.codegen.lto.flag() {
        flags.extend(["-C".to_string(), format!("lto={lto}")]);
    }
    if let Some(threshold) = options.codegen.inline_threshold {
        flags.extend([
            "-C".to_string(),
            format!("llvm-args=--inline-threshold={threshold}"),
        ]);
    }
    if let Some(level) = options.codegen.mir_opt_level {
        // MIR optimization level; unstable, hence `RUSTC_BOOTSTRAP=1`.
        flags.extend(["-Z".to_string(), format!("mir-opt-level={level}")]);
    }
    if options.codegen.randomize_layout {
        // Per-build `repr(Rust)` field order. Unstable, hence `RUSTC_BOOTSTRAP=1`
        // (set in `compile_stub`); the toolchain is frozen in the container.
        flags.extend(["-Z".to_string(), "randomize-layout".to_string()]);
        flags.extend([
            "-Z".to_string(),
            format!("layout-seed={}", options.codegen.layout_seed),
        ]);
    }
    flags.extend(["-C".to_string(), strip_flag(options.strip).to_string()]);
    // `strip=symbols` empties the symbol and debug tables but leaves the
    // linker's debug directory (RSDS) pointing at a PDB next to the scratch
    // output, so the stub's file stem and a path-shaped reference survive into
    // the artifact. `/DEBUG:NONE` stops link.exe from emitting the record (and
    // the PDB) at all. MSVC-only: the GNU linker rejects the flag.
    if options.strip && target_is_msvc(options.arch) {
        flags.extend(["-C".to_string(), "link-arg=/DEBUG:NONE".to_string()]);
    }
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

/// The `--remap-path-prefix` for the stub's own source directory.
///
/// [`hardening_flags`] remaps the manifest dir and the cargo home, but the stub
/// is compiled from a scratch directory that can sit outside the manifest dir
/// (a `PICARO_BUNDLE_ROOT` elsewhere), in which case the absolute path of its
/// `main.rs` would leak into the artifact. Returns an empty list for a debug
/// build or `trim_paths: none` (both keep paths on purpose).
fn stub_dir_remap(options: CompileOptions, stub_dir: Option<&Path>) -> Vec<String> {
    let mut flags = Vec::new();
    if options.debug || options.trim_paths == PathTrim::None {
        return flags;
    }
    if let Some(dir) = stub_dir {
        push_remap(dir, REMAP_TO, &mut flags);
    }
    flags
}

/// Flags that make the linker stamp a deterministic value instead of the current
/// time.
///
/// The COFF `TimeDateStamp` — and the copy the linker writes into the debug
/// directory in `.rdata` — is the one per-build value `rustc` cannot derive from
/// the source: `link.exe` writes the current time unless asked otherwise. Two
/// compiles of identical inputs then differ by a handful of bytes, which breaks
/// the guarantee in `docs/design/reproduction.md`.
///
/// `/Brepro` makes MSVC's linker use a content hash; rust-lld and recent MinGW
/// `ld` accept `--no-insert-timestamp`. A toolchain that rejects the flag fails
/// loudly at link time, which is the right failure mode for a contract that
/// claims byte-identical rebuilds.
fn reproducible_link_flags(arch: Arch) -> Vec<String> {
    if target_is_msvc(arch) {
        vec!["-C".to_string(), "link-arg=/Brepro".to_string()]
    } else {
        vec![
            "-C".to_string(),
            "link-arg=-Wl,--no-insert-timestamp".to_string(),
        ]
    }
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

    // `--remap-path-prefix` is last-match-wins, so the stub dir remap must come
    // after the manifest-dir remap to win when the bundle sits inside the
    // manifest dir (the default `packed/<plan>-<run>/build` is). Otherwise the
    // run label survives into the artifact as
    // `packed\<plan>-<pid>-<nanos>\build\main.rs` and also feeds the linker's
    // `/Brepro` hash, so two builds of the same inputs differ.
    let mut hardening = hardening_flags(options, manifest_dir, home.as_deref());
    hardening.extend(stub_dir_remap(options, stub_rs.parent()));
    // A deterministic linker timestamp is part of the reproduction contract:
    // it is the only per-build value rustc does not derive from the source.
    hardening.extend(reproducible_link_flags(options.arch));

    let mut cmd = Command::new(rustc);
    if options.codegen.uses_unstable() {
        // `-Z randomize-layout` is unstable: the pinned stable toolchain accepts it
        // under the bootstrap escape hatch, which is acceptable because the
        // toolchain is frozen inside the container.
        cmd.env("RUSTC_BOOTSTRAP", "1");
    }
    if !is_native_target(options.arch) {
        cmd.arg("--target").arg(stub_target(options.arch));
    }
    if compiles_as_dll(options.kind) {
        // A library the host loads with the normal image loader, or one a
        // reflective shellcode wraps. The crate name follows the output's stem
        // so the artifact does not report the build's internal file name; the
        // linker takes the export directory's `Name` from the link output itself.
        cmd.arg("--crate-type").arg("cdylib");
        cmd.arg("--crate-name").arg(crate_name(output));
    }
    cmd.arg(stub_rs)
        .arg("--edition")
        .arg("2021")
        .args(hardening)
        .arg("-C")
        .arg(panic_flag(options.kind))
        .arg("-C")
        .arg(format!("codegen-units={}", options.codegen.codegen_units))
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
        // Shellcode is the packed DLL wrapped in a reflective loader: the
        // intermediate image must be a DLL, or there is nothing to reflect.
        (OutputKind::Dll | OutputKind::Shellcode, false) => {
            Err(BuildError::CompilationFailed(format!(
                "'{}' was built as a {} (build.output.kind: {}) but the compiled image is an \
             executable: no export was linked",
                path.display(),
                kind.label(),
                kind.label()
            )))
        }
        (OutputKind::Exe, true) => Err(BuildError::CompilationFailed(format!(
            "'{}' was built as an executable but the compiled image is a DLL",
            path.display()
        ))),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests;
