//! Small filesystem and URL helpers shared across modules.
//!
//! Keeping these in one place avoids the two copies that had already drifted
//! apart (`file_url_to_path` in the CLI and the plan loader, `find_in_path` in
//! the audit and the signer).

use std::path::{Path, PathBuf};

use crate::plan::schema::OutputKind;

/// Default root of the per-build bundles.
pub const DEFAULT_BUNDLE_ROOT: &str = "packed";

/// Name of the resolved plan inside a bundle.
pub const BUNDLE_PLAN: &str = "plan.yaml";

/// One build bundle: the only tree a build writes.
///
/// Every run gets `packed/<plan>-<run>/`, so the source, the encrypted blobs,
/// the compiler output, the delivered artifact and the provenance live
/// together. `output.path` only decides where the delivered artifact is copied;
/// it never changes the bundle root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleLayout {
    /// `packed/<plan>-<run>/`.
    pub root: PathBuf,
    /// The resolved plan (`<root>/plan.yaml`).
    pub plan: PathBuf,
    /// Source and compiler workspace (`<root>/build/`): `main.rs`, the
    /// `include_bytes!` blobs, the compiled PE, the PDB and the module sources.
    pub build: PathBuf,
    /// The canonical artifact (`<root>/dist/<name>`).
    pub dist: PathBuf,
    /// Provenance and signing material (`<root>/artifacts/`).
    pub artifacts: PathBuf,
    /// The artifact file name (also used for the manifest and CA names).
    pub artifact_name: String,
    /// The canonical artifact inside the bundle (`dist/<name>`).
    pub bundled_artifact: PathBuf,
    /// Where the delivered artifact goes (`output.path`, or the bundled copy).
    pub artifact: PathBuf,
}

impl BundleLayout {
    /// Resolves the bundle for `plan_name`.
    ///
    /// `root` overrides the bundle root (the `pack` `--dir` and
    /// `PICARO_BUNDLE_ROOT`); `None` uses `packed/` relative to the process
    /// working directory. `suffix` is the run label: `run_nonce()` for a unique
    /// build, or a validated `--build-name`.
    ///
    /// `output` is the optional `build.output.path`: a file path (or a
    /// directory, which gets the default name) is the delivered location; a
    /// missing value delivers to `<bundle>/dist/<plan>.<ext>`.
    pub(crate) fn resolve(
        plan_name: &str,
        output: Option<&Path>,
        kind: OutputKind,
        root: Option<&Path>,
        suffix: &str,
    ) -> Self {
        let base = bundle_root(root);
        let id = format!(
            "{}-{}",
            package_dir_name(plan_name),
            package_dir_name(suffix)
        );
        let root = base.join(id);
        let build = root.join("build");
        let dist = root.join("dist");
        let artifacts = root.join("artifacts");
        let default_name = format!("{}.{}", package_dir_name(plan_name), kind.extension());
        let artifact_name = match output {
            Some(path) if is_dir_like(path) => default_name,
            Some(path) => path
                .file_name()
                .and_then(|name| name.to_str())
                .filter(|name| !name.is_empty())
                .map(str::to_string)
                .unwrap_or(default_name),
            None => default_name,
        };
        let bundled_artifact = dist.join(&artifact_name);
        let artifact = match output {
            Some(path) if is_dir_like(path) => path.join(&artifact_name),
            Some(path) => path.to_path_buf(),
            None => bundled_artifact.clone(),
        };
        Self {
            plan: root.join(BUNDLE_PLAN),
            build,
            dist,
            artifacts,
            artifact_name,
            bundled_artifact,
            artifact,
            root,
        }
    }

    /// Removes the generated subdirectories of a reused bundle and recreates
    /// them.
    ///
    /// Only `build/`, `dist/` and `artifacts/` are touched: a `plan.yaml` in
    /// the bundle root is preserved (the caller rewrites it), and a directory
    /// the user put there is never deleted.
    pub(crate) fn prepare(&self) -> std::io::Result<()> {
        for dir in [&self.build, &self.dist, &self.artifacts] {
            if dir.exists() {
                std::fs::remove_dir_all(dir)?;
            }
            std::fs::create_dir_all(dir)?;
        }
        Ok(())
    }

    /// The manifest for this bundle's artifact (`artifacts/<stem>.manifest.json`).
    pub fn manifest_path(&self) -> PathBuf {
        self.artifacts.join(manifest_name(&self.artifact_name, ""))
    }

    /// The replay manifest (`artifacts/<stem>.manifest.replay.json`).
    pub fn replay_manifest_path(&self) -> PathBuf {
        self.artifacts
            .join(manifest_name(&self.artifact_name, ".replay"))
    }
}

/// The bundle root: an explicit override, `PICARO_BUNDLE_ROOT`, or `packed/`.
///
/// The legacy `PICARO_BUILD_DIR` is deliberately not consulted: it named the
/// old throwaway scratch directory, and a container wrapper that still sets it
/// would otherwise relocate the bundle (which is the archive) out of the
/// mounted tree, where it is lost with the container.
fn bundle_root(explicit: Option<&Path>) -> PathBuf {
    if let Some(root) = explicit.filter(|root| !root.as_os_str().is_empty()) {
        return root.to_path_buf();
    }
    std::env::var_os("PICARO_BUNDLE_ROOT")
        .filter(|root| !root.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_BUNDLE_ROOT))
}

/// Whether `path` names a directory (existing, or with a trailing separator).
fn is_dir_like(path: &Path) -> bool {
    path.is_dir()
        || path.to_string_lossy().ends_with(std::path::MAIN_SEPARATOR)
        || path.to_string_lossy().ends_with('/')
        || path.to_string_lossy().ends_with('\\')
}

/// `<stem>.manifest<suffix>.json`.
fn manifest_name(artifact_name: &str, suffix: &str) -> String {
    let stem = Path::new(artifact_name)
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("artifact");
    format!("{stem}.manifest{suffix}.json")
}

/// A single, filesystem-safe directory component derived from `name`.
pub(crate) fn package_dir_name(name: &str) -> String {
    let cleaned: String = name
        .trim()
        .chars()
        .map(|c| {
            if matches!(c, '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|') {
                '_'
            } else {
                c
            }
        })
        .collect();
    let cleaned = cleaned.trim_matches(|c: char| c == ' ' || c == '.');
    if cleaned.is_empty() || cleaned == "." || cleaned == ".." {
        "package".to_string()
    } else {
        cleaned.to_string()
    }
}

/// A process- and time-unique label (`<pid>-<nanos>`) for a build run.
pub(crate) fn run_nonce() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    format!("{}-{nanos}", std::process::id())
}

/// Accepts a `--build-name` only when it is a single, ordinary directory name.
///
/// The flag names the bundle suffix; it is not a path. Rejecting separators, a
/// drive prefix and `.`/`..` keeps a mistyped name from writing anywhere else
/// on disk.
pub(crate) fn bare_dir_component(name: &str) -> crate::error::Result<&str> {
    let trimmed = name.trim();
    let invalid = trimmed.is_empty()
        || trimmed == "."
        || trimmed == ".."
        || trimmed.contains('/')
        || trimmed.contains('\\')
        || trimmed.contains(':');
    if invalid {
        return Err(crate::error::PackerError::Usage(format!(
            "--build-name must be a single directory name (got {name:?})"
        )));
    }
    Ok(trimmed)
}

/// Turns the part after `file://` into a local path.
///
/// Handles the `file:///C:/x` form produced by URL libraries, which points at
/// `C:/x` (the leading slash before a drive letter is an artifact). A Unix path
/// keeps its leading slash.
pub(crate) fn file_url_to_path(rest: &str) -> String {
    let bytes = rest.as_bytes();
    if bytes.len() >= 3 && bytes[0] == b'/' && bytes[1].is_ascii_alphabetic() && bytes[2] == b':' {
        rest[1..].to_string()
    } else {
        rest.to_string()
    }
}

/// Searches `PATH` for `name`, returning the first match that is a file.
pub(crate) fn find_in_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|candidate| candidate.is_file())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bundle(output: Option<&Path>) -> BundleLayout {
        BundleLayout::resolve(
            "demo",
            output,
            OutputKind::Exe,
            Some(Path::new("work")),
            "run",
        )
    }

    #[test]
    fn a_windows_drive_loses_the_leading_slash() {
        assert_eq!(file_url_to_path("/C:/tools/x.exe"), "C:/tools/x.exe");
    }

    #[test]
    fn a_unix_path_keeps_its_leading_slash() {
        assert_eq!(file_url_to_path("/opt/picaro/x"), "/opt/picaro/x");
    }

    #[test]
    fn a_path_without_a_drive_is_left_alone() {
        assert_eq!(file_url_to_path("relative/x"), "relative/x");
    }

    #[test]
    fn a_bundle_is_one_tree_under_the_root() {
        let layout = bundle(None);
        assert_eq!(layout.root, PathBuf::from("work/demo-run"));
        assert_eq!(layout.plan, PathBuf::from("work/demo-run/plan.yaml"));
        assert_eq!(layout.build, PathBuf::from("work/demo-run/build"));
        assert_eq!(layout.dist, PathBuf::from("work/demo-run/dist"));
        assert_eq!(layout.artifacts, PathBuf::from("work/demo-run/artifacts"));
        assert_eq!(
            layout.bundled_artifact,
            PathBuf::from("work/demo-run/dist/demo.exe")
        );
        assert_eq!(layout.artifact, layout.bundled_artifact);
    }

    #[test]
    fn output_path_is_only_the_delivered_artifact() {
        let layout = bundle(Some(Path::new("deliver/demo.exe")));
        assert_eq!(layout.artifacts, PathBuf::from("work/demo-run/artifacts"));
        assert_eq!(
            layout.bundled_artifact,
            PathBuf::from("work/demo-run/dist/demo.exe")
        );
        assert_eq!(layout.artifact, PathBuf::from("deliver/demo.exe"));
    }

    #[test]
    fn an_output_directory_gets_the_default_name() {
        let layout = bundle(Some(Path::new("deliver/")));
        assert_eq!(layout.artifact, PathBuf::from("deliver/demo.exe"));
    }

    #[test]
    fn the_manifest_lives_in_artifacts() {
        let layout = bundle(None);
        assert_eq!(
            layout.manifest_path(),
            PathBuf::from("work/demo-run/artifacts/demo.manifest.json")
        );
        assert_eq!(
            layout.replay_manifest_path(),
            PathBuf::from("work/demo-run/artifacts/demo.manifest.replay.json")
        );
    }

    #[test]
    fn every_output_kind_gets_its_extension() {
        let dll = BundleLayout::resolve(
            "demo",
            None,
            OutputKind::Dll,
            Some(Path::new("work")),
            "run",
        );
        assert_eq!(dll.artifact_name, "demo.dll");
        let bin = BundleLayout::resolve(
            "demo",
            None,
            OutputKind::Shellcode,
            Some(Path::new("work")),
            "run",
        );
        assert_eq!(bin.artifact_name, "demo.bin");
    }

    #[test]
    fn a_plan_name_cannot_escape_its_parent() {
        let layout = BundleLayout::resolve(
            "../evil",
            Some(Path::new("deliver/loader.exe")),
            OutputKind::Exe,
            Some(Path::new("work")),
            "run",
        );
        assert_eq!(layout.root, PathBuf::from("work/_evil-run"));
        assert_eq!(layout.artifact_name, "loader.exe");
    }

    #[test]
    fn an_absent_tool_is_not_found() {
        assert!(find_in_path("picaro-definitely-not-installed.exe").is_none());
    }
}
