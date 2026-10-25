//! Small filesystem and URL helpers shared across modules.
//!
//! Keeping these in one place avoids the two copies that had already drifted
//! apart (`file_url_to_path` in the CLI and the plan loader, `find_in_path` in
//! the audit and the signer).

use std::path::{Path, PathBuf};

/// The package directory and the final artifact path for a plan.
///
/// Every run emits one self-contained folder named after the plan: the stub
/// source, the encrypted payloads, the artifact, the manifest and the CA live
/// together. The folder is created inside the configured output directory (the
/// parent of `output.path`), or under `packed/` when the plan declares a bare
/// filename. A path that already ends in `<plan>/<file>` is left alone, so
/// `pack` output stays where it was.
pub(crate) fn package_paths(plan_name: &str, output: &Path) -> (PathBuf, PathBuf) {
    let dir_name = package_dir_name(plan_name);
    let file_name = output
        .file_name()
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| std::ffi::OsStr::new("artifact"));
    let parent = output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty());
    let package = match parent {
        Some(parent) if parent.file_name() == Some(std::ffi::OsStr::new(&dir_name)) => {
            parent.to_path_buf()
        }
        Some(parent) => parent.join(&dir_name),
        None => Path::new(crate::pack::DEFAULT_OUTPUT_DIR).join(&dir_name),
    };
    (package.clone(), package.join(file_name))
}

/// A single, filesystem-safe directory name derived from the plan name.
fn package_dir_name(plan_name: &str) -> String {
    let cleaned: String = plan_name
        .trim()
        .chars()
        .map(|c| {
            if matches!(c, '/' | '\\' | ':') {
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
    fn a_build_gets_a_folder_named_after_the_plan() {
        assert_eq!(
            package_paths("full-evasion", Path::new("dist/full-evasion.exe")),
            (
                PathBuf::from("dist/full-evasion"),
                PathBuf::from("dist/full-evasion/full-evasion.exe")
            )
        );
    }

    #[test]
    fn an_existing_plan_folder_is_not_nested_twice() {
        assert_eq!(
            package_paths("calc", Path::new("packed/calc/calc.exe")),
            (
                PathBuf::from("packed/calc"),
                PathBuf::from("packed/calc/calc.exe")
            )
        );
    }

    #[test]
    fn a_bare_filename_lands_under_packed() {
        assert_eq!(
            package_paths("calc", Path::new("calc.exe")),
            (
                PathBuf::from("packed/calc"),
                PathBuf::from("packed/calc/calc.exe")
            )
        );
    }

    #[test]
    fn a_plan_name_cannot_escape_its_parent() {
        let (package, artifact) = package_paths("../evil", Path::new("dist/loader.exe"));
        assert_eq!(package, PathBuf::from("dist/_evil"));
        assert_eq!(artifact, PathBuf::from("dist/_evil/loader.exe"));
    }

    #[test]
    fn an_absent_tool_is_not_found() {
        assert!(find_in_path("picaro-definitely-not-installed.exe").is_none());
    }
}
