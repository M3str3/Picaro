//! Offline Windows Defender scan via `MpCmdRun.exe`.
//!
//! `MpCmdRun.exe` is looked up at its canonical absolute locations first — the
//! Defender install directory, then the versioned engine directory Windows
//! actually runs — because on many systems it is not on `PATH` at all. Only if
//! none exists do we fall back to `PATH`. The scan is skipped gracefully when
//! the tool is absent (e.g. a third-party AV replaced Defender).
//!
//! Two details matter for a scan to succeed: the target must be an **absolute**
//! path (`MpCmdRun -File <relative>` fails with `hr = 0x80508023`), and a clean
//! run prints "found no threats", so the output text — not the exit code —
//! decides whether a threat was found.

use std::path::{Path, PathBuf};

/// Canonical `MpCmdRun.exe` location, present on every Windows install.
const DEFENDER_CLI: &str = r"C:\Program Files\Windows Defender\MpCmdRun.exe";
/// Versioned engine directory; the binary here is the one Windows actually uses.
const DEFENDER_PLATFORM: &str = r"C:\ProgramData\Microsoft\Windows Defender\Platform";

/// Result of the Defender scan.
#[derive(Debug, PartialEq)]
pub enum DefenderResult {
    /// `MpCmdRun.exe` is not available; the scan was skipped.
    NotAvailable,
    /// No threats found (exit code 0).
    Clean,
    /// A threat was found (exit code 2); carries the tool's output.
    ThreatFound(String),
    /// The scan failed or returned an unexpected code.
    Error(String),
}

/// Runs the Defender scan against `path`.
pub fn scan(path: &Path) -> DefenderResult {
    let Some(tool) = resolve_tool() else {
        return DefenderResult::NotAvailable;
    };

    // MpCmdRun resolves `-File` against its own working directory and rejects a
    // relative path, so hand it an absolute one instead of trusting the caller.
    let target = absolute(path);
    let output = std::process::Command::new(&tool)
        .arg("-Scan")
        .arg("-ScanType")
        .arg("3")
        .arg("-File")
        .arg(&target)
        .output();

    match output {
        Ok(out) => {
            let text = format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            classify(&text, out.status.success())
        }
        Err(e) => DefenderResult::Error(e.to_string()),
    }
}

/// Maps a completed `MpCmdRun` run to a [`DefenderResult`].
///
/// The exit code is not a reliable threat signal (`-Scan` returns 0 even when it
/// reports a detection, and non-zero on internal errors), so the output text
/// decides. `"no threat"` is checked first because `"found no threats"` also
/// contains `"threat"`.
fn classify(text: &str, success: bool) -> DefenderResult {
    let lower = text.to_ascii_lowercase();
    if lower.contains("no threat") || lower.contains("0 threats") {
        DefenderResult::Clean
    } else if lower.contains("threat") {
        DefenderResult::ThreatFound(text.trim().to_string())
    } else if success {
        DefenderResult::Clean
    } else {
        DefenderResult::Error(text.trim().to_string())
    }
}

/// Makes `path` absolute, so `MpCmdRun -File` can open it.
fn absolute(path: &Path) -> PathBuf {
    std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf())
}

/// Finds `MpCmdRun.exe`: the canonical install path first, then the newest
/// versioned engine directory, then `PATH` as a last resort.
fn resolve_tool() -> Option<PathBuf> {
    let classic = Path::new(DEFENDER_CLI);
    if classic.is_file() {
        return Some(classic.to_path_buf());
    }
    newest_platform_cli().or_else(|| find_in_path("MpCmdRun.exe"))
}

/// The newest `Platform\<version>\MpCmdRun.exe`, when the versioned engine
/// directory exists.
///
/// Version directory names (`4.18.26080.4-0`) sort lexicographically wrong once
/// the component width differs (`4.18.1000…` before `4.18.999…`), so they are
/// compared numerically.
fn newest_platform_cli() -> Option<PathBuf> {
    let mut candidates: Vec<(Vec<u64>, PathBuf)> = std::fs::read_dir(DEFENDER_PLATFORM)
        .ok()?
        .flatten()
        .filter_map(|entry| {
            let path = entry.path().join("MpCmdRun.exe");
            path.is_file().then(|| {
                let key = version_key(&entry.file_name().to_string_lossy());
                (key, path)
            })
        })
        .collect();
    candidates.sort();
    candidates.pop().map(|(_, path)| path)
}

/// Numeric components of a version-like directory name (`4.18.26080.4-0` →
/// `[4, 18, 26080, 4, 0]`), so they compare numerically rather than as text.
fn version_key(name: &str) -> Vec<u64> {
    name.split(|c: char| !c.is_ascii_digit())
        .filter(|s| !s.is_empty())
        .filter_map(|s| s.parse().ok())
        .collect()
}

/// Searches `PATH` for `name`; the last-resort lookup for a non-standard
/// install, so a system where the tool is not on `PATH` still works.
fn find_in_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|p| p.is_file())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_run_is_not_a_threat() {
        // The word "threats" appears here too; only "no threat" disambiguates.
        let text = "Scan starting...\nScan finished.\nScanning C:\\x.exe found no threats.\n";
        assert_eq!(classify(text, true), DefenderResult::Clean);
    }

    #[test]
    fn detection_is_reported_even_on_a_zero_exit() {
        // MpCmdRun returns exit code 0 for `-Scan` even when it detects.
        let text = "Scanning C:\\x.exe found 1 threats.\n";
        assert_eq!(
            classify(text, true),
            DefenderResult::ThreatFound(text.trim().to_string())
        );
    }

    #[test]
    fn a_real_failure_is_an_error() {
        let text = "CmdTool: Failed with hr = 0x80508023.";
        assert_eq!(
            classify(text, false),
            DefenderResult::Error(text.to_string())
        );
    }

    #[test]
    fn silent_success_is_clean() {
        assert_eq!(classify("Scan finished.\n", true), DefenderResult::Clean);
    }

    #[test]
    fn version_keys_order_numerically() {
        assert_eq!(version_key("4.18.26080.4-0"), vec![4, 18, 26080, 4, 0]);
        assert!(version_key("4.18.26080.4-0") > version_key("4.18.26080.3-0"));
        // The width difference that breaks a plain string sort.
        assert!(version_key("4.18.1000.0-0") > version_key("4.18.999.0-0"));
    }
}
