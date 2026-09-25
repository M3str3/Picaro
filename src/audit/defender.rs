//! Offline Windows Defender scan via `MpCmdRun.exe`.
//!
//! If the Defender CLI is available at its standard path, we invoke it against
//! the binary and interpret the exit code. This gives a cheap, local
//! "does Defender flag this file" signal. It is skipped gracefully when the
//! tool is not present (e.g. third-party AV installed instead).

use std::path::Path;

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
    let mpcmdrun = r"C:\Program Files\Windows Defender\MpCmdRun.exe";
    if !Path::new(mpcmdrun).exists() {
        return DefenderResult::NotAvailable;
    }

    let output = std::process::Command::new(mpcmdrun)
        .arg("-Scan")
        .arg("-ScanType")
        .arg("3")
        .arg("-File")
        .arg(path)
        .output();

    match output {
        Ok(out) => {
            let text = format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            let lower = text.to_ascii_lowercase();
            if lower.contains("threat") || lower.contains("detected") {
                DefenderResult::ThreatFound(text.trim().to_string())
            } else if out.status.success() {
                DefenderResult::Clean
            } else {
                // MpCmdRun can return a non-zero code on internal errors too
                // (e.g. "Failed with hr = ..."), so treat those as errors.
                DefenderResult::Error(text.trim().to_string())
            }
        }
        Err(e) => DefenderResult::Error(e.to_string()),
    }
}
