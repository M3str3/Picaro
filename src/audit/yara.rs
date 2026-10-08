//! YARA scanning via the `yara` CLI.
//!
//! There is no maintained, ergonomic libyara crate for Rust, so the audit runs
//! the `yara` binary as a subprocess against a temporary copy of the artifact
//! bytes. The scan is strictly best-effort: a missing scanner degrades to a
//! soft note instead of failing the audit, because YARA coverage is optional
//! for a measurement run.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Distinguishes one temp dump from the next within a process; combined with the
/// process id this is enough to avoid clobbering another audit's file.
static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// Result of a YARA scan.
#[derive(Debug, PartialEq)]
pub struct YaraResult {
    pub matches: Vec<String>,
    pub note: &'static str,
}

/// Scans `data` against every rule file under `yara/`.
///
/// The `note` explains an empty `matches` list: no rules were present, the
/// scanner is missing, or (empty) the scan ran and found nothing.
pub fn scan(data: &[u8]) -> YaraResult {
    let rules = rule_files();
    if rules.is_empty() {
        return YaraResult {
            matches: Vec::new(),
            note: "ruleset empty",
        };
    }

    let yara = yara_binary();

    let Some(temp) = dump_to_temp(data) else {
        // The temp directory is normally writable; if it is not, report a scan
        // that could not run rather than pretending the binary is clean.
        return YaraResult {
            matches: Vec::new(),
            note: "scan failed",
        };
    };

    let mut found = BTreeSet::new();
    for rule in &rules {
        let output = std::process::Command::new(&yara)
            .arg(rule)
            .arg(&temp)
            .output();
        match output {
            Ok(out) => found.extend(parse_stdout(&out.stdout)),
            Err(_) => {
                // A missing (or unspawnable) scanner is a soft note, never an
                // audit failure.
                let _ = std::fs::remove_file(&temp);
                return YaraResult {
                    matches: Vec::new(),
                    note: "yara not found in PATH",
                };
            }
        }
    }

    let _ = std::fs::remove_file(&temp);
    YaraResult {
        matches: found.into_iter().collect(),
        note: "",
    }
}

/// Rule files under `yara/`, sorted for deterministic output.
fn rule_files() -> Vec<PathBuf> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("yara");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut files: Vec<PathBuf> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.is_file())
        .filter(|path| {
            path.extension()
                .and_then(|e| e.to_str())
                .map(|e| e.eq_ignore_ascii_case("yar") || e.eq_ignore_ascii_case("yara"))
                .unwrap_or(false)
        })
        .collect();
    files.sort();
    files
}

/// The `yara` executable, overridable for tests via `PICARO_YARA`.
fn yara_binary() -> String {
    match std::env::var("PICARO_YARA") {
        Ok(path) if !path.trim().is_empty() => path,
        _ => "yara".to_string(),
    }
}

/// Writes `data` to a unique file under the system temp directory.
fn dump_to_temp(data: &[u8]) -> Option<PathBuf> {
    let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let name = format!("picaro-yara-{}-{}.bin", std::process::id(), seq);
    let path = std::env::temp_dir().join(name);
    std::fs::write(&path, data).ok()?;
    Some(path)
}

/// Extracts rule names from `yara` stdout.
///
/// A matching line looks like `mimikatz_wdigest /tmp/foo.bin`; the rule name is
/// the first whitespace-delimited token. Blank lines are ignored.
fn parse_stdout(stdout: &[u8]) -> Vec<String> {
    String::from_utf8_lossy(stdout)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter_map(|line| line.split_whitespace().next())
        .map(str::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parser_extracts_rule_names_and_ignores_blank_lines() {
        let stdout =
            b"mimikatz_sekurlsa /tmp/foo.bin\n\nmimikatz_decryptkeysign /tmp/foo.bin\n   \n";
        assert_eq!(
            parse_stdout(stdout),
            vec!["mimikatz_sekurlsa", "mimikatz_decryptkeysign"]
        );
    }

    #[test]
    fn parser_takes_the_first_token_of_each_line() {
        // A line with no filename still yields its first token.
        assert_eq!(parse_stdout(b"rule_name\n"), vec!["rule_name"]);
    }

    #[test]
    fn rule_discovery_finds_the_committed_mimikatz_rules() {
        let rules = rule_files();
        assert!(
            rules.iter().any(|p| p.ends_with("mimikatz.yara")),
            "expected the committed rule file among: {rules:?}"
        );
    }

    #[test]
    fn an_unreachable_yara_override_is_a_soft_note() {
        let original = std::env::var("PICARO_YARA").ok();
        std::env::set_var("PICARO_YARA", "/nonexistent/picaro-yara-missing");

        let result = scan(b"not a real payload");
        assert!(result.matches.is_empty());
        assert_eq!(result.note, "yara not found in PATH");

        match original {
            Some(value) => std::env::set_var("PICARO_YARA", value),
            None => std::env::remove_var("PICARO_YARA"),
        }
    }
}
