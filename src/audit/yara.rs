//! YARA scanning (stub).
//!
//! There is no stable, ergonomic YARA crate for Rust (the `yara` crates are
//! FFI wrappers around libyara and are unmaintained/awkward), so this is a
//! stub. It checks whether rule files exist under `yara/` and reports that the
//! engine is not wired yet.
//!
//! To integrate later:
//! 1. Add a dependency on a libyara FFI wrapper (e.g. `yara` or `yara-sys`).
//! 2. Or invoke the `yara` CLI as a subprocess against a temp dump of the file.
//! 3. Compile the rules in `yara/*.yar` and scan the binary bytes.

use std::path::Path;

/// Result of the (currently stub) YARA scan.
#[derive(Debug, PartialEq)]
pub struct YaraResult {
    pub matches: Vec<String>,
    pub note: &'static str,
}

/// Scans `data` against any rules in `yara/`.
pub fn scan(_data: &[u8]) -> YaraResult {
    if rule_files_found() {
        YaraResult {
            matches: Vec::new(),
            note: "rules found, but no YARA engine is wired yet (TODO)",
        }
    } else {
        YaraResult {
            matches: Vec::new(),
            note: "ruleset empty",
        }
    }
}

fn rule_files_found() -> bool {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("yara");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return false;
    };
    for entry in entries.flatten() {
        let is_rule = entry
            .path()
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.eq_ignore_ascii_case("yar") || e.eq_ignore_ascii_case("yara"))
            .unwrap_or(false);
        if is_rule {
            return true;
        }
    }
    false
}
