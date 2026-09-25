//! String scan over the binary's printable ASCII strings.
//!
//! Extracts printable ASCII runs and matches them against a few regexes, to
//! surface static-evasion signals: paths to System32, dynamically-resolved NT
//! API names (`Nt*`/`Zw*`), technique keywords, and URLs/IPs.

use std::collections::BTreeSet;
use std::sync::OnceLock;

use regex::Regex;

/// Sensitive literals that must never appear in cleartext in a generated
/// stub's code/data sections.
///
/// This is the shared list used by both the audit's string scan and the
/// `#[ignore]` integration test. Import-table DLL names (`kernel32.dll`,
/// `ntdll.dll`) are deliberately omitted: they are legitimate PE metadata in
/// `.idata`, not stub string literals (the scan of the code/data sections
/// excludes `.idata` anyway).
pub const SENSITIVE_LITERALS: &[&str] = &[
    "AmsiScanBuffer",
    "AmsiOpenSession",
    "AmsiScanString",
    "amsi.dll",
    "EtwEventWrite",
    "EtwEventWriteFull",
    "powershell",
    r"C:\Windows",
    "svchost",
    "NtUnmapViewOfSection",
];

/// Findings of the string scan.
#[derive(Debug, Default, PartialEq)]
pub struct StringFindings {
    pub paths: Vec<String>,
    pub apis: Vec<String>,
    pub techniques: Vec<String>,
    pub urls_ips: Vec<String>,
    /// Sensitive literals (from [`SENSITIVE_LITERALS`]) found in cleartext.
    pub sensitive: Vec<String>,
}

impl StringFindings {
    /// Total number of flagged strings across all categories.
    pub fn total_flagged(&self) -> usize {
        self.paths.len()
            + self.apis.len()
            + self.techniques.len()
            + self.urls_ips.len()
            + self.sensitive.len()
    }
}

/// Returns the sensitive literals (from [`SENSITIVE_LITERALS`]) that appear in
/// cleartext within `data`, which should be the stub's code/data sections (see
/// [`crate::audit::pe_info::code_data`]).
///
/// Matching is case-insensitive and done over printable ASCII runs, so a
/// partial coincidence (`Amsi` inside another word) is not a false positive: we
/// match the full literal, not a bare prefix.
pub fn find_sensitive_literals(data: &[u8]) -> Vec<String> {
    let mut found = BTreeSet::new();
    for s in extract_strings(data, 4) {
        let lower = s.to_ascii_lowercase();
        for lit in SENSITIVE_LITERALS {
            if lower.contains(&lit.to_ascii_lowercase()) {
                found.insert(lit.to_string());
            }
        }
    }
    found.into_iter().collect()
}

fn path_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)system32").expect("static regex"))
}

/// NT API names (`NtXxx`/`ZwXxx`, camelCase). These indicate dynamic resolution
/// via `GetProcAddress`, since such names are not normally statically imported.
fn api_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\b(Nt|Zw)[A-Z][a-zA-Z]{1,}\b").expect("static regex"))
}

fn url_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)https?://[^\s]+").expect("static regex"))
}

fn ip_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").expect("static regex"))
}

fn technique_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)(hollow|inject|loader|shellcode)").expect("static regex"))
}

/// Runs the string scan over `data`.
///
/// `imported` is the set of statically-imported function names (lowercased);
/// API names found in this set are not reported as "dynamically resolved".
pub fn scan(data: &[u8], imported: &BTreeSet<String>) -> StringFindings {
    let mut paths = BTreeSet::new();
    let mut apis = BTreeSet::new();
    let mut techniques = BTreeSet::new();
    let mut urls_ips = BTreeSet::new();

    for s in extract_strings(data, 4) {
        if path_re().is_match(&s) {
            paths.insert(s.clone());
        }
        if let Some(m) = api_re().find(&s) {
            let name = m.as_str();
            if !imported.contains(&name.to_ascii_lowercase()) {
                apis.insert(name.to_string());
            }
        }
        if technique_re().is_match(&s) {
            techniques.insert(s.clone());
        }
        if let Some(m) = url_re().find(&s) {
            urls_ips.insert(m.as_str().to_string());
        }
        if let Some(m) = ip_re().find(&s) {
            urls_ips.insert(m.as_str().to_string());
        }
    }

    StringFindings {
        paths: paths.into_iter().collect(),
        apis: apis.into_iter().collect(),
        techniques: techniques.into_iter().collect(),
        urls_ips: urls_ips.into_iter().collect(),
        // Populated by the caller over the code/data sections only.
        sensitive: Vec::new(),
    }
}

/// Extracts printable ASCII runs of at least `min_len` bytes.
fn extract_strings(data: &[u8], min_len: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut start = None;
    for (i, &b) in data.iter().enumerate() {
        let printable = (0x20..=0x7E).contains(&b);
        match (start, printable) {
            (None, true) => start = Some(i),
            (Some(s), false) => {
                if i - s >= min_len {
                    out.push(String::from_utf8_lossy(&data[s..i]).to_string());
                }
                start = None;
            }
            _ => {}
        }
    }
    if let Some(s) = start {
        if data.len() - s >= min_len {
            out.push(String::from_utf8_lossy(&data[s..]).to_string());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_known_patterns() {
        let data = b"junk C:\\Windows\\System32\\cmd.exe NtUnmapViewOfSection hollow inject http://evil.example.com/x 1.2.3.4 tail";
        let f = scan(data, &BTreeSet::new());

        assert!(!f.paths.is_empty(), "should detect a System32 path");
        assert!(f.apis.contains(&"NtUnmapViewOfSection".to_string()));
        assert!(!f.techniques.is_empty(), "should detect technique keywords");
        assert!(!f.urls_ips.is_empty(), "should detect URL and IP");
    }

    #[test]
    fn excludes_statically_imported_names() {
        let data = b"NtUnmapViewOfSection NtWriteFile";
        let mut imported = BTreeSet::new();
        imported.insert("ntwritefile".to_string());
        let f = scan(data, &imported);
        assert!(f.apis.contains(&"NtUnmapViewOfSection".to_string()));
        assert!(!f.apis.contains(&"NtWriteFile".to_string()));
    }

    #[test]
    fn clean_buffer_has_no_findings() {
        let data = b"this is a completely clean and boring string with nothing in it";
        let f = scan(data, &BTreeSet::new());
        assert_eq!(f.total_flagged(), 0);
    }

    #[test]
    fn extracts_minimum_length_strings() {
        // `\0` is not printable, so it splits the two runs; "abc" is too short.
        let s = extract_strings(b"abc\0defgh", 4);
        assert_eq!(s, vec!["defgh".to_string()]);
    }
}
