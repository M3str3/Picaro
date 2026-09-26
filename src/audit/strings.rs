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
/// `#[ignore]` integration test. `ntdll.dll`/`kernel32.dll` are checked too:
/// the scan runs over [`crate::audit::pe_info::code_data`], which blanks the
/// import table's own DLL/function-name strings (wherever the toolchain placed
/// them) so those are not false positives.
pub const SENSITIVE_LITERALS: &[&str] = &[
    "AmsiScanBuffer",
    "AmsiOpenSession",
    "AmsiScanString",
    "amsi.dll",
    "EtwEventWrite",
    "EtwEventWriteFull",
    "ntdll.dll",
    "kernel32.dll",
    "powershell",
    r"C:\Windows",
    "svchost",
    "NtUnmapViewOfSection",
    "NtAllocateVirtualMemory",
    "NtWriteVirtualMemory",
    "NtReadVirtualMemory",
    "NtResumeThread",
    // Sleep obfuscation (ekko): resolved dynamically, must stay obfuscated.
    "SystemFunction032",
    "RtlCaptureContext",
    "NtContinue",
    // Bouncer: analysis-environment indicators, reconstructed at runtime.
    // `test` is deliberately absent: it is too short to be a meaningful signal
    // and would match unrelated strings.
    "vboxservice",
    "vmwaretray",
    "vmtoolsd",
    "wireshark",
    "procmon",
    "x64dbg",
    "x32dbg",
    "sandbox",
    "malware",
    "analysis",
    // Mimikatz-style runtime arguments: a YAML `build.payload.args` literal is a
    // telltale signature, so it must reach the stub through `StringsConfig`.
    "sekurlsa::logonpasswords",
    "privilege::debug",
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

/// Returns the sensitive literals that appear in a generated stub's *source*,
/// ignoring comments.
///
/// The leak guardrail scans the compiled stub's binary for [`SENSITIVE_LITERALS`],
/// but a Rust/Windows binary embeds some of those names through no fault of the
/// stub: the `windows` crate graph ships `ntdll.dll` (see
/// `windows-result`'s `hresult.rs`) and the import table carries every imported
/// DLL name. A binary hit alone therefore cannot prove a leak. Cross-checking
/// against the source — which is entirely ours — does: a literal that is only in
/// the binary comes from the toolchain, while one that is also written in the
/// generated source is a genuine fragment leak.
///
/// Both the plain form and the Rust-escaped form (backslashes doubled) are
/// matched, so a Windows path leaked as `"C:\\Windows"` is still recognized.
#[cfg(test)]
pub fn find_sensitive_literals_in_source(source: &str) -> Vec<String> {
    let stripped = strip_comments(source);
    let mut found = BTreeSet::new();
    for lit in SENSITIVE_LITERALS {
        if stripped.contains(lit) || stripped.contains(&lit.replace('\\', "\\\\")) {
            found.insert(lit.to_string());
        }
    }
    found.into_iter().collect()
}

/// Removes Rust comments from `source`, preserving string/char/raw-string
/// literal contents and line structure.
///
/// Comment characters are replaced by spaces (newlines are kept) so the
/// surrounding tokens are not glued together. Used by
/// [`find_sensitive_literals_in_source`] so that a name mentioned only in a
/// doc comment is not mistaken for a leaked literal, and by technique tests
/// that check their rendered fragment's *code* for cleartext.
#[cfg(test)]
pub(crate) fn strip_comments(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut out = bytes.to_vec();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'/' if bytes.get(i + 1) == Some(&b'/') => {
                while i < bytes.len() && bytes[i] != b'\n' {
                    out[i] = b' ';
                    i += 1;
                }
            }
            b'/' if bytes.get(i + 1) == Some(&b'*') => {
                let mut depth = 0usize;
                while i < bytes.len() {
                    if bytes[i] == b'/' && bytes.get(i + 1) == Some(&b'*') {
                        depth += 1;
                        out[i] = b' ';
                        if i + 1 < bytes.len() {
                            out[i + 1] = b' ';
                        }
                        i += 2;
                    } else if bytes[i] == b'*' && bytes.get(i + 1) == Some(&b'/') {
                        depth -= 1;
                        out[i] = b' ';
                        if i + 1 < bytes.len() {
                            out[i + 1] = b' ';
                        }
                        i += 2;
                        if depth == 0 {
                            break;
                        }
                    } else {
                        if bytes[i] != b'\n' {
                            out[i] = b' ';
                        }
                        i += 1;
                    }
                }
            }
            b'"' => i = skip_string(bytes, i),
            b'\'' => i = skip_char_or_lifetime(bytes, i),
            b'b' => match bytes.get(i + 1) {
                Some(&b'"') => i = skip_string(bytes, i + 1),
                Some(&b'r') => i = skip_raw_string(bytes, i + 1).unwrap_or(i + 1),
                _ => i += 1,
            },
            b'r' => i = skip_raw_string(bytes, i).unwrap_or(i + 1),
            _ => i += 1,
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Skips a normal string literal starting at the opening `"` at `i`, honouring
/// backslash escapes. Returns the index just past the closing quote.
#[cfg(test)]
fn skip_string(bytes: &[u8], i: usize) -> usize {
    let mut j = i + 1;
    while j < bytes.len() {
        match bytes[j] {
            b'\\' => j += 2,
            b'"' => return j + 1,
            _ => j += 1,
        }
    }
    bytes.len()
}

/// If a raw string starts at `i` (at the `r` of `r"…"`/`r#"…"#` or the `r` of
/// `br"…"`), returns the index just past its closing delimiter.
#[cfg(test)]
fn skip_raw_string(bytes: &[u8], i: usize) -> Option<usize> {
    let mut j = i + 1;
    let mut hashes = 0;
    while bytes.get(j) == Some(&b'#') {
        hashes += 1;
        j += 1;
    }
    if bytes.get(j) != Some(&b'"') {
        return None;
    }
    j += 1;
    while j < bytes.len() {
        if bytes[j] == b'"' {
            let mut k = j + 1;
            let mut seen = 0;
            while seen < hashes && bytes.get(k) == Some(&b'#') {
                seen += 1;
                k += 1;
            }
            if seen == hashes {
                return Some(k);
            }
        }
        j += 1;
    }
    Some(bytes.len())
}

/// Skips a char literal (`'a'`, `'\n'`, `'\u{1F600}'`) or a lifetime (`'a`)
/// starting at the `'` at `i`.
#[cfg(test)]
fn skip_char_or_lifetime(bytes: &[u8], i: usize) -> usize {
    match bytes.get(i + 1) {
        Some(&b'\\') => {
            let mut j = i + 2;
            while j < bytes.len() && bytes[j] != b'\'' {
                j += 1;
            }
            (j + 1).min(bytes.len())
        }
        Some(_) if bytes.get(i + 2) == Some(&b'\'') => i + 3,
        _ => i + 1,
    }
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

    #[test]
    fn finds_sensitive_literals() {
        let data = b"junk AmsiScanBuffer and amsi.dll and EtwEventWrite";
        let found = find_sensitive_literals(data);
        assert!(found.contains(&"AmsiScanBuffer".to_string()));
        assert!(found.contains(&"amsi.dll".to_string()));
        assert!(found.contains(&"EtwEventWrite".to_string()));
        assert!(!found.contains(&"powershell".to_string()));
    }

    #[test]
    fn sensitive_literals_are_case_insensitive() {
        let found = find_sensitive_literals(b"AMSISCANBUFFER");
        assert!(found.contains(&"AmsiScanBuffer".to_string()));
    }

    #[test]
    fn source_scan_ignores_comments() {
        // Doc comments and line comments must not count as leaks.
        let src = "/// Patches `AmsiScanBuffer` (see ntdll.dll).\n// amsi.dll\nlet x = 1;";
        assert!(find_sensitive_literals_in_source(src).is_empty());
    }

    #[test]
    fn source_scan_finds_leaked_literals() {
        let src = r#"let dll = std::ffi::CString::new("amsi.dll").unwrap();"#;
        assert!(find_sensitive_literals_in_source(src).contains(&"amsi.dll".to_string()));
    }

    #[test]
    fn source_scan_matches_escaped_windows_path() {
        let src = r#"let p = "C:\\Windows\\System32\\svchost.exe";"#;
        let found = find_sensitive_literals_in_source(src);
        assert!(found.contains(&r"C:\Windows".to_string()));
        assert!(found.contains(&"svchost".to_string()));
    }

    #[test]
    fn strip_comments_keeps_string_contents() {
        // A `//` inside a string literal is not a comment.
        let src = "let u = \"http://example\"; // comment\nlet l = \"ntdll.dll\";";
        let stripped = strip_comments(src);
        assert!(stripped.contains("http://example"));
        assert!(stripped.contains("ntdll.dll"));
        assert!(!stripped.contains("comment"));
    }

    #[test]
    fn strip_comments_handles_block_and_raw_strings() {
        let src = r##"/* a /* nested */ b */ let r = r#"has " quote"#; let c = '"';"##;
        let stripped = strip_comments(src);
        assert!(!stripped.contains("nested"));
        assert!(stripped.contains("has \" quote"));
        assert!(stripped.contains("let r"));
    }
}
