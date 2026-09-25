//! Rendering of the audit report.
//!
//! Produces a plain-text, human-readable report. No colors, no tables: just
//! aligned labels and short lists, so it survives copy/paste into notes.

use std::path::Path;

use super::defender::DefenderResult;
use super::pe_info::{ImportItem, PeAudit};
use super::strings::StringFindings;
use super::yara::YaraResult;

/// Imported function names that are widely used as malware signatures.
const SUSPICIOUS_IMPORTS: &[&str] = &[
    "VirtualAllocEx",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "NtUnmapViewOfSection",
    "NtCreateThreadEx",
    "NtWriteVirtualMemory",
    "SetWindowsHookEx",
    "QueueUserAPC",
    "CryptEncrypt",
    "CryptDecrypt",
];

/// Section filter for `--focus`.
pub struct Focus {
    sections: Option<Vec<String>>,
}

impl Focus {
    /// Parses a comma-separated focus list.
    pub fn parse(s: Option<&str>) -> Self {
        let sections = s.map(|s| {
            s.split(',')
                .map(|x| x.trim().to_ascii_lowercase())
                .filter(|x| !x.is_empty())
                .collect()
        });
        Focus { sections }
    }

    fn enabled(&self, name: &str) -> bool {
        match &self.sections {
            None => true,
            Some(list) => list.iter().any(|x| x == name),
        }
    }
}

/// Renders the full report.
pub fn render(
    path: &Path,
    size: usize,
    pe: &PeAudit,
    strings: &StringFindings,
    yara: &YaraResult,
    defender: &DefenderResult,
    focus: &Focus,
) -> String {
    let mut out = String::new();

    out.push_str(&format!("=== Audit: {} ===\n", path.display()));
    out.push_str(&format!("Size:     {size} bytes\n"));
    out.push_str(&format!("Arch:     {}\n", pe.arch));
    out.push_str(&format!("Subsystem: {}\n", pe.subsystem));
    out.push_str(&format!(
        "Signature: {}\n",
        if pe.has_signature {
            "present (Authenticode)"
        } else {
            "none"
        }
    ));
    out.push_str(&format!(
        "Manifest:  {}\n",
        if pe.has_manifest { "present" } else { "none" }
    ));
    out.push_str(&format!("Overlay:   {} bytes\n", pe.overlay));
    out.push_str(&format!("Timestamp: {}\n", format_timestamp(pe.timestamp)));

    if focus.enabled("sections") {
        out.push_str(&render_sections(pe));
    }
    if focus.enabled("imports") {
        out.push_str(&render_imports(pe));
    }
    if focus.enabled("exports") {
        out.push_str(&render_exports(pe));
    }
    if focus.enabled("strings") {
        out.push_str(&render_strings(strings));
    }
    if focus.enabled("yara") {
        out.push_str(&render_yara(yara));
    }
    if focus.enabled("defender") {
        out.push_str(&render_defender(defender));
    }

    out.push_str(&render_summary(pe, strings));

    out
}

fn render_sections(pe: &PeAudit) -> String {
    let mut out = String::from("\nSections:\n");
    for s in &pe.sections {
        let flag = if s.entropy > 7.0 { "  ⚠ high" } else { "" };
        out.push_str(&format!(
            "  {:<8} {:>5} KB  entropy {:.2}{}\n",
            s.name,
            s.size / 1024,
            s.entropy,
            flag
        ));
    }
    out
}

fn render_imports(pe: &PeAudit) -> String {
    let total_functions: usize = pe.imports.iter().map(|d| d.functions.len()).sum();
    let mut out = format!(
        "\nImports ({} DLLs, {} functions):\n",
        pe.imports.len(),
        total_functions
    );
    for dll in &pe.imports {
        let names: Vec<String> = dll
            .functions
            .iter()
            .map(|f| match f {
                ImportItem::Named(n) => n.clone(),
                ImportItem::Ordinal(o) => format!("Ordinal({o})"),
            })
            .collect();
        out.push_str(&format!(
            "  {} ({}): {}\n",
            dll.name,
            dll.functions.len(),
            names.join(", ")
        ));
    }

    let suspicious: Vec<String> = pe
        .imports
        .iter()
        .flat_map(|d| &d.functions)
        .filter_map(|f| match f {
            ImportItem::Named(n) => SUSPICIOUS_IMPORTS
                .iter()
                .find(|s| s.eq_ignore_ascii_case(n))
                .map(|s| s.to_string()),
            ImportItem::Ordinal(_) => None,
        })
        .collect();

    out.push_str(&format!(
        "\nSuspicious imports flagged: {}\n",
        suspicious.len()
    ));
    if suspicious.is_empty() {
        out.push_str("(none of the \"known malware API\" patterns matched)\n");
    } else {
        for s in &suspicious {
            out.push_str(&format!("  {s}\n"));
        }
    }
    out
}

fn render_exports(pe: &PeAudit) -> String {
    if pe.exports.is_empty() {
        "\nExports: none\n".to_string()
    } else {
        let mut out = format!("\nExports ({}):\n", pe.exports.len());
        for e in &pe.exports {
            out.push_str(&format!("  {e}\n"));
        }
        out
    }
}

fn render_strings(strings: &StringFindings) -> String {
    let mut out = String::from("\nStrings scan:\n");
    out.push_str(&format!("  Paths (System32): {}\n", strings.paths.len()));
    for p in &strings.paths {
        out.push_str(&format!("    {p}\n"));
    }
    out.push_str(&format!("  APIs by name:     {}\n", strings.apis.len()));
    for a in &strings.apis {
        out.push_str(&format!("    {a}\n"));
    }
    out.push_str(&format!(
        "  Technique names:  {}\n",
        strings.techniques.len()
    ));
    for t in &strings.techniques {
        out.push_str(&format!("    {t}\n"));
    }
    out.push_str(&format!("  URLs/IPs:         {}\n", strings.urls_ips.len()));
    for u in &strings.urls_ips {
        out.push_str(&format!("    {u}\n"));
    }
    out.push_str(&format!(
        "  Sensitive:        {}\n",
        strings.sensitive.len()
    ));
    for s in &strings.sensitive {
        out.push_str(&format!("    {s}\n"));
    }
    out.push_str(&format!(
        "  Total flagged:    {}\n",
        strings.total_flagged()
    ));
    out
}

fn render_yara(yara: &YaraResult) -> String {
    if yara.matches.is_empty() {
        format!("\nYARA matches: none ({})\n", yara.note)
    } else {
        let mut out = format!("\nYARA matches: {}\n", yara.matches.len());
        for m in &yara.matches {
            out.push_str(&format!("  {m}\n"));
        }
        out
    }
}

fn render_defender(defender: &DefenderResult) -> String {
    let line = match defender {
        DefenderResult::NotAvailable => "not run (MpCmdRun.exe not found)".to_string(),
        DefenderResult::Clean => "clean (no threats found)".to_string(),
        DefenderResult::ThreatFound(details) => format!("THREAT FOUND\n{details}"),
        DefenderResult::Error(e) => format!("error\n{e}"),
    };
    format!("\nDefender scan: {line}\n")
}

fn render_summary(pe: &PeAudit, strings: &StringFindings) -> String {
    let suspicious = pe
        .imports
        .iter()
        .flat_map(|d| &d.functions)
        .filter(|f| match f {
            ImportItem::Named(n) => SUSPICIOUS_IMPORTS.iter().any(|s| s.eq_ignore_ascii_case(n)),
            ImportItem::Ordinal(_) => false,
        })
        .count();

    let high_entropy = pe.sections.iter().any(|s| s.entropy > 7.0);
    let string_flags = strings.total_flagged();

    let risk = if suspicious == 0 && string_flags == 0 {
        "LOW"
    } else if suspicious <= 2 && string_flags <= 3 {
        "MEDIUM"
    } else {
        "HIGH"
    };

    let mut out = format!("\n=== Summary ===\nStatic risk: {risk}\n");

    if suspicious == 0 {
        out.push_str("- IAT is minimal\n");
    } else {
        out.push_str(&format!("- {suspicious} suspicious imports\n"));
    }
    if string_flags == 0 {
        out.push_str("- No suspicious strings\n");
    } else {
        out.push_str(&format!("- {string_flags} flagged strings\n"));
    }
    if high_entropy {
        out.push_str("- High entropy section present (expected for encrypted payload)\n");
    }
    if !pe.has_signature {
        out.push_str("- No signature (expected for research)\n");
    }
    if pe.overlay > 0 {
        out.push_str(&format!("- Overlay of {} bytes\n", pe.overlay));
    }

    out
}

/// Formats a PE timestamp (Unix seconds) as a UTC date-time.
fn format_timestamp(ts: Option<u32>) -> String {
    match ts {
        None => "unset (0)".to_string(),
        Some(u32::MAX) => "reproducible (SOURCE_DATE_EPOCH)".to_string(),
        Some(ts) => {
            let (year, month, day) = civil_from_days((ts / 86400) as i64);
            let secs = (ts % 86400) as i64;
            let hour = secs / 3600;
            let min = (secs % 3600) / 60;
            let sec = secs % 60;
            format!("{year:04}-{month:02}-{day:02} {hour:02}:{min:02}:{sec:02} UTC")
        }
    }
}

/// Howard Hinnant's days-from-civil inverse: Unix days → (year, month, day).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::pe_info::{DllImport, PeAudit, SectionAudit};

    fn sample_pe() -> PeAudit {
        PeAudit {
            arch: "x64",
            subsystem: "GUI",
            timestamp: Some(0),
            has_signature: false,
            has_manifest: false,
            overlay: 0,
            sections: vec![SectionAudit {
                name: ".text".to_string(),
                size: 1024,
                entropy: 6.0,
                file_offset: 0,
            }],
            imports: vec![DllImport {
                name: "KERNEL32.dll".to_string(),
                functions: vec![ImportItem::Named("VirtualAllocEx".to_string())],
            }],
            exports: vec![],
            import_text_ranges: vec![],
        }
    }

    #[test]
    fn renders_all_sections() {
        let pe = sample_pe();
        let strings = StringFindings::default();
        let yara = YaraResult {
            matches: vec![],
            note: "ruleset empty",
        };
        let focus = Focus::parse(None);
        let out = render(
            Path::new("test.exe"),
            12345,
            &pe,
            &strings,
            &yara,
            &DefenderResult::NotAvailable,
            &focus,
        );

        assert!(out.contains("=== Audit: test.exe ==="));
        assert!(out.contains("Sections:"));
        assert!(out.contains("Imports"));
        assert!(out.contains("VirtualAllocEx"));
        assert!(out.contains("Strings scan:"));
        assert!(out.contains("YARA matches:"));
        assert!(out.contains("Defender scan:"));
        assert!(out.contains("=== Summary ==="));
    }

    #[test]
    fn focus_limits_sections() {
        let pe = sample_pe();
        let strings = StringFindings::default();
        let yara = YaraResult {
            matches: vec![],
            note: "ruleset empty",
        };
        let focus = Focus::parse(Some("imports"));
        let out = render(
            Path::new("test.exe"),
            12345,
            &pe,
            &strings,
            &yara,
            &DefenderResult::NotAvailable,
            &focus,
        );

        assert!(out.contains("Imports"));
        assert!(!out.contains("Sections:"));
        assert!(!out.contains("Strings scan:"));
    }

    #[test]
    fn timestamp_formatting() {
        assert_eq!(format_timestamp(None), "unset (0)");
        assert_eq!(
            format_timestamp(Some(u32::MAX)),
            "reproducible (SOURCE_DATE_EPOCH)"
        );
        // 2020-01-01 00:00:00 UTC = 1577836800.
        assert_eq!(
            format_timestamp(Some(1577836800)),
            "2020-01-01 00:00:00 UTC"
        );
    }
}
