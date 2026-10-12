//! Rendering of the audit report.
//!
//! The layout follows the `picaro · audit` design: a command echo, a
//! horizontal metadata bar, uppercase section headings with flush-left content,
//! an entropy gauge per section and a closing summary whose risk level is the
//! one thing the eye should land on.
//!
//! Color is applied through a [`Palette`] the caller may disable, so the same
//! renderer serves an interactive terminal and a redirected file (docs, notes)
//! without leaking escape codes into the latter. Everything that carries
//! meaning is also encoded in structure and glyphs, never in color alone.

use std::path::Path;

use crate::ui::{glyph, Meta, Palette, Tone};

use super::defender::DefenderResult;
use super::pe_info::{ImportItem, PeAudit};
use super::strings::{self, StringFindings};
use super::yara::YaraResult;
use super::SUSPICIOUS_IMPORTS;

/// Width of the entropy gauge, in terminal cells.
const BAR_WIDTH: usize = 20;
/// Entropy below this reads as ordinary code or data.
const ENTROPY_LOW_MAX: f64 = 4.0;
/// Entropy at or above this looks packed/encrypted enough to be worth flagging.
const ENTROPY_HIGH_MIN: f64 = 6.5;
/// Width of the rule above the summary.
const RULE_WIDTH: usize = 60;
/// Key column width of the `strings` section.
const STRING_KEY_WIDTH: usize = 18;
/// The imports list wraps at this width so names stay in the report column.
const IMPORTS_WRAP: usize = 78;
/// Maximum length of a string-listing preview, in characters.
///
/// A run of printable bytes can glue several Rust string literals together (they
/// are not NUL-separated) and grow to hundreds of characters; the preview keeps
/// the report readable while the match is still recognizable.
const STRING_PREVIEW_WIDTH: usize = 72;
/// Most flagged-string labels listed on the summary line before `+N more`.
const SUMMARY_LABELS_MAX: usize = 6;

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
#[allow(clippy::too_many_arguments)]
pub fn render(
    path: &Path,
    size: usize,
    pe: &PeAudit,
    strings: &StringFindings,
    yara: &YaraResult,
    defender: &DefenderResult,
    focus: &Focus,
    ui: &Palette,
) -> String {
    let mut out = String::new();

    out.push_str(&ui.command_line("audit", path.display()));
    out.push('\n');
    out.push('\n');
    out.push_str(&render_meta(size, pe, ui));

    if focus.enabled("sections") {
        out.push_str(&render_sections(pe, ui));
    }
    if focus.enabled("imports") {
        out.push_str(&render_imports(pe, ui));
        out.push_str(&render_suspicious(pe, ui));
    }
    if focus.enabled("exports") {
        out.push_str(&render_exports(pe, ui));
    }
    if focus.enabled("strings") {
        out.push_str(&render_strings(strings, ui));
    }
    if focus.enabled("yara") {
        out.push_str(&render_yara(yara, ui));
    }
    if focus.enabled("defender") {
        out.push_str(&render_defender(defender, ui));
    }

    out.push_str(&render_summary(pe, strings, defender, ui));

    out
}

/// The metadata bar: size, architecture, subsystem, signature, overlay and
/// timestamp.
fn render_meta(size: usize, pe: &PeAudit, ui: &Palette) -> String {
    let items = [
        Meta {
            key: "SIZE",
            value: format!("{} bytes", group_number(size)),
            tone: Tone::Value,
        },
        Meta {
            key: "ARCH",
            value: pe.arch.to_string(),
            tone: Tone::Value,
        },
        Meta {
            key: "SUBSYSTEM",
            value: pe.subsystem.to_string(),
            tone: Tone::Value,
        },
        Meta {
            key: "SIGNATURE",
            value: if pe.has_signature {
                "present (Authenticode)".to_string()
            } else {
                "none".to_string()
            },
            tone: if pe.has_signature {
                Tone::Ok
            } else {
                Tone::Warn
            },
        },
        Meta {
            key: "OVERLAY",
            value: format!("{} bytes", group_number(pe.overlay)),
            tone: Tone::Value,
        },
        Meta {
            key: "TIMESTAMP",
            value: format_timestamp(pe.timestamp),
            tone: Tone::Value,
        },
    ];
    ui.meta_bar(&items)
}

/// A blank line, an uppercase heading and an optional dim note, then a newline.
fn section(ui: &Palette, title: &str, note: Option<String>) -> String {
    let mut line = ui.heading(title);
    if let Some(note) = note {
        line.push_str(&format!("  {}", ui.dim(note)));
    }
    format!("\n{line}\n")
}

/// Names of the imports matching the "known malware API" list.
fn suspicious_imports(pe: &PeAudit) -> Vec<String> {
    pe.imports
        .iter()
        .flat_map(|d| &d.functions)
        .filter_map(|f| match f {
            ImportItem::Named(n) => SUSPICIOUS_IMPORTS
                .iter()
                .find(|s| s.eq_ignore_ascii_case(n))
                .map(|s| s.to_string()),
            ImportItem::Ordinal(_) => None,
        })
        .collect()
}

fn render_sections(pe: &PeAudit, ui: &Palette) -> String {
    let mut out = section(ui, "SECTIONS", None);
    for s in &pe.sections {
        let entropy = format!("{:.2}", s.entropy);
        out.push_str(&format!(
            "{:<9}{:<7}  {}  {}\n",
            s.name,
            kb(s.size),
            entropy_bar(ui, s.entropy),
            ui.dim(entropy)
        ));
    }
    out
}

fn render_imports(pe: &PeAudit, ui: &Palette) -> String {
    let total_functions: usize = pe.imports.iter().map(|d| d.functions.len()).sum();
    let note = format!(
        "{} dlls {} {} functions",
        pe.imports.len(),
        glyph::DOT,
        group_number(total_functions)
    );
    let mut out = section(ui, "IMPORTS", Some(note));
    for dll in &pe.imports {
        out.push_str(&format!(
            "{} {}\n",
            ui.heading(&dll.name),
            ui.dim(format!("({})", dll.functions.len()))
        ));
        let names: Vec<String> = dll
            .functions
            .iter()
            .map(|f| match f {
                ImportItem::Named(n) => n.clone(),
                ImportItem::Ordinal(o) => format!("Ordinal({o})"),
            })
            .collect();
        out.push_str(&ui.dim(fill(&names, IMPORTS_WRAP)));
        out.push('\n');
    }
    out
}

fn render_suspicious(pe: &PeAudit, ui: &Palette) -> String {
    let mut out = section(ui, "SUSPICIOUS IMPORTS", None);
    let suspicious = suspicious_imports(pe);
    if suspicious.is_empty() {
        out.push_str(&status_line(
            ui,
            ui.check(),
            ui.dim("IAT looks minimal"),
            None,
        ));
    } else {
        for name in &suspicious {
            out.push_str(&format!("{} {}\n", ui.bang(), ui.error(name)));
        }
    }
    out
}

fn render_exports(pe: &PeAudit, ui: &Palette) -> String {
    let note = (!pe.exports.is_empty()).then(|| pe.exports.len().to_string());
    let mut out = section(ui, "EXPORTS", note);
    if pe.exports.is_empty() {
        out.push_str(&format!("{} {}\n", ui.faint(glyph::DOT), ui.dim("none")));
    } else {
        for e in &pe.exports {
            out.push_str(&format!("  {}\n", ui.dim(e)));
        }
    }
    out
}

fn render_strings(strings: &StringFindings, ui: &Palette) -> String {
    let mut out = section(ui, "STRINGS", None);

    out.push_str(&string_row(ui, "paths (system32)", strings.paths.len()));
    out.push_str(&list_items(ui, &strings.paths));

    out.push_str(&string_row(ui, "apis by name", strings.apis.len()));
    out.push_str(&list_items(ui, &strings.apis));

    out.push_str(&string_row(ui, "technique names", strings.techniques.len()));
    for s in &strings.techniques {
        out.push_str(&preview_line(ui, s, technique_note(s)));
    }

    out.push_str(&string_row(ui, "urls / ips", strings.urls_ips.len()));
    out.push_str(&list_items(ui, &strings.urls_ips));

    out.push_str(&string_row(ui, "sensitive", strings.sensitive.len()));
    out.push_str(&list_items(ui, &strings.sensitive));

    let flagged = strings.total_flagged();
    let value = if flagged == 0 {
        ui.ok(flagged)
    } else {
        ui.warn(flagged)
    };
    out.push_str(&format!(
        "{} {}\n",
        ui.dim(format!(
            "{:<width$}",
            "total flagged",
            width = STRING_KEY_WIDTH
        )),
        value
    ));
    out
}

fn render_yara(yara: &YaraResult, ui: &Palette) -> String {
    let mut out = section(ui, "YARA", None);
    if yara.matches.is_empty() {
        let note = if yara.note.is_empty() {
            None
        } else {
            Some(format!("({})", yara.note))
        };
        out.push_str(&status_line(ui, ui.check(), ui.dim("no matches"), note));
    } else {
        for m in &yara.matches {
            out.push_str(&format!("{} {}\n", ui.bang(), ui.error(m)));
        }
    }
    out
}

fn render_defender(defender: &DefenderResult, ui: &Palette) -> String {
    let mut out = section(ui, "DEFENDER", None);
    match defender {
        DefenderResult::NotAvailable => {
            out.push_str(&status_line(
                ui,
                ui.faint(glyph::DOT),
                ui.dim("not run"),
                Some("(MpCmdRun.exe not found)".to_string()),
            ));
        }
        DefenderResult::Clean => {
            out.push_str(&status_line(
                ui,
                ui.check(),
                ui.ok("clean"),
                Some("(no threats found)".to_string()),
            ));
        }
        DefenderResult::ThreatFound(details) => {
            out.push_str(&status_line(ui, ui.cross(), ui.error("threat found"), None));
            for line in details.lines() {
                out.push_str(&format!("  {}\n", ui.error(line)));
            }
        }
        DefenderResult::Error(e) => {
            out.push_str(&status_line(
                ui,
                ui.bang(),
                ui.warn("scan failed"),
                defender_note(e),
            ));
        }
    }
    out
}

/// Condenses the (often very long) `MpCmdRun` failure output into the one
/// useful token, the HRESULT.
///
/// The raw output buries `hr = 0x…` in a multi-line wall of text and a temp
/// path, which would blow up the report; the HRESULT plus a pointer to the log
/// is what a reader actually needs.
fn defender_note(message: &str) -> Option<String> {
    let collapsed = message.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.is_empty() {
        return None;
    }

    if let Some(start) = collapsed.to_ascii_lowercase().find("hr = ") {
        let code: String = collapsed[start + "hr = ".len()..]
            .chars()
            .take_while(|c| c.is_ascii_hexdigit() || matches!(c, 'x' | 'X'))
            .collect();
        if !code.is_empty() {
            return Some(format!("hr = {code} {} see MpCmdRun.log", glyph::DOT));
        }
    }

    Some(truncate_chars(&collapsed, 90))
}

/// Shortens `text` to at most `max` characters, appending an ellipsis.
fn truncate_chars(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let mut out: String = text.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

fn render_summary(
    pe: &PeAudit,
    strings: &StringFindings,
    defender: &DefenderResult,
    ui: &Palette,
) -> String {
    let suspicious = suspicious_imports(pe).len();
    let string_flags = strings.total_flagged();
    let high_entropy = pe.sections.iter().any(|s| s.entropy >= ENTROPY_HIGH_MIN);

    let (label, tone) = if suspicious == 0 && string_flags == 0 {
        ("LOW RISK", Tone::Ok)
    } else if suspicious <= 2 && string_flags <= 3 {
        ("MEDIUM RISK", Tone::Warn)
    } else {
        ("HIGH RISK", Tone::Bad)
    };

    let mut out = String::new();
    out.push('\n');
    out.push_str(&ui.rule(RULE_WIDTH));
    out.push('\n');
    out.push_str(&format!("\n{}\n", ui.heading("SUMMARY")));
    out.push_str(&format!("\n{}\n", ui.bold(ui.tone(tone, label))));

    if suspicious == 0 {
        out.push_str(&status_line(ui, ui.check(), ui.dim("IAT is minimal"), None));
    } else {
        out.push_str(&status_line(
            ui,
            ui.bang(),
            ui.warn(format!("{suspicious} suspicious imports")),
            None,
        ));
    }

    if string_flags == 0 {
        out.push_str(&status_line(
            ui,
            ui.check(),
            ui.dim("no suspicious strings"),
            None,
        ));
    } else {
        out.push_str(&status_line(
            ui,
            ui.bang(),
            ui.warn(format!("{string_flags} flagged strings")),
            Some(summarize_labels(&flagged_labels(strings))),
        ));
    }

    if high_entropy {
        out.push_str(&status_line(
            ui,
            ui.bang(),
            ui.warn("high entropy section"),
            Some("expected for the encrypted payload".to_string()),
        ));
    }
    if !pe.has_signature {
        out.push_str(&status_line(
            ui,
            ui.bang(),
            ui.warn("unsigned binary"),
            Some("expected for research".to_string()),
        ));
    }
    if pe.has_manifest {
        out.push_str(&status_line(
            ui,
            ui.faint(glyph::DOT),
            ui.dim("manifest embedded"),
            None,
        ));
    }
    if pe.overlay > 0 {
        out.push_str(&status_line(
            ui,
            ui.faint(glyph::DOT),
            ui.dim(format!("overlay of {} bytes", group_number(pe.overlay))),
            None,
        ));
    }

    match defender {
        DefenderResult::NotAvailable => {}
        DefenderResult::Clean => {
            out.push_str(&status_line(ui, ui.check(), ui.dim("defender clean"), None))
        }
        DefenderResult::ThreatFound(_) => out.push_str(&status_line(
            ui,
            ui.cross(),
            ui.error("defender flagged this binary"),
            None,
        )),
        DefenderResult::Error(_) => out.push_str(&status_line(
            ui,
            ui.bang(),
            ui.warn("defender scan failed"),
            Some("(check MpCmdRun.log)".to_string()),
        )),
    }

    out
}

/// Short labels for every flagged string, in report order, for the summary.
///
/// A `technique names` hit contributes its keyword(s) rather than the whole
/// (often glued-together) string, so the summary stays compact and answers
/// *which* strings were flagged at a glance.
fn flagged_labels(strings: &StringFindings) -> Vec<String> {
    let mut labels: Vec<String> = Vec::new();
    labels.extend(strings.paths.iter().map(|s| truncate_chars(s, 40)));
    labels.extend(strings.apis.iter().cloned());
    labels.extend(strings.techniques.iter().map(|s| {
        let keywords = strings::technique_keywords(s);
        if keywords.is_empty() {
            truncate_chars(s, 40)
        } else {
            keywords.join("/")
        }
    }));
    labels.extend(strings.urls_ips.iter().cloned());
    labels.extend(strings.sensitive.iter().cloned());
    labels
}

/// Joins up to [`SUMMARY_LABELS_MAX`] labels into a parenthesized one-liner,
/// summarizing the rest as `+N more`.
fn summarize_labels(labels: &[String]) -> String {
    let mut shown: Vec<String> = labels
        .iter()
        .take(SUMMARY_LABELS_MAX)
        .map(|l| truncate_chars(l, 32))
        .collect();
    if labels.len() > SUMMARY_LABELS_MAX {
        shown.push(format!("+{} more", labels.len() - SUMMARY_LABELS_MAX));
    }
    format!("({})", shown.join(", "))
}

/// A `marker text` line, plus a dim trailing note when present.
///
/// Used both for section status lines (`✓ no matches`) and for the summary
/// bullets; callers pass the note already formatted (some wrap it in
/// parentheses) so the upstream text is never rewritten.
fn status_line(
    ui: &Palette,
    marker: String,
    text: impl std::fmt::Display,
    note: Option<String>,
) -> String {
    let mut line = format!("{marker} {text}");
    if let Some(note) = note {
        line.push_str(&format!("  {}", ui.dim(note)));
    }
    line.push('\n');
    line
}

/// A `key  value` row of the `strings` section.
fn string_row(ui: &Palette, key: &str, value: usize) -> String {
    format!(
        "{} {}\n",
        ui.dim(format!("{key:<width$}", width = STRING_KEY_WIDTH)),
        ui.value(value)
    )
}

/// The found strings of one category, indented under their count, each
/// truncated to [`STRING_PREVIEW_WIDTH`].
fn list_items(ui: &Palette, items: &[String]) -> String {
    items
        .iter()
        .map(|item| preview_line(ui, item, None))
        .collect()
}

/// One indented string entry: a truncated preview plus an optional dim note.
fn preview_line(ui: &Palette, text: &str, note: Option<String>) -> String {
    let mut line = format!("  {}", ui.dim(truncate_chars(text, STRING_PREVIEW_WIDTH)));
    if let Some(note) = note {
        line.push_str(&format!("  {}", ui.faint(format!("[{note}]"))));
    }
    line.push('\n');
    line
}

/// Annotates a `technique names` hit with the keyword(s) that triggered it, so
/// an incidental substring is distinguishable from a real name.
fn technique_note(s: &str) -> Option<String> {
    let keywords = strings::technique_keywords(s);
    (!keywords.is_empty()).then(|| keywords.join(", "))
}

/// The entropy gauge: a fixed-width bar whose fill tracks `entropy` (0–8) and
/// whose color encodes how packed the section looks.
fn entropy_bar(ui: &Palette, entropy: f64) -> String {
    let ratio = (entropy / 8.0).clamp(0.0, 1.0);
    let filled = (ratio * BAR_WIDTH as f64).round() as usize;
    let tone = if entropy < ENTROPY_LOW_MAX {
        Tone::OkDim
    } else if entropy < ENTROPY_HIGH_MIN {
        Tone::Warn
    } else {
        Tone::Bad
    };
    format!(
        "{}{}",
        ui.tone(tone, glyph::BLOCK.repeat(filled)),
        ui.faint(glyph::SHADE.repeat(BAR_WIDTH - filled))
    )
}

/// Fills `items` into lines of at most `width` columns, two spaces apart.
///
/// Wrapping here (rather than letting the terminal do it) keeps a long import
/// list inside the report column instead of running to the window edge.
fn fill(items: &[String], width: usize) -> String {
    let mut lines: Vec<String> = Vec::new();
    let mut line = String::new();
    for item in items {
        let item_len = item.chars().count();
        if line.is_empty() {
            line = item.clone();
        } else if line.chars().count() + 2 + item_len <= width {
            line.push_str("  ");
            line.push_str(item);
        } else {
            lines.push(std::mem::take(&mut line));
            line = item.clone();
        }
    }
    if !line.is_empty() {
        lines.push(line);
    }
    lines.join("\n")
}

/// Formats bytes as whole kilobytes, as the section rows show them.
fn kb(bytes: usize) -> String {
    format!("{} KB", bytes / 1024)
}

/// Groups a number's digits in threes with spaces (`13 824`), which is easier
/// to scan than an unbroken run at these magnitudes.
fn group_number(n: usize) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, ch) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(' ');
        }
        out.push(ch);
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

    /// Renders the sample PE through the plain palette (no escape codes).
    fn render_sample(focus: Option<&str>) -> String {
        let pe = sample_pe();
        let strings = StringFindings::default();
        let yara = YaraResult {
            matches: vec![],
            note: "ruleset empty",
        };
        render(
            Path::new("test.exe"),
            12345,
            &pe,
            &strings,
            &yara,
            &DefenderResult::NotAvailable,
            &Focus::parse(focus),
            &Palette::plain(),
        )
    }

    /// Renders the sample PE with `findings` as its string scan.
    fn render_with_strings(findings: &StringFindings) -> String {
        let yara = YaraResult {
            matches: vec![],
            note: "ruleset empty",
        };
        render(
            Path::new("test.exe"),
            12345,
            &sample_pe(),
            findings,
            &yara,
            &DefenderResult::NotAvailable,
            &Focus::parse(None),
            &Palette::plain(),
        )
    }

    /// The summary must name the flagged strings, not just count them, and the
    /// list must explain *why* each matched. (A statically imported DLL name is
    /// filtered out before the report; the sample uses `amsi.dll`, which is a
    /// real leak candidate.)
    #[test]
    fn summary_names_the_flagged_strings() {
        let findings = StringFindings {
            apis: vec!["NtUnmapViewOfSection".to_string()],
            techniques: vec!["the target loader to initialize".to_string()],
            sensitive: vec!["amsi.dll".to_string()],
            ..StringFindings::default()
        };

        let out = render_with_strings(&findings);
        assert!(out.contains("[loader]"), "missing keyword note: {out}");
        assert!(
            out.contains("NtUnmapViewOfSection, loader, amsi.dll"),
            "summary should list labels: {out}"
        );
    }

    /// A glued run of concatenated Rust literals must not flood the report.
    #[test]
    fn long_string_previews_are_truncated() {
        let long = format!("loader {}", "x".repeat(200));
        let findings = StringFindings {
            techniques: vec![long.clone()],
            ..StringFindings::default()
        };

        let out = render_with_strings(&findings);
        assert!(!out.contains(&long), "full string leaked: {out}");
        assert!(out.contains('\u{2026}'), "no ellipsis: {out}");
    }

    #[test]
    fn renders_all_sections() {
        let out = render_sample(None);

        assert!(out.contains("picaro audit"), "missing echo: {out}");
        assert!(out.contains("test.exe"));
        assert!(out.contains("SECTIONS"));
        assert!(out.contains("IMPORTS"));
        assert!(out.contains("VirtualAllocEx"));
        assert!(out.contains("SUSPICIOUS IMPORTS"));
        assert!(out.contains("STRINGS"));
        assert!(out.contains("paths (system32)"));
        assert!(out.contains("YARA"));
        assert!(out.contains("DEFENDER"));
        assert!(out.contains("SUMMARY"));
        // One suspicious import ⇒ medium risk.
        assert!(out.contains("MEDIUM RISK"), "missing risk: {out}");
    }

    #[test]
    fn focus_limits_sections() {
        let out = render_sample(Some("imports"));

        assert!(out.contains("IMPORTS"));
        assert!(!out.contains("SECTIONS"));
        assert!(!out.contains("paths (system32)"));
        assert!(!out.contains("YARA"));
    }

    /// The plain palette must not leak escape codes into a report meant to be
    /// copy-pasted.
    #[test]
    fn plain_report_has_no_escape_codes() {
        let out = render_sample(None);
        assert!(!out.contains('\u{1b}'), "escapes leaked: {out:?}");
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

    #[test]
    fn groups_thousands() {
        assert_eq!(group_number(0), "0");
        assert_eq!(group_number(999), "999");
        assert_eq!(group_number(1000), "1 000");
        assert_eq!(group_number(13_824), "13 824");
        assert_eq!(group_number(1_234_567), "1 234 567");
    }

    /// The Defender failure note keeps only the HRESULT and the log pointer.
    #[test]
    fn defender_note_condenses_to_hresult() {
        let note = defender_note(
            "Scan starting...\nCmdTool: Failed with hr = 0x80508023. Check\\Temp\\MpCmdRun.log for more information",
        )
        .expect("non-empty message");
        assert_eq!(
            note,
            format!("hr = 0x80508023 {} see MpCmdRun.log", glyph::DOT)
        );
        assert_eq!(defender_note("   "), None);
    }

    /// The gauge is always exactly `BAR_WIDTH` cells wide, whatever the value.
    #[test]
    fn entropy_bar_has_fixed_width() {
        let ui = Palette::plain();
        for entropy in [0.0, 0.17, 5.89, 7.9, 8.0] {
            assert_eq!(entropy_bar(&ui, entropy).chars().count(), BAR_WIDTH);
        }
        assert_eq!(entropy_bar(&ui, 0.0), glyph::SHADE.repeat(BAR_WIDTH));
        assert_eq!(entropy_bar(&ui, 8.0), glyph::BLOCK.repeat(BAR_WIDTH));
    }

    #[test]
    fn fill_wraps_within_width() {
        let items: Vec<String> = ["aaaa", "bbbb", "cccc", "dddd"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let filled = fill(&items, 14);
        for line in filled.lines() {
            assert!(line.chars().count() <= 14, "too wide: {line:?}");
        }
        assert!(
            filled.lines().count() > 1,
            "should have wrapped: {filled:?}"
        );
    }
}
