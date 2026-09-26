//! Baseline comparison for `audit --baseline`.
//!
//! Evasion claims are worth nothing unmeasured, but a single measurement is only
//! a snapshot. Comparing a build against a saved baseline turns the audit into a
//! regression gate: a sensitive literal, a suspicious import or an entropy jump
//! that was not there before fails the run with exit code 3.
//!
//! Only the *static* signals are compared. The Defender result is
//! environment-dependent, so it is reported by `--json` but never drives a
//! decision here.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::ui::Palette;

use super::model::Report;

/// Sections at or above this entropy look packed/encrypted (mirrors the report).
const ENTROPY_HIGH_MIN: f64 = 6.5;

/// One regression: a signal that was absent from the baseline and is now present.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Regression {
    /// Short category (`sensitive literal`, `suspicious import`, `entropy`, ...).
    pub kind: String,
    /// Human-readable detail.
    pub detail: String,
}

/// The result of comparing a report against a baseline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Comparison {
    /// Path of the baseline the comparison used.
    pub baseline: String,
    /// Entropy increase tolerated before it counts as a regression.
    pub entropy_tolerance: f64,
    /// Static-evasion regressions, worst-first by category.
    pub regressions: Vec<Regression>,
    /// Signals that improved (informational).
    pub improvements: Vec<String>,
}

/// Compares `current` against `baseline` and classifies the differences.
pub fn compare(
    baseline: &Report,
    current: &Report,
    baseline_label: &str,
    entropy_tolerance: f64,
) -> Comparison {
    let mut regressions = Vec::new();
    let mut improvements = Vec::new();

    compare_sensitive_literals(baseline, current, &mut regressions, &mut improvements);
    compare_suspicious_imports(baseline, current, &mut regressions, &mut improvements);
    compare_entropy(
        baseline,
        current,
        entropy_tolerance,
        &mut regressions,
        &mut improvements,
    );
    compare_yara(baseline, current, &mut regressions);

    Comparison {
        baseline: baseline_label.to_string(),
        entropy_tolerance,
        regressions,
        improvements,
    }
}

/// Sensitive literals that reappeared (or disappeared, when fixed).
fn compare_sensitive_literals(
    baseline: &Report,
    current: &Report,
    regressions: &mut Vec<Regression>,
    improvements: &mut Vec<String>,
) {
    let base: BTreeSet<&String> = baseline.strings.sensitive.iter().collect();
    let cur: BTreeSet<&String> = current.strings.sensitive.iter().collect();
    for lit in cur.difference(&base) {
        regressions.push(Regression {
            kind: "sensitive literal".to_string(),
            detail: (*lit).clone(),
        });
    }
    for lit in base.difference(&cur) {
        improvements.push(format!("sensitive literal gone: {lit}"));
    }
}

/// Suspicious imports that reappeared (or disappeared, when fixed).
fn compare_suspicious_imports(
    baseline: &Report,
    current: &Report,
    regressions: &mut Vec<Regression>,
    improvements: &mut Vec<String>,
) {
    let base = baseline.suspicious_imports();
    let cur = current.suspicious_imports();
    for name in cur.difference(&base) {
        regressions.push(Regression {
            kind: "suspicious import".to_string(),
            detail: name.clone(),
        });
    }
    for name in base.difference(&cur) {
        improvements.push(format!("suspicious import gone: {name}"));
    }
}

/// Sections whose entropy grew past the tolerance, or new high-entropy sections.
fn compare_entropy(
    baseline: &Report,
    current: &Report,
    tolerance: f64,
    regressions: &mut Vec<Regression>,
    improvements: &mut Vec<String>,
) {
    for section in &current.sections {
        match baseline.sections.iter().find(|b| b.name == section.name) {
            Some(base) => {
                let delta = section.entropy - base.entropy;
                if delta > tolerance {
                    regressions.push(Regression {
                        kind: "entropy".to_string(),
                        detail: format!(
                            "{} {:.2} -> {:.2} (+{:.2})",
                            section.name, base.entropy, section.entropy, delta
                        ),
                    });
                } else if -delta > tolerance {
                    improvements.push(format!(
                        "{} entropy {:.2} -> {:.2}",
                        section.name, base.entropy, section.entropy
                    ));
                }
            }
            // A section the baseline did not have: only a problem when it looks
            // packed, since an ordinary new code/data section is unremarkable.
            None if section.entropy >= ENTROPY_HIGH_MIN => regressions.push(Regression {
                kind: "new high-entropy section".to_string(),
                detail: format!("{} ({:.2})", section.name, section.entropy),
            }),
            None => {}
        }
    }
}

/// New YARA matches against the baseline.
fn compare_yara(baseline: &Report, current: &Report, regressions: &mut Vec<Regression>) {
    for rule in &current.yara.matches {
        if !baseline.yara.matches.contains(rule) {
            regressions.push(Regression {
                kind: "yara".to_string(),
                detail: rule.clone(),
            });
        }
    }
}

/// Renders the comparison as a report section.
pub fn render(comparison: &Comparison, ui: &Palette) -> String {
    let mut out = String::new();
    out.push('\n');
    out.push_str(&ui.heading("BASELINE"));
    out.push('\n');
    out.push_str(&format!(
        "{} {}\n",
        ui.dim("against"),
        ui.target(&comparison.baseline)
    ));
    out.push_str(&format!(
        "{} {:.2}\n",
        ui.dim("entropy tolerance"),
        comparison.entropy_tolerance
    ));

    if comparison.regressions.is_empty() {
        out.push_str(&format!("{} {}\n", ui.check(), ui.ok("no regressions")));
    } else {
        out.push_str(&format!(
            "{} {}\n",
            ui.bang(),
            ui.error(format!("{} regression(s)", comparison.regressions.len()))
        ));
        for regression in &comparison.regressions {
            out.push_str(&format!(
                "  {} {} {}\n",
                ui.cross(),
                ui.error(&regression.kind),
                ui.dim(&regression.detail)
            ));
        }
    }

    for improvement in &comparison.improvements {
        out.push_str(&format!("  {} {}\n", ui.check(), ui.ok(improvement)));
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::model::{Defender, Dll, Section, Strings, Yara};

    fn report(sensitive: &[&str], imports: &[&str], sections: &[(&str, f64)]) -> Report {
        Report {
            report_schema: super::super::model::REPORT_SCHEMA,
            binary: "x.exe".to_string(),
            size: 1,
            arch: "x64".to_string(),
            subsystem: "console".to_string(),
            timestamp: None,
            has_signature: false,
            has_manifest: false,
            overlay: 0,
            sections: sections
                .iter()
                .map(|(name, entropy)| Section {
                    name: (*name).to_string(),
                    size: 1,
                    entropy: *entropy,
                })
                .collect(),
            imports: vec![Dll {
                name: "k.dll".to_string(),
                functions: imports.iter().map(|s| (*s).to_string()).collect(),
            }],
            exports: Vec::new(),
            strings: Strings {
                paths: Vec::new(),
                apis: Vec::new(),
                techniques: Vec::new(),
                urls_ips: Vec::new(),
                sensitive: sensitive.iter().map(|s| (*s).to_string()).collect(),
            },
            yara: Yara {
                matches: Vec::new(),
                note: "ruleset empty".to_string(),
            },
            defender: Defender {
                status: "unavailable".to_string(),
            },
        }
    }

    #[test]
    fn identical_reports_have_no_regressions() {
        let base = report(&["amsi.dll"], &["VirtualAllocEx"], &[(".rdata", 6.0)]);
        let current = base.clone();
        let comparison = compare(&base, &current, "base.json", 0.1);
        assert!(comparison.regressions.is_empty(), "{comparison:?}");
    }

    #[test]
    fn a_new_sensitive_literal_is_a_regression() {
        let base = report(&[], &[], &[]);
        let current = report(&["AmsiScanBuffer"], &[], &[]);
        let comparison = compare(&base, &current, "base.json", 0.1);
        assert_eq!(comparison.regressions.len(), 1);
        assert_eq!(comparison.regressions[0].kind, "sensitive literal");
        assert_eq!(comparison.regressions[0].detail, "AmsiScanBuffer");
    }

    #[test]
    fn a_disappearing_literal_is_an_improvement() {
        let base = report(&["AmsiScanBuffer"], &[], &[]);
        let current = report(&[], &[], &[]);
        let comparison = compare(&base, &current, "base.json", 0.1);
        assert!(comparison.regressions.is_empty());
        assert_eq!(comparison.improvements.len(), 1);
    }

    #[test]
    fn a_suspicious_import_is_a_regression_but_a_plain_one_is_not() {
        let base = report(&[], &["LoadLibraryA"], &[]);
        let current = report(&[], &["LoadLibraryA", "WriteProcessMemory"], &[]);
        let comparison = compare(&base, &current, "base.json", 0.1);
        assert_eq!(comparison.regressions.len(), 1);
        assert_eq!(comparison.regressions[0].detail, "WriteProcessMemory");
    }

    #[test]
    fn an_entropy_jump_above_the_tolerance_is_a_regression() {
        let base = report(&[], &[], &[(".rdata", 6.0)]);
        let current = report(&[], &[], &[(".rdata", 6.4)]);
        let comparison = compare(&base, &current, "base.json", 0.1);
        assert_eq!(comparison.regressions.len(), 1);
        assert_eq!(comparison.regressions[0].kind, "entropy");
    }

    #[test]
    fn entropy_within_the_tolerance_is_ignored() {
        let base = report(&[], &[], &[(".rdata", 6.0)]);
        let current = report(&[], &[], &[(".rdata", 6.05)]);
        let comparison = compare(&base, &current, "base.json", 0.1);
        assert!(comparison.regressions.is_empty());
        assert!(comparison.improvements.is_empty());
    }

    #[test]
    fn a_new_high_entropy_section_is_a_regression() {
        let base = report(&[], &[], &[(".text", 6.0)]);
        let current = report(&[], &[], &[(".text", 6.0), (".new", 7.5)]);
        let comparison = compare(&base, &current, "base.json", 0.1);
        assert_eq!(comparison.regressions.len(), 1);
        assert_eq!(comparison.regressions[0].kind, "new high-entropy section");
    }

    #[test]
    fn a_new_low_entropy_section_is_not_a_regression() {
        let base = report(&[], &[], &[(".text", 6.0)]);
        let current = report(&[], &[], &[(".text", 6.0), (".rsrc", 3.0)]);
        let comparison = compare(&base, &current, "base.json", 0.1);
        assert!(comparison.regressions.is_empty());
    }

    #[test]
    fn comparison_survives_a_json_round_trip() {
        let base = report(&[], &[], &[]);
        let current = report(&["amsi.dll"], &[], &[]);
        let comparison = compare(&base, &current, "base.json", 0.1);
        let json = serde_json::to_string(&comparison).expect("serialize");
        let back: Comparison = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.regressions.len(), 1);
    }
}
