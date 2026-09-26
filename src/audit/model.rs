//! Serializable model of an audit report.
//!
//! The pretty report ([`super::report`]) is for humans; this is its
//! machine-readable twin, printed by `audit --json` and consumed by
//! `audit --baseline` (see [`super::baseline`]). Keeping an explicit model
//! decouples the JSON format from the internal parser types.
//!
//! The format carries only what a static audit observes on disk; the Defender
//! result is environment-dependent and therefore reported but never used in a
//! regression decision.

use std::collections::BTreeSet;
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::defender::DefenderResult;
use super::pe_info::{ImportItem, PeAudit};
use super::strings::StringFindings;
use super::yara::YaraResult;

/// Version of the JSON report document (bump on breaking format changes).
pub const REPORT_SCHEMA: u32 = 1;

/// A full audit report in a stable, serializable shape.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Report {
    /// Report format version.
    pub report_schema: u32,
    /// Path of the audited binary.
    pub binary: String,
    /// File size, in bytes.
    pub size: usize,
    /// Architecture label (`x64`/`x86`/`unknown`).
    pub arch: String,
    /// Subsystem label (`GUI`/`console`/`unknown`).
    pub subsystem: String,
    /// PE timestamp, when non-zero.
    pub timestamp: Option<u32>,
    /// Whether the PE carries an Authenticode signature.
    pub has_signature: bool,
    /// Whether the PE carries an embedded manifest resource.
    pub has_manifest: bool,
    /// Size of any overlay (bytes after the last section).
    pub overlay: usize,
    /// Sections with their entropy.
    pub sections: Vec<Section>,
    /// Imported DLLs and their functions.
    pub imports: Vec<Dll>,
    /// Exported function names.
    pub exports: Vec<String>,
    /// String scan findings.
    pub strings: Strings,
    /// YARA scan result.
    pub yara: Yara,
    /// Offline Defender scan result.
    pub defender: Defender,
}

/// One section.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Section {
    pub name: String,
    pub size: usize,
    pub entropy: f64,
}

/// One imported DLL.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Dll {
    pub name: String,
    /// Function names; by-ordinal imports are `#<n>`.
    pub functions: Vec<String>,
}

/// String scan findings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Strings {
    pub paths: Vec<String>,
    pub apis: Vec<String>,
    pub techniques: Vec<String>,
    pub urls_ips: Vec<String>,
    pub sensitive: Vec<String>,
}

/// YARA scan result.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Yara {
    pub matches: Vec<String>,
    pub note: String,
}

/// Defender scan result (environment-dependent; not used for regression).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Defender {
    pub status: String,
}

impl Report {
    /// Assembles the report from the already-analyzed parts.
    pub fn from_parts(
        binary: &Path,
        size: usize,
        pe: &PeAudit,
        strings: &StringFindings,
        yara: &YaraResult,
        defender: &DefenderResult,
    ) -> Self {
        Self {
            report_schema: REPORT_SCHEMA,
            binary: binary.display().to_string(),
            size,
            arch: pe.arch.to_string(),
            subsystem: pe.subsystem.to_string(),
            timestamp: pe.timestamp,
            has_signature: pe.has_signature,
            has_manifest: pe.has_manifest,
            overlay: pe.overlay,
            sections: pe
                .sections
                .iter()
                .map(|s| Section {
                    name: s.name.clone(),
                    size: s.size,
                    entropy: s.entropy,
                })
                .collect(),
            imports: pe
                .imports
                .iter()
                .map(|d| Dll {
                    name: d.name.clone(),
                    functions: d
                        .functions
                        .iter()
                        .map(|f| match f {
                            ImportItem::Named(n) => n.clone(),
                            ImportItem::Ordinal(o) => format!("#{o}"),
                        })
                        .collect(),
                })
                .collect(),
            exports: pe.exports.clone(),
            strings: Strings {
                paths: strings.paths.clone(),
                apis: strings.apis.clone(),
                techniques: strings.techniques.clone(),
                urls_ips: strings.urls_ips.clone(),
                sensitive: strings.sensitive.clone(),
            },
            yara: Yara {
                matches: yara.matches.clone(),
                note: yara.note.to_string(),
            },
            defender: Defender {
                status: defender_status(defender).to_string(),
            },
        }
    }

    /// Every imported function name across all DLLs, deduplicated.
    pub fn imported_names(&self) -> BTreeSet<String> {
        self.imports
            .iter()
            .flat_map(|d| d.functions.iter().cloned())
            .collect()
    }

    /// The suspicious imports (see [`super::SUSPICIOUS_IMPORTS`]) this report
    /// contains, deduplicated.
    pub fn suspicious_imports(&self) -> BTreeSet<String> {
        let imported = self.imported_names();
        super::SUSPICIOUS_IMPORTS
            .iter()
            .filter(|name| imported.contains(**name))
            .map(|name| name.to_string())
            .collect()
    }
}

/// Short label for the Defender result.
fn defender_status(result: &DefenderResult) -> &'static str {
    match result {
        DefenderResult::NotAvailable => "unavailable",
        DefenderResult::Clean => "clean",
        DefenderResult::ThreatFound(_) => "threat",
        DefenderResult::Error(_) => "error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::pe_info::PeAudit;

    fn empty_pe() -> PeAudit {
        PeAudit {
            arch: "x64",
            subsystem: "console",
            timestamp: None,
            has_signature: false,
            has_manifest: false,
            overlay: 0,
            sections: Vec::new(),
            imports: Vec::new(),
            exports: Vec::new(),
            import_text_ranges: Vec::new(),
        }
    }

    #[test]
    fn ordinals_are_rendered_with_a_hash_prefix() {
        let mut pe = empty_pe();
        pe.imports = vec![crate::audit::pe_info::DllImport {
            name: "x.dll".to_string(),
            functions: vec![ImportItem::Named("Foo".into()), ImportItem::Ordinal(7)],
        }];
        let report = Report::from_parts(
            Path::new("x.exe"),
            10,
            &pe,
            &StringFindings::default(),
            &YaraResult {
                matches: Vec::new(),
                note: "ruleset empty",
            },
            &DefenderResult::NotAvailable,
        );
        assert_eq!(report.imports[0].functions, vec!["Foo", "#7"]);
        assert!(report.imported_names().contains("#7"));
    }

    #[test]
    fn suspicious_imports_are_filtered_against_the_shared_list() {
        let mut pe = empty_pe();
        pe.imports = vec![crate::audit::pe_info::DllImport {
            name: "k.dll".to_string(),
            functions: vec![
                ImportItem::Named("VirtualAllocEx".into()),
                ImportItem::Named("LoadLibraryA".into()),
            ],
        }];
        let report = Report::from_parts(
            Path::new("x.exe"),
            10,
            &pe,
            &StringFindings::default(),
            &YaraResult {
                matches: Vec::new(),
                note: "ruleset empty",
            },
            &DefenderResult::Clean,
        );
        let suspicious = report.suspicious_imports();
        assert!(suspicious.contains("VirtualAllocEx"));
        assert!(!suspicious.contains("LoadLibraryA"));
    }
}
