//! Static audit of a PE binary: header, sections, imports/exports, strings,
//! YARA (stub) and an optional offline Defender scan.
//!
//! This is the measurement infrastructure for the static-evasion axis: it
//! reports what a binary looks like on disk before we add evasion, so each
//! later technique can be measured against this baseline.

pub mod defender;
pub mod pe_info;
pub mod report;
pub mod strings;
pub mod yara;

use std::collections::BTreeSet;
use std::path::Path;

use pe_info::ImportItem;
use report::Focus;

/// Audit error.
#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    /// The binary could not be read from disk.
    #[error("could not read binary '{path}': {source}")]
    ReadBinary {
        path: String,
        #[source]
        source: std::io::Error,
    },
    /// The file is not a valid PE (or is truncated).
    #[error("not a valid PE: {0}")]
    InvalidPe(String),
}

/// Runs a full static audit of `binary` and returns the rendered report.
///
/// `focus`, when set, restricts the report to a comma-separated list of
/// sections (e.g. `imports,strings`).
pub fn run(binary: &Path, focus: Option<&str>) -> Result<String, AuditError> {
    let data = std::fs::read(binary).map_err(|source| AuditError::ReadBinary {
        path: binary.display().to_string(),
        source,
    })?;

    let size = data.len();
    let pe = pe_info::analyze(&data)?;

    // Names already statically imported (reported separately), so the string
    // scan can report only dynamically-resolved API names.
    let imported: BTreeSet<String> = pe
        .imports
        .iter()
        .flat_map(|d| &d.functions)
        .filter_map(|f| match f {
            ImportItem::Named(n) => Some(n.to_ascii_lowercase()),
            ImportItem::Ordinal(_) => None,
        })
        .collect();

    let strings_scan = strings::scan(&data, &imported);
    // Sensitive literals are checked over the code/data sections only, so
    // import-table DLL names (in `.idata`) are not false positives.
    let code_data = pe_info::code_data(&data, &pe.sections);
    let mut strings = strings_scan;
    strings.sensitive = strings::find_sensitive_literals(&code_data);
    let yara = yara::scan(&data);
    let defender = defender::scan(binary);
    let focus = Focus::parse(focus);

    Ok(report::render(
        binary, size, &pe, &strings, &yara, &defender, &focus,
    ))
}
