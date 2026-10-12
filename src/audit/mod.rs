//! Static audit of a PE binary: header, sections, imports/exports, strings,
//! YARA (stub) and an optional offline Defender scan.
//!
//! This is the measurement infrastructure for the static-evasion axis: it
//! reports what a binary looks like on disk before we add evasion, so each
//! later technique can be measured against this baseline. `audit --json` emits
//! the same data as [`model::Report`], and `audit --baseline` turns it into a
//! regression gate (see [`baseline`]).

pub mod baseline;
pub mod defender;
pub mod model;
pub mod pe_info;
pub mod report;
pub mod strings;
pub mod yara;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::ui::Palette;
use pe_info::ImportItem;
use report::Focus;

/// Imported functions widely used as malware signatures.
///
/// Shared by the report's risk summary and the baseline regression gate: a
/// build that reintroduces one of these has lost IAT-level evasion. Kept
/// deliberately short and high-signal to avoid noise.
pub const SUSPICIOUS_IMPORTS: &[&str] = &[
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
    /// The baseline file could not be read.
    #[error("could not read baseline '{path}': {source}")]
    BaselineRead {
        path: String,
        #[source]
        source: std::io::Error,
    },
    /// The baseline file is not a valid audit report.
    #[error("could not parse baseline '{path}': {source}")]
    BaselineParse {
        path: String,
        #[source]
        source: serde_json::Error,
    },
    /// The JSON report could not be serialized.
    #[error("could not serialize the audit report: {0}")]
    Json(serde_json::Error),
}

/// What `picaro audit` should produce.
#[derive(Debug, Clone)]
pub struct AuditOptions {
    /// `--focus`: comma-separated section list (pretty output only).
    pub focus: Option<String>,
    /// `--json`: emit the machine-readable report instead of the pretty one.
    pub json: bool,
    /// `--baseline`: compare against a previous `--json` report.
    pub baseline: Option<PathBuf>,
    /// `--entropy-tolerance`: entropy increase tolerated before it fails.
    pub entropy_tolerance: f64,
}

impl Default for AuditOptions {
    fn default() -> Self {
        Self {
            focus: None,
            json: false,
            baseline: None,
            entropy_tolerance: DEFAULT_ENTROPY_TOLERANCE,
        }
    }
}

/// Default entropy tolerance, in bits per byte.
///
/// The payload ciphertext makes a section's entropy wobble slightly between
/// builds, so a small increase is noise, not a regression.
pub const DEFAULT_ENTROPY_TOLERANCE: f64 = 0.1;

/// The rendered report plus the baseline outcome.
pub struct Outcome {
    /// What to print: pretty text or pretty JSON.
    pub output: String,
    /// Number of baseline regressions (0 when no baseline was given).
    pub regressions: usize,
}

/// The JSON document printed by `audit --json`.
///
/// The report is flattened at the top level so its own output is a valid
/// baseline: `serde` ignores the extra `baseline` key when reading it back.
#[derive(Serialize)]
struct JsonOutput<'a> {
    #[serde(flatten)]
    report: &'a model::Report,
    #[serde(skip_serializing_if = "Option::is_none")]
    baseline: Option<&'a baseline::Comparison>,
}

/// Runs a static audit of `binary` and returns the rendered output.
///
/// `options.focus` restricts the *pretty* report to a comma-separated list of
/// sections; `--json` always emits the full report. When a baseline is given,
/// the comparison is appended (pretty) or embedded (JSON) and its regressions
/// are reported in [`Outcome::regressions`] for the caller to set an exit code.
pub fn run(binary: &Path, options: &AuditOptions, ui: &Palette) -> Result<Outcome, AuditError> {
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
    // Sensitive literals are checked over the code/data sections only, with the
    // import table's own strings blanked out, so its DLL/function names (e.g.
    // `kernel32.dll`) are not false positives regardless of where the linker
    // placed them. A statically imported DLL name is still excluded outright:
    // the `windows` crate graph embeds `ntdll.dll` (`windows-result`) and the
    // linker keeps it depending on the build, which is toolchain noise. The
    // source guardrail still checks those names.
    let code_data = pe_info::code_data(&data, &pe.sections, &pe.import_text_ranges);
    let imported_dlls: BTreeSet<String> = pe
        .imports
        .iter()
        .map(|d| d.name.to_ascii_lowercase())
        .collect();
    let mut strings = strings_scan;
    strings.sensitive = strings::find_sensitive_literals_excluding(&code_data, &imported_dlls);
    let yara = yara::scan(&data);
    let defender = defender::scan(binary);

    let report = model::Report::from_parts(binary, size, &pe, &strings, &yara, &defender);
    let comparison = match &options.baseline {
        Some(path) => Some(load_comparison(path, &report, options.entropy_tolerance)?),
        None => None,
    };

    let output = if options.json {
        let envelope = JsonOutput {
            report: &report,
            baseline: comparison.as_ref(),
        };
        format!(
            "{}\n",
            serde_json::to_string_pretty(&envelope).map_err(AuditError::Json)?
        )
    } else {
        let focus = Focus::parse(options.focus.as_deref());
        let mut out = report::render(binary, size, &pe, &strings, &yara, &defender, &focus, ui);
        if let Some(comparison) = &comparison {
            out.push_str(&baseline::render(comparison, ui));
        }
        out
    };

    Ok(Outcome {
        output,
        regressions: comparison.map_or(0, |c| c.regressions.len()),
    })
}

/// Loads a baseline report and compares `current` against it.
fn load_comparison(
    path: &Path,
    current: &model::Report,
    entropy_tolerance: f64,
) -> Result<baseline::Comparison, AuditError> {
    let label = path.display().to_string();
    let text = std::fs::read_to_string(path).map_err(|source| AuditError::BaselineRead {
        path: label.clone(),
        source,
    })?;
    let baseline: model::Report =
        serde_json::from_str(&text).map_err(|source| AuditError::BaselineParse {
            path: label.clone(),
            source,
        })?;
    Ok(baseline::compare(
        &baseline,
        current,
        &label,
        entropy_tolerance,
    ))
}
