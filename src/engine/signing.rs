//! Authenticode signing of the packed artifact via `signtool.exe`.
//!
//! Signing is the last build step (it hashes the artifact), and it is fully
//! optional. Three modes:
//!
//! - `lab` — an automatic **certificate authority + leaf** pair in the current
//!   user's store: a self-signed CA (`<subject> Root CA`) and a code-signing
//!   certificate signed by it. Both are created on first use and reused
//!   afterwards, and the CA's public certificate is exported next to the
//!   artifact (`<stem>.ca.cer`) so the lab can trust it. Nothing is added to the
//!   local trust stores: signing does not change this machine's trust. This is a
//!   lab identity: it gives no SmartScreen reputation.
//! - `store` — a certificate already in the current user's store, matched by
//!   `thumbprint` or `subject`.
//! - `file` — a `.pfx`/`.p12` file; the password is read from the environment
//!   variable named by `password_env`, never from the YAML.
//!
//! `signtool.exe` ships with the Windows SDK (Visual Studio) and is usually not
//! on `PATH`, so it is looked up in `PATH`, then `BATESIAN_SIGNTOOL`, then the
//! Windows Kits install directories, and finally `output.sign.signtool`.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Serialize;

use crate::config::schema::SignConfig;

/// Subject used by `mode: lab` when none is configured.
const DEFAULT_LAB_SUBJECT: &str = "CN=batesian lab code signing";

/// Signing error.
#[derive(Debug, thiserror::Error)]
pub enum SigningError {
    /// `signtool.exe` could not be located.
    #[error(
        "`signtool.exe` was not found ({0}); install the Windows SDK (Visual Studio) \
         or set `output.sign.signtool`"
    )]
    SigntoolNotFound(String),
    /// An external tool could not be started.
    #[error("could not run `{tool}`: {source}")]
    ToolFailed {
        tool: String,
        #[source]
        source: std::io::Error,
    },
    /// An external tool ran but failed.
    #[error("`{tool}` failed:\n{stderr}")]
    CommandFailed { tool: String, stderr: String },
    /// The certificate or CA could not be resolved or created.
    #[error("certificate: {0}")]
    Certificate(String),
    /// The `.pfx` password environment variable is missing or unreadable.
    #[error(
        "could not read the signing password from the environment variable '{0}' \
         (set it, or leave `password_env` unset for a passwordless .pfx)"
    )]
    PasswordEnv(String),
    /// The `file` mode needs a path to a `.pfx`/`.p12`.
    #[error("output.sign.mode 'file' needs a 'file' path")]
    MissingPfx,
}

/// What was used to sign the artifact (recorded in the build manifest).
#[derive(Debug, Clone, Serialize)]
pub struct Signature {
    /// Signing mode (`lab`, `store` or `file`).
    pub mode: String,
    /// Certificate subject, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// Issuer (the lab CA for `mode: lab`), when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    /// Certificate thumbprint (store/lab modes).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thumbprint: Option<String>,
    /// Path of the exported CA certificate (`mode: lab`), for lab trust.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ca_file: Option<String>,
    /// RFC 3161 timestamp server, when one was used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp_url: Option<String>,
}

/// Signs `exe` according to `config`.
///
/// `None` or `mode: none` is a no-op and returns `Ok(None)`.
pub fn sign(exe: &Path, config: Option<&SignConfig>) -> Result<Option<Signature>, SigningError> {
    let Some(config) = config else {
        return Ok(None);
    };
    if config.mode == "none" {
        return Ok(None);
    }

    let signtool = signtool_path(config)?;
    let mut args: Vec<String> = vec!["sign".to_string()];
    let mut signature = Signature {
        mode: config.mode.clone(),
        subject: config.subject.clone(),
        issuer: None,
        thumbprint: None,
        ca_file: None,
        timestamp_url: config.timestamp_url.clone(),
    };

    match config.mode.as_str() {
        "lab" => {
            let subject = config
                .subject
                .clone()
                .unwrap_or_else(|| DEFAULT_LAB_SUBJECT.to_string());
            let leaf_subject = ensure_cn(&subject);
            let ca_subject = format!("{leaf_subject} Root CA");
            ensure_ca(&ca_subject)?;
            let leaf = ensure_leaf(&leaf_subject, &ca_subject)?;
            // Export the CA (public) next to the artifact so the lab can trust
            // it; nothing is added to this machine's stores.
            let ca_file = ca_export_path(exe);
            export_certificate(&ca_subject, &ca_file)?;
            signature.issuer = Some(ca_subject);
            signature.subject = Some(subject);
            signature.thumbprint = Some(leaf.clone());
            signature.ca_file = Some(ca_file.display().to_string());
            args.push("/sha1".to_string());
            args.push(leaf);
        }
        "store" => {
            let thumbprint = resolve_store_cert(config)?;
            args.push("/sha1".to_string());
            args.push(thumbprint.clone());
            signature.thumbprint = Some(thumbprint);
        }
        "file" => {
            let file = config.file.as_ref().ok_or(SigningError::MissingPfx)?;
            args.push("/f".to_string());
            args.push(file.display().to_string());
            if let Some(var) = &config.password_env {
                let password =
                    std::env::var(var).map_err(|_| SigningError::PasswordEnv(var.clone()))?;
                args.push("/p".to_string());
                args.push(password);
            }
        }
        other => {
            return Err(SigningError::Certificate(format!(
                "unknown sign mode '{other}'"
            )))
        }
    }

    args.push("/fd".to_string());
    args.push("SHA256".to_string());
    if let Some(url) = &config.timestamp_url {
        args.push("/tr".to_string());
        args.push(url.clone());
        args.push("/td".to_string());
        args.push("SHA256".to_string());
    }
    args.push(exe.display().to_string());

    run_tool(&signtool, &args)?;
    Ok(Some(signature))
}

/// Locates `signtool.exe` for `config` (see the module docs for the order).
pub fn signtool_path(config: &SignConfig) -> Result<PathBuf, SigningError> {
    if let Some(path) = &config.signtool {
        if path.is_file() {
            return Ok(path.clone());
        }
        return Err(SigningError::SigntoolNotFound(format!(
            "'{}' does not exist",
            path.display()
        )));
    }
    if let Some(from_env) = std::env::var_os("BATESIAN_SIGNTOOL") {
        let path = PathBuf::from(from_env);
        if path.is_file() {
            return Ok(path);
        }
    }
    if let Some(path) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path) {
            let candidate = dir.join("signtool.exe");
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }
    if let Some(found) = find_in_windows_kits() {
        return Ok(found);
    }
    Err(SigningError::SigntoolNotFound(
        "not in PATH and no Windows 10/11 SDK was found under 'Windows Kits\\10\\bin'".to_string(),
    ))
}

/// Finds the newest `...\Windows Kits\10\bin\<version>\x64\signtool.exe`.
fn find_in_windows_kits() -> Option<PathBuf> {
    const ROOTS: &[&str] = &[
        r"C:\Program Files (x86)\Windows Kits\10\bin",
        r"C:\Program Files\Windows Kits\10\bin",
    ];
    let mut best: Option<(Vec<u32>, PathBuf)> = None;
    for root in ROOTS {
        let Ok(entries) = std::fs::read_dir(root) else {
            continue;
        };
        for entry in entries.flatten() {
            let candidate = entry.path().join("x64").join("signtool.exe");
            if !candidate.is_file() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().to_string();
            let version: Vec<u32> = name.split('.').filter_map(|p| p.parse().ok()).collect();
            if best.as_ref().is_none_or(|(current, _)| version > *current) {
                best = Some((version, candidate));
            }
        }
    }
    best.map(|(_, path)| path)
}

/// `CN=<name>` when `subject` is a bare name.
fn ensure_cn(subject: &str) -> String {
    if subject.contains('=') {
        subject.to_string()
    } else {
        format!("CN={subject}")
    }
}

/// Creates (once) a self-signed CA certificate. Returns its thumbprint.
fn ensure_ca(ca_subject: &str) -> Result<String, SigningError> {
    let escaped = escape_single_quotes(ca_subject);
    let find = format!(
        "$c = Get-ChildItem Cert:\\CurrentUser\\My \
         | Where-Object {{ $_.Subject -eq '{escaped}' }} | Select-Object -First 1; \
         if ($c) {{ $c.Thumbprint }}"
    );
    let existing = powershell(&find)?;
    if !existing.is_empty() {
        return Ok(normalize_thumbprint(&existing));
    }

    let create = format!(
        "$c = New-SelfSignedCertificate -Type Custom -Subject '{escaped}' \
         -KeyUsage CertSign,CRLSign,DigitalSignature \
         -TextExtension @('2.5.29.19={{critical}}{{text}}ca=1&pathlength=1') \
         -CertStoreLocation Cert:\\CurrentUser\\My -KeyExportPolicy Exportable \
         -NotAfter (Get-Date).AddYears(5); \
         if ($c) {{ $c.Thumbprint }}"
    );
    let created = powershell(&create)?;
    if created.is_empty() {
        return Err(SigningError::Certificate(
            "New-SelfSignedCertificate returned no CA".to_string(),
        ));
    }
    Ok(normalize_thumbprint(&created))
}

/// Creates (once) a code-signing certificate signed by the lab CA. The search
/// also matches the issuer, so a stale self-signed certificate with the same
/// subject is not reused.
fn ensure_leaf(leaf_subject: &str, ca_subject: &str) -> Result<String, SigningError> {
    let leaf = escape_single_quotes(leaf_subject);
    let ca = escape_single_quotes(ca_subject);
    let find = format!(
        "$c = Get-ChildItem Cert:\\CurrentUser\\My -CodeSigningCert \
         | Where-Object {{ $_.Subject -eq '{leaf}' -and $_.Issuer -eq '{ca}' }} \
         | Select-Object -First 1; if ($c) {{ $c.Thumbprint }}"
    );
    let existing = powershell(&find)?;
    if !existing.is_empty() {
        return Ok(normalize_thumbprint(&existing));
    }

    let create = format!(
        "$ca = Get-ChildItem Cert:\\CurrentUser\\My \
         | Where-Object {{ $_.Subject -eq '{ca}' }} | Select-Object -First 1; \
         if (-not $ca) {{ throw 'lab CA not found' }}; \
         $c = New-SelfSignedCertificate -Type CodeSigningCert -Subject '{leaf}' \
         -Signer $ca -CertStoreLocation Cert:\\CurrentUser\\My \
         -NotAfter (Get-Date).AddYears(2); if ($c) {{ $c.Thumbprint }}"
    );
    let created = powershell(&create)?;
    if created.is_empty() {
        return Err(SigningError::Certificate(
            "New-SelfSignedCertificate returned no certificate".to_string(),
        ));
    }
    Ok(normalize_thumbprint(&created))
}

/// `<stem>.ca.cer` next to the artifact.
fn ca_export_path(exe: &Path) -> PathBuf {
    let stem = exe
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("artifact");
    let name = format!("{stem}.ca.cer");
    match exe.parent().filter(|p| !p.as_os_str().is_empty()) {
        Some(dir) => dir.join(name),
        None => PathBuf::from(name),
    }
}

/// Exports the CA's public certificate (DER `.cer`) to `dest`.
///
/// The private key is never exported: this file is only meant to be installed
/// in a lab machine's trusted root store. Nothing is added to the local stores.
fn export_certificate(ca_subject: &str, dest: &Path) -> Result<(), SigningError> {
    let subject = escape_single_quotes(ca_subject);
    let dest = escape_single_quotes(&dest.display().to_string());
    let script = format!(
        "$c = Get-ChildItem Cert:\\CurrentUser\\My \
         | Where-Object {{ $_.Subject -eq '{subject}' }} | Select-Object -First 1; \
         if (-not $c) {{ throw 'lab CA not found' }}; \
         Export-Certificate -Cert $c -FilePath '{dest}' -Type CERT -Force | Out-Null"
    );
    powershell(&script)?;
    Ok(())
}

/// Resolves the thumbprint of a certificate already in the current user's store.
fn resolve_store_cert(config: &SignConfig) -> Result<String, SigningError> {
    let script = if let Some(thumbprint) = &config.thumbprint {
        let thumbprint = escape_single_quotes(thumbprint);
        format!(
            "$c = Get-ChildItem Cert:\\CurrentUser\\My \
             | Where-Object {{ $_.Thumbprint -eq '{thumbprint}' }} | Select-Object -First 1; \
             if ($c) {{ $c.Thumbprint }}"
        )
    } else {
        let subject = escape_single_quotes(config.subject.as_deref().unwrap_or(""));
        format!(
            "$c = Get-ChildItem Cert:\\CurrentUser\\My -CodeSigningCert \
             | Where-Object {{ $_.Subject -eq '{subject}' }} | Select-Object -First 1; \
             if ($c) {{ $c.Thumbprint }}"
        )
    };
    let found = powershell(&script)?;
    if found.is_empty() {
        return Err(SigningError::Certificate(format!(
            "no matching certificate in the current user's store ({})",
            config
                .thumbprint
                .as_deref()
                .map(|t| format!("thumbprint {t}"))
                .unwrap_or_else(|| format!(
                    "subject '{}'",
                    config.subject.as_deref().unwrap_or("")
                ))
        )));
    }
    Ok(normalize_thumbprint(&found))
}

/// Runs a PowerShell snippet and returns its trimmed stdout.
fn powershell(script: &str) -> Result<String, SigningError> {
    let output = Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ])
        .output()
        .map_err(|source| SigningError::ToolFailed {
            tool: "powershell".to_string(),
            source,
        })?;
    if !output.status.success() {
        return Err(SigningError::CommandFailed {
            tool: "powershell".to_string(),
            stderr: combine(&output),
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Runs `tool` with `args`, mapping a non-zero exit to a clear error.
fn run_tool(tool: &Path, args: &[String]) -> Result<(), SigningError> {
    let output =
        Command::new(tool)
            .args(args)
            .output()
            .map_err(|source| SigningError::ToolFailed {
                tool: tool.display().to_string(),
                source,
            })?;
    if !output.status.success() {
        return Err(SigningError::CommandFailed {
            tool: tool.display().to_string(),
            stderr: combine(&output),
        });
    }
    Ok(())
}

/// `stdout` then `stderr`, trimmed (tools disagree on which one they use).
fn combine(output: &std::process::Output) -> String {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    format!("{}{}", stdout.trim(), stderr.trim())
        .trim()
        .to_string()
}

/// Escapes single quotes for a PowerShell single-quoted string.
fn escape_single_quotes(value: &str) -> String {
    value.replace('\'', "''")
}

/// Keeps only the hex digits of a thumbprint and upper-cases them.
fn normalize_thumbprint(value: &str) -> String {
    value
        .chars()
        .filter(char::is_ascii_hexdigit)
        .collect::<String>()
        .to_ascii_uppercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(mode: &str) -> SignConfig {
        SignConfig {
            mode: mode.to_string(),
            subject: None,
            thumbprint: None,
            file: None,
            password_env: None,
            timestamp_url: None,
            signtool: None,
        }
    }

    #[test]
    fn normalizes_a_spaced_thumbprint() {
        assert_eq!(
            normalize_thumbprint("de ad be ef 00"),
            "DEADBEEF00".to_string()
        );
    }

    #[test]
    fn escapes_single_quotes_for_powershell() {
        assert_eq!(escape_single_quotes("CN=it's"), "CN=it''s");
    }

    #[test]
    fn a_bare_subject_gets_a_cn_prefix() {
        assert_eq!(ensure_cn("Contoso"), "CN=Contoso");
        assert_eq!(ensure_cn("CN=Contoso"), "CN=Contoso");
    }

    #[test]
    fn the_ca_certificate_is_exported_next_to_the_artifact() {
        assert_eq!(
            ca_export_path(Path::new("dist/widget.exe")),
            PathBuf::from("dist/widget.ca.cer")
        );
        assert_eq!(
            ca_export_path(Path::new("widget.exe")),
            PathBuf::from("widget.ca.cer")
        );
    }

    #[test]
    fn an_explicit_missing_signtool_is_reported() {
        let mut cfg = config("file");
        cfg.signtool = Some(PathBuf::from("definitely/not/here/signtool.exe"));
        let err = signtool_path(&cfg).expect_err("must fail");
        assert!(err.to_string().contains("does not exist"), "{err}");
    }

    #[test]
    fn an_explicit_existing_signtool_is_used() {
        let path =
            std::env::temp_dir().join(format!("batesian_signtool_{}.exe", std::process::id()));
        std::fs::write(&path, b"stub").expect("write");
        let mut cfg = config("file");
        cfg.signtool = Some(path.clone());
        assert_eq!(signtool_path(&cfg).expect("resolve"), path);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn mode_none_is_a_no_op() {
        let exe = std::env::temp_dir().join("batesian_none.exe");
        let signature = sign(&exe, Some(&config("none"))).expect("no-op");
        assert!(signature.is_none());
    }
}
