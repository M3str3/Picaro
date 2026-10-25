//! Authenticode signing of the packed artifact.
//!
//! Signing is the last build step (it hashes the artifact), and it is fully
//! optional. Three modes:
//!
//! - `lab` — an automatic **certificate authority + leaf** pair: a self-signed
//!   CA (`<subject> Root CA`) and a code-signing certificate signed by it. Both
//!   are created on first use and reused afterwards, and the CA's public
//!   certificate is exported next to the artifact (`<stem>.ca.cer`) so the lab
//!   can trust it. Nothing is added to the local trust stores: signing does not
//!   change this machine's trust. This is a lab identity: it gives no SmartScreen
//!   reputation.
//! - `store` — a certificate already in the current user's store, matched by
//!   `thumbprint` or `subject`. This reads the *Windows* certificate store, so it
//!   is only available on Windows.
//! - `file` — a `.pfx`/`.p12` file; the password is read from the environment
//!   variable named by `password_env`, never from the YAML.
//!
//! Two backends can sign, and the same plan works on either:
//!
//! - **`signtool.exe`** (Windows SDK) — the native tool on Windows. It also
//!   reads the certificate store, which is what `mode: store` needs.
//! - **`osslsigncode`** — a portable Authenticode signer built on OpenSSL. It
//!   lets the same build sign on Linux, including inside the Docker image where
//!   no Windows SDK exists. The `lab` identity is generated with `openssl`.
//!
//! [`locate_signer`] picks a backend: an explicit `output.sign.signtool` path,
//! then `signtool.exe` (PATH, `PICARO_SIGNTOOL`, Windows Kits), then
//! `osslsigncode` (PATH). `mode: store` always needs `signtool`, because only it
//! (or Windows itself) knows about the certificate store.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};

use crate::paths::find_in_path;
use crate::plan::schema::SignPlan;

/// Subject used by `mode: lab` when none is configured.
const DEFAULT_LAB_SUBJECT: &str = "CN=picaro lab code signing";

/// X.509 extensions applied to the generated code-signing leaf certificate.
const LEAF_EXTENSIONS: &str = "\
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=critical,codeSigning
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
";

/// Signing error.
#[derive(Debug, thiserror::Error)]
pub enum SigningError {
    /// `signtool.exe` could not be located.
    #[error(
        "`signtool.exe` was not found ({0}); install the Windows SDK (Visual Studio) \
         or set `output.sign.signtool`"
    )]
    SigntoolNotFound(String),
    /// No signing backend (neither `signtool` nor `osslsigncode`) is available.
    #[error("no signing backend was found ({0})")]
    NoSignerFound(String),
    /// `mode: store` was requested off Windows.
    #[error(
        "`output.sign.mode: store` reads the Windows certificate store, which only \
         exists on Windows; inside a container use `mode: file` (a .pfx) or `mode: lab`"
    )]
    StoreRequiresWindows,
    /// An external tool was not found on `PATH`.
    #[error("`{tool}` was not found on PATH; install it (Debian: `apt-get install {package}`)")]
    ToolMissing {
        /// Tool name (without the `.exe` suffix).
        tool: String,
        /// Distribution package that provides it.
        package: String,
    },
    /// An external tool could not be started.
    #[error("could not run `{tool}`: {source}")]
    ToolFailed {
        /// Tool that failed to start.
        tool: String,
        #[source]
        source: std::io::Error,
    },
    /// An external tool ran but failed.
    #[error("`{tool}` failed:\n{stderr}")]
    CommandFailed {
        /// Tool that ran.
        tool: String,
        /// Combined stdout+stderr of the failed run.
        stderr: String,
    },
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
    /// Filesystem failure while writing signing material or the signed artifact.
    #[error("signing I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// What was used to sign the artifact (recorded in the build manifest).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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

/// The Authenticode backend that will sign the artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Backend {
    /// `signtool.exe` (Windows SDK).
    Signtool,
    /// `osslsigncode` (portable, OpenSSL based).
    Osslsigncode,
}

/// The signing tool that will be used, and where it is.
///
/// Returned by [`locate_signer`] so a dry run can report what would sign without
/// running anything.
#[derive(Debug, Clone)]
pub struct Signer {
    /// Human label for the backend (`signtool` or `osslsigncode`).
    pub label: &'static str,
    /// Resolved path to the tool.
    pub path: PathBuf,
    /// Which backend this is.
    backend: Backend,
}

/// Signs `exe` according to `plan`.
///
/// `None` or `mode: none` is a no-op and returns `Ok(None)`.
pub fn sign(exe: &Path, plan: Option<&SignPlan>) -> Result<Option<Signature>, SigningError> {
    let Some(plan) = plan else {
        return Ok(None);
    };
    if plan.mode == "none" {
        return Ok(None);
    }
    match plan.mode.as_str() {
        "lab" | "store" | "file" => {}
        other => {
            return Err(SigningError::Certificate(format!(
                "unknown sign mode '{other}'"
            )))
        }
    }

    let signer = locate_signer(plan)?;
    let signature = match signer.backend {
        Backend::Signtool => sign_with_signtool(exe, plan, &signer.path)?,
        Backend::Osslsigncode => sign_with_osslsigncode(exe, plan, &signer.path)?,
    };
    Ok(Some(signature))
}

/// Resolves the backend that will sign `plan`, without signing anything.
///
/// This is the order (see the module docs): an explicit `output.sign.signtool`
/// path, then `signtool.exe`, then `osslsigncode`. `mode: store` requires the
/// store, so it always resolves to `signtool` and fails clearly off Windows.
pub fn locate_signer(plan: &SignPlan) -> Result<Signer, SigningError> {
    if plan.mode == "store" {
        if !cfg!(windows) {
            return Err(SigningError::StoreRequiresWindows);
        }
        let path = find_signtool(plan)?.ok_or_else(|| {
            SigningError::SigntoolNotFound(
                "not in PATH and no Windows 10/11 SDK was found under 'Windows Kits\\10\\bin'"
                    .to_string(),
            )
        })?;
        return Ok(Signer {
            label: "signtool",
            path,
            backend: Backend::Signtool,
        });
    }

    if let Some(path) = find_signtool(plan)? {
        return Ok(Signer {
            label: "signtool",
            path,
            backend: Backend::Signtool,
        });
    }
    if let Some(path) = find_in_path(osslsigncode_name()) {
        return Ok(Signer {
            label: "osslsigncode",
            path,
            backend: Backend::Osslsigncode,
        });
    }
    Err(SigningError::NoSignerFound(
        "install the Windows SDK (signtool.exe) or osslsigncode \
         (Debian: `apt-get install osslsigncode`)"
            .to_string(),
    ))
}

/// Finds `signtool.exe`: an explicit path (error if it does not exist), then
/// `PICARO_SIGNTOOL`, then `PATH`, then the Windows Kits directories.
///
/// `Ok(None)` means "not found", so the caller can fall back to `osslsigncode`.
fn find_signtool(plan: &SignPlan) -> Result<Option<PathBuf>, SigningError> {
    if let Some(path) = &plan.signtool {
        if path.is_file() {
            return Ok(Some(path.clone()));
        }
        return Err(SigningError::SigntoolNotFound(format!(
            "'{}' does not exist",
            path.display()
        )));
    }
    if let Some(from_env) = std::env::var_os("PICARO_SIGNTOOL") {
        let path = PathBuf::from(from_env);
        if path.is_file() {
            return Ok(Some(path));
        }
    }
    if let Some(path) = find_in_path("signtool.exe") {
        return Ok(Some(path));
    }
    Ok(find_in_windows_kits())
}

/// The `osslsigncode` executable name (`osslsigncode.exe` on Windows).
fn osslsigncode_name() -> &'static str {
    if cfg!(windows) {
        "osslsigncode.exe"
    } else {
        "osslsigncode"
    }
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

/// Signs with `signtool.exe` (the Windows-native backend).
fn sign_with_signtool(exe: &Path, plan: &SignPlan, tool: &Path) -> Result<Signature, SigningError> {
    let mut args: Vec<String> = vec!["sign".to_string()];
    let mut signature = Signature {
        mode: plan.mode.clone(),
        subject: plan.subject.clone(),
        issuer: None,
        thumbprint: None,
        ca_file: None,
        timestamp_url: plan.timestamp_url.clone(),
    };

    match plan.mode.as_str() {
        "lab" => {
            let subject = plan
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
            let thumbprint = resolve_store_cert(plan)?;
            args.push("/sha1".to_string());
            args.push(thumbprint.clone());
            signature.thumbprint = Some(thumbprint);
        }
        "file" => {
            let file = plan.file.as_ref().ok_or(SigningError::MissingPfx)?;
            args.push("/f".to_string());
            args.push(path_str(file));
            if let Some(var) = &plan.password_env {
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
    if let Some(url) = &plan.timestamp_url {
        args.push("/tr".to_string());
        args.push(url.clone());
        args.push("/td".to_string());
        args.push("SHA256".to_string());
    }
    args.push(path_str(exe));

    run_tool(tool, &args)?;
    Ok(signature)
}

/// The certificate material handed to `osslsigncode`.
enum Credentials {
    /// A PKCS#12 container plus its password (possibly empty).
    Pkcs12 { file: PathBuf, password: String },
    /// A PEM certificate (leaf, optionally followed by the CA) plus its key.
    Pem { certs: PathBuf, key: PathBuf },
}

/// Signs with `osslsigncode` (the portable backend).
fn sign_with_osslsigncode(
    exe: &Path,
    plan: &SignPlan,
    tool: &Path,
) -> Result<Signature, SigningError> {
    let mut signature = Signature {
        mode: plan.mode.clone(),
        subject: plan.subject.clone(),
        issuer: None,
        thumbprint: None,
        ca_file: None,
        timestamp_url: plan.timestamp_url.clone(),
    };

    let credentials = match plan.mode.as_str() {
        "lab" => {
            let subject = plan
                .subject
                .clone()
                .unwrap_or_else(|| DEFAULT_LAB_SUBJECT.to_string());
            let identity = ensure_lab_identity(exe, &subject)?;
            // Export the CA (public, DER) next to the artifact so the lab can
            // trust it; the private key never leaves the state directory.
            let ca_file = ca_export_path(exe);
            std::fs::copy(&identity.ca_cert, &ca_file)?;
            signature.subject = Some(subject);
            signature.issuer = Some(identity.ca_subject.clone());
            signature.thumbprint = Some(identity.thumbprint.clone());
            signature.ca_file = Some(ca_file.display().to_string());
            Credentials::Pem {
                certs: identity.chain,
                key: identity.key,
            }
        }
        "file" => {
            let file = plan.file.clone().ok_or(SigningError::MissingPfx)?;
            Credentials::Pkcs12 {
                file,
                password: read_password(plan)?,
            }
        }
        other => {
            return Err(SigningError::Certificate(format!(
                "sign mode '{other}' is not supported by osslsigncode"
            )))
        }
    };

    // `osslsigncode` cannot sign in place, so sign to a sibling and swap it in.
    let out = signed_temp_path(exe);
    let _ = std::fs::remove_file(&out);
    let args = osslsigncode_args(plan, exe, &out, &credentials);
    if let Err(error) = run_tool(tool, &args) {
        let _ = std::fs::remove_file(&out);
        return Err(error);
    }
    std::fs::rename(&out, exe)?;
    Ok(signature)
}

/// Builds the `osslsigncode sign` argument vector.
///
/// Kept separate from the process call so it can be asserted without a tool.
fn osslsigncode_args(
    plan: &SignPlan,
    exe: &Path,
    out: &Path,
    credentials: &Credentials,
) -> Vec<String> {
    let mut args: Vec<String> = vec!["sign".to_string()];
    match credentials {
        Credentials::Pkcs12 { file, password } => {
            args.push("-pkcs12".to_string());
            args.push(path_str(file));
            args.push("-pass".to_string());
            args.push(password.clone());
        }
        Credentials::Pem { certs, key } => {
            args.push("-certs".to_string());
            args.push(path_str(certs));
            args.push("-key".to_string());
            args.push(path_str(key));
        }
    }
    args.push("-h".to_string());
    args.push("sha256".to_string());
    if let Some(url) = &plan.timestamp_url {
        // `-ts` is an RFC 3161 timestamp, matching the plan's `timestamp_url`.
        args.push("-ts".to_string());
        args.push(url.clone());
    }
    args.push("-in".to_string());
    args.push(path_str(exe));
    args.push("-out".to_string());
    args.push(path_str(out));
    args
}

/// Reads the `.pfx` password from `password_env`, or an empty string when none
/// is configured (an unencrypted `.pfx`), never from the YAML.
fn read_password(plan: &SignPlan) -> Result<String, SigningError> {
    match &plan.password_env {
        Some(var) => std::env::var(var).map_err(|_| SigningError::PasswordEnv(var.clone())),
        None => Ok(String::new()),
    }
}

/// The lab CA + leaf identity persisted on disk (the `osslsigncode` backend).
struct LabIdentity {
    /// PEM file with the leaf certificate followed by the CA certificate.
    chain: PathBuf,
    /// PEM file with the leaf private key.
    key: PathBuf,
    /// The CA public certificate in DER (`.cer`).
    ca_cert: PathBuf,
    /// The CA subject, recorded in the manifest as the issuer.
    ca_subject: String,
    /// SHA-1 thumbprint of the leaf certificate.
    thumbprint: String,
}

/// Creates (once) or reuses the lab CA + leaf identity for `subject`, using
/// `openssl`, and returns the paths needed to sign with `osslsigncode`.
///
/// The identity is persisted under a per-subject directory so repeated builds
/// reuse the same CA (the lab only installs `<stem>.ca.cer` once). In the Docker
/// image that directory lives under the mounted work directory, so it survives
/// across runs.
fn ensure_lab_identity(exe: &Path, subject: &str) -> Result<LabIdentity, SigningError> {
    let dir = lab_state_dir(exe, subject);
    let ca_key = dir.join("ca.key");
    let ca_pem = dir.join("ca.pem");
    let ca_der = dir.join("ca.der");
    let leaf_key = dir.join("leaf.key");
    let leaf_pem = dir.join("leaf.pem");
    let leaf_chain = dir.join("leaf-chain.pem");
    let leaf_csr = dir.join("leaf.csr");
    let leaf_ext = dir.join("leaf.ext");

    let leaf_subject = ensure_cn(subject);
    let ca_subject = format!("{leaf_subject} Root CA");

    let complete = ca_key.is_file()
        && ca_pem.is_file()
        && ca_der.is_file()
        && leaf_key.is_file()
        && leaf_pem.is_file()
        && leaf_chain.is_file();
    if !complete {
        std::fs::create_dir_all(&dir)?;
        restrict_dir(&dir);
        generate_lab_identity(
            &ca_key,
            &ca_pem,
            &ca_der,
            &leaf_key,
            &leaf_pem,
            &leaf_chain,
            &leaf_csr,
            &leaf_ext,
            &dir.join("ca.srl"),
            &leaf_subject,
            &ca_subject,
        )?;
        let _ = std::fs::remove_file(&leaf_csr);
        let _ = std::fs::remove_file(&leaf_ext);
        let _ = std::fs::remove_file(dir.join("ca.srl"));
        restrict_file(&ca_key);
        restrict_file(&leaf_key);
    }

    let thumbprint = cert_sha1_fingerprint(&leaf_pem)?;
    Ok(LabIdentity {
        chain: leaf_chain,
        key: leaf_key,
        ca_cert: ca_der,
        ca_subject,
        thumbprint,
    })
}

/// Runs the `openssl` commands that create the CA, the leaf and the DER export.
#[allow(clippy::too_many_arguments)]
fn generate_lab_identity(
    ca_key: &Path,
    ca_pem: &Path,
    ca_der: &Path,
    leaf_key: &Path,
    leaf_pem: &Path,
    leaf_chain: &Path,
    leaf_csr: &Path,
    leaf_ext: &Path,
    ca_serial: &Path,
    leaf_subject: &str,
    ca_subject: &str,
) -> Result<(), SigningError> {
    let openssl = Path::new("openssl");

    // Self-signed CA: it may sign certificates and has no key-usage ambiguity.
    run_capture(
        openssl,
        &strings([
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-sha256",
            "-days",
            "1825",
            "-keyout",
            &path_str(ca_key),
            "-out",
            &path_str(ca_pem),
            "-subj",
            &openssl_subject(ca_subject),
            "-addext",
            "basicConstraints=critical,CA:TRUE,pathlen:1",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign,digitalSignature",
            "-addext",
            "subjectKeyIdentifier=hash",
        ]),
    )?;

    // Leaf key + CSR.
    run_capture(
        openssl,
        &strings([
            "req",
            "-new",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-sha256",
            "-keyout",
            &path_str(leaf_key),
            "-out",
            &path_str(leaf_csr),
            "-subj",
            &openssl_subject(leaf_subject),
        ]),
    )?;

    // Sign the CSR with the CA, applying the code-signing extensions.
    std::fs::write(leaf_ext, LEAF_EXTENSIONS)?;
    run_capture(
        openssl,
        &strings([
            "x509",
            "-req",
            "-in",
            &path_str(leaf_csr),
            "-CA",
            &path_str(ca_pem),
            "-CAkey",
            &path_str(ca_key),
            "-CAcreateserial",
            // `-CAcreateserial` would write `ca.srl` into the current directory;
            // pin it to the state directory instead.
            "-CAserial",
            &path_str(ca_serial),
            "-days",
            "730",
            "-sha256",
            "-extfile",
            &path_str(leaf_ext),
            "-out",
            &path_str(leaf_pem),
        ]),
    )?;

    // The chain file `osslsigncode -certs` expects: leaf first, then the CA.
    let mut chain = std::fs::read(leaf_pem)?;
    chain.extend_from_slice(&std::fs::read(ca_pem)?);
    std::fs::write(leaf_chain, chain)?;

    // The CA in DER, exported next to the artifact as `<stem>.ca.cer`.
    run_capture(
        openssl,
        &strings([
            "x509",
            "-in",
            &path_str(ca_pem),
            "-outform",
            "der",
            "-out",
            &path_str(ca_der),
        ]),
    )?;
    Ok(())
}

/// The SHA-1 thumbprint of a PEM certificate, via `openssl x509 -fingerprint`.
fn cert_sha1_fingerprint(cert: &Path) -> Result<String, SigningError> {
    let out = run_capture(
        Path::new("openssl"),
        &strings([
            "x509",
            "-in",
            &path_str(cert),
            "-noout",
            "-fingerprint",
            "-sha1",
        ]),
    )?;
    let value = out
        .lines()
        .find_map(|line| line.split_once('=').map(|(_, value)| value.trim()))
        .ok_or_else(|| {
            SigningError::Certificate("could not read the certificate fingerprint".to_string())
        })?;
    Ok(normalize_thumbprint(value))
}

/// The persistent lab identity directory for `subject`.
///
/// `PICARO_SIGN_DIR` overrides the default, which is
/// `<artifact dir>/.picaro/lab/<slug>` — under the mounted work directory in the
/// container, so the CA is reused across runs.
fn lab_state_dir(exe: &Path, subject: &str) -> PathBuf {
    let base = match std::env::var_os("PICARO_SIGN_DIR") {
        Some(dir) => PathBuf::from(dir),
        None => artifact_dir(exe).join(".picaro").join("lab"),
    };
    base.join(identity_slug(subject))
}

/// A filesystem-safe slug for `subject` (`"CN=Acme"` → `"cn-acme"`).
fn identity_slug(subject: &str) -> String {
    let mut slug = String::new();
    for ch in subject.chars() {
        if ch.is_ascii_alphanumeric() {
            slug.push(ch.to_ascii_lowercase());
        } else if !slug.ends_with('-') {
            slug.push('-');
        }
    }
    let slug = slug.trim_matches('-').to_string();
    if slug.is_empty() {
        "lab".to_string()
    } else {
        slug
    }
}

/// The directory holding `exe` (or `.` when it has no parent).
fn artifact_dir(exe: &Path) -> PathBuf {
    match exe.parent().filter(|p| !p.as_os_str().is_empty()) {
        Some(dir) => dir.to_path_buf(),
        None => PathBuf::from("."),
    }
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

/// The temporary file `osslsigncode` writes before it is swapped in.
fn signed_temp_path(exe: &Path) -> PathBuf {
    let name = exe
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("artifact");
    artifact_dir(exe).join(format!(".{name}.picaro-signed"))
}

/// `path` as a string for a tool argument (non-UTF-8 paths are not supported by
/// the external signers anyway).
fn path_str(path: &Path) -> String {
    path.display().to_string()
}

/// Collects string slices into an owned argument vector.
fn strings<const N: usize>(items: [&str; N]) -> Vec<String> {
    items.iter().map(|item| (*item).to_string()).collect()
}

/// Converts an RFC 4514 subject (`CN=Acme, O=Acme Inc`) into the
/// slash-separated form `openssl -subj` expects (`/CN=Acme/O=Acme Inc`).
fn openssl_subject(dn: &str) -> String {
    let mut out = String::new();
    for rdn in dn.split(',') {
        let rdn = rdn.trim();
        if rdn.is_empty() {
            continue;
        }
        out.push('/');
        out.push_str(&rdn.replace('/', "\\/"));
    }
    out
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
fn resolve_store_cert(plan: &SignPlan) -> Result<String, SigningError> {
    let script = if let Some(thumbprint) = &plan.thumbprint {
        let thumbprint = escape_single_quotes(thumbprint);
        format!(
            "$c = Get-ChildItem Cert:\\CurrentUser\\My \
             | Where-Object {{ $_.Thumbprint -eq '{thumbprint}' }} | Select-Object -First 1; \
             if ($c) {{ $c.Thumbprint }}"
        )
    } else {
        let subject = escape_single_quotes(plan.subject.as_deref().unwrap_or(""));
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
            plan.thumbprint
                .as_deref()
                .map(|t| format!("thumbprint {t}"))
                .unwrap_or_else(|| format!("subject '{}'", plan.subject.as_deref().unwrap_or("")))
        )));
    }
    Ok(normalize_thumbprint(&found))
}

/// Runs a PowerShell snippet and returns its trimmed stdout.
fn powershell(script: &str) -> Result<String, SigningError> {
    run_capture(
        Path::new("powershell"),
        &strings([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ]),
    )
}

/// Runs `tool` with `args`, mapping a non-zero exit to a clear error.
fn run_tool(tool: &Path, args: &[String]) -> Result<(), SigningError> {
    let output = Command::new(tool)
        .args(args)
        .output()
        .map_err(|source| tool_failed(tool, source))?;
    if !output.status.success() {
        return Err(SigningError::CommandFailed {
            tool: tool.display().to_string(),
            stderr: combine(&output),
        });
    }
    Ok(())
}

/// Runs `tool` with `args` and returns its trimmed stdout.
fn run_capture(tool: &Path, args: &[String]) -> Result<String, SigningError> {
    let output = Command::new(tool)
        .args(args)
        .output()
        .map_err(|source| tool_failed(tool, source))?;
    if !output.status.success() {
        return Err(SigningError::CommandFailed {
            tool: tool.display().to_string(),
            stderr: combine(&output),
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Maps a failed process spawn to the right error (a missing tool gets a hint
/// about the package that provides it).
fn tool_failed(tool: &Path, source: std::io::Error) -> SigningError {
    if source.kind() == std::io::ErrorKind::NotFound {
        let name = tool
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("tool")
            .trim_end_matches(".exe")
            .to_string();
        return SigningError::ToolMissing {
            tool: name.clone(),
            package: name,
        };
    }
    SigningError::ToolFailed {
        tool: tool.display().to_string(),
        source,
    }
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

/// Restricts a directory to the owner (`0700` on Unix).
#[cfg(unix)]
fn restrict_dir(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700));
}

/// Restricts a directory to the owner (a no-op off Unix).
#[cfg(not(unix))]
fn restrict_dir(_path: &Path) {}

/// Restricts a file to the owner (`0600` on Unix).
#[cfg(unix)]
fn restrict_file(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}

/// Restricts a file to the owner (a no-op off Unix).
#[cfg(not(unix))]
fn restrict_file(_path: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(mode: &str) -> SignPlan {
        SignPlan {
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
    fn a_subject_is_converted_to_the_openssl_format() {
        assert_eq!(openssl_subject("CN=Acme"), "/CN=Acme");
        assert_eq!(
            openssl_subject("CN=Acme, O=Acme Inc"),
            "/CN=Acme/O=Acme Inc"
        );
    }

    #[test]
    fn the_identity_slug_is_filesystem_safe() {
        assert_eq!(
            identity_slug("CN=picaro lab code signing"),
            "cn-picaro-lab-code-signing"
        );
        assert_eq!(identity_slug("CN=Acme, O=Acme Inc"), "cn-acme-o-acme-inc");
        // A subject with nothing usable still maps to a directory name.
        assert_eq!(identity_slug("==="), "lab");
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
    fn the_lab_state_lives_beside_the_artifact() {
        assert_eq!(
            lab_state_dir(Path::new("dist/widget.exe"), "CN=Acme"),
            PathBuf::from("dist/.picaro/lab/cn-acme")
        );
    }

    #[test]
    fn the_signed_temp_file_is_a_hidden_sibling() {
        assert_eq!(
            signed_temp_path(Path::new("dist/widget.exe")),
            PathBuf::from("dist/.widget.exe.picaro-signed")
        );
        assert_eq!(
            signed_temp_path(Path::new("widget.exe")),
            PathBuf::from("./.widget.exe.picaro-signed")
        );
    }

    #[test]
    fn osslsigncode_arguments_cover_hash_timestamp_and_io() {
        let mut cfg = plan("file");
        cfg.timestamp_url = Some("http://timestamp.example/".to_string());
        let mut args = osslsigncode_args(
            &cfg,
            Path::new("in.exe"),
            Path::new(".in.exe.signed"),
            &Credentials::Pkcs12 {
                file: PathBuf::from("cert.pfx"),
                password: "pw".to_string(),
            },
        );

        assert_eq!(args.remove(0), "sign");
        let joined = args.join(" ");
        assert!(joined.contains("-pkcs12 cert.pfx"), "{joined}");
        assert!(joined.contains("-pass pw"), "{joined}");
        assert!(joined.contains("-h sha256"), "{joined}");
        assert!(joined.contains("-ts http://timestamp.example/"), "{joined}");
        assert!(joined.contains("-in in.exe"), "{joined}");
        assert!(joined.contains("-out .in.exe.signed"), "{joined}");
    }

    #[test]
    fn osslsigncode_uses_pem_credentials_for_the_lab() {
        let cfg = plan("lab");
        let args = osslsigncode_args(
            &cfg,
            Path::new("in.exe"),
            Path::new("out.exe"),
            &Credentials::Pem {
                certs: PathBuf::from("leaf-chain.pem"),
                key: PathBuf::from("leaf.key"),
            },
        );
        let joined = args.join(" ");
        assert!(joined.contains("-certs leaf-chain.pem"), "{joined}");
        assert!(joined.contains("-key leaf.key"), "{joined}");
        assert!(!joined.contains("-ts"), "no timestamp was configured");
    }

    #[test]
    fn an_explicit_missing_signtool_is_reported() {
        let mut cfg = plan("file");
        cfg.signtool = Some(PathBuf::from("definitely/not/here/signtool.exe"));
        let err = find_signtool(&cfg).expect_err("must fail");
        assert!(err.to_string().contains("does not exist"), "{err}");
    }

    #[test]
    fn an_explicit_existing_signtool_is_used() {
        let path = std::env::temp_dir().join(format!("picaro_signtool_{}.exe", std::process::id()));
        std::fs::write(&path, b"stub").expect("write");
        let mut cfg = plan("file");
        cfg.signtool = Some(path.clone());
        assert_eq!(find_signtool(&cfg).expect("resolve"), Some(path.clone()));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn mode_none_is_a_no_op() {
        let exe = std::env::temp_dir().join("picaro_none.exe");
        let signature = sign(&exe, Some(&plan("none"))).expect("no-op");
        assert!(signature.is_none());
    }
}
