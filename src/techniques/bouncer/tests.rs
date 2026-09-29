//! Tests for the bouncer gate technique.

use super::{
    glob_match, Mode, OnFail, Params, ANALYSIS_PATH_TOKENS, ANALYSIS_PROCESSES, DEF,
    HYPERVISOR_VENDOR_TOKENS,
};
use crate::audit::strings::{find_sensitive_literals_in_source, strip_comments};
use crate::engine::obfuscation::{StringStrategy, StringsConfig};
use crate::techniques::TechniqueKind;

/// A fully-populated parameter set, extracted from `DEF.params_example`.
fn full_params() -> Params {
    let step: TechniqueKind =
        serde_yml::from_str(DEF.params_example).expect("the params example must parse");
    let TechniqueKind::Bouncer { params } = step else {
        panic!("the params example must be a bouncer step");
    };
    params
}

fn xor_strings() -> StringsConfig {
    StringsConfig::from_yaml(None).expect("default strings")
}

fn stack_strings() -> StringsConfig {
    StringsConfig {
        strategy: StringStrategy::Stack,
        key: None,
    }
}

#[test]
fn def_is_well_formed() {
    assert_eq!(DEF.name, "bouncer");
    assert_eq!(DEF.attck, &["T1497.001", "T1614.001"]);
    assert_eq!(DEF.category, crate::techniques::Category::Preparation);
    assert_eq!(DEF.stability, crate::techniques::Stability::Experimental);
    assert!(DEF.conflicts.is_empty());
    assert!(!DEF.stub_fragment.is_empty());
    assert!(!DEF.readme.is_empty());
}

#[test]
fn defaults_are_all_and_silent() {
    let step: TechniqueKind =
        serde_yml::from_str("technique: bouncer\n").expect("bouncer should parse");
    let TechniqueKind::Bouncer { params } = step else {
        panic!("expected a bouncer step");
    };
    assert_eq!(params, Params::default());
    assert_eq!(params.mode, Mode::All);
    assert_eq!(params.on_fail, OnFail::Silent);
    assert!(params.is_noop(), "an empty bouncer declares no check");
}

#[test]
fn parses_every_documented_field() {
    let params = full_params();
    assert_eq!(params.mode, Mode::All);
    assert_eq!(params.on_fail, OnFail::Silent);
    assert_eq!(params.hostname.as_deref(), Some("WORKSTATION-*"));
    assert_eq!(params.username.as_deref(), Some("admin"));
    assert_eq!(params.domain.as_deref(), Some("CORP"));
    assert_eq!(params.language, ["en-US", "es-ES"]);
    assert_eq!(params.keyboard, ["0409", "0C0A"]);
    assert!(params.requires_not_in_vm());
    assert!(params.requires_not_in_sandbox());
    assert_eq!(params.min_uptime_min, Some(10));
    assert_eq!(params.min_ram_mb, Some(4096));
    assert!(!params.is_noop());
}

#[test]
fn a_false_vote_disables_the_check() {
    let step: TechniqueKind = serde_yml::from_str(
        "technique: bouncer\nparams:\n  not_in_vm: false\n  not_in_sandbox: false\n",
    )
    .expect("bouncer should parse");
    let TechniqueKind::Bouncer { params } = step else {
        panic!("expected a bouncer step");
    };
    assert!(!params.requires_not_in_vm());
    assert!(!params.requires_not_in_sandbox());
    assert!(
        params.is_noop(),
        "only `true` activates a check, so `false` is a no-op"
    );
}

#[test]
fn glob_matching_distinguishes_workstation_from_laptop() {
    assert!(glob_match("WORKSTATION-*", "WORKSTATION-01"));
    assert!(glob_match("WORKSTATION-*", "workstation-lab"));
    assert!(!glob_match("WORKSTATION-*", "LAPTOP-01"));
}

#[test]
fn glob_matching_is_case_insensitive_and_supports_question_mark() {
    assert!(glob_match("admin", "Admin"));
    assert!(glob_match("Admin", "admin"));
    assert!(glob_match("srv-0?", "SRV-09"));
    assert!(!glob_match("srv-0?", "SRV-109"));
    assert!(glob_match("*", "anything"));
    assert!(!glob_match("host", "host-extra"));
}

#[test]
fn mode_all_aborts_when_a_single_check_fails() {
    // Three checks declared, two pass: `all` rejects the host.
    assert!(!Mode::All.accepts(3, 2));
    assert!(Mode::All.accepts(3, 3));
    assert!(Mode::All.accepts(1, 1));
}

#[test]
fn mode_any_continues_when_a_single_check_passes() {
    assert!(Mode::Any.accepts(3, 1));
    assert!(!Mode::Any.accepts(3, 0));
    // Both modes continue when nothing is declared (the no-op contract).
    assert!(Mode::Any.accepts(0, 0));
    assert!(Mode::All.accepts(0, 0));
}

#[test]
fn render_fragment_substitutes_every_placeholder() {
    let fragment = full_params().render_fragment(&xor_strings());
    assert!(
        !fragment.contains('$'),
        "an unsubstituted placeholder would break the stub"
    );
    assert!(fragment.contains("pub fn bouncer()"));
    assert!(fragment.contains("const MODE_ALL: bool = true;"));
    assert!(fragment.contains("const ON_FAIL_EXIT: bool = false;"));
    assert!(fragment.contains("fn glob_match("));
}

#[test]
fn render_fragment_bakes_in_mode_and_on_fail() {
    let step: TechniqueKind = serde_yml::from_str(
        "technique: bouncer\nparams:\n  mode: any\n  on_fail: exit\n  hostname: \"h\"\n",
    )
    .expect("bouncer should parse");
    let TechniqueKind::Bouncer { params } = step else {
        panic!("expected a bouncer step");
    };
    let fragment = params.render_fragment(&xor_strings());
    assert!(fragment.contains("const MODE_ALL: bool = false;"));
    assert!(fragment.contains("const ON_FAIL_EXIT: bool = true;"));
}

#[test]
fn render_fragment_obfuscates_every_check_literal() {
    // Both strategies must keep the configured patterns and the built-in
    // environment names out of cleartext.
    let literals = [
        "WORKSTATION-*",
        "admin",
        "CORP",
        "en-US",
        "es-ES",
        "0409",
        "0C0A",
    ];
    let environment_names: Vec<&str> = ANALYSIS_PROCESSES
        .iter()
        .chain(ANALYSIS_PATH_TOKENS)
        .chain(HYPERVISOR_VENDOR_TOKENS)
        .copied()
        .collect();

    for strings in [xor_strings(), stack_strings()] {
        let fragment = full_params().render_fragment(&strings);
        // Doc comments legitimately mention examples; only the emitted *code*
        // must be free of the literals.
        let code = strip_comments(&fragment);
        for literal in literals.iter().chain(environment_names.iter()) {
            assert!(
                !code.contains(literal),
                "'{literal}' leaked in cleartext with strategy {}",
                strings.strategy.label()
            );
        }
    }
}

#[test]
fn rendered_fragment_has_no_sensitive_literals() {
    // The same guardrail the compiled-stub test applies, checked at the source
    // level so it runs without rustc.
    let fragment = full_params().render_fragment(&xor_strings());
    let leaked = find_sensitive_literals_in_source(&fragment);
    assert!(
        leaked.is_empty(),
        "the rendered fragment leaks sensitive literals: {leaked:?}"
    );
}

#[test]
fn fragment_has_no_forbidden_patterns() {
    for forbidden in [
        "println!",
        "eprintln!",
        "unwrap",
        "expect",
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
