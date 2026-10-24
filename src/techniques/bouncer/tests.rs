//! Tests for the bouncer gate technique.

use super::{
    glob_match, mask_v4, mask_v6, parse_cidr, Elevation, IntegrityLevel, OnReject, Params,
    ProcessCheck, ProcessState, RejectAction, Requirement, ANALYSIS_PATH_TOKENS,
    ANALYSIS_PROCESSES, DEF, HYPERVISOR_VENDOR_TOKENS,
};
use crate::audit::strings::{find_sensitive_literals_in_source, strip_comments};
use crate::engine::obfuscation::{StringStrategy, StringsConfig};
use crate::techniques::TechniqueKind;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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

fn parse_step(yaml: &str) -> Params {
    let step: TechniqueKind = serde_yml::from_str(yaml).expect("bouncer should parse");
    let TechniqueKind::Bouncer { params } = step else {
        panic!("expected a bouncer step");
    };
    params
}

#[test]
fn def_is_well_formed() {
    assert_eq!(DEF.name, "bouncer");
    assert_eq!(DEF.attck, &["T1497.001", "T1614.001", "T1033", "T1016"]);
    assert_eq!(DEF.category, crate::techniques::Category::Preparation);
    assert_eq!(DEF.stability, crate::techniques::Stability::Stable);
    assert!(DEF.conflicts.is_empty());
    assert!(!DEF.stub_fragment.is_empty());
    assert!(!DEF.readme.is_empty());
}

#[test]
fn defaults_declare_no_check_and_abort() {
    let step: TechniqueKind =
        serde_yml::from_str("technique: bouncer\n").expect("bouncer should parse");
    let TechniqueKind::Bouncer { params } = step else {
        panic!("expected a bouncer step");
    };
    assert_eq!(params, Params::default());
    assert_eq!(params.on_reject.action, RejectAction::Abort);
    assert!(params.on_reject.exit_code.is_none());
    assert!(params.on_reject.decoy.is_none());
    assert!(!params.anti_analysis.hypervisor);
    assert!(!params.anti_analysis.sandbox);
    assert!(!params.is_decoy());
    assert!(params.is_noop(), "an empty bouncer declares no check");
}

#[test]
fn parses_every_documented_field() {
    let params = full_params();
    assert_eq!(params.require.len(), 11);
    assert_eq!(params.any_of.len(), 2);
    assert!(params.anti_analysis.hypervisor);
    assert!(params.anti_analysis.sandbox);
    assert_eq!(params.on_reject.action, RejectAction::Decoy);
    assert_eq!(
        params
            .on_reject
            .decoy
            .as_ref()
            .map(|decoy| decoy.path.as_str()),
        Some("%TEMP%\\report.docx")
    );
    assert_eq!(
        params
            .on_reject
            .decoy
            .as_ref()
            .and_then(|decoy| decoy.payload.as_deref()),
        Some("decoy_doc")
    );
    assert!(params.is_decoy());
    assert!(!params.is_noop());
    params
        .validate()
        .expect("the documented example must validate");
}

#[test]
fn requirements_are_a_uniform_single_vote_list() {
    // Each entry is one requirement, so `any_of` no longer depends on the sign
    // of a check: every variant is a plain vote.
    let params = parse_step(
        "technique: bouncer\nparams:\n  require:\n    - hostname: \"WS-*\"\n    - ram_mb: 2048\n  any_of:\n    - locale: [en-US]\n    - keyboard: [\"0409\"]\n",
    );
    assert_eq!(
        params.require,
        vec![
            Requirement::Hostname("WS-*".to_string()),
            Requirement::RamMb(2048),
        ]
    );
    assert_eq!(
        params.any_of,
        vec![
            Requirement::Locale(vec!["en-US".to_string()]),
            Requirement::Keyboard(vec!["0409".to_string()]),
        ]
    );
    assert!(!params.is_noop());
}

#[test]
fn a_process_requirement_keeps_its_polarity() {
    let params = parse_step(
        "technique: bouncer\nparams:\n  require:\n    - process: { name: \"corp-agent\", state: present }\n",
    );
    assert_eq!(
        params.require,
        vec![Requirement::Process(ProcessCheck {
            name: "corp-agent".to_string(),
            state: ProcessState::Present,
        })]
    );
    assert!(!params.is_noop(), "a process requirement is a real check");
}

#[test]
fn ip_requirements_accept_both_families() {
    let params = parse_step(
        "technique: bouncer\nparams:\n  require:\n    - ip: [10.0.0.0/8, 192.168.1.0, fd00::/8, 2001:db8::1]\n",
    );
    let Requirement::Ip(cidrs) = &params.require[0] else {
        panic!("expected an IP requirement");
    };
    assert_eq!(cidrs.len(), 4);
    assert_eq!(
        parse_cidr("192.168.1.0"),
        Some(super::Cidr {
            prefix: 32,
            address: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)),
        })
    );
    assert_eq!(
        parse_cidr("2001:db8::1"),
        Some(super::Cidr {
            prefix: 128,
            address: IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1)),
        })
    );
    params.validate().expect("valid CIDRs must validate");
}

#[test]
fn cidr_masks_match_the_network() {
    assert_eq!(mask_v4(8), 0xff00_0000);
    assert_eq!(mask_v4(0), 0);
    assert_eq!(mask_v4(32), u32::MAX);
    assert_eq!(mask_v6(8), 0xff00_0000_0000_0000_0000_0000_0000_0000);
    assert_eq!(mask_v6(0), 0);
    assert_eq!(mask_v6(128), u128::MAX);

    assert_eq!(parse_cidr("10.0.0.0/33"), None);
    assert_eq!(parse_cidr("fd00::/129"), None);
    assert_eq!(parse_cidr("not-an-address"), None);
    assert_eq!(parse_cidr("10.0.0.0/nope"), None);
}

#[test]
fn validate_rejects_shapes_serde_accepts() {
    let empty_list = parse_step("technique: bouncer\nparams:\n  require:\n    - locale: []\n");
    assert!(empty_list.validate().is_err());

    let bad_cidr =
        parse_step("technique: bouncer\nparams:\n  require:\n    - ip: [\"10.0.0.0/99\"]\n");
    assert!(bad_cidr.validate().is_err());

    let empty_pattern =
        parse_step("technique: bouncer\nparams:\n  require:\n    - hostname: \" \"\n");
    assert!(empty_pattern.validate().is_err());
}

#[test]
fn validate_checks_the_rejection_policy() {
    let abort_with_code = parse_step(
        "technique: bouncer\nparams:\n  require: [{ ram_mb: 1 }]\n  on_reject: { action: abort, exit_code: 7 }\n",
    );
    assert!(abort_with_code.validate().is_err());

    let huge_code = parse_step(
        "technique: bouncer\nparams:\n  require: [{ ram_mb: 1 }]\n  on_reject: { action: exit, exit_code: 300 }\n",
    );
    assert!(huge_code.validate().is_err(), "exit codes are 0..=255");

    let decoy_without_asset = parse_step(
        "technique: bouncer\nparams:\n  require: [{ ram_mb: 1 }]\n  on_reject: { action: decoy }\n",
    );
    assert!(decoy_without_asset.validate().is_err());

    let decoy_on_abort = parse_step(
        "technique: bouncer\nparams:\n  require: [{ ram_mb: 1 }]\n  on_reject: { action: abort, decoy: { path: x, payload: p } }\n",
    );
    assert!(decoy_on_abort.validate().is_err());

    let decoy = parse_step(
        "technique: bouncer\nparams:\n  require: [{ ram_mb: 1 }]\n  on_reject: { action: decoy, decoy: { path: x, payload: p } }\n",
    );
    decoy.validate().expect("a decoy policy validates");
    assert!(decoy.is_decoy());
    assert!(!decoy.on_reject.exits_process());
}

#[test]
fn the_exit_policy_resolves_its_code() {
    let exit = OnReject {
        action: RejectAction::Exit,
        ..OnReject::default()
    };
    assert_eq!(exit.effective_exit_code(), 1);
    assert!(exit.exits_process());

    let decoy_zero = OnReject {
        action: RejectAction::Decoy,
        ..OnReject::default()
    };
    assert_eq!(decoy_zero.effective_exit_code(), 0);
    assert!(!decoy_zero.exits_process());

    let decoy_nonzero = OnReject {
        action: RejectAction::Decoy,
        exit_code: Some(4),
        ..OnReject::default()
    };
    assert_eq!(decoy_nonzero.effective_exit_code(), 4);
    assert!(decoy_nonzero.exits_process());
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
fn requirements_round_trip_as_single_key_maps() {
    // The wizard serializes the plan with `serde_yml`, which would render a
    // derived externally-tagged enum as a YAML tag (`!ip …`). The hand-written
    // impls keep the map form, which is what a human writes and what the
    // flattened `TechniqueKind` can read back.
    let requirement = Requirement::Ip(vec!["10.0.0.0/8".to_string()]);
    let yaml = serde_yml::to_string(&requirement).expect("serialize");
    assert!(yaml.contains("ip:"), "tagged form: {yaml}");
    let parsed: Requirement = serde_yml::from_str(&yaml).expect("deserialize");
    assert_eq!(parsed, requirement);

    let negated = Requirement::Not(Box::new(Requirement::Hostname("x".to_string())));
    let yaml = serde_yml::to_string(&negated).expect("serialize");
    assert!(yaml.contains("not:"), "tagged form: {yaml}");
    let parsed: Requirement = serde_yml::from_str(&yaml).expect("deserialize");
    assert_eq!(parsed, negated);

    assert!(
        serde_yml::from_str::<Requirement>("hostname: a\nusername: b\n").is_err(),
        "a requirement must have exactly one key"
    );
    assert!(serde_yml::from_str::<Requirement>("nope: a\n").is_err());
}

#[test]
fn render_fragment_substitutes_every_placeholder() {
    let fragment = full_params().render_fragment(&xor_strings());
    assert!(
        !fragment.contains('$'),
        "an unsubstituted placeholder would break the stub"
    );
    assert!(fragment.contains("pub fn bouncer()"));
    assert!(fragment.contains("const REQUIRE_NOT_HYPERVISOR: bool = true;"));
    assert!(fragment.contains("const REQUIRE_NOT_SANDBOX: bool = true;"));
    assert!(fragment.contains("const ON_REJECT_DECOY: bool = true;"));
    assert!(fragment.contains("const ON_REJECT_EXIT: bool = false;"));
    assert!(fragment.contains("fn glob_match("));
    assert!(fragment.contains("fn drop_decoy("));
    assert!(fragment.contains("fn local_addresses("));
    assert!(fragment.contains("fn token_is_elevated("));
    assert!(fragment.contains("fn privilege_enabled("));
    assert!(fragment.contains("require_declared += 1;"));
    assert!(fragment.contains("any_declared += 1;"));
    assert!(fragment.contains("!("), "the example declares a negation");
}

#[test]
fn a_requirement_can_be_negated() {
    let params = parse_step(
        "technique: bouncer\nparams:\n  require:\n    - not: { hostname: \"ANALYST-*\" }\n    - not: { ip: [\"10.0.0.0/8\"] }\n",
    );
    assert_eq!(
        params.require,
        vec![
            Requirement::Not(Box::new(Requirement::Hostname("ANALYST-*".to_string()))),
            Requirement::Not(Box::new(Requirement::Ip(vec!["10.0.0.0/8".to_string()]))),
        ]
    );
    params.validate().expect("negations validate");

    let fragment = params.render_fragment(&xor_strings());
    let code = strip_comments(&fragment);
    assert!(code.contains("!(glob_match("), "the negation is emitted");
    assert!(!code.contains("ANALYST-*"), "the pattern leaked");
    assert!(!code.contains("10.0.0.0/8"), "the CIDR leaked");
}

#[test]
fn nested_negation_and_invalid_inner_requirements_are_rejected() {
    let nested = parse_step(
        "technique: bouncer\nparams:\n  require:\n    - not: { not: { hostname: a } }\n",
    );
    assert!(nested.validate().is_err(), "`not` cannot wrap `not`");

    let invalid = parse_step(
        "technique: bouncer\nparams:\n  require:\n    - not: { ip: [\"10.0.0.0/99\"] }\n",
    );
    assert!(
        invalid.validate().is_err(),
        "validation must recurse into `not`"
    );
}

#[test]
fn render_fragment_bakes_in_the_rejection_policy() {
    let exit = parse_step(
        "technique: bouncer\nparams:\n  require: [{ ram_mb: 1 }]\n  on_reject: { action: exit, exit_code: 7 }\n",
    );
    let fragment = exit.render_fragment(&xor_strings());
    assert!(fragment.contains("const ON_REJECT_DECOY: bool = false;"));
    assert!(fragment.contains("const ON_REJECT_EXIT: bool = true;"));
    assert!(fragment.contains("const EXIT_CODE: i32 = 7;"));

    let abort = parse_step("technique: bouncer\nparams:\n  require: [{ ram_mb: 1 }]\n");
    let fragment = abort.render_fragment(&xor_strings());
    assert!(fragment.contains("const ON_REJECT_DECOY: bool = false;"));
    assert!(fragment.contains("const ON_REJECT_EXIT: bool = false;"));
    assert!(fragment.contains("const EXIT_CODE: i32 = 0;"));
}

#[test]
fn render_fragment_obfuscates_every_check_literal() {
    // Both strategies must keep the configured patterns and the built-in
    // environment names out of cleartext.
    let literals = [
        "WORKSTATION-*",
        "admin",
        "analyst*",
        "CORP",
        "en-US",
        "es-ES",
        "0409",
        "0C0A",
        "corp-agent.exe",
        "SeDebugPrivilege",
        "10.0.0.0/8",
        "fd00::/8",
        "%TEMP%\\report.docx",
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

#[test]
fn integrity_levels_report_their_rid() {
    assert_eq!(IntegrityLevel::Low.rid(), 0x1000);
    assert_eq!(IntegrityLevel::Medium.rid(), 0x2000);
    assert_eq!(IntegrityLevel::High.rid(), 0x3000);
    assert_eq!(IntegrityLevel::System.rid(), 0x4000);
}

#[test]
fn keyboard_requirements_accept_only_four_hex_digits() {
    for value in ["0409", "0x0409", "0X0C0A"] {
        let params = parse_step(&format!(
            "technique: bouncer\nparams:\n  require:\n    - keyboard: [\"{value}\"]\n"
        ));
        params.validate().expect("a four-digit KLID must validate");
    }

    for value in ["409", "abéc", "0409ab", "0409 x"] {
        let params = parse_step(&format!(
            "technique: bouncer\nparams:\n  require:\n    - keyboard: [\"{value}\"]\n"
        ));
        assert!(
            params.validate().is_err(),
            "'{value}' must not validate as a keyboard layout id"
        );
    }
}

#[test]
fn keyboard_normalization_stays_char_safe() {
    // The helper runs inside the generated stub, so this is a source-level
    // guard against reintroducing a byte-index slice, which panics on a
    // non-ASCII KLID such as "abéc".
    assert!(
        !DEF.stub_fragment.contains("text[text.len() - 4..]"),
        "normalize_klid must not slice a String by byte index"
    );
    assert!(
        DEF.stub_fragment.contains("text.chars().collect()"),
        "normalize_klid must normalize by characters"
    );
}

#[test]
fn elevation_parses_both_polarities() {
    let elevated =
        parse_step("technique: bouncer\nparams:\n  require:\n    - elevation: elevated\n");
    assert_eq!(
        elevated.require,
        vec![Requirement::Elevation(Elevation::Elevated)]
    );
    let unelevated =
        parse_step("technique: bouncer\nparams:\n  require:\n    - elevation: unelevated\n");
    assert_eq!(
        unelevated.require,
        vec![Requirement::Elevation(Elevation::Unelevated)]
    );
}
