//! Tests for PowerShell hosting.

use super::{CommandMode, Mode, Params, DEF};
use crate::engine::obfuscation::StringsConfig;
use crate::techniques::RuntimeStep;

#[test]
fn def_is_well_formed() {
    assert_eq!(DEF.name, "powershell_hosting");
    assert!(!DEF.stub_fragment.is_empty());
    assert!(!DEF.readme.is_empty());
    assert_eq!(
        DEF.formats,
        &[crate::plan::schema::PayloadFormat::Powershell]
    );
}

#[test]
fn params_example_parses() {
    let step: RuntimeStep =
        serde_yml::from_str(DEF.params_example).expect("params_example should parse");
    assert_eq!(step.name(), "powershell_hosting");
}

#[test]
fn params_default_to_run_and_override() {
    let params: Params = serde_yml::from_str("{}").expect("empty params");
    assert_eq!(params.mode, Mode::Run);
    assert_eq!(params.command_mode, CommandMode::Override);
    assert!(params.command.is_none());
    assert!(params.payload.is_none());
}

#[test]
fn params_parse_explicit_values() {
    let params: Params = serde_yml::from_str(
        "payload: powerup\nmode: interactive\ncommand: Invoke-AllChecks\ncommand_mode: join\n",
    )
    .expect("explicit params");
    assert_eq!(params.payload.as_deref(), Some("powerup"));
    assert_eq!(params.mode, Mode::Interactive);
    assert_eq!(params.command.as_deref(), Some("Invoke-AllChecks"));
    assert_eq!(params.command_mode, CommandMode::Join);
}

#[test]
fn render_fragment_reuses_the_dotnet_hosting_block() {
    let strings = StringsConfig::from_yaml(None).expect("default strings");
    let params = Params {
        payload: Some("powerup".to_string()),
        ..Params::default()
    };
    let fragment = params.render_fragment(&strings);
    // The launcher is a managed assembly, so the fragment is the CLR host: it
    // must load an assembly from memory and run its entry point.
    assert!(fragment.contains("run_assembly"));
    assert!(fragment.contains("fn execute_payload"));
    // No cleartext CLR version reaches the rendered fragment.
    assert!(!fragment.contains("v4.0.30319"));
}
