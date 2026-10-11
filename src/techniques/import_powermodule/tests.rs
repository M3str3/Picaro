//! Tests for importing a PowerShell module.

use super::{Params, DEF};
use crate::engine::obfuscation::StringsConfig;
use crate::techniques::RuntimeStep;

#[test]
fn def_is_well_formed() {
    assert_eq!(DEF.name, "import_powermodule");
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
    assert_eq!(step.name(), "import_powermodule");
}

#[test]
fn params_default_to_no_payload() {
    let params: Params = serde_yml::from_str("{}").expect("empty params");
    assert!(params.payload.is_none());
}

#[test]
fn render_fragment_is_the_psmodule_placeholder() {
    let strings = StringsConfig::from_yaml(None).expect("default strings");
    let fragment = Params::default().render_fragment(&strings);
    assert!(fragment.contains("fn execute_payload"));
    // The diagnostic text is obfuscated: the plaintext never reaches the fragment
    // (its comment still names the build kind, which is not a runtime literal).
    assert!(!fragment.contains("runs only in a"));
}
