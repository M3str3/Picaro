//! Tests for <technique name>.

use super::{Params, DEF};
use crate::techniques::PipelineStep;

// TODO: replace with real tests. At minimum:
//  1. the params YAML parses (with defaults and with explicit values);
//  2. `render_fragment` substitutes the placeholders;
//  3. `DEF` metadata is well-formed.

#[test]
fn def_is_well_formed() {
    assert!(!DEF.name.is_empty());
    assert!(!DEF.stub_fragment.is_empty());
    assert!(!DEF.readme.is_empty());
}

#[test]
fn params_example_parses() {
    let step: PipelineStep =
        serde_yml::from_str(DEF.params_example).expect("params_example should parse");
    // Ensure the variant round-trips.
    let _ = step;
}
