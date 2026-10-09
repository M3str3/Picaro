//! `build.payloads.<name>.args`: the payload's command line.
//!
//! Metadata only (see [`crate::features`]). The block and the PEB patching live
//! in [`crate::engine::args`].

use crate::techniques::{ParamDef, ParamKind, Stability};

use super::{FeatureDef, FeatureScope};

/// Static metadata for payload arguments.
pub const DEF: FeatureDef = FeatureDef {
    name: "args",
    attck: &["T1036", "T1055"],
    stability: Stability::Stable,
    requires: &[],
    conflicts: &[],
    scope: FeatureScope::Payload,
    yaml: "build.payloads.<name>.args",
    doc_path: "src/features/args/README.md",
    readme: include_str!("README.md"),
    params: &[
        ParamDef {
            key: "args",
            description: "Arguments fixed at build time; each token is quoted per the Windows \
                          `CommandLineToArgvW` rules.",
            required: false,
            default: None,
            kind: ParamKind::List,
        },
        ParamDef {
            key: "args_mode",
            description: "`join` appends the runtime args to the YAML args; `override` lets the \
                          runtime args replace them.",
            required: false,
            default: Some("join"),
            kind: ParamKind::Enum(&["join", "override"]),
        },
    ],
    params_example: "args:\n  - privilege::debug\n  - log\nargs_mode: join\n",
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn def_is_well_formed() {
        assert_eq!(DEF.name, "args");
        assert_eq!(DEF.scope, FeatureScope::Payload);
        assert_eq!(DEF.stability, Stability::Stable);
        assert!(DEF.readme.starts_with("# "));
    }
}
