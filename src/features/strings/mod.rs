//! `build.stub.strings`: string obfuscation for the generated stub.
//!
//! Metadata only (see [`crate::features`]). The strategy and the rendering live
//! in [`crate::engine::obfuscation`].

use crate::techniques::{ParamDef, ParamKind, Stability};

use super::{FeatureDef, FeatureScope};

/// Static metadata for string obfuscation.
pub const DEF: FeatureDef = FeatureDef {
    name: "strings",
    attck: &["T1027"],
    stability: Stability::Stable,
    requires: &[],
    conflicts: &[],
    scope: FeatureScope::Loader,
    yaml: "build.stub.strings",
    doc_path: "src/features/strings/README.md",
    readme: include_str!("README.md"),
    params: &[
        ParamDef {
            key: "strategy",
            description: "`xor` XORs each literal with a 32-byte key and rebuilds it at runtime; \
                          `stack` emits one store per byte and needs no decoder.",
            required: false,
            default: Some("xor"),
            kind: ParamKind::Enum(&["xor", "stack"]),
        },
        ParamDef {
            key: "key",
            description:
                "`random` (per build) or `literal:<64 hex chars>` for a fixed 32-byte XOR \
                          key.",
            required: false,
            default: Some("random"),
            kind: ParamKind::Str,
        },
    ],
    params_example: "strategy: xor\nkey: random\n",
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn def_is_well_formed() {
        assert_eq!(DEF.name, "strings");
        assert_eq!(DEF.scope, FeatureScope::Loader);
        assert_eq!(DEF.stability, Stability::Stable);
        assert!(DEF.readme.starts_with("# "));
    }
}
