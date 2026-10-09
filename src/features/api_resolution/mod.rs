//! `build.stub.api_resolution`: how the loader resolves the payload's imports.
//!
//! Metadata only (see [`crate::features`]). The catalogue and the rendering live
//! in [`crate::engine::api_resolution`].

use crate::techniques::{Capability, ParamDef, ParamKind, Stability};

use super::{FeatureDef, FeatureScope};

/// Static metadata for the payload import proxy.
pub const DEF: FeatureDef = FeatureDef {
    name: "api_resolution",
    attck: &["T1106"],
    stability: Stability::Experimental,
    // The proxies are rebuilt on the syscall layer, which is x64-only, and they
    // live in the loader image, so only `reflective_loading` can use them.
    requires: &[Capability::WindowsX64],
    conflicts: &["process_hollowing"],
    scope: FeatureScope::Loader,
    yaml: "build.stub.api_resolution",
    doc_path: "src/features/api_resolution/README.md",
    readme: include_str!("README.md"),
    params: &[
        ParamDef {
            key: "mode",
            description: "`none` leaves import resolution untouched; `proxy` serves catalogue \
                          hits from proxies generated in the loader.",
            required: false,
            default: Some("none"),
            kind: ParamKind::Enum(&["none", "proxy"]),
        },
        ParamDef {
            key: "apis",
            description: "Catalogue entries to proxy, written as `dll!function` (the module side \
                          is normalized on lookup).",
            required: false,
            default: None,
            kind: ParamKind::List,
        },
        ParamDef {
            key: "unmatched",
            description: "What an import outside the catalogue does: `forward` resolves it \
                          normally, `abort` fails the load on the first one.",
            required: false,
            default: Some("forward"),
            kind: ParamKind::Enum(&["forward", "abort"]),
        },
    ],
    params_example: "mode: proxy\napis:\n  - \"kernel32!ReadProcessMemory\"\nunmatched: abort\n",
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn def_is_well_formed() {
        assert_eq!(DEF.name, "api_resolution");
        assert_eq!(DEF.scope, FeatureScope::Loader);
        assert_eq!(DEF.stability, Stability::Experimental);
        assert!(DEF.conflicts.contains(&"process_hollowing"));
        assert!(DEF.readme.starts_with("# "));
    }
}
