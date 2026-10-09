//! `build.stub.syscalls`: how the generated stub invokes the kernel.
//!
//! Metadata only (see [`crate::features`]). The configuration types and the
//! rendering live in [`crate::engine::syscalls`], which also owns the `Nt*`
//! catalogue and the SSN resolvers.

use crate::techniques::{ParamDef, ParamKind, Stability};

use super::{FeatureDef, FeatureScope};

/// Static metadata for the syscall layer.
pub const DEF: FeatureDef = FeatureDef {
    name: "syscalls",
    attck: &["T1106"],
    stability: Stability::Stable,
    // `mode: none` is portable; only `mode: indirect` is x64-only (x86 indirect
    // syscalls are a parked workstream, see `docs/x86.md`).
    requires: &[],
    conflicts: &[],
    scope: FeatureScope::Loader,
    yaml: "build.stub.syscalls",
    doc_path: "src/features/syscalls/README.md",
    readme: include_str!("README.md"),
    params: &[
        ParamDef {
            key: "mode",
            description: "`none` maps the `nt_*` helpers to the Win32 APIs; `indirect` resolves \
                          SSNs at runtime and calls the kernel through the ntdll gadget.",
            required: false,
            default: Some("none"),
            kind: ParamKind::Enum(&["none", "indirect"]),
        },
        ParamDef {
            key: "resolver",
            description: "How `mode: indirect` learns each SSN: `hells_gate` reads the live ntdll \
                          stub, `tartarus_gate` a clean on-disk copy, `api_hash` matches exports \
                          by a precomputed FNV-1a hash.",
            required: false,
            default: Some("hells_gate"),
            kind: ParamKind::Enum(&["hells_gate", "tartarus_gate", "api_hash"]),
        },
    ],
    params_example: "mode: indirect\nresolver: hells_gate\n",
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn def_is_well_formed() {
        assert_eq!(DEF.name, "syscalls");
        assert_eq!(DEF.scope, FeatureScope::Loader);
        assert_eq!(DEF.stability, Stability::Stable);
        assert!(!DEF.attck.is_empty());
        assert!(DEF.readme.starts_with("# "));
    }
}
