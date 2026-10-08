//! `build.stub.syscalls`: how the generated stub invokes the kernel.
//!
//! Metadata only (see [`crate::features`]). The configuration types and the
//! rendering live in [`crate::engine::syscalls`], which also owns the `Nt*`
//! catalogue and the SSN resolvers.

use crate::techniques::Stability;

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
