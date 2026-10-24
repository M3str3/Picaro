//! `build.stub.syscalls.stack_spoofing`: ntdll-shaped frames around every
//! syscall.
//!
//! Metadata only (see [`crate::features`]). The block, its parameters and the
//! rendering live in [`crate::engine::syscalls::stack_spoofing`]; it is a
//! property of the syscall layer, not a `runtime:` step.

use crate::techniques::{ParamDef, ParamKind, Stability};

use super::{FeatureDef, FeatureScope};

/// Static metadata for the stack-spoofing block.
pub const DEF: FeatureDef = FeatureDef {
    name: "stack_spoofing",
    attck: &["T1036"],
    stability: Stability::Stable,
    requires: &[crate::techniques::Capability::WindowsX64],
    conflicts: &[],
    scope: FeatureScope::Loader,
    yaml: "build.stub.syscalls.stack_spoofing",
    doc_path: "src/features/stack_spoofing/README.md",
    readme: include_str!("README.md"),
    params: &[ParamDef {
        key: "decoy_bytes",
        description: "Bytes of fabricated stack written below `Rsp` before every syscall, clamped \
                      to `0x80..=0x8000` and 16-byte aligned.",
        required: false,
        default: Some("0x1000"),
        kind: ParamKind::Str,
    }],
    params_example: "decoy_bytes: 4096\n",
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn def_is_well_formed() {
        assert_eq!(DEF.name, "stack_spoofing");
        assert_eq!(DEF.scope, FeatureScope::Loader);
        assert_eq!(DEF.stability, Stability::Stable);
        assert_eq!(DEF.attck, ["T1036"]);
        assert!(DEF
            .requires
            .contains(&crate::techniques::Capability::WindowsX64));
        assert_eq!(DEF.yaml, "build.stub.syscalls.stack_spoofing");
        assert!(DEF.readme.starts_with("# "));
    }
}
