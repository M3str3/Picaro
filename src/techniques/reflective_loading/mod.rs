//! Reflective loading.
//!
//! Maps a PE into the current process (manual mapping) and runs its entry
//! point, so the payload executes without an external target process and
//! without touching disk. For a `format: shellcode` payload there is no image
//! to map, so the raw bytes are copied into an executable allocation and run
//! instead. See `README.md` for the full write-up.

use serde::{Deserialize, Serialize};

use crate::engine::obfuscation::StringsConfig;
use crate::plan::schema::PayloadFormat;

use super::{Capability, Category, Stability, TechniqueDef};

/// Parameters for reflective loading: which payload to load (the payload
/// format and export live in the payload's `build.payloads` entry).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Params {
    /// Name of the payload in `build.payloads` to load. Optional when the plan
    /// declares exactly one payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<String>,
}

/// Static metadata for reflective loading.
pub const DEF: TechniqueDef = TechniqueDef {
    name: "reflective_loading",
    attck: &["T1620"],
    stability: Stability::Experimental,
    requires: &[Capability::WindowsX64, Capability::WindowsX86],
    conflicts: &["process_hollowing"],
    category: Category::Execution,
    doc_path: "src/techniques/reflective_loading/README.md",
    stub_fragment: include_str!("stub_fragment.rs"),
    formats: &[
        super::PayloadFormat::Pe,
        super::PayloadFormat::Dll,
        super::PayloadFormat::Shellcode,
    ],
    requires_indirect_syscalls: false,
    params_example: "technique: reflective_loading\n",
    readme: include_str!("README.md"),
    // Allocation and page protection go through the syscall layer
    // (`nt_alloc_vm`/`nt_protect_vm`), so `mode: indirect` removes the
    // VirtualAlloc/VirtualProtect imports. `CreateThread` stays Win32
    // (`NtCreateThreadEx` takes eleven arguments — see the technique README).
    syscalls: &["NtAllocateVirtualMemory", "NtProtectVirtualMemory"],
    resolves_imports: true,
};

/// The shellcode format's fragment: the same technique, but a runner instead of
/// a PE mapper. Rendered when `build.payloads.<name>.format: shellcode`.
pub const SHELLCODE_FRAGMENT: &str = include_str!("stub_fragment_shellcode.rs");

impl Params {
    /// Renders the reflective-loading stub fragment (no per-build parameters,
    /// so `strings` is unused here).
    pub fn render_fragment(&self, _strings: &StringsConfig) -> String {
        DEF.stub_fragment.to_string()
    }

    /// Renders the fragment that matches the payload's binary format.
    ///
    /// `pe` and `dll` share the PE mapper; a DLL may additionally name an
    /// export to call (`build.payloads.<name>.export`, obfuscated through `strings`). A
    /// `shellcode` payload gets the raw-code runner instead.
    pub fn render_fragment_for(
        &self,
        strings: &StringsConfig,
        format: PayloadFormat,
        export: Option<&str>,
    ) -> String {
        if !format.is_pe_image() {
            return SHELLCODE_FRAGMENT.to_string();
        }

        let export_def = match export {
            Some(name) => format!(
                "Some({})",
                strings.obfuscate(name).render_stub_expr("dll_export")
            ),
            None => "None".to_string(),
        };
        self.render_fragment(strings)
            .replace("$DLL_EXPORT_DEF$", &export_def)
    }
}

#[cfg(test)]
mod tests;
