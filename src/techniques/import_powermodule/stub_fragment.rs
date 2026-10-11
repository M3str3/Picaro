// --- import_powermodule (psmodule-only) ---
//
// This technique is rendered in **C#** for a `build.output.kind: psmodule` build
// (`engine::managed::build_module`): the module is a managed assembly, not a Rust
// stub. This Rust fragment exists only so the registry entry is well-formed and
// the compile guardrail can build a stub for it; `plan::validate` rejects the
// technique outside a psmodule build, so it is never emitted into an artifact.
fn execute_payload(_image: &mut [u8]) -> Result<i32, String> {
    Err($MSG_PSMODULE_ONLY$.to_string())
}
