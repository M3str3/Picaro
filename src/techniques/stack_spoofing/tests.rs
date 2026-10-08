//! Tests for stack spoofing.

use super::{default_decoy_bytes, Params, DEF, MAX_DECOY_BYTES, MESSAGES, MIN_DECOY_BYTES};
use crate::engine::obfuscation::StringsConfig;
use crate::techniques::{Capability, Category, TechniqueKind};

/// Renders the block with the default (obfuscating) string strategy.
fn render(params: &Params) -> String {
    let strings = StringsConfig::from_yaml(None).expect("default strings");
    params.render_fragment(&strings)
}

#[test]
fn parses_params_from_empty_yaml() {
    let step: TechniqueKind =
        serde_yml::from_str("technique: stack_spoofing\n").expect("stack_spoofing should parse");
    assert_eq!(
        step,
        TechniqueKind::StackSpoofing {
            params: Params::default()
        }
    );
}

#[test]
fn defaults_to_a_page_of_decoy() {
    assert_eq!(default_decoy_bytes(), 0x1000);
    assert_eq!(Params::default().decoy_bytes, 0x1000);
}

#[test]
fn def_is_well_formed() {
    assert_eq!(DEF.name, "stack_spoofing");
    assert_eq!(DEF.category, Category::Preparation);
    assert_eq!(DEF.attck, ["T1036"]);
    assert_eq!(DEF.requires, [Capability::WindowsX64]);
    assert!(
        DEF.syscalls.is_empty(),
        "the technique replaces the trampoline instead of adding syscalls of its own"
    );
    assert!(!DEF.stub_fragment.is_empty());
    assert!(!DEF.readme.is_empty());
}

#[test]
fn the_block_replaces_the_trampoline() {
    assert!(
        DEF.stub_fragment.contains("\".global nt_invoke\""),
        "the block must define the symbol the nt_* helpers call"
    );
    assert!(
        DEF.stub_fragment.contains("jmp nt_invoke_raw"),
        "the raw trampoline has to stay reachable under its renamed symbol"
    );
    assert!(
        DEF.stub_fragment.contains("fn nt_invoke("),
        "the Rust side needs the declaration with the trampoline's signature"
    );
}

#[test]
fn every_placeholder_is_substituted() {
    let block = render(&Params::default());
    assert!(
        !block.contains('$'),
        "unsubstituted placeholder in the rendered block"
    );
    assert!(!block.contains("MSG_"), "a message placeholder survived");
}

#[test]
fn every_diagnostic_is_obfuscated() {
    let block = render(&Params::default());
    for (placeholder, text) in MESSAGES {
        assert!(
            !DEF.stub_fragment.contains(text),
            "cleartext diagnostic for {placeholder} in the fragment"
        );
        assert!(
            !block.contains(text),
            "cleartext diagnostic for {placeholder} in the rendered block"
        );
    }
}

#[test]
fn the_decoy_size_is_clamped_and_rendered() {
    let custom = Params {
        decoy_bytes: 0x2000,
    };
    assert!(render(&custom).contains("sub rsp, 8192"));

    // Below the minimum the frames would overlap the copied arguments.
    let tiny = Params { decoy_bytes: 8 };
    assert_eq!(tiny.clamped_decoy_bytes(), MIN_DECOY_BYTES);
    assert!(render(&tiny).contains("sub rsp, 128"));

    // Above the maximum every syscall would rewrite half a stack.
    let huge = Params {
        decoy_bytes: usize::MAX,
    };
    assert_eq!(huge.clamped_decoy_bytes(), MAX_DECOY_BYTES);
    assert!(render(&huge).contains("sub rsp, 32768"));

    // The shift must keep the stack 16-byte aligned.
    let odd = Params {
        decoy_bytes: 0x1_0001,
    };
    assert_eq!(odd.clamped_decoy_bytes() % 16, 0);
}

#[test]
fn the_arguments_are_copied_to_their_new_offsets() {
    let block = render(&Params::default());
    for offset in [40, 48, 56, 64, 72, 80, 88, 96, 104] {
        assert!(
            block.contains(&format!("mov [rsp + {offset}], r10"))
                && block.contains(&format!("mov r10, [rbx + {offset}]")),
            "argument at [rsp+{offset}] must be copied down with the stack"
        );
    }
}

#[test]
fn the_syscall_argument_registers_are_never_clobbered() {
    // rcx/rdx/r8/r9 carry arguments 1-4 into the kernel; the spoof may only use
    // registers the trampoline sets afterwards (rax, r10, r11) and rbx.
    let block = render(&Params::default());
    let asm = block
        .split(".intel_syntax noprefix")
        .nth(1)
        .expect("the asm block must be present");
    for register in ["rcx", "rdx", "r8", "r9"] {
        assert!(
            !asm.contains(&format!("[{register} +")),
            "{register} carries a syscall argument and must not be used as scratch"
        );
    }
}

#[test]
fn the_register_holding_the_return_address_is_saved_and_restored() {
    let block = render(&Params::default());
    assert!(block.contains("mov [rip + SPOOF_RBX], rbx"));
    assert!(
        block.contains("mov rbx, [rip + SPOOF_RBX]"),
        "the restore label must put the caller's rbx back"
    );
    assert!(
        block.contains("mov rsp, [rip + SPOOF_STACK]"),
        "the restore label must put the caller's stack pointer back"
    );
}

#[test]
fn the_restore_label_returns_the_status_untouched() {
    let block = render(&Params::default());
    let restore = block
        .split("picaro_spoof_restore:\",")
        .nth(1)
        .expect("the restore label must be in the asm");
    assert!(
        !restore.contains("xor eax") && !restore.contains("mov eax"),
        "eax carries the NTSTATUS back to the helper and must survive the restore"
    );
}

#[test]
fn fragment_has_no_forbidden_patterns() {
    for forbidden in [
        "anyhow",
        "static mut",
        "println!",
        "eprintln!",
        "unwrap(",
        "expect(",
        "todo!",
        "unimplemented!",
        "panic!",
    ] {
        assert!(
            !DEF.stub_fragment.contains(forbidden),
            "the fragment must not use {forbidden}"
        );
    }
}
