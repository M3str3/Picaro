# Indirect Syscalls (Hell's Gate / Tartarus Gate / API hashing)

- Title: Indirect Syscalls (Hell's Gate / Tartarus Gate / API hashing)
- ATT&CK: T1106 (Native API)
- YAML key: `build.stub.syscalls.mode = indirect`
- Introduced in: phase 6a (Hell's Gate), phase 6b (Tartarus Gate),
  API hashing

## What it does

Replaces calls to suspicious Win32 APIs with NT syscalls whose SSN is resolved
at run time. Three resolvers exist:

- **Hell's Gate** reads each SSN out of the Nt* stub prologue in the *live*
  `ntdll`. It is the default and fails with a clear error when an EDR has hooked
  the export stub.
- **Tartarus Gate** reads each SSN from a clean copy of `ntdll` read from disk,
  so hooks in the live export stubs do not hide the SSN.
- **API hashing** (`resolver: api_hash`) matches each required function by a
  precomputed FNV-1a 64-bit hash of its name while walking a clean copy of
  `ntdll` read from disk, so neither `GetProcAddress` nor any function-name
  string is needed. The SSN is read from the clean prologue; the gadget still
  comes from the live `ntdll`.

The `syscall` instruction is executed through a `syscall; ret` gadget inside
`ntdll`, so it always appears to originate in `ntdll` (not in private stub
code), userland hooks in `ntdll` are bypassed, and the stub's IAT no longer
contains the suspicious imports.

This is not a pipeline technique: it is a loader configuration
(`build.stub.syscalls`), because it changes how the stub talks to the kernel,
not how the payload runs.

## YAML example

```yaml
build:
  stub:
    syscalls:
      mode: indirect      # none | indirect
      resolver: hells_gate  # hells_gate | tartarus_gate | api_hash
```

Without the block the defaults are `mode: none`, `resolver: hells_gate`.

```yaml
# indirect syscalls + process hollowing (abridged)
build:
  stub:
    syscalls:
      mode: indirect
      resolver: hells_gate
runtime:
  - technique: process_hollowing
    params:
      target: "C:\\Windows\\System32\\svchost.exe"
```

## How it works

1. **Fragment contract.** Technique fragments always call the `nt_*` helpers
   (`nt_alloc_vm`, `nt_write_vm`, `nt_read_vm`, `nt_resume_thread`,
   `nt_unmap_view`, `nt_protect_vm`, `nt_suspend_thread`, `nt_query_info_process`,
   `nt_get_context_thread`) and never the Win32 APIs directly. The stub template
   provides the `$SYSCALLS_BLOCK$` block with two implementations of each helper:
   - `mode: none`: a direct call to the Win32 API (`VirtualAllocEx`,
     `WriteProcessMemory`, `ReadProcessMemory`, `ResumeThread`; the Nt* functions
     `windows-rs` does not declare are resolved dynamically via `GetProcAddress`).
   - `mode: indirect`: a syscall through the `ntdll` gadget.

   The fragment does not know which mode is active: the code is identical in
   both.

2. **SSN resolution.** `init_syscalls()` runs once, before the techniques. For
   each Nt* function required by the build's techniques (the deduplicated union
   of `TechniqueDef::syscalls`):
   - **Hell's Gate** resolves the address with `GetProcAddress` (the name is
     obfuscated with `StringsConfig` and rebuilt at run time), reads the first 8
     bytes of the stub, and verifies the canonical prologue
     `4C 8B D1 B8 ?? ?? ?? ??` (`mov r10, rcx; mov eax, <SSN>`), extracting the
     SSN from bytes 4..8. If the prologue does not match (an EDR hook),
     `resolve_ssns` returns `PatternMismatch` with a message pointing at
     `resolver: tartarus_gate`.
   - **Tartarus Gate** reads `C:\Windows\System32\ntdll.dll` from disk, walks the
     file's export directory to find each function's RVA, converts the RVA to a
     file offset via the section table, and reads the same prologue from the
     clean copy. Hooks in the live ntdll cannot hide the SSN; the gadget still
     comes from the live ntdll's `.text` (which is not hooked).
   - **API hashing** reads the same clean copy from disk and walks its export
     directory, but matches each required function by a precomputed FNV-1a
     64-bit hash of its name instead of by name. The packer computes the hash at
     build time and embeds it as a numeric constant (`table.<x> =
     resolve_ssn(&file, 0x…)`), so the Nt* name never exists in the stub at all.
     The hash function is mirrored in the generated stub and in
     `engine::syscalls::api_hash` (kept in sync; unit-tested).

   Only the required functions are resolved: if a technique is not in the
   pipeline its SSNs are not resolved (less time, fewer strings or hashes).

3. **The `syscall; ret` gadget.** The ntdll image's PE section table is walked
   in memory to locate `.text`, which is scanned for the first `0F 05 C3`. Its
   address is stored as the gadget.

4. **ASM trampoline (`nt_invoke`).** On stable Rust this uses
   `core::arch::global_asm!` with an exported function. The Rust signature is:

   ```rust
   extern "system" {
       fn nt_invoke(
           arg1: usize, arg2: usize, arg3: usize, arg4: usize,
           arg5: usize, arg6: usize, ssn: u32, gadget: usize,
       ) -> i32; // NTSTATUS
   }
   ```

   Arguments 1-4 arrive in rcx/rdx/r8/r9; 5-8 on the caller's stack (`[rsp+40]`
   through `[rsp+64]`, after the return address and the 32-byte shadow space).
   The `syscall` expects: `r10` = arg1, `eax` = SSN, args 1-4 in the same
   registers, args 5-6 in `[rsp+8]`/`[rsp+16]` (with `rsp` pointing at the
   return address). The trampoline rearranges the frame and `jmp r11`s to the
   gadget; the gadget's `ret` returns straight to the Rust caller.

   ```asm
   nt_invoke:
       mov r10, rcx        ; r10 = arg1
       mov rax, [rsp + 40] ; rax = arg5
       mov [rsp + 8], rax  ; the syscall reads arg5 from [rsp+8]
       mov rax, [rsp + 48] ; rax = arg6
       mov [rsp + 16], rax ; the syscall reads arg6 from [rsp+16]
       mov eax, [rsp + 56] ; eax = SSN
       mov r11, [rsp + 64] ; r11 = gadget (syscall; ret)
       jmp r11
   ```

   Verified on `x86_64-pc-windows-msvc` (rustc 1.90) and with
   `-C target-feature=+crt-static`; LLVM's integrated assembler accepts
   `.intel_syntax noprefix` on both Windows targets.

5. **Helpers.** Each helper wraps `nt_invoke` with the NT function's signature:

   - `nt_alloc_vm(process, &base, zero_bits, &size, alloc_type, protect)`
   - `nt_write_vm(process, base, buf, size, &written)`
   - `nt_read_vm(process, base, buf, size, &read)`
   - `nt_resume_thread(thread, &previous_count)`
   - `nt_unmap_view(process, base)`
   - `nt_protect_vm(process, base, size, new_protect, &old_protect)`
   - `nt_suspend_thread(thread, &previous_count)`
   - `nt_query_info_process(process, info_class, info, info_len, &return_len)`
   - `nt_get_context_thread(thread, &context)`

   All return `NTSTATUS` (`i32`); fragments treat `< 0` as an error.

## What it evades

- Userland hooks in `ntdll` (EDR): the SSN is read from `ntdll` itself and the
  call reaches the kernel without passing through the hooked exported stub.
- Static IAT analysis: `VirtualAllocEx`, `WriteProcessMemory`,
  `ReadProcessMemory` and `ResumeThread` disappear from the import table; the
  `NtUnmapViewOfSection` string no longer appears in the binary (measured).
- `GetProcAddress`-based resolution and name strings: with `resolver: api_hash`
  the stub never calls `GetProcAddress` for the Nt* functions and never contains
  their names (not even obfuscated) — only the precomputed hash constants.

## What detects it

- Kernel callbacks (PsSetCreateProcessNotifyRoutine, ObRegisterCallbacks) and
  ETW-TI: the syscall is indistinguishable from a legitimate `ntdll` call.
- Syscall-origin checks: with indirect calls the instruction already points into
  `ntdll`, which is exactly what this method fixes relative to direct syscalls.
- Stack inspection / stack-spoofing detectors (the call stack does not show
  `ntdll`): pending a future phase.
- SSN anomalies (signatures built from SSNs that change between Windows builds).

## Measurements

See `docs/measurements/phase6a_iat_reduction.md`: the before/after IAT with
`batesian audit`, sizes, and confirmation that the Nt* strings do not appear in
the binary.

## Implementation notes

- **Why indirect over direct.** A direct syscall (`syscall` in our own code) is
  caught by the syscall-origin check (the instruction must reside in a
  Microsoft-signed module). By jumping to a `syscall; ret` gadget inside
  `ntdll`, the instruction originates in `ntdll` and that check is passed.
- **What happens if ntdll is hooked.** Hell's Gate reads the SSN from the
  export stub's prologue; a hook (an EDR `jmp`) replaces `mov r10, rcx; mov eax,
  <SSN>` and the stub fails with `PatternMismatch`. Tartarus Gate and API hashing
  sidestep this entirely by reading the SSN from a clean, unhooked copy of ntdll
  read from disk, and only use the live ntdll for the `syscall; ret` gadget.
- Rendering is programmatic (`src/engine/syscalls.rs`): the block is assembled
  from `TechniqueDef::syscalls` (the union of the pipeline's requirements), so a
  new technique only declares its Nt* functions and its helpers are emitted if
  (and only if) they are needed.
- The Nt* names never reach the binary: Hell's/Tartarus Gate rebuild them at run
  time via `StringsConfig` (as with `patch_amsi`); API hashing never emits them
  at all, embedding only the precomputed hashes. The
  `no_sensitive_literals_in_generated_stubs` guardrail covers these strings.
- The FNV-1a 64-bit hash is mirrored in the packer (`engine::syscalls::api_hash`)
  and in the generated stub; the PE-file walk helpers (`rva_to_offset`, `pe16_at`,
  `pe32_at`) are shared between the Tartarus Gate and API-hashing resolvers via
  the `$FILE_PE_HELPERS$` fragment.

## References

- Hell's Gate (am0nsec, RtlMateusz — VX-Underground):
  https://vxug.fakedoma.in/papers/VXUG/Exclusive/HellsGate.pdf
- Tartarus' Gate (trickster0):
  https://github.com/trickster0/TartarusGate
- Direct syscalls: a journey from high to low (Dylan Tran, Outflank):
  https://outflank.nl/blog/2020/12/26/direct-syscalls-in-beacon-object-files/
- Direct syscalls vs indirect syscalls (Outflank):
  https://www.outflank.nl/blog/2023/12/13/direct-syscalls-vs-indirect-syscalls/
- Syscall detection / instrumentation callbacks (n4r1b):
  https://github.com/Deputation/instrumentation_callbacks
