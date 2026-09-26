# Indirect Syscalls (Hell's Gate)

- Title: Indirect Syscalls (Hell's Gate)
- ATT&CK: T1106 (Native API)
- YAML key: `build.stub.syscalls.mode = indirect`
- Introduced in: phase 6a

## What it does

Replaces calls to suspicious Win32 APIs with NT syscalls whose SSN is resolved
at run time via Hell's Gate. The `syscall` instruction is executed through a
`syscall; ret` gadget inside `ntdll`, so it always appears to originate in
`ntdll` (not in private stub code), userland hooks in `ntdll` are bypassed, and
the stub's IAT no longer contains the suspicious imports.

This is not a pipeline technique: it is a loader configuration
(`build.stub.syscalls`), because it changes how the stub talks to the kernel,
not how the payload runs.

## YAML example

```yaml
build:
  stub:
    syscalls:
      mode: indirect      # none | indirect
      resolver: hells_gate  # hells_gate (tartarus_gate arrives in 6b)
```

Without the block the defaults are `mode: none`, `resolver: hells_gate`.

```yaml
# examples/configs/test-syscalls.yaml (abridged)
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
   `nt_unmap_view`). The stub template provides the `$SYSCALLS_BLOCK$` block
   with two implementations of each helper:
   - `mode: none`: a direct call to the Win32 API (`VirtualAllocEx`,
     `WriteProcessMemory`, `ReadProcessMemory`, `ResumeThread`; the unmap is
     resolved dynamically via `GetProcAddress` as before).
   - `mode: indirect`: a syscall through the `ntdll` gadget.

   The fragment does not know which mode is active: the code is identical in
   both.

2. **SSN resolution (Hell's Gate).** `init_syscalls()` runs once, before the
   techniques. For each Nt* function required by the build's techniques (the
   deduplicated union of `TechniqueDef::syscalls`):
   - its address in `ntdll` is obtained with `GetProcAddress` (the name is
     obfuscated with `StringsConfig` and rebuilt at run time);
   - the first 8 bytes of the stub are read;
   - the canonical prologue `4C 8B D1 B8 ?? ?? ?? ??`
     (`mov r10, rcx; mov eax, <SSN>`) is verified and the SSN is extracted from
     bytes 4..8.
   - If the prologue does not match (an EDR hook), `resolve_ssns` returns
     `PatternMismatch` with a clear message; Tartarus Gate (phase 6b) will
     handle it. If `GetProcAddress` fails, `FunctionNotFound`.

   Only the required functions are resolved: if a technique is not in the
   pipeline its SSNs are not resolved (less time, fewer strings).

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

   All return `NTSTATUS` (`i32`); fragments treat `< 0` as an error.

## What it evades

- Userland hooks in `ntdll` (EDR): the SSN is read from `ntdll` itself and the
  call reaches the kernel without passing through the hooked exported stub.
- Static IAT analysis: `VirtualAllocEx`, `WriteProcessMemory`,
  `ReadProcessMemory` and `ResumeThread` disappear from the import table; the
  `NtUnmapViewOfSection` string no longer appears in the binary (measured).

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
- **What happens if ntdll is hooked.** The prologue is no longer
  `mov r10, rcx; mov eax, <SSN>` and Hell's Gate cannot read the SSN: the stub
  fails with `PatternMismatch` (clear message). Tartarus Gate (phase 6b) will
  provide the fallback by scanning `ntdll`'s `.text` byte by byte, matching
  whole prologues (including neighbouring SSNs).
- Rendering is programmatic (`src/engine/syscalls.rs`): the block is assembled
  from `TechniqueDef::syscalls` (the union of the pipeline's requirements), so a
  new technique only declares its Nt* functions and its helpers are emitted if
  (and only if) they are needed.
- The Nt* names never reach the binary: they are rebuilt at run time via
  `StringsConfig` (as with `patch_amsi`). The
  `no_sensitive_literals_in_generated_stubs` guardrail covers these strings.
- Resolving SSNs by API hashing instead of `GetProcAddress` (so not even the
  obfuscated names are needed) remains a future direction.

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
