# Syscall layer (indirect syscalls)

- ATT&CK: T1106 (Native API)
- YAML: `build.stub.syscalls.mode = indirect`
- Introduced in: phase 6a (Hell's Gate), 6b (Tartarus Gate) and 6c (API hashing)

## What it does

Replaces calls to suspicious Win32 APIs with NT syscalls whose SSN is resolved at
runtime. The `syscall` instruction executes from a `syscall; ret` gadget inside
`ntdll`, so it always appears to originate in `ntdll` (not in private stub code),
userland hooks in `ntdll` are bypassed, and the stub's IAT no longer contains the
suspicious imports.

It is not a pipeline technique: it is a loader configuration
(`build.stub.syscalls`), because it changes how the stub talks to the kernel, not
how the payload runs.

## Resolvers

- **Hell's Gate** (default) reads each SSN out of the Nt* stub prologue in the
  *live* `ntdll`. Fails with `PatternMismatch` when an EDR has hooked an export
  stub.
- **Tartarus Gate** reads each SSN from a clean copy of `ntdll` read from disk,
  so hooks in the live stubs do not hide the SSN. The gadget still comes from the
  live `ntdll`'s `.text`.
- **API hashing** (`resolver: api_hash`) walks the same clean copy but matches
  each function by a precomputed FNV-1a 64-bit hash of its name, so neither
  `GetProcAddress` nor any function-name string is needed.

## YAML

```yaml
build:
  stub:
    syscalls:
      mode: indirect        # none | indirect
      resolver: hells_gate  # hells_gate | tartarus_gate | api_hash
```

Without the block the defaults are `mode: none`, `resolver: hells_gate`:

```yaml
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
   `nt_unmap_view`, `nt_protect_vm`, `nt_suspend_thread`,
   `nt_query_info_process`, `nt_query_info_thread`, `nt_get_context_thread`,
   `nt_set_context_thread`, `nt_create_thread_ex`, `nt_wait_for_single_object`,
   `nt_close`) and never the Win32 APIs directly. `$SYSCALLS_BLOCK$` gives each
   helper two implementations — a direct Win32 call for `mode: none`, a syscall
   through the ntdll gadget for `mode: indirect` — so the fragment code is
   identical in both modes.
2. **SSN resolution.** `init_syscalls()` runs once, before the techniques, for
   the deduplicated union of the active pipeline's `TechniqueDef::syscalls`:
   - *Hell's Gate* resolves the address with `GetProcAddress`, reads the first 8
     bytes of the stub and verifies the canonical prologue
     `4C 8B D1 B8 ?? ?? ?? ??` (`mov r10, rcx; mov eax, <SSN>`), taking the SSN
     from bytes 4..8. A mismatch returns `PatternMismatch` pointing at
     `resolver: tartarus_gate`.
   - *Tartarus Gate* reads `C:\Windows\System32\ntdll.dll` from disk, walks the
     file's export directory to find each function's RVA, converts the RVA to a
     file offset via the section table and reads the prologue from the clean
     copy.
   - *API hashing* does the same walk but matches each function by its FNV-1a
     hash, embedded as a numeric constant, so the Nt* name never exists in the
     stub. The hash is mirrored in `engine::syscalls::api_hash` and the generated
     stub (kept in sync; unit-tested).
3. **The gadget.** The in-memory PE section table locates `.text`, which is
   scanned for the first `0F 05 C3` (`syscall; ret`).
4. **Trampoline (`nt_invoke`).** A `core::arch::global_asm!` shim with eleven
   argument slots plus the SSN and the gadget. `syscall` pushes no return
   address, so the kernel reads arguments 5+ from exactly the slots the Windows
   x64 ABI already put them in: the shim only sets `r10` (argument 1), `eax`
   (SSN) and `r11` (gadget) and `jmp`s, and the gadget's trailing `ret` returns
   straight to the Rust caller. Eleven slots is the widest call a technique
   needs (`NtCreateThreadEx`, which replaced `CreateRemoteThread`). Verified on
   `x86_64-pc-windows-msvc` (rustc 1.90) and with `-C target-feature=+crt-static`.
5. **Helpers.** Each `nt_*` helper wraps `nt_invoke` with the NT function's
   signature and returns `NTSTATUS` (`i32`); fragments treat `< 0` as an error.

## What it evades

- Userland hooks in `ntdll`: the call reaches the kernel without passing through
  the hooked exported stub.
- Static IAT analysis: `VirtualAllocEx`, `WriteProcessMemory`,
  `ReadProcessMemory`, `ResumeThread`, `Get`/`SetThreadContext`,
  `CreateRemoteThread`, `WaitForSingleObject`, `GetExitCodeProcess` and
  `CloseHandle` leave the import table, and the `NtUnmapViewOfSection` string no
  longer appears in the binary (measured in [Measurements](../measurements.md)).
- `GetProcAddress`-based resolution and name strings: with `resolver: api_hash`
  the stub never calls `GetProcAddress` for the Nt* functions and never contains
  their names — only the precomputed hash constants.

## What detects it

- Kernel callbacks (PsSetCreateProcessNotifyRoutine, ObRegisterCallbacks) and
  ETW-TI: the syscall is indistinguishable from a legitimate `ntdll` call.
- Stack inspection / stack-spoofing detectors (the call stack does not show
  `ntdll`): pending a future phase. Stack spoofing and unhooking are not
  implemented.
- SSN anomalies: signatures built from SSNs that change between Windows builds.

## Implementation notes

- **Why indirect over direct.** A direct syscall fails the syscall-origin check
  (the instruction must reside in a Microsoft-signed module); jumping to a
  `syscall; ret` gadget inside `ntdll` passes it.
- Rendering is programmatic (`src/engine/syscalls.rs`): a new technique only
  declares its Nt* functions in `TechniqueDef::syscalls`, and its helpers are
  emitted only when needed.
- The Nt* names never reach the binary: Hell's/Tartarus Gate rebuild them at
  runtime via `StringsConfig`; API hashing never emits them. The
  `no_sensitive_literals_in_generated_stubs` guardrail covers these strings.
- The FNV-1a hash is mirrored in the packer and the stub; the PE-file walk
  helpers (`rva_to_offset`, `pe16_at`, `pe32_at`) are shared between the Tartarus
  Gate and API-hashing resolvers via `$FILE_PE_HELPERS$`.

## References

- Hell's Gate (am0nsec, RtlMateusz — VX-Underground):
  https://vxug.fakedoma.in/papers/VXUG/Exclusive/HellsGate.pdf
- Tartarus' Gate (trickster0): https://github.com/trickster0/TartarusGate
- Direct vs indirect syscalls (Outflank):
  https://www.outflank.nl/blog/2023/12/13/direct-syscalls-vs-indirect-syscalls/
- Syscall detection / instrumentation callbacks (n4r1b):
  https://github.com/Deputation/instrumentation_callbacks
