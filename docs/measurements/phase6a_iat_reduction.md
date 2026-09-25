# Indirect syscalls — phase 6a IAT reduction

Static audit before/after: the process-hollowing stub with
`build.stub.syscalls.mode = none` (baseline) vs `mode = indirect` (Hell's Gate).

## Binaries

- Before: `dist/test_packed.exe` (`examples/configs/test-hollowing.yaml`,
  process hollowing, `build.stub.syscalls` absent → default `none`)
- After: `dist/test_syscalls.exe` (`examples/configs/test-syscalls.yaml`,
  process hollowing, `build.stub.syscalls.mode = indirect`)

## Config (YAML delta)

```yaml
# test-syscalls.yaml (the only difference vs test-hollowing.yaml)
build:
  stub:
    syscalls:
      mode: indirect
      resolver: hells_gate
```

## Sizes

| Binary          | Size     |
|-----------------|----------|
| before (none)   | 517 632  |
| after (indirect)| 525 312  |

Delta: +7 680 bytes (the SSN table, resolver and trampoline; the Win32 import
thunks that disappeared were smaller than the layer that replaced them).

## IAT before/after

| Import             | Before | After |
|--------------------|--------|-------|
| VirtualAllocEx     | yes    | no    |
| WriteProcessMemory | yes    | no    |
| ReadProcessMemory  | yes    | no    |
| ResumeThread       | yes    | no    |
| CreateProcessA     | yes    | yes   |
| GetThreadContext   | yes    | yes   |
| SetThreadContext   | yes    | yes   |
| WaitForSingleObject| yes    | yes   |
| GetExitCodeProcess | yes    | yes   |
| LoadLibraryA       | yes    | yes   |
| GetProcAddress     | yes    | yes   |
| GetModuleHandleA   | yes    | yes   |
| CloseHandle        | yes    | yes   |

- Before: `5 dlls · 105 functions`, 2 suspicious imports
  (`VirtualAllocEx`, `WriteProcessMemory`).
- After: `5 dlls · 101 functions`, `✓ IAT looks minimal` (0 suspicious).

The table is the phase 6a snapshot. Later work removed the stub's `user32`
dependency entirely (`MessageBoxA`): the stub marker is now printed to stderr
instead of shown in a dialog, so current builds link one fewer import.

The four flagged imports are gone; everything the stub still calls from
userland stays (out of scope for 6a). `GetThreadContext`/`SetThreadContext`/
`WaitForSingleObject`/`GetExitCodeProcess` migrate in a later phase, as does
`reflective_loading` (`VirtualAlloc`, `VirtualProtect`, `CreateThread`,
`WaitForSingleObject` — untouched in 6a; `test_amsi_patch.exe` is byte-for-byte
identical in behavior).

## Strings scan

- Before: `apis by name 1` — `NtUnmapViewOfSection` (the dynamically-resolved
  export name; already obfuscated, but still flagged by the audit scan).
- After: `apis by name 0`. The unmap now goes through the syscall layer
  (SSN-resolved), so the name string disappears entirely.

Sensitive scan (`Sensitive:` line): `ntdll.dll` in both — a known toolchain
false positive (`windows-result` embeds it; see AGENTS.md), unrelated to the
stub's code.

## NT names in the final binary

```
strings dist/test_syscalls.exe | grep -E "Nt(AllocateVirtualMemory|WriteVirtualMemory|ReadVirtualMemory|ResumeThread|UnmapViewOfSection)"
→ (no output)
```

None of the five NT function names appears in the binary (they are
reconstructed at runtime via `StringsConfig`; the guardrail test
`no_sensitive_literals_in_generated_stubs` enforces this).

## Runtime verification

- `cargo test -- --ignored` passes on Windows: the indirect stub initializes
  the syscall layer, and every `nt_*` call in the hollowing flow returns
  `STATUS_SUCCESS` (unmap, alloc, write, read, resume; remote write verified
  by reading `MZ` back from the target process). The stub then hands off to
  the payload.
- Note: on this host the hollowed svchost crashes running the test payload
  (exit code `0xC0000005` relayed by the stub). The **pristine
  pre-phase-6a baseline crashes identically** (verified against `git stash`),
  so it is a pre-existing process-hollowing limitation on this machine
  (payload import table is never resolved in the hollowed process), not an
  effect of the syscall layer. Both modes produce identical behavior.

## Defender

`batesian audit` Defender scan was skipped/unavailable in this session
(`hr = 0x80508023`) because Windows Defender was disabled on the test machine.
