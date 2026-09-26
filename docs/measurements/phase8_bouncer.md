# Phase 8 — bouncer (static baseline and runtime gate)

## Scope

Static and runtime measurement of the `bouncer` Preparation technique
(`src/techniques/bouncer/`), added in phase 8. The static numbers compare the
same packed payload with and without the gate; the runtime result shows the gate
blocking or allowing the payload.

- Host: the Windows x64 development machine (rustc 1.90, msvc).
- Anchor: `reflective_loading` with no Preparation technique.

## Configs used

- Baseline: `examples/configs/test-reflective.yaml`
  (`reflective_loading`).
- Host name only: `examples/configs/test-bouncer.yaml`
  (`bouncer` with `hostname: "*"` → `reflective_loading`).
- Full: `examples/configs/test-bouncer-full.yaml`
  (`bouncer` with every check declared → `reflective_loading`).
- Never matches: `examples/configs/test-bouncer-miss.yaml`
  (`bouncer` with `hostname: "batesian-no-such-host-*"`).

All use `strings.strategy: xor`, `syscalls.mode: none` and the same
`examples/payloads/test_payload.exe`.

## Size

| Build | Output | Size |
|-------|--------|------|
| baseline | `dist/test_packed_reflective.exe` | 514,560 B (503 KB) |
| bouncer, host name only | `dist/test_bouncer.exe` | 542,720 B (530 KB) |
| bouncer, every check | `dist/test_bouncer_full.exe` | ~571 KB |

The host-name-only gate adds ~28 KB (the `bouncer` module plus `GetComputerNameW`).
The full gate adds ~56 KB over the baseline.

## Imports

| Build | DLLs | Functions |
|-------|------|-----------|
| baseline | 3 | 96 |
| bouncer, host name only | 3 | 97 |
| bouncer, every check | 5 | 109 |

The full gate adds 13 imports and two DLLs (`user32.dll`, `advapi32.dll`):

- `kernel32.dll`: `GetComputerNameW`, `GetComputerNameExW`, `GetUserNameW`,
  `GetUserDefaultLocaleName`, `GetTickCount64`, `GetSystemInfo`,
  `CreateToolhelp32Snapshot`, `Process32FirstW`, `Process32NextW`,
  `GlobalMemoryStatusEx`.
- `user32.dll`: `GetKeyboardLayout`, `GetKeyboardLayoutList`,
  `GetKeyboardLayoutNameW`.
- `advapi32.dll` (one function, `GetUserNameW`).

This import set is the technique's most observable static signature (see the
README's "What detects it").

## Strings

`batesian audit dist/test_bouncer_full.exe --focus strings` reports
`sensitive 0`, `total flagged 0`. A direct byte scan of the packed binary finds
none of the check literals in cleartext:

```
WORKSTATION- admin CORP en-US es-ES 0409 0C0A        → 0 hits each
vboxservice vmwaretray vmtoolsd wireshark procmon
x64dbg x32dbg sandbox malware analysis               → 0 hits each
VMwareVMware VBoxVBoxVBox KVMKVMKVM XenVMMXenVMM
TCGTCGTCGTCG                                          → 0 hits each
```

## Runtime gate

`batesian build` + run, on the Windows host:

| Config | Host matches? | Payload marker on stdout | Result |
|--------|---------------|--------------------------|--------|
| `test-bouncer-miss.yaml` | no | absent | gate aborts, exit code 0 (silent) |
| `test-bouncer.yaml` | yes | present (`PAYLOAD_MARKER_7f3a9c2e`) | payload runs |

Automated by `tests/cli.rs::bouncer_gate_blocks_and_allows_on_windows`
(`cargo test -- --ignored`, Windows only) and
`tests/cli.rs::build_with_bouncer_produces_pe`.

## Guardrail

`engine::compiler::tests::no_sensitive_literals_in_generated_stubs`
(`cargo test --bin batesian -- --ignored`) compiles a stub for `bouncer` and
passes with the new `SENSITIVE_LITERALS` entries (`vboxservice`, `vmwaretray`,
`vmtoolsd`, `wireshark`, `procmon`, `x64dbg`, `x32dbg`, `sandbox`, `malware`,
`analysis`).

## Date

- 2026-09-26
