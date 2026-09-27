# Measurements

Point-in-time static and dynamic results for the evasion phases, plus the one EDR
report so far. These are snapshots from the phase that produced them, not a
description of the current tree: the plans named inside were the ones in use at
the time and have since been consolidated into `examples/plans/` and
`tests/plans/`. Reproduce any number with `picaro audit <binary>` (add
`--baseline <report.json>` to compare against a saved run).

## Summary

| Phase | Build (baseline → measured) | Key result |
| --- | --- | --- |
| 5 | process hollowing, before string obfuscation | marker + target hidden by a hardcoded XOR; risk MEDIUM (2 suspicious imports, 3 toolchain path strings) |
| 6 | string obfuscation `xor` / `stack` | no static change vs. phase 5; obfuscation is formal, per-string, configurable |
| 6 | sleep obfuscation (ekko) | 487 → 505 KB; only `CreateEventW` + `VirtualQuery` added |
| 6a | indirect syscalls | suspicious imports 2 → 0; `NtUnmapViewOfSection` string gone |
| 7 | ETW patch + anti-debug | 499 → 505 KB; `+CheckRemoteDebuggerPresent`, `+GetThreadContext` |
| 8 | bouncer | 503 KB → 530 KB (host only) / ~571 KB (full); literals stay obfuscated |
| EDR | CrowdStrike Falcon | hollowing blocked at runtime (partial) |

## Phase 5 — static baseline (process hollowing)

Before formal string obfuscation, the stub hid its two sensitive literals
(`STUB_MARKER_<hex>` and the hollowing target) with a hardcoded XOR key `0x5A`.

- Size 1,598,976 B; `.rdata` 339 KB, entropy 6.81.
- `STUB_MARKER` and `system32` absent from `strings`.
- Static risk MEDIUM (2 suspicious imports, 3 flagged strings — all debug-info
  paths from the `windows`/`getrandom` crates, unrelated to the literals).

## Phase 6 — string obfuscation (`xor` / `stack`)

Same build with `build.stub.strings` active.

- `xor`: 1,598,464 B; `stack`: 1,600,512 B. `.rdata` unchanged (339 KB, 6.81).
- Neither `STUB_MARKER` nor `system32` appears in `strings` under either
  strategy — identical to the phase 5 baseline, which already XORed.
- The marker/target are a rounding error next to the XChaCha20 payload
  ciphertext, so the feature's value is that it is per-string, keyed per build
  and configurable, and that `stack` ships a no-decoder variant.
- Caveat: the first `stack` build leaked a literal prefix
  (`STUB_MARKER_`, `C:\Windows\Syste`) because LLVM constant-folded the byte
  stores; each store is now wrapped in `std::hint::black_box`
  (`src/engine/obfuscation.rs::render_stack_expr`).

## Phase 6 — sleep obfuscation (ekko)

`reflective_loading` with and without `sleep_obfuscation`, same stub template and
payload.

- 487 KB → 505 KB (+18 KB, mostly `.text`); entropy unchanged (`.text` 6.27 →
  6.25, `.rdata` 7.26 → 7.25).
- Only two imports added: `CreateEventW` (completion event) and `VirtualQuery`
  (the image-run walk). The timer-queue family, `NtContinue`,
  `RtlCaptureContext` and `SystemFunction032` are resolved at runtime.
- Strings scan clean (`sensitive 0`, `technique names 0`, `paths 0`, `urls 0`).
- The value is runtime, not static: during the `WaitForSingleObject` delay the
  image region is RC4 ciphertext. Verifying it needs a debugger
  (`VirtualQuery` + a memory dump inside the sleep window).

## Phase 6a — indirect syscalls

Process hollowing with `build.stub.syscalls.mode` `none` (before) vs `indirect`
(Hell's Gate).

- 517,632 B → 525,312 B (+7,680 B: the SSN table, resolver and trampoline).
- Suspicious imports 2 → 0: `VirtualAllocEx`, `WriteProcessMemory`,
  `ReadProcessMemory` and `ResumeThread` disappear from the IAT; the
  `NtUnmapViewOfSection` string goes too. `✓ IAT looks minimal`.
- None of the five NT function names appears in the binary (`strings` finds
  nothing; they are rebuilt at runtime through `StringsConfig`).
- Runtime: every `nt_*` call in the hollowing flow returns `STATUS_SUCCESS`. The
  hollowed `svchost` still crashes on the test payload, but the pristine
  pre-6a baseline crashes identically — a pre-existing hollowing limitation, not
  an effect of the syscall layer.

## Phase 7 — ETW patch + anti-debug

`reflective_loading` with and without `anti_debug → patch_etw`.

- 498,688 B → 505,344 B (+6,656 B); entropy unchanged.
- Only two imports added: `CheckRemoteDebuggerPresent` and `GetThreadContext`.
  `IsDebuggerPresent` is already imported by the Rust standard library's panic
  machinery, and `patch_etw` reuses `VirtualProtect`/`LoadLibraryA`/
  `GetProcAddress`. No new DLL.
- `patch_etw` adds `ntdll.dll`, `EtwEventWrite` and `EtwEventWriteFull` as
  obfuscated runtime literals; `anti_debug` has no string literals. Both keep the
  strings scan clean.
- The audit's "suspicious imports" summary does not classify debugger APIs as
  suspicious, so the tell-tale imports show up in the raw listing, not there.

## Phase 8 — bouncer

`reflective_loading` with an optional `bouncer` gate.

- 514,560 B (503 KB) baseline → 542,720 B (530 KB) for a host-name-only gate
  (+28 KB, +1 import) → ~571 KB for every check (+56 KB, +13 imports, two extra
  DLLs: `user32`, `advapi32`).
- The full import set (`GetComputerName*`, `GetUserNameW`,
  `GetUserDefaultLocaleName`, `GetKeyboardLayout*`, `CreateToolhelp32Snapshot`,
  `GetSystemInfo`, `GlobalMemoryStatusEx`) is the technique's most observable
  static signature.
- `sensitive 0` and `total flagged 0`: every check literal (host/user patterns,
  analysis process names, hypervisor vendor tokens) is rebuilt at runtime.
- Runtime: a host that does not match aborts the pipeline silently (exit `0`),
  the intended host runs the payload. Covered by
  `tests/cli.rs::bouncer_gate_blocks_and_allows_on_windows`.

## CrowdStrike Falcon — process hollowing (partial)

- The stub prints its own marker, but the payload never runs inside `svchost.exe`:
  the suspend → unmap → RWX write → resume sequence is detected at runtime.
  Expected for a tier-1 EDR, since the phase goal is static evasion.
- Falcon also blocks `picaro.exe` itself (`Access denied`): the audit module
  embeds malware-API and technique keywords for its string scan, so the
  measurement tool trips the heuristics it is meant to measure.

## Adding a report

Add a section here rather than a new file. For an EDR test, record:

```markdown
## <EDR> — <technique> (<date>)

- Product / version / configuration:
- Result: blocked | allowed | partial
- Where it was blocked (static scan, runtime hook, ETW-TI, kernel callback, …):
- Evidence (screenshot / log path):
- Plan used:
```

For new runs, the Defender line uses the real `MpCmdRun.exe`: it is resolved from
its absolute install path (falling back to the versioned engine directory, then
`PATH`) and the target is passed as an absolute path too — a relative `-File`
fails with `hr = 0x80508023`. The YARA ruleset is still empty, so its line is a
placeholder until rules exist.
