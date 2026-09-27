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
| x86 | TLS provisioning (M1/M2) | `TlsSetValue` → loader's array; a payload reads its own `thread_local` (`tls=42`) |
| x86 | reflective loading (static) | 468 KB; 1 suspicious import (`VirtualAllocEx`); no literals leak |
| M5 | .NET hosting (static) | 389 KB managed fixture / 1.7 MB SharpHound; the CLR-hosting imports (`mscoree`, `ole32`, `oleaut32`) are the signature |
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

## x86 — static baseline (reflective loading, 2026-09-27)

`examples/plans/x86.yaml` (32-bit `test_payload_x86.exe`, `reflective_loading`,
`strings: xor`), packed and audited on Windows:

- 468,480 B; `arch x86`, console subsystem, unsigned, no overlay.
- Sections: `.text` 280 KB / entropy 6.41, `.rdata` 163 KB / 7.45, `.data` 2 KB,
  `.fptable` 0 KB, `.reloc` 10 KB / 6.51.
- Imports: 3 DLLs, 93 functions; one suspicious (`VirtualAllocEx`, the syscall
  layer's `mode: none` mapping of `nt_alloc_vm`).
- Strings: 1 flagged (`NtUtto`, a false positive — a fragment of the obfuscated
  syscall-layer data), 0 paths, 0 URLs, 0 technique names, 0 sensitive literals.
- Defender: clean; `audit` risk MEDIUM (one suspicious import + one flagged
  string + the expected high-entropy payload section).

## x86 — TLS provisioning for a manually mapped image (2026-09-27)

Found while porting the techniques to x86, with a payload that *reads* a
`thread_local` (the older test payloads only printed to stdout, so they never
touched TLS). Everything below was reproduced with standalone probes on
Windows 10 x64 (and under WOW64 for the 32-bit numbers); the arrays and the
teardown code are the same on both architectures, only the offsets differ:

| | x64 | x86 |
| --- | --- | --- |
| The array a CRT reads (`_tls_index` → block) | `TEB->ThreadLocalStoragePointer`, `gs:[0x58]` | `fs:[0x2C]` |
| The array `TlsAlloc`/`TlsSetValue` use | `TEB->TlsSlots`, `gs:[0x1480]` | `fs:[0xE10]` |

1. **`TlsSetValue` is not what a CRT reads.** Provisioning a mapped image with
   `TlsAlloc` + `TlsSetValue` (what picaro did) makes its `thread_local` reads
   return *another module's* data: the payload printed
   `tls=1526337116` instead of `42` on x86 and `tls=1809635094` on x64. Writing
   the block into the loader's array at the same index fixes the value on both
   architectures.
2. **The index has to be reserved.** Writing the loader's array at an index that
   is *not* claimed by `TlsAlloc` makes ntdll fault when the thread exits: it
   reads the block header at `block - 8` (a `VirtualAlloc`ed block faults with
   `0xC0000005`; a heap block reports `0xC0000374`). Reserving the index with
   `TlsAlloc` first (which sets its bit in `PEB->TlsBitmap`) makes the teardown
   leave the entry alone — the process then exits with the payload's own code.
3. **`TlsAlloc` returns the lowest free index**, which can be a loaded module's
   `_tls_index` (`1` for `KERNELBASE` on both architectures). picaro accepts the
   collision — it costs that module its thread-locals in that thread — because
   the alternative (hand-picking a free index) is exactly the unreserved entry
   that (2) rules out. `build.stub.debug` logs the index.

Verified end to end after the fix: a 32-bit and a 64-bit payload packed with
`reflective_loading` print `tls=42` and exit `0`; the same payload hollowed into
`svchost.exe` writes `PAYLOAD_MARKER_7f3a9c2e tls=42` and its exit code (`42`)
comes back through the stub.

## M5 — .NET hosting (static, 2026-09-27)

`dotnet_hosting` with a managed payload, `arch: x86`, packed and audited on
Windows. Two builds: the 4 KB managed fixture (`tests/fixtures/managed_x86.exe`)
and the real-world `SharpHound.exe` (1.3 MB, 32-bit .NET).

| | fixture | SharpHound |
| --- | --- | --- |
| Artifact | 398,336 B (389 KB) | 1,750,528 B (1.7 MB) |
| `.text` | 305 KB / 6.35 | 305 KB / 6.37 |
| `.rdata` | 69 KB / 5.55 | 1390 KB / 7.97 |

- Imports: 6 DLLs, 103 functions, `IAT looks minimal` (no suspicious import).
  The hosting surface is visible and expected: `mscoree.dll!CLRCreateInstance`,
  `ole32.dll!CoInitializeEx` and the `oleaut32` `SAFEARRAY`/`BSTR` family
  (`SafeArrayCreateVector`, `SafeArrayAccessData`, `SafeArrayUnaccessData`,
  `SysAllocStringLen`, `SysStringLen`, `SysFreeString`, `VariantClear`, …).
  `mscoree.dll` is a static import — the stub never `LoadLibrary`s it at runtime.
- Strings: 1 sensitive hit (`ntdll.dll`, imported) and, for SharpHound, one
  false-positive "api by name" (`ZwSj`, a fragment of the obfuscated syscall-layer
  data — the same effect as `NtUtto` in the x86 baseline). The CLR version string
  (`v4.0.30319`) and `COMPLUS_Version` are rebuilt at runtime and do not appear.
- Defender: clean; `audit` risk MEDIUM (flagged string + the encrypted payload's
  high-entropy section + unsigned, all expected).
- Runtime: the fixture prints `MANAGED_MARKER_7f3a9c2e args=0 x64=False` and exits
  `42`; SharpHound's output is identical to running the original, line for line
  (modulo its own timestamps).

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
