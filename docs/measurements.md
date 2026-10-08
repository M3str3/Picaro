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
| DLL | host-loaded DLL (`kind: dll`) | 366 KB; loaded by CPython, .NET and `rundll32`; the chain's `42` comes back from the two blocking hosts |
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

## Parallel technique batch — callbacks, module stomping, fibers (2026-09-28)

Three in-process Execution techniques added in one batch, each built from its own
`code_examples/<name>/smoke.yaml` with the 6-byte demo shellcode
(`examples/payloads/demo_shellcode.bin`), `strings: xor`, `syscalls: none`.

| | `execution_callbacks` | `module_stomping` | `fibers` |
| --- | --- | --- | --- |
| Artifact | 376 KB | 378 KB (387,584 B) | 372 KB (380,416 B) |
| Imports only this one has | `VirtualAllocEx`, `VirtualProtectEx` (both gone with `syscalls: indirect`, 95 → 93 imported functions) | `LoadLibraryA`, `GetCurrentProcess`, `VirtualProtectEx` | `ConvertThreadToFiber`, `CreateFiberEx`, `SwitchToFiber`, `DeleteFiber`, `ConvertFiberToThread`, `VirtualProtectEx`; no `CreateThread`/`GetExitCodeThread` (the reflective shellcode runner has them) |
| Strings | sensitive 0, API names 0, technique names 0 | sensitive 0 | sensitive 0 |
| `audit` | LOW RISK, "IAT looks minimal" | LOW RISK | LOW RISK |
| Runtime | exit `42` (x64 and x86) | exit `42` (x64 and x86) | exit `42` (x64 and x86) |

- The runtime row is the packed artifact itself (`code_examples/<name>/smoke.exe`,
  produced by `picaro build` and executed on the Windows host): the demo
  shellcode (`mov eax, 42; ret`) runs and the stub relays its exit code. The
  artifacts are gitignored scratch and were not kept.
- Every one of the three also builds and runs as an **i686** stub
  (`code_examples/<name>/smoke-x86.yaml`), so the x86 claim in each DEF is
  measured, not assumed.
- They chain as documented: one artifact with `fibers` → `execution_callbacks` →
  `module_stomping` (three shellcode payloads, `code_examples/chain/chain.yaml`)
  runs all three steps in order and exits with the payload's code (`42`).
- `execution_callbacks` resolves `crypt32.dll!CertEnumSystemStoreLocation`
  dynamically (`LoadLibraryA` + `GetProcAddress`, both names obfuscated), so
  neither the module nor the entry point appears in the IAT or in `.rdata`.
- `module_stomping` keeps the stomped module's own `.text` mapping, so the added
  static surface is `LoadLibraryA` + `GetCurrentProcess` + the protection change;
  `.text` capacity was probed on live modules (`wininet.dll` 1,957,888 B,
  `dbghelp.dll` 1,712,128 B, `amsi.dll` 53,248 B — a poor target for a staged
  payload, besides the `patch_amsi` conflict).
- `fibers` was also probed directly (`code_examples/fibers/harness/`): the
  payload's `eax` returns as the step's exit code, a second `fibers` run on the
  same thread works after `ConvertFiberToThread`, a fiber function that returns
  ends the process silently (exit 0 — the explicit switch back is required), and
  protecting the decrypted buffer's own heap pages hangs the switch when the
  loader's fiber state shares the page (hence the dedicated region).

## Batch 2 — ntdll unhooking, Early Bird, PE injection, PPID spoofing (2026-09-28)

Four techniques added in a second parallel batch. Each was built from its own
plan under `code_examples/<name>/` and **run end to end**, not just compiled.

| | `unhook_ntdll` | `early_bird` | `pe_injection` | `ppid_spoofing` |
| --- | --- | --- | --- | --- |
| Category | preparation | execution | execution | control |
| Artifact | 405 KB (x64) / 371 KB (x86) | 362 KB (x64) | 587 KB (x64) / 529 KB (x86) | 279 KB (x64) / 242 KB (x86) |
| Payload | — | `shellcode` | `pe` | — |
| `audit` | LOW RISK · sensitive 0 · technique names 0 · System32 paths 0 | LOW RISK · no suspicious strings | — | — |
| Runtime proof | the following step still exits `42` | the APC kills the target (`0xC000001D`) | the payload's own exit code (`42`) returns | the child's exit code (`7`) returns |

- **`unhook_ntdll`** restores 1,482,908 bytes of `.text` at the live ntdll base.
  Two measured constraints: the write window must be `PAGE_EXECUTE_READWRITE`
  (with `PAGE_READWRITE` the protection call faults on its return, because it
  returns *through* an ntdll stub inside the region being rewritten), and on x86
  the section's base relocations must be applied — the live 32-bit ntdll differs
  from the file in 19,004 bytes (HIGHLOW fixups, delta `0x2bda0000`), so a raw
  copy crashes the stub. With `syscalls.mode: indirect` the
  `VirtualProtectEx`/`VirtualAllocEx` imports disappear (x64 artifacts).
- **`early_bird`**'s proof is a two-byte `ud2` payload plus a bounded `wait_ms`:
  the loader relays the target's `0xC000001D`
  (`STATUS_ILLEGAL_INSTRUCTION`), which can only happen if the APC was
  delivered. Verified on x64 and x86. **Target choice matters:** the 32-bit
  `notepad.exe` of this Windows build is a launcher shim, so `QueueUserAPC` on
  its thread fails with `ERROR_INVALID_HANDLE` (measured `0x80070006`), while the
  64-bit one works and `cmd.exe` works on both architectures. The default target
  is `svchost.exe`; check the target first when a run fails on an unusual image.
- **`pe_injection`** returns the payload's own exit code (`42`) through the stub
  on x64 and x86, for a minimal payload and for one with unusual section
  alignment; a stack probe reports the same `rsp & 0xF` injected and direct, so
  the thread starts with the same alignment as a normally created one.
- **`ppid_spoofing`** relays the child's exit code (`7`) and the chain keeps
  running; the spoof itself was verified from PowerShell (`Win32_Process`
  reports the configured parent's PID while the real creator is the loader). A
  missing parent fails loudly (`exit 1`) and a detached child outlives the
  loader.

## Batch 3 — thread hijacking, stack spoofing, self-deletion (2026-09-29)

Host: `x86_64-pc-windows-msvc` (rustc 1.90), release stub unless noted, Windows 11.

- **`thread_hijacking`** (T1055.003, execution, shellcode only): a throwaway
  `ping.exe -t 127.0.0.1` started by hand, payload `ud2` (`0f 0b`, two bytes).
  The target's thread was redirected and died with `0xC000001D`
  (`STATUS_ILLEGAL_INSTRUCTION`); the loader — `wait_ms: 4000` — relayed exactly
  that code as its own exit status, which is the proof the redirection happened.
  No thread was created in the target. Running it against `notepad.exe` produced
  `0xC0000005` events instead: the *crash code* of a hijacked thread depends on
  what the payload does with the (private) stack, so `ud2` is the payload to use
  when the point is the proof. The target's own exit code can only be relayed
  when `wait_ms` covers its death.

- **`stack_spoofing`** (T1036, preparation, x64): indirect syscalls with
  `resolver: tartarus_gate`, a shellcode payload through `reflective_loading`.
  The payload's exit code (`42`) is relayed, so every syscall in the chain ran
  with the stack shifted by 4 KB and its arguments copied — the copy is the part
  that could silently corrupt a wide call. `init_stack_spoofing` resolves 16
  fabricated return sites from the live ntdll. Two findings worth keeping:
  - The decoy fill loop originally wrote a full 128-byte block whenever its
    cursor was below the caller's `rsp`, which could run up to 124 bytes *past*
    that pointer and overwrite the caller's real return address. With the
    argument copy in place the syscall itself still succeeded, so the symptom was
    a hang in the *first* spoofed syscall (`NtAllocateVirtualMemory`), not a
    crash. The loop bound is now one block below `rsp`.
  - The structural minimum for `decoy_bytes` is `0x70` (the fabricated frames
    plus the nine copied argument slots), but every value below `0x80` faults in
    the first spoofed syscall on this host (`0xC0000005`) while `0x80` and above
    work. The clamp is `0x80` and the sweep is committed as
    `code_examples/stack_spoofing/bisect.py`, so the floor can be re-measured
    instead of trusted.

- **`self_deletion`** (T1070.004, preparation): the artifact's own path, three
  variants, measured with a stand-in process that opens *its own* image
  (`code_examples/self_deletion/probe.cs`):

  | Variant | Result |
  |---------|--------|
  | `FileDispositionInformationEx` (64) `DELETE|POSIX_SEMANTICS`, share `RW+DELETE` | `FALSE`, `ERROR_ACCESS_DENIED` |
  | `FileDispositionInformation` (13), share `RW+DELETE` | `FALSE`, `ERROR_ACCESS_DENIED` |
  | `FileDispositionInformation` (13), share `READ` | `FALSE`, `ERROR_ACCESS_DENIED` |
  | `FileDispositionInformationEx` (64) `DELETE`, share `READ` | `FALSE`, `ERROR_ACCESS_DENIED` |
  | `FileRenameInformation` (10) to `:stream`, share `READ` | **`TRUE`** |

  A mapped image cannot be deleted on this build, which is why the default is the
  rename: after `mode: rename_ads` the path is a 0-byte file and the loader's
  386,560 bytes live in a randomly named alternate data stream (verified with
  `Get-Item -Stream *`), with the payload still running from the mapped section
  and relaying exit code `42`. `mode: helper` — a detached `cmd.exe` that sleeps
  two seconds and deletes — removes the file outright: verified by listing the
  directory after the run.

## DLL output (`build.output.kind: dll`) — host matrix (2026-09-30)

Host: `x86_64-pc-windows-msvc` (rustc 1.90), Windows 11. Artifact:
`tests/plans/dll.yaml` — shellcode `mov eax, 42; ret`, `entry: export:Run`, no
syscalls — built with `picaro build tests/plans/dll.yaml` (366 KB,
`dist/test_dll.dll`). The chain returns `42`, so a host that reports `42` proves
its export ran the chain and did not merely map the module; the committed host
examples are in `examples/hosts/` (the scratch variants used here — lab-signed,
resources — are in `code_examples/dll-output/`).

| Host | Loads it with | Entry | Result |
| --- | --- | --- | --- |
| CPython 3.14 | `ctypes.CDLL(...).Run()` | `export:Run` (blocks) | `42`, marker on stderr (`ctypes_host.py`) |
| .NET (PowerShell 5.1 `Add-Type`) | `[DllImport]` P/Invoke, 4-argument shape | `export:Run` | `42`; `test_dll.dll` in the host's module list (`pinvoke_host.ps1`) |
| `rundll32.exe` | `rundll32 test_dll.dll,Run` | `export:Run` | chain ran (marker on the redirected stderr), exit code `0` (`rundll32_host.ps1`) |
| Java | `System.load` | `jni_on_load` | not measured: no JDK on the measurement host |

Findings:

- **`rundll32` needs its handles redirected.** It is a GUI-subsystem binary, so
  neither cmd nor bash hands it the parent console, and
  `AttachConsole(ATTACH_PARENT_PROCESS)` cannot attach a console that was never
  there. `Start-Process -RedirectStandardError` is what makes the chain's output
  observable, and it is the recipe in `examples/hosts/rundll32_host.ps1`; started
  plainly from bash, the chain still runs and the marker goes nowhere.
- **`rundll32` does not relay the export's return value.** `Run` returns `42`
  and `rundll32` still exits `0`. When the return code is the evidence, use
  `ctypes`/P-Invoke, which see it, or a payload with a side effect.
- **The DLL appears in the host's module list** (`test_dll.dll @ 0x7FF…`): the
  image-load telemetry the design predicts (section 9) is real — the mode removes
  the *process* IoC, not the module.
- **`entry: auto` exports `DllMain`, `JNI_OnLoad` and `Run`** — the `picaro
  audit` EXPORTS section lists all three (`examples/plans/dll.yaml`), one of which
  no ordinary DLL has.
- **The PE records the delivered name**: `strings dist/test_dll.dll` shows
  `test_dll.dll` (and `test_dll.pdb`), confirming D-15 — the intermediate is named
  after the output stem and `--crate-name` follows it.
- **Resources are legitimate in a DLL.** A `kind: dll` plan with an icon and
  version info (`.rsrc` 16 KB, 366 → 382 KB) still runs (`Run()` → `42`), and
  `GetFileVersionInfo` reads it back (`CompanyName Contoso Ltd`,
  `FileDescription Widget Helper`). The *application* manifest is rejected at
  build time, as designed.

### Signing (lab) and Defender

`build.output.sign.mode: lab` signs through `signtool.exe` on Windows (resolved
from the Windows Kits install):

- Before signing: `SIGNATURE none`; Defender **clean**.
- After signing (`dist/dll_signed.dll`, same plan plus `sign: { mode: lab }`):
  `SIGNATURE present (Authenticode)`, overlay 1,480 B, Defender still **clean**.
- `signtool verify -pa -v` walks the whole chain — `CN=picaro lab code signing`
  ← `CN=picaro lab code signing Root CA` — and fails only with *"a root
  certificate which is not trusted"*: the lab CA is exported next to the artifact
  (`dll_signed.ca.cer`) and no trust store is modified.
- The signed DLL loads and returns `42` exactly like the unsigned one.

Not measured: a Defender *verdict* change with the signature (both are clean
here). The design's remaining Phase D item is the **Java** row (`System.load`
plus a latch); the parked `AttachCurrentThread` extension is what makes the JVM
wait for the worker.

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
