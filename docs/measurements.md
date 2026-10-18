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
| Shellcode | shellcode output (`kind: shellcode`, sRDI) | `.bin` builds and runs; a PE payload mapped reflectively prints its marker (bootstrap arg swap + TLS provisioning fixed in the vendored loader) |
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
- The `processes` check (arbitrary, `state: present|absent`) reuses the single
  `CreateToolhelp32Snapshot` enumeration the `not_in_sandbox` heuristic already
  needs, so it adds no import of its own. The `on_fail: decoy` path writes the
  file with standard-library I/O (no new import) and grows the artifact by the
  encrypted decoy asset (a `format: plain` payload). Neither has its own
  byte-level baseline yet.

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
   `TlsAlloc` + `TlsSetValue` (what Picaro did) makes its `thread_local` reads
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
   `_tls_index` (`1` for `KERNELBASE` on both architectures). Picaro accepts the
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

## Polymorphism — repeated-build `.text` diversity (2026-10-11)

Goal: two builds of the same plan must not share a byte-identical `.text`.
Measured on `examples/plans/shellcode.yaml`, `x86_64-pc-windows-msvc`, SHA-256 of
the `.text` raw section truncated to 16 hex chars:

| Scenario | Builds | Distinct `.text` |
|---|---|---|
| `mode: none` (baseline) | 2 | 1 (byte-identical) |
| `mode: codegen` (seeded codegen profile only) | 4 | 3 (one collision) |
| `mode: full` (default: profile + per-build immediates) | 6 | 6 |
| `mode: full`, `seed: literal:0xdeadbeef` | 2 | 1 (reproducible) |

The default is `full`, so two ordinary builds differ in `.text`; the codegen
profile alone is not enough (its ~12 combinations collide ~8% of the time), and
the per-build source immediates remove that residual.

**But a different `.text` hash is not different code.** The same pair of builds,
disassembled with Capstone (x86-64, `.text` ≈ 300 KB, ≈ 74 000 instructions):

| Pair | Instructions | Differing | Mnemonic multiset overlap |
|---|---|---|---|
| same codegen profile (`dist/mimikatz.picaro2.exe` vs `...picaro3.exe`) | 74,639 each | 8 (0.01%) | 1.0000 |
| different codegen profile (`...picaro4.exe` vs `...picaro5.exe`) | 67,747 vs 68,654 | layout shifted | 0.9995 |

So the feature is **build-time code diversity**: hashes and layout-sensitive byte
fuzzy hashes move outright, and the codegen knobs (next section) change the
instruction stream too — but the control-flow structure is unchanged, so a
CFG-aware similarity or a human disassembly still matches the loader. The
regression guard is the `#[ignore]` test
`two_polymorphism_seeds_differ_in_the_text_section`. Design and limitations:
[Polymorphism](design/polymorphism.md).

### Codegen knobs — the instruction stream moves (2026-10-11)

The codegen profile now also varies `-C llvm-args=--inline-threshold` and
`-Z mir-opt-level` (and offers `-Z randomize-layout`). Unlike the earlier
measures, these change the *instructions*. Measured with Capstone (x86-64) on
`examples/plans/shellcode.yaml`, with the seed and every pool pinned so exactly
one knob differs between the two builds:

| Knob varied | `.text` A → B (bytes) | Instructions A → B | Identical (addr, mnem, ops) tuples |
|---|---|---|---|
| `inline_threshold` (`25` vs `300`) | 309,248 → 310,272 | 73,896 → 74,037 | **0.64%** |
| `mir_opt_level` (`0` vs `3`) | 309,760 → 307,712 | 67,951 → 67,432 | **1.08%** |
| `randomize_layout` (on vs off) | 309,760 → 309,760 | 74,020 → 74,020 | **100% (no-op)** |

Ten builds of `examples/plans/shellcode.yaml` with distinct seeds produced **10
distinct `.text`** sections (sizes 272,896–310,784 bytes), up from 6/6 before the
knobs. `randomize_layout` is a no-op for this stub: it reorders `repr(Rust)`
fields, and the stub keeps almost none in memory at `opt-level >= s` (most data
is `std`/`windows` types, which are not randomized). It stays opt-in.

Harness: `pefile` for the section, Capstone for the disassembly
(`pefile.PE(data=…)` on bytes, as in the polymorphism notes above).

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

## Syscall resolvers — runtime verification (2026-10-09)

- Host: Windows x64, rustc 1.90, `x86_64-pc-windows-msvc`.
- Artifacts: `mode: indirect` + `reflective_loading`, one per resolver
  (`hells_gate`, `tartarus_gate`, `api_hash`), ~579–580 KB each.
- Result: all three reach the kernel and run the payload (exit `0`,
  `PAYLOAD_MARKER_7f3a9c2e`). Hell's Gate resolves `NtAllocateVirtualMemory` →
  SSN 24 and `NtProtectVirtualMemory` → SSN 80 from the live prologues; Tartarus
  and API hashing resolve the same from the clean on-disk copy
  (`GetModuleFileNameW` path, `TimeDateStamp` matched).
- Covered by the e2e `indirect_syscall_resolvers_run_the_payload` (`tests/cli.rs`).
- The three resolvers were reorganized under `src/engine/syscalls/resolvers/<name>/`
  (each self-contained; the registry drives `techniques list`/`show`/`validate`).

## PowerShell hosting — runtime verification (2026-10-11)

- Host: Windows x64 (`10.0.26200`), rustc 1.90, `x86_64-pc-windows-msvc`,
  .NET Framework 4.0 `csc.exe` + Windows PowerShell 5.1
  (`System.Management.Automation`, GAC `v4.0_3.0.0.0`).
- Artifact: `examples/plans/powershell-run.yaml` (`format: powershell`,
  `patch_amsi` + `patch_etw` + `powershell_hosting`), ~492 KB.
- Result: the `.ps1` is compiled to a managed launcher at build time (csc) and
  the stub hosts the PowerShell engine in its own process; the demo script's
  `Get-PicaroMarker` returns `picaro-ok`, exit `0`. **No `powershell.exe` child
  and no script on disk.** All three invocation paths verified:
  - baked default (`command: Get-PicaroMarker`) → `picaro-ok`;
  - run-time override (`picaro-ps.picaro.exe '6*7'`) → `42`
    (`command_mode: override`);
  - `mode: interactive` (a line on stdin) → `picaro-ok`.
- Covered by the e2e `packs_and_runs_a_powershell_payload` (`tests/cli.rs`,
  `#[ignore]`).
- Note: the launcher flushes `Console.Out`/`Console.Error` before returning,
  because the stub's `main` ends with `std::process::exit`, which skips the CLR's
  normal shutdown and would otherwise drop a piped run's output.

## PowerShell module — runtime verification (2026-10-11)

- Host: Windows x64, rustc 1.90, .NET Framework 4.0 `csc.exe`, Windows
  PowerShell 5.1.
- Artifact: `examples/plans/powershell-module.yaml` (`kind: psmodule`,
  `patch_amsi` + `import_powermodule`), 11 KB, output `dist/picaro-psmodule.dll`.
- Result: `Import-Module .\dist\picaro-psmodule.dll` in a fresh
  `powershell.exe -NoProfile` prints `picaro-ok` from `Get-PicaroMarker` — the
  script's functions land in the importing session.
- **The `.ps1` never reaches disk in cleartext**: the module embeds the script as
  XChaCha20-Poly1305 ciphertext (hex), decrypted in `OnImport`. Verified by
  scanning the `.dll` byte-wise (UTF-16 and ASCII): neither `Get-PicaroMarker`
  (the script) nor `amsi.dll` / `AmsiScanBuffer` (XOR-scrambled) appear.
- The packer's XChaCha20 was ported to C# for the module (`System.Numerics`
  `BigInteger` for Poly1305) and validated against the draft-irtf-cfrg-xchacha-03
  A.3 vector.
- Covered by the e2e `packs_and_imports_a_powershell_module` (`tests/cli.rs`,
  `#[ignore]`).

### PowerShell hosting — host sensitivity (2026-10-11)

- With Defender's real-time protection **enabled** on the measurement host, a
  `patch_amsi` + `powershell_hosting` artifact runs the script ~2 times in 3
  (the AMSI patch is intermittently interfered with); **without** the AMSI patch
  it is 12/12, and a plain `powershell_hosting` is stable. The e2e
  `packs_and_runs_a_powershell_payload` therefore retries; a **Defender-off lab
  host** is the intended environment for runtime verification.
- The `patch_amsi` patch was corrected while investigating: it now returns
  `S_OK` **and** writes `AMSI_RESULT_CLEAN` (0) to the caller's out-parameter
  (the old `sub eax, eax; ret` left it uninitialized, which a caller that reads
  the result — `System.Management.Automation` does on every script — saw as
  non-deterministic).

## ETW/AMSI patch — expanded coverage (2026-10-12)

- `patch_etw` now covers four exports — `EtwEventWrite` (always),
  `EtwEventWriteFull`, `EtwEventWriteEx` and `NtTraceEvent` (best effort) — and
  `patch_amsi` three — `AmsiScanBuffer` (always), `AmsiScanString` and
  `AmsiOpenSession` (best effort). The extra variants are opt-out through
  `params` and default on. `AmsiScanString` and `AmsiOpenSession` write the
  caller's out-parameter from the correct argument slot (5th and 2nd
  respectively); `NtTraceEvent` is patched exactly like the `Etw*` writers.
- Static surface is unchanged: every export name is a `StringsConfig` runtime
  literal resolved through `GetProcAddress`, so none reaches `.rdata` or the
  import table. `NtTraceEvent` was added to `SENSITIVE_LITERALS`;
  `EtwEventWriteEx` is covered by the `EtwEventWrite` substring. The guardrail
  `no_sensitive_literals_in_generated_stubs` (one stub per technique, x64) stays
  clean, and both fragments compile for x86 and x64
  (`compiles_the_x86_preparations_for_i686`).
- The native patches are exercised end to end by
  `x86_preparations_run_before_the_payload` (32-bit stub, `patch_amsi` +
  `patch_etw`, payload runs) and `build_with_amsi_patch_produces_pe`.
- **Managed path (`AmsiUtils`).** A `patch_amsi` step now also emits a C#
  `PatchManagedScan` into the generated launcher (`powershell_hosting`) and the
  generated module (`import_powermodule`): it sets
  `System.Management.Automation.AmsiUtils.amsiInitFailed` to `true` by reflection,
  so PowerShell's own scan entry returns before it calls into `amsi.dll`. Both
  reflection names are XOR-scrambled with fresh per-string keys. Verified by the
  e2e `packs_and_runs_a_powershell_payload` and
  `packs_and_imports_a_powershell_module` (each compiles the generated C# and
  runs it).
- Not measured: a scan that *should* be caught with and without the extended
  variants needs an AMSI-invoking payload and a Defender-on host; the AMSI rows
  stay a lab claim, not a measured number.

## Hardware-breakpoint AMSI/ETW bypass — compile-verified (2026-10-12)

- New `hardware_breakpoints` Preparation technique: it arms an *execute* debug
  register (`DR0`–`DR3`, `Dr7` local-enable, `R/W`/`LEN` = 00) on the watched
  exports and installs a vectored exception handler that answers
  `EXCEPTION_SINGLE_STEP`. On the trap it sets `Rax = 0`, stores
  `AMSI_RESULT_CLEAN` in the caller's out-parameter (`[Rsp+0x30]` for
  `AmsiScanBuffer`, `[Rsp+0x28]` for `AmsiScanString` — the same offsets the
  software patch writes) and resumes at the caller.
- Defaults watch `AmsiScanBuffer` + `EtwEventWrite` (two of the four registers);
  `scan_string`/`open_session` raise it to four. x64 only — the handler pops the
  x64 return address and writes the AMD64 `CONTEXT`; `requires` is
  `windows-x64`.
- Static surface: every library/export name goes through `StringsConfig`, so
  none reaches `.rdata`; arming goes through the syscall layer's
  `nt_get_context_thread`/`nt_set_context_thread`, so `mode: indirect` removes
  the `GetThreadContext`/`SetThreadContext` imports. `AddVectoredExceptionHandler`
  stays a Win32 import (a loader entry point, not a syscall).
- **Not measured.** The debug-register/vectored-handler flow is
  compile-verified only; it has not been run against an AMSI- or ETW-invoking
  payload on a Defender-off host, which is why `stability` is `Experimental`.
  The per-thread scope (only the thread that ran the Preparation is covered) and
  the four-register ceiling are the two things a lab run should confirm.

## Low-effort hardening Preparations — compile-verified (2026-10-12)

- New `process_mitigations` Preparation: `SetProcessMitigationPolicy` for
  `ProcessSignaturePolicy` (`MicrosoftSignedOnly`, the BlockDLLs mitigation; the
  load-bearing one), `ProcessExtensionPointDisablePolicy` and, opt-in,
  `ProcessSystemCallDisablePolicy` (`DisableWin32kSystemCalls`). All three are
  documented Win32 process-config APIs (`kernel32`), arch-neutral, and need no
  syscall-layer routing (`syscalls: &[]`).
- New `hide_thread_from_debugger` Preparation:
  `SetThreadInformation(GetCurrentThread(), ThreadHideFromDebugger=0x11)` — the
  Win32 wrapper over `NtSetInformationThread`. Also arch-neutral, no syscall-layer
  routing.
- Both are `Experimental`: the APIs and their ABI are settled and the fragments
  compile, but neither effect (an EDR DLL actually refused; a debugger actually
  detached) has been measured, which needs a host with an unsigned userland agent
  and an attached debugger respectively.

## Image path spoofing — compile-verified (2026-10-12)

- New `image_path_spoofing` Preparation (T1036.005): it follows
  `PEB->ProcessParameters` (`gs:[0x60]`/`fs:[0x30]`, offset `0x20`/`0x10`) to the
  `ImagePathName` `UNICODE_STRING` (`0x60`/`0x30`) and rewrites its `Length`,
  `MaximumLength` and `Buffer` to point at a leaked wide copy of the decoy path,
  so `GetModuleFileNameW(NULL)` reports the decoy. No `Nt*` call is involved
  (`syscalls: &[]`) and the decoy path goes through `StringsConfig`.
- Kernel-side queries are not affected: `QueryFullProcessImageNameW` /
  `NtQueryInformationProcess` read the kernel's view, not the PEB. The technique
  is `Experimental` — the PEB write is compile-verified, the
  `GetModuleFileNameW` effect still needs a host run.
- Interactions: `plan::validate` warns when `self_deletion` or a `timestomping`
  with no explicit `target` follows it (both resolve the running image's path at
  run time); `self_deletion` is a declared conflict.

## Erase PE header / hide module — compile-verified (2026-10-12)

- New `erase_pe_header` Preparation (T1027): `GetModuleHandleA(NULL)` → `e_lfanew`
  at `+0x3C` → `SizeOfHeaders` at `+0x54` (both PE32/PE32+), then
  `nt_protect_vm` RW → `write_bytes` zeroes the DOS/NT headers and the section
  table → protection restored. Erasing the header removes the data directories the
  loader itself needs, so it must run last; `conflicts: ["sleep_obfuscation"]` and
  `plan::validate` warns when `sleep_obfuscation` follows it.
- New `hide_module` Preparation (T1014): walks `PEB->Ldr->InLoadOrderModuleList`
  and unlinks the matched `LDR_DATA_TABLE_ENTRY` (and its `InMemoryOrder` /
  `InInitOrder` links) so userland PEB walkers cannot find it. `modules: [..]`
  names entries (a name not found is an error); `hide_self` (default) unlinks the
  running image. No `Nt*` call (`syscalls: &[]`). Kernel-backed enumerations
  (ToolHelp32, `NtQueryVirtualMemory`) are not fooled.
- Offsets are arch-aware (`LDR_DATA_TABLE_ENTRY` and `UNICODE_STRING` layouts).
  Both are `Experimental`: compile-verified only, no host measurement.
- **Latent x86 bug found while writing `hide_module`:** `src/engine/args.rs`'s
  `$ARGS_BLOCK$` writes the `UNICODE_STRING.Buffer` at `+8` on both widths; on
  x86 the pointer is at `+4`, so the x86 `args` path appears to clobber the next
  field. Not touched (out of scope) — flagged for a separate fix.

## Network stager — runtime verification (2026-10-14)

- Host: Windows x64, rustc 1.90, `x86_64-pc-windows-msvc`; the server is a
  loopback `TcpListener` inside the test process, so no real network is involved.
- Artifacts: `network_stager` + `reflective_loading` (`format: shellcode`, a
  `mov eax, N; ret` blob). The exit code is the evidence: a strictly staged
  artifact embeds no copy, so `43` can only come from the bytes that were
  fetched at run time; the embedded fallback is `42`.
- Result (the five `#[ignore]`d e2e tests in `tests/cli.rs`):
  - `stages_and_runs_a_payload_over_winhttp` — the in-process WinHTTP fetch
    runs the served blob (`43`); no child process and no temp file.
  - `a_staged_payload_with_a_fallback_prefers_the_fetched_copy` — `fallback:
    embedded` with the server up prefers the fetched copy (`43`), not the
    embedded one (`42`).
  - `a_staged_payload_with_a_fallback_runs_the_embedded_copy_when_the_fetch_fails`
    — with the fetch refused at connect, the chain does not fail: the embedded
    copy runs (`42`).
  - `stages_and_runs_a_payload_over_a_child_downloader` — the child-process
    transport (`curl`) still fetches and runs (`43`) after the transport split.
  - `stages_a_wire_encrypted_payload_over_winhttp` — the step-level wire crypto
    (`crypto: xchacha20poly1305`) decrypts the fetched blob in the stub before
    it is staged (`43`).
- Compile net: `compiles_both_stager_transports_for_i686` compiles both
  transports for i686 (stdcall `extern "system"`), so the dynamically resolved
  WinHTTP aliases are validated for x86 too.
- Static: the in-process transport adds no `winhttp.dll` import (every entry
  point is resolved at run time; `LoadLibraryA`/`GetProcAddress` were already
  imported) and no WinHTTP name reaches `.rdata` (obfuscated defs) — asserted by
  the fragment-render unit tests.

## Measurement round — the compile-verified cloud (2026-10-14)

Host: Windows 11 Pro 26200 (x64), rustc 1.90, Defender real-time protection off
(the lab condition). Everything below ran there with
`cargo test --test cli --features live-tests -- --ignored`; the new tests are
`#[ignore]`d like the rest. The payloads are
`examples/payloads/probe_payload.rs` (reads the in-process state back:
`GetModuleFileNameW(NULL)`, the PEB `ImagePathName`, `K32EnumProcessModules`, the
image header, an unsigned-DLL load and an `AmsiScanBuffer` call),
`test_tls_payload.rs` (a real `.CRT$XLB` callback) and the committed fixtures.
This section supersedes the "compile-verified" notes above.

**Green — now measured, not compile-verified:**

- `hide_module` (T1014): a probe in the same process reports `loader_listed=no`
  after the step (`K32EnumProcessModules` no longer sees the image) with the
  header intact and the chain still running. The walk found four modules and
  matched the self entry; the unlink removed **two** links, not three — the main
  image is not a member of the initialization-order list and its
  `InInitializationOrderLinks` are **null** on this build, so the unguarded unlink
  the fragment used wrote through null and took the process down (`0xC0000005`).
  Fixed with the standard integrity test (a link is removed only when both
  neighbours point back at the entry).
- `erase_pe_header` (T1027): the image base loses `MZ` and `PE\0\0` in memory
  while the process keeps running and the following `reflective_loading` step
  executes.
- `process_mitigations` (T1562.001): `LoadLibraryW` of a locally built, unsigned
  DLL fails (`ERROR_ACCESS_DENIED`) with the default `block_dlls`, and succeeds in
  the control build; the Microsoft-signed modules the stub itself needs still
  load.
- `dll_hollowing` (T1574.002): the demo shellcode (`mov eax, 42; ret`) runs from
  `wininet.dll`'s `.text` and the artifact exits `42`.
- `hardware_breakpoints` (T1562.001/T1562.006): a call to `AmsiScanBuffer` with a
  null context returns `S_OK` with `AMSI_RESULT_CLEAN` written to the caller's
  out-parameter; the control build gets the real return, `E_INVALIDARG`
  (`0x80070057`). The real function body therefore never runs. There is **no**
  detection number: on this host the AMSI test sample runs unflagged (the
  provider is inert with real-time protection off), so a "blocked vs allowed"
  comparison is not measurable there.
- `image_path_spoofing` (T1036.005): the PEB `ImagePathName` is really repointed
  (a direct PEB read shows the decoy), but **`GetModuleFileNameW(NULL)` is not
  fooled** on this build — it resolves the main module through the loader list.
  The README claim and the e2e now assert the PEB field, not that API.
- `pe_injection` (T1055.002), plain and TLS paths: the payload's exit code (`42`)
  is relayed on both, and with a payload carrying a real `.CRT$XLB` callback the
  callback's marker file is written before the entry point's, which is what the
  TLS provisioning is for. Two root causes were fixed in sequence (below).
- `process_hollowing` TLS callbacks: the same payload's callback now runs on the
  hollowed main thread and both markers land in order
  (`packs_and_runs_a_hollowed_payload_with_tls_callbacks`).

**The two TLS reds — one root cause, found under a debugger:**

The loader emulated the call into each TLS callback at the wrong 16-byte stack
phase. `pe_injection`'s prologue is a thread start routine — entered with
`rsp % 16 == 8`, the ABI's "as if called" state — so its `call rax` handed the
callback `rsp % 16 == 0`; `process_hollowing` pushed a return address on the
pointer the target thread parked with, the same phase the entry-point hand-off
correctly uses. Every frame the callback built was then off by eight until a
`movaps` of a frame local faulted. The crash signature in both cases:
`0xC0000005` with **fault address `-1`** (the kernel's report for that
misalignment, not a page fault), `rip` in ntdll, and the live bytes at `rip`
read back as `movaps [rbp+0x170], xmm0` with `rbp % 16 == 8` — i.e. an aligned
instruction handed a misaligned local.

The fix, measured 2026-10-14: in `pe_injection`'s prologue, `sub rsp, 8` around
the callback loop with `add rsp, 8` before the jump to the entry point; in
`process_hollowing`, base the emulated call on `(parked_rsp & !0xF) - 8` and
restore `parked_rsp` with a context write after the callbacks, because the
entry-point hand-off keeps that context and must still see the loader's state.
Both e2e tests are green. The method: a small child-following debugger
(`code_examples/round-debugger/`, scratch) in `--attach` mode — `x64dbg`'s
headless build does not follow child processes, and the crash lives in the
spawned `svchost.exe`. A separate bug in that tool (the debug-event constants
for `CREATE_PROCESS`/`EXCEPTION` were transposed, which looked like this
Windows build mis-tagging events) sent the first diagnosis down the wrong path
before the dump was trustworthy; the tool now reads the live bytes at `rip`,
the register phases and a module-resolved stack scan.

**Red — measured failures, with root causes:**

- `process_ghosting` (T1055.012): never ran on a host. First failure:
  `CreateFileMappingW(PAGE_EXECUTE_READWRITE)` → `ERROR_ACCESS_DENIED` — a
  delete-pending file refuses a writable mapping. The measured alternatives:
  mapping it read-only succeeds, but a *data* mapping keeps file offsets, so the
  image's RVAs do not line up and the entry point lands in the wrong bytes;
  creating the writable section before the delete mark makes the mark itself fail
  with `ERROR_ACCESS_DENIED`. A working design needs an image section
  (`NtCreateSection(SEC_IMAGE)` + `NtMapViewOfSection`), which the syscall layer
  does not have. Registry state moved to `Stability::Unimplemented`, so a build
  that selects it warns.

**Test-harness bugs found and fixed by the round** (parallel runs, shared scratch
paths): `engine::compiler`'s `compile_i686` and `tests/cli.rs`'s
`build_args_payload` derived their scratch directory from the test *name* / a
fixed stem plus the process id, so two tests running at once shared — and
clobbered — each other (`LNK1104: cannot open file`, `permission denied`). Both
now use a per-call sequence number.

Not measured in this round: `process_mitigations`' `win32k_filter` and
`extension_points` (`block_dlls` is the load-bearing one and is measured), and
the 32-bit variants of the new tests. (`hide_thread_from_debugger` was in this
list when the round closed; it was measured the same day — see the next
section.)

## `hide_thread_from_debugger` — a debugger round (2026-10-14)

Host: Windows 11 Pro 26200 (x64), Defender real-time off. Debuggers: x64dbg
headless (`headless.exe`, config with `EntryBreakpoint`/`SystemBreakpoint`/
`TlsCallbacks` off, so the run is not stalled by its own breakpoints) and the
local child-following debugger (`code_examples/round-debugger/`, `DEBUG_PROCESS`
mode). Payload: a reflectively loaded PE whose `main` writes a pre-marker, raises
the debug event with an `int3`, writes a post-marker and exits `42`.

| Scenario | Result |
|----------|--------|
| `SetThreadInformation(h, 0x11, null, 0)` | **fails**: `ERROR_INVALID_PARAMETER` (`0x57`) |
| `SetThreadInformation(h, 0x11, buf, 1/4/8)` | **fails**: `ERROR_INVALID_PARAMETER` (`0x57`) |
| `NtSetInformationThread(h, 0x11, null, 0)` | `STATUS_SUCCESS` |
| No debugger, step or no step | identical: the `int3` kills the process (`0x80000003`), pre-marker only |
| x64dbg, control | logs the breakpoint: `Last chance exception … (80000003, EXCEPTION_BREAKPOINT)` |
| x64dbg, after the step | **no exception event logged**; the process exits `0x80000003 (STATUS_BREAKPOINT)` |
| `DEBUG_PROCESS` tool, control | `BREAKPOINT seen at 0x1400011c8 (the debugger observed it)` |
| `DEBUG_PROCESS` tool, after the step | **no event at all** — no breakpoint, no exit |

What the two last rows mean: the call itself does not tear the session down
(x64dbg keeps it and still reports the exit code), and it does not detach the
debugger immediately — what disappears is the hidden thread's *event stream*,
so a breakpoint on it goes to the process as unhandled. The README used to claim
"a debugger attached to the process is detached"; the measured behaviour is the
narrower, stronger one above. The `DEBUG_PROCESS` row is stronger still: the
debug port goes silent for that thread (no exit event either).

Product fix the round forced: the fragment used kernel32's
`SetThreadInformation`, which does not support the class at all, so the step
failed *without* a debugger (`ERROR_INVALID_PARAMETER`, chain aborted). It now
calls `NtSetInformationThread` through the syscall layer
(`nt_set_info_thread`, both modes — `mode: indirect` routes it through the
gadget), which is also what the project's "kernel-facing calls go through
`nt_*`" rule asked for. `DEF.syscalls` is `["NtSetInformationThread"]`; the new
e2e (`hide_thread_from_debugger_is_inert_without_a_debugger`) asserts the step
completes and the payload still runs; registry state moved to `Stable`.

## `sleep_obfuscation` — the window observed from outside (2026-10-14)

Host: Windows 11 Pro 26200 (x64), Defender real-time off. No debugger: a
**passive sampler** (`code_examples/`, scratch, ~150 lines of `rustc`) spawns the
artifact, finds its main module with ToolHelp, and every 250 ms walks
`base .. base + SizeOfImage` with `VirtualQueryEx`, reading each 4 KiB page and
hashing it — plus recording the page's protection. It reports, per sample, how
many pages differ from the first sample. Artifact: `sleep_obfuscation
{sleep_ms: 6000}` + a reflective-loaded payload that writes a marker and exits
`42`.

| t | changed pages | protect histogram | state |
|---|---|---|---|
| 0.02 s | 0 | `0x02=82 0x04=2 0x20=134` | baseline |
| 0.28 s | 17 | `0x04=21 0x08=197` | encryption begins (flip is `WRITECOPY`; a chunk's write makes its pages `RW`) |
| 1.04 s – 7.07 s | **218 / 218** | `0x04=218` | RC4 ciphertext + writable, 6.04 s ≈ `sleep_ms` |
| 7.32 s – 7.83 s | 154 → 83 → 13 | `0x04=218` | decryption pass |
| 8.08 s | **0 / 218** | `0x02=71 0x04=13 0x20=134` | byte-exact restore (sample catches the restore's tail) |
| 8.55 s+ | 1 | `0x02=82 0x04=2 0x20=134` | protections exactly at baseline; the one page is loader state |

The `MZ` page is ciphertext in the window (`4d 5a 90 00 …` → `7f e0 a4 c5 …`).
**Control:** the plain `sleep` technique with the same 6 s kept 0/218 pages
changed and the baseline histogram throughout — the signal is the technique.

Crypto check: the 16-byte RC4 key is recoverable from the generated stub (the
`$SLEEP_KEY_DEF$` literal is xor-obfuscated with the strings key), and
`RC4(key)` reproduces the observed `plain ^ cipher` keystream of the first chunk
(65 520 bytes) **byte for byte**. Later chunks do **not** repeat that keystream:
the README's detection note ("equal-size chunks share keystream bytes") is
measured false — consistent with `SystemFunction032` destroying the key buffer
between calls. The mechanism is not reproduced from the build key by the obvious
candidates (S-box first/last 16 bytes, keystream prefix, XOR, or a simply
continued stream); the *fact* is recorded, the mutation is marked unproven.

Product changes: the README's Measurements section carries the table and the
corrected detection bullet, the `DEF` comment states why the state stays
`Experimental` (the operational form — encrypting during the *payload's* sleeps
— and the payload-region enumeration are open workstreams), and the new e2e
(`sleep_obfuscation_sleeps_and_still_runs_the_payload`) asserts the part that
needs no observer: the wait really takes `sleep_ms` and the chain continues.

## `packs_and_runs_sharphound` red under real-time protection (2026-10-15)

The full cli suite came back 34/35: `packs_and_runs_sharphound` failed with
`could not load the assembly from memory (0x8007000b)`. **Not a regression** —
the whole chain was cleared until the host was the only suspect left:

- The stub logs `loading 1355776 bytes` — exactly the fixture's size — and the
  fixture is a valid IL-only AnyCPU .NET Framework assembly (metadata
  `v4.0.30319`, Costura-packed) that runs correctly from disk.
- A **clean 32-bit PowerShell** (`Assembly.Load(bytes)` on the fixture's own
  bytes) fails with the same "incorrect format" error, and so does 64-bit
  PowerShell; framework assemblies (`System.dll`, `mscorlib.dll`) load from
  memory fine in that same shell, so the CLR's from-memory path works and the
  refusal is specific to these bytes.
- **Defender's real-time protection was back on** (`Get-MpComputerStatus`:
  `RealTimeProtectionEnabled = True`, `Age = 0 h`) — the UI disable did not
  survive the overnight reboot (last boot 03:10; two Oct-14 KBs and .NET 4.8.1
  servicing level 533509). Its event log has the matching `1116` detections,
  all `amsi:`-prefixed, with `Trojan:MSIL/SharpHound.VD!MTB` and the path of
  the *host* (`dist/sharphound.exe`, `dist/sh_debug.exe`, and the two
  PowerShells), at 06:40 and 06:42.
- Mechanism: the CLR consults **AMSI when loading an assembly from memory**;
  with real-time protection on, a Defender-flagged assembly is refused and the
  host sees a bare `BAD_FORMAT`. With it off (the lab condition, and yesterday's
green run) the same load succeeds. Recorded as a detection fact in
  `dotnet_hosting`'s README ("What detects it"); the acceptance test stays red
  on a protected host by design. **Confirmed both ways the same day:** with
  real-time protection off again, the same artifact loads and the test is green
  (35/35 cli, 39/39 bin).
- **Process lesson for the next round:** check
  `Get-MpComputerStatus | select RealTimeProtectionEnabled` at the *start* of a
  measurement round instead of trusting an earlier "it is off" — a reboot can
  silently restore real-time protection, and everything else in this round was
  measured under the wrong premise (most tests still passed; this one did not).

## Reflective loading — TLS provisioning measured and removed, bounds guards (2026-10-18)

Host: Windows x64, rustc 1.90.0, Defender real-time protection off (checked at
the start of the round). Artifacts are `picaro build` output built **without**
`--debug` unless noted; the payloads are repository fixtures plus two scratch
ones (a cdylib and a UI exe), and the scratch inputs live in `build/`
(gitignored): `build/tls-measure.yaml`, `build/chello-measure.yaml`,
`build/tls-dll-measure.yaml`, `build/msgbox-measure.yaml`.

The round was meant to find out whether the TLS provisioning the 2026-09-27
entry measured — and commit `92dd019` dropped — could come back without the
release-only heap corruption the 2026-10-17 entries describe. **It could not**,
and the numbers below are what settled it: the healthy TLS results reproduce,
but the index the mapper has to take is the one that caused the corruption.

- **TLS provisioning, release.** `examples/payloads/test_hollow_payload.rs` (a
  Rust exe that reads its own `thread_local` and writes
  `PAYLOAD_MARKER_7f3a9c2e tls=<n>`) packed with `reflective_loading`: the marker
  read `tls=42` and the artifact exited `42`.
- **The same artifact built with `--debug`.** Same result, and the trace shows
  the reserved index: `payload TLS index 1 (96 bytes)`.
- **Control — provisioning disabled** (one build with the mapper's step
  skipped): the same payload wrote `tls=1`. The check is therefore not vacuous:
  without it the payload reads whatever block slot 0 pointed at instead of its
  own.
- **The collision cost, observed.** The index is `1`, which the 2026-09-27 entry
  above identifies as `KERNELBASE`'s: the mapper takes that module's per-thread
  block in the calling thread. Nothing in these runs depended on it — the debug
  stub printed its traces *after* provisioning and kept running, and each
  payload ran to completion.
- **Release UI payload — clean once.** `build/msgbox.exe` (a Rust exe showing a
  `MessageBoxTimeoutW` that dismisses itself, then exiting 42) packed with the
  provisioning enabled: the artifact exited `42`, and the box appeared and closed
  with nothing else on screen (observed on the lab host by the operator, not
  inferred from the exit code). One clean run against a *reliably reproducible*
  2026-10-17 crash is not a fix, so this does not clear the finding — it is
  recorded as the closest reproduction attempt the round made.
- **DLL/export path, release.** A scratch Rust cdylib (`build/tls_dll.rs`) whose
  exported `Run` reads a `thread_local`, packed as `format: dll` +
  `export: Run`: the marker read `tls=42` and the stub **resumed and exited
  `0`** after the export returned, so replacing the slot does not break the
  stub's own later work in this configuration.
- **A payload with no static TLS of its own, release.** `build/c_exe.exe` (MSVC
  C, writes `c_exe_marker.txt` and returns 42): marker written, exit `42`.
- **Not measured:** the header/section/entry-point guards, the no-relocations
  refusal (a `/FIXED` payload that has to move) and the forwarded-export refusal
  are compile-verified only (`compiles_reflective_loading_stub_for_every_format`,
  `compiles_a_reflective_stub_for_i686` and the rendered-fragment unit tests).
  x86 was compiled in this round, not run.

Decision: **the provisioning stays out.** What is measured is that `TlsAlloc`
hands the mapper `1`, a loaded module's index, in the stub's own process, and the
2026-10-17 entries measure what that does to a UI payload in release. The one
alternative — skipping the collisions — writes at an index the loader's
`ThreadLocalStoragePointer` does not cover, because that array is sized for the
modules the loader knows about. That part is **inferred, not measured**: no write
above index `1` has ever been attempted from this technique, and the array's
capacity is not observable from user mode (the heap block's size is, with
`HeapWalk`, if the array is on the process heap — the cheapest measurement the
next round could make). Until then the mapper only runs the payload's
`DLL_PROCESS_ATTACH` callbacks, and a payload that reads a thread-local is out of
scope (measured: `tls=1` instead of `tls=42`).

The real fix is the loader's own static-TLS path: give the mapped image a module
entry, or drive the `NtSetInformationProcess` TLS class `LdrpHandleTlsData` uses,
under the loader lock, so the *loader* allocates the index, the block and the
slot. That is a feature with its own measurement round, not a patch to this
fragment.

## Reflective loading — why user-mode TLS provisioning cannot work (2026-10-18, second round)

Host: Windows x64, Defender real-time protection off (checked at the start of
the round). Method: a scratch plain-exe reproducer (`build/tls_repro.rs`,
gitignored) that does only what the mapper's TLS step does — read `gs:[0x58]`,
copy the loader's entries, allocate a wider array and a payload block, publish
the index, leave the thread — plus the real artifact under the project's lldb
wrapper. This round was run because the 2026-10-18 entry above left "skipping
the collision" as inferred rather than measured.

- **The index spaces are not shared.** A plain process has static module indices
  `0` and `1` (the exe and one DLL) and its `TlsAlloc` also returns `1`: the
  dynamic and static counters are independent and only overlap numerically. A
  `TlsAlloc` result is therefore not "past every module" in any guaranteed way.
- **The loader's array holds the modules' entries.** Reading
  `TEB.ThreadLocalStoragePointer` alongside the `LDR_DATA_TABLE_ENTRY` list shows
  populated entries `0` and `1` only. `HeapSize` on that block did not return,
  i.e. it is not a process-heap allocation.
- **A wider private array still crashes — in `LdrShutdownThread`.** The
  reproducer installed a `VirtualAlloc` array whose payload index was past every
  module's, then let the thread return: `0xC0000005` in `LdrShutdownThread`
  reading `array - 0x10` (the heap chunk header), so ntdll frees the thread's TLS
  array from a heap it owns. With no provisioning the same program exits `42`.
- **A process-heap array or block does not help.** The `heap/heap` and
  `heap/virtual` variants reach `LdrShutdownThread → RtlFreeHeap` and stop on an
  internal breakpoint (`0x80000003`, the heap handle/validation error) instead of
  an access violation: neither the array nor the entries are process-heap blocks.
  Clobbering a *module's* slot with a process-heap block shows the same
  breakpoint — the 2026-10-17 crash seen from the other side.
- **`ExitProcess` does not run that teardown.** Provisioning on the main thread
  and letting the process exit (no restore) survives; the fault needs a thread
  that *returns* (`RtlExitUserThread`).
- **Restoring the loader's array before the thread returns survives** (the
  reproducer exits `42`), but it only moves the window: the payload's
  `thread_local` reads are then wrong again, and a payload that calls
  `ExitProcess` or keeps running on other threads is not covered.
- **The real artifact agrees.** `dist/poc_faithful_fix.exe` (Docker image, rustc
  1.98.1, `indirect` + `api_hash`, `proxy` + `all`, `strings: xor`,
  `polymorphism: full`) dies with `0xC0000005` reading `block - 8`, where the
  pointer is a 64 KiB-aligned `nt_alloc_vm` region holding the payload's `.tls`
  template; `dist/poc_faithful_notls.exe` is clean, re-confirmed in this round.

Conclusion: the provisioning cannot be done from user mode by writing the TEB
array or an entry in it. The only path is the loader's own static-TLS code
(`LdrpHandleTlsData`, or the `NtSetInformationProcess` TLS class it drives) with
a module entry and the loader lock — which also makes the image visible in the
load list, a product decision rather than a fragment patch. The fragment stays
with the callbacks only, pinned by
`the_mapper_does_not_provision_static_tls`.
