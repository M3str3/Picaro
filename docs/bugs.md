# Known bugs and deferred hardening

This page is the backlog for defects that were confirmed but intentionally left
for a later session. It is not a wish list: every entry below is a real,
reproducible-by-reading defect (or a documented contract that the code does not
implement). Fix the entry, add the test, and delete the section.

The lab rule still applies: anything that compiles a stub or runs an artifact is
a live test and belongs to the dedicated lab host. The inert suite
(`cargo test`) must stay green for every change here.

## Fixed in the 2026-10-24 session

These were reported by the bug-bounty round and are no longer open:

- `NtOpenProcessToken` had a bogus fourth `attributes` argument; the helper is
  now three arguments and the `advapi32!OpenProcessToken` proxy passes the
  out-pointer in the kernel's slot.
- `network_stager` kept a failed attempt's error after a later attempt
  succeeded, so a successful retry was discarded (or ran the stale embedded
  copy). The retry outcome now prefers `fetched` over the last error.
- `patch_etw` patched x86 `stdcall` exports with a bare `ret`; it now emits
  `ret imm16` with the per-export argument bytes.
- `self_deletion` hard-coded the x64 `FILE_RENAME_INFORMATION` layout; it now
  selects the x86/x64 header and length offset, and validates the stream name.
- `reflective_loading` now bounds-checks relocation block headers and fixup
  targets, the TLS directory, the callback array and every callback address.
- `process_hollowing` now refuses a relocation-free image that moved, checks
  `SizeOfHeaders`/section ranges, clamps section destinations to `SizeOfImage`,
  uses the image's IAT width, bounds the DLL-name read and checks the remote
  `LoadLibraryA` exit status.
- The shared import resolver now falls back to `FirstThunk` when
  `OriginalFirstThunk` is zero, uses checked RVA arithmetic, bounds the IAT
  destination and reads names with `CStr::from_bytes_until_nul`.
- Payload names can no longer break out of the generated step comment.
- Staging/decryption failures now honour the step's `on_fail`.
- Non-ASCII strings survive both obfuscation strategies; an all-zero XOR key and
  `stack` with an explicit key are rejected.
- `DuplicateTokenEx` no longer passes the impersonation level as
  `EffectiveOnly` (the filtered-token bug); see the remaining level gap below.
- `guardrail` validates `expire_on` and `run_key`; `self_deletion` validates its
  stream; DLL/shellcode builds reject `erase_pe_header` and a targetless
  `timestomping`.
- Export names reject Rust keywords; the custom-stub `$SYSCALLS_BLOCK$` warning
  is emitted in both syscall modes.
- `thread_hijacking` closes the process handle on error; `veh_execution`
  checks `ExceptionAddress`; `hardware_breakpoints` rejects its AMSI
  dependencies, checks the VEH handler and initializes `AmsiOpenSession`'s
  out-parameter; `pe_injection` bounds the TLS callback array;
  `unhook_ntdll` restores the protection before propagating a relocation error;
  `dotnet_hosting` retries only on `DISP_E_BADPARAMCOUNT`.

## Open

### 1. Unknown `params` keys are silently dropped (medium)

`src/techniques/mod.rs:72-81`, every technique `Params`, `src/plan/schema.rs`.

`RuntimeStep` flattens the technique enum and `StepControl`, and only the
`bouncer` and `drop` parameter structs carry `deny_unknown_fields`. A typo such
as `params: { targte: ... }` deserializes to `Params::default()` and silently
hollows the default target; an `on_fial` typo becomes `on_fail: stop`. This
contradicts `docs/getting-started.md:60` and `docs/plan.md:10` ("unknown keys are
an error"). The existing
`src/plan/schema.rs::a_flat_param_is_dropped_and_the_default_applies` locks in
the *flat-key* migration hazard, not the `params` typo.

Why deferred: serde does not allow `deny_unknown_fields` on a struct that is
flattened. The fix needs a pre-deserialization pass over the raw
`serde_yml::Value` (compare every `params` key against the technique's known
keys) or a custom deserializer. Add a test per technique or one table-driven
test over the registry.

### 2. `conflicts` metadata is display-only and internally inconsistent (medium-low)

`src/techniques/mod.rs`, `src/features/mod.rs`, `src/plan/validate.rs`.

`TechniqueDef::conflicts` / `FeatureDef::conflicts` are rendered by
`techniques show` and checked for self-conflict, but never enforced. Some pairs
are rejected by bespoke validators (`api_resolution` + `process_hollowing`),
some only get an order advisory (`erase_pe_header` + `sleep_obfuscation`,
`image_path_spoofing` + `self_deletion`), and one declared pair is explicitly
accepted by a test (`reflective_loading` + `process_hollowing` as two steps,
`src/plan/validate.rs::accepts_two_execution_techniques_as_separate_steps`).

Why deferred: a blanket enforcement would break valid flat multi-step plans.
The design question is whether a conflict is per-payload, per-step or
per-build; answer it before touching the registry or the validator.

### 3. `DuplicateTokenEx` does not apply the requested impersonation level (medium)

`src/engine/api_resolution.rs:1276-1309`, `src/engine/syscalls/mod.rs`.

The wrapper now passes `EffectiveOnly = 0`, so the duplicate is not filtered,
but the requested `ImpersonationLevel` is still ignored: `NtDuplicateToken`
keeps the source token's level. A correct implementation mirrors Win32:
duplicate with `EffectiveOnly = FALSE`, then call
`NtSetInformationToken(TokenImpersonationLevel, ...)` on the new token. The
syscall layer has no `NtSetInformationToken` helper yet; add it with the usual
`none`/`indirect` pair, `SSNS` field and proxy metadata, then add a live test
that duplicates a token at `SecurityImpersonation` and checks
`TokenImpersonationLevel`.

### 4. Ekko runtime leaks handles and has a partial-queue failure window (medium-low)

`src/engine/templates/sleep_runtime.rs.tpl:341-347, 537-547`.

`h_event` is created per call and never closed; the queue is deleted only when
`DeleteTimerQueueEx` resolved. Every `queue_timer(...)?` also returns without
closing the event or deleting the queue, and because some timers are already
queued at that point the caller can resume while the timer thread still
encrypts the image. The same block backs the `Sleep` hook, so a payload that
sleeps in a loop leaks one kernel event handle per call.

Why deferred: cleanup on every path needs a drop guard (or an explicit error
path) and a live re-measurement of the hook. Do it as one change, not an
ad-hoc `CloseHandle` on the success path only.

### 5. Network-stager transport hygiene (low)

`src/techniques/network_stager/transport_subprocess.rs:123-133`,
`src/techniques/network_stager/transport_winhttp.rs:257-281`.

If the child downloader succeeds but `std::fs::read` fails, the decrypted
temp file is left on disk (`?` skips the `remove_file`). Neither transport caps
the body size, while the packer-side fetch caps at 64 MiB
(`src/engine/fetch.rs:15`), so a hostile or misconfigured server can grow the
stub's memory without bound. Add a size limit shared by both transports and a
cleanup guard around the read.

### 6. Launcher template re-scans user text with later placeholders (low)

`src/engine/managed.rs:256-263`.

`render_launcher` applies `.replace()` sequentially. A script or command that
contains `$JOIN$`, `$INTERACTIVE$`, `$COMMAND$` or `$AMSI_UTILS_HELPER$` is
inserted first and rescanned by the later replacements, so the C# literal can
differ from the file on disk. Render the template in one pass (or replace on a
copy that only contains the template).

### 7. `retf` gadget fallback (low, latent)

`src/engine/syscalls/prelude.rs:206-244` (mirror in `src/engine/syscalls/mod.rs`).

`scan_gadget` returns a `0F 05 CB` (`syscall; retf`) fallback when `.text` has
no `0F 05 C3`. `find_gadget` then returns it without scanning the rest of the
image for a proper `syscall; ret`. A `retf` pops a far return address and
corrupts the caller's stack. ntdll ships `0F 05 C3` in every supported build,
so this is latent; add a synthetic-module test and either scan the whole image
for a near return before accepting `retf`, or reject `retf` outright.

### 8. `reflective_loading` discards `DllMain`'s FALSE (low, needs a decision)

`src/techniques/reflective_loading/stub_fragment.rs:887-900`.

`call_dll_main` ignores the BOOL. A payload whose `DllMain(DLL_PROCESS_ATTACH)`
returns FALSE signalled that initialization failed, but the export path still
calls the requested export and the entry-point path returns `Ok(0)`. Decide
whether a FALSE should fail the load (mirroring the OS loader) or is a
best-effort warning, then document it in the README.

### 9. `process_ghosting` has the same unbounded relocation walk (moot while unimplemented)

`src/techniques/process_ghosting/stub_fragment.rs:240-296`.

`fix_relocations` trusts the relocation directory, the block header and the
page RVA, exactly like the old `reflective_loading` code. `process_ghosting` is
`Stability::Unimplemented` and cannot reach this path today, but whoever
implements the `NtCreateSection(SEC_IMAGE)` path must copy the bounds checks
from `reflective_loading` (directory/header, per-entry target and width, TLS).

### 10. Import descriptor with `OriginalFirstThunk != 0` and `FirstThunk == 0` (low)

`src/engine/imports.rs:164-186` and the IAT write in `patch_imports`.

The ILT fallback is fixed, but the IAT destination is still `FirstThunk`. A
descriptor that declares an ILT and leaves `FirstThunk` zero yields low IAT
RVAs; with the identity mapping used by `patch_imports`, that can point at the
DOS header and overwrite it. Reject such a descriptor as `Malformed` (or apply
a policy) instead of writing near RVA 0.

### 11. `dotnet_hosting` leaks the parameter `SAFEARRAY`s (low)

`src/techniques/dotnet_hosting/stub_fragment.rs:225-276`.

The `string[]`/`object[]` arrays created for `Invoke_3` are never destroyed,
including on the `DISP_E_BADPARAMCOUNT` retry. `SafeArrayDestroy` is not in the
fragment's current imports; add it and destroy the arrays after `Invoke_3`
returns (the retry needs its own empty array).

### 12. `reflective_loading` does not clamp section protections (low, hardening)

`src/techniques/reflective_loading/stub_fragment.rs:585-625`.

`fix_memory_protections` computes `VirtualAddress + VirtualSize` without
checking `SizeOfImage`. `NtProtectVirtualMemory` would fail rather than write,
so the impact is a failed load, not an out-of-bounds write. Clamp it the same
way the section write path is clamped.

## How to validate a fix

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
```

Live suite (dedicated lab host, Defender real-time protection off):

```bash
cargo build
cargo test --features live-tests -- --ignored
```

Never run the live suite on a shared or hosted machine. Verify
`Get-MpComputerStatus | select RealTimeProtectionEnabled` is `False` before
starting; a reboot can silently restore it.
