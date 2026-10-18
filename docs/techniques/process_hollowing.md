# Process hollowing — evidence

## Why this document exists

Process hollowing used to write the payload's sections into the target without
resolving the payload's import table, so the first call to an imported function
jumped into unmapped memory (`0xC0000005`). Fixing that exposed a second
limitation (TLS) and, while validating the fix, a third: a **relocation bug** in
the hollowing fragment itself.

## The blocker the TLS work uncovered

The fragment's relocation walk had `IMAGE_REL_BASED_HIGHLOW` (3) and
`IMAGE_REL_BASED_DIR64` (10) the wrong way round. An x64 image emits DIR64 for
every absolute address, so the code patched only the **low 32 bits** of each
relocated pointer. A payload loaded at its preferred base (0x140000000) inside a
target whose base is a high address (e.g. 0x7ff68ad10000) ended up with every
absolute pointer truncated into the low 4 GB — its TLS directory, its IAT and its
CRT's globals — which is why the payload faulted no matter how much loader state
was reconstructed. With the two constants swapped back the relocated addresses
are exact (measured: `AddressOfIndex` moved from `0x18ad2f240` — low half only —
to `0x7ff68ad2f240`).

## The TLS the loader would have provided

A `CREATE_SUSPENDED` target has not run its loader, so the payload's imported
DLLs are absent; a manually mapped image also never gets a TLS index, a
per-thread TLS block or an OS TLS slot. `stub_fragment.rs` now reproduces that
part of the loader:

1. **Let the target's loader initialize.** Patch the original entry point to
   `jmp $` (`EB FE`), resume, poll until the thread parks there (`PEB->Ldr` is
   then populated), suspend again.
2. **Load each imported DLL in the target** (remote `LoadLibraryA` through
   `NtCreateThreadEx`).
3. **Provision the payload's TLS.** Run `TlsAlloc` *in the target* (a throwaway
   remote thread; the index comes back as its exit status), publish the index
   where the payload reads `_tls_index`, allocate a private copy of the `.tls`
   template and point the main thread's TLS slot at it.
4. **Run the payload's `DLL_PROCESS_ATTACH` callbacks.** On the main thread, one
   at a time, parking it on a dedicated `jmp $` (`EB FE`) stub between calls so
   each callback runs with a TLS array in its TEB.
5. **Redirect the entry point.** `Rip` — not just `Rcx` — is set to the payload's
   entry. Without that the thread resumed inside the replaced image.

## Measured behavior

All runs on the development host, `svchost.exe` as the target, the Rust test
payload (`examples/payloads/test_payload.exe`):

| Scenario | Result |
|----------|--------|
| Hollowing, no import resolution (pre-fix baseline) | `0xC0000005` |
| Hollowing, imports resolved, relocations truncated | `0xC0000005` / `0xC0000409` |
| Hollowing, DIR64 relocations applied | TLS write hung on a low-half address |
| Hollowing, relocations + TLS provisioned | payload runs; the stub relays exit `0` |
| Hollowing + a `.CRT$XLB` callback, call based on the parked `rsp` | target dies: `0xC0000005`, fault address `-1` |
| Same, call based on `(rsp & !0xF) - 8` and `rsp` restored | callback's marker written, then the entry point's; exit `42` |

Rows 5–6 are the TLS-callback path (2026-10-14, Windows 11 26200). Row 5's
`-1` fault address is the signature of a misaligned `movaps`: the debugger's live
bytes at `rip` were `movaps [rbp+0x170], xmm0` with `rbp % 16 == 8`. The call
was issued from the stack pointer the thread parked with, so the callback ran
with `rsp % 16 == 0` while the ABI — and every frame the callback built — assumes
`8`. Rounding the emulated call site down to 16 bytes and restoring the parked
pointer before the hand-off fixed it, because the hand-off to the payload's entry
point must also see the loader's state.

The single-marker rows above are the current state: `.\dist\test_packed.exe`
exits with the payload's own exit code (`0`). In a debug build
(`build.stub.debug: true`) the stub also prints its `STUB_MARKER_<hex>`, which has
to be read in Process Explorer, because the hollowed `svchost.exe` has no console
attached. The end-to-end test asserts only "the stub did not fail through its own
error path".

## Remaining work

- The e2e tests are `#[ignore]`d by policy (`live-tests`): they compile a stub and
  run a loader, so they run by hand on the lab host. The callback-bearing payload
  one (`packs_and_runs_a_hollowed_payload_with_tls_callbacks`) is **green**
  (2026-10-14); it was the red that motivated row 5.

## References

- `src/engine/imports.rs` — the shared import resolver.
- `src/techniques/process_hollowing/stub_fragment.rs` — relocations, TLS
  provisioning and the entry-point hand-off.
- [Syscall layer](../features/ref/syscalls.md) — the syscall layer the hollowing
  fragment calls through (`nt_create_thread_ex` is what replaced
  `CreateRemoteThread`).
