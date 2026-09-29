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
4. **Redirect the entry point.** `Rip` — not just `Rcx` — is set to the payload's
   entry. Without that the thread resumed inside the replaced image.

## Measured behaviour

All runs on the development host, `svchost.exe` as the target, the Rust test
payload (`examples/payloads/test_payload.exe`):

| Scenario | Result |
|----------|--------|
| Hollowing, no import resolution (pre-fix baseline) | `0xC0000005` |
| Hollowing, imports resolved, relocations truncated | `0xC0000005` / `0xC0000409` |
| Hollowing, DIR64 relocations applied | TLS write hung on a low-half address |
| Hollowing, relocations + TLS provisioned | payload runs; the stub relays exit `0` |

The last row is the current state: `.\dist\test_packed.exe` prints its
`STUB_MARKER_<hex>` and exits with the payload's own exit code (`0`). The
end-to-end test still asserts only "the stub did not fail through its own error
path"; the marker itself still needs Process Explorer, because the hollowed
`svchost.exe` has no console attached.

## Remaining work

- **TLS callbacks are not run.** A callback has to run on a thread, and a thread
  that has never started has no TLS array in its TEB, so its TLS slot cannot be
  provisioned the way the main thread's is (measured: writing the slot of a fresh
  thread faults the target). Running them needs either the callback executed on
  the main thread — parked on a `jmp $` stub between calls — or hand-building the
  callback thread's TLS array from the main thread's entries.
- The end-to-end test could assert the payload's exit code once the marker
  question above is solved in a way that survives a console-less target.

## References

- `src/engine/imports.rs` — the shared import resolver.
- `src/techniques/process_hollowing/stub_fragment.rs` — relocations, TLS
  provisioning and the entry-point hand-off.
- [Syscall layer](../features/ref/syscalls.md) — the syscall layer the hollowing
  fragment calls through (`nt_create_thread_ex` is what replaced
  `CreateRemoteThread`).
