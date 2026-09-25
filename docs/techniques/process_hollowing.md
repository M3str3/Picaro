# Process hollowing — payload import resolution

## Why this document exists

Process hollowing used to write the payload's sections into the target without
ever resolving the payload's import table. The payload's IAT therefore still
held pointers into the original image, and the first call to an imported
function jumped into unmapped memory (`0xC0000005`). This document describes the
fix and, importantly, the *second* limitation the fix exposed.

## What changed

`src/engine/imports.rs` renders a shared resolver into the stub
(`$IMPORTS_BLOCK$`). Both execution techniques use it:

- **process hollowing** (`src/techniques/process_hollowing/stub_fragment.rs`):
  after relocations, before the image is written, every thunk is resolved with
  `LoadLibraryA` + `GetProcAddress` and written into the payload's IAT slot.
  A failure aborts before the thread is redirected, so the payload never runs
  with a half-filled IAT.
- **reflective loading** (`src/techniques/reflective_loading/stub_fragment.rs`):
  its previous in-fragment `fix_imports` was replaced by the same resolver, so
  the walk now exists once.

Resolution runs in the packer stub's current process. System DLLs share one
base per session (ASLR for system DLLs is session-wide), so an address resolved
there is valid in the target **provided the target also has that DLL mapped**.
API set names (`api-ms-win-*`) are virtual; the loader resolves them through the
API set schema and `LoadLibraryA` returns the contract host, with a
family-based fallback (CRT contracts → `ucrtbase`, the rest → `kernel32`).

## The limitation the fix exposed

A process created with `CREATE_SUSPENDED` has **not run its loader yet**. On the
development host (Windows 10.0.26200 x64) this is directly observable:

- `PEB->Ldr` is `NULL` at the point the stub reads the PEB.
- Only `ntdll.dll` and the main image are mapped: reading a locally resolved
  `kernel32.dll` or `user32.dll` base from the target fails with
  `ERROR_PARTIAL_COPY`, while the same read from the `ntdll.dll` base succeeds.
- Consequently the payload's non-`ntdll` imports resolve to addresses that are
  not mapped in the target. Fixing the IAT is necessary but not sufficient.

Attempting to let the target's own loader initialize the swapped-in image does
not work either: when the main image is unmapped and replaced with a private
allocation, the loader fails during initialization and the process exits with
`STATUS_DLL_INIT_FAILED` (`0xC0000142`) — even when the entry point is a bare
`jmp $`, i.e. before any payload code runs. The loader is happy when the
original image is left in place.

A separate problem affects manually mapped images in general: the OS TLS slot a
module needs for `#[thread_local]` state is allocated by the loader when the
module is loaded. Neither hollowing nor reflective loading creates one, so a
Rust payload aborts with `STATUS_STACK_BUFFER_OVERRUN` (`0xC0000409`) once its
CRT touches thread-local state.

## Measured behaviour

All runs on the development host, `svchost.exe` as the hollowing target:

| Scenario | Result |
|----------|--------|
| Hollowing, no import resolution (pre-fix baseline) | `0xC0000005` |
| Hollowing, import resolution only (this change) | `0xC0000005` |
| Let the loader run first, then hollow and resolve imports | payload starts, then `0xC0000409` (CRT/TLS fast-fail) |
| Reflective loading | exits `0`; the payload's marker is printed |

That last row is *not* a hollowing result: reflective loading maps the payload
into a fully initialized process, so the marker reaches the terminal. Hollowing
is the case that cannot complete. The existing end-to-end tests therefore only
assert that the stub does not fail through **its own** error path (exit code
`1`); for hollowing they do not yet prove the payload runs to completion.

## Proposed follow-up

To make a full PE actually run in a hollowed target, the loader state has to be
provisioned, not just the IAT:

1. Let the target's loader initialize first (patch the original entry to a
   spin loop, resume, wait until the thread is parked, then suspend).
2. Load each imported DLL **in the target** so its base and TLS slot exist
   (e.g. `NtCreateThreadEx` calling `LoadLibraryA`, to stay off the static IAT).
3. Only then hollow and hand off, and run the payload's TLS callbacks.

That is a larger change than the import-table fix and is deliberately out of
scope here; this document records the evidence so the next session starts from
facts instead of re-deriving them.

## References

- `src/engine/imports.rs` — the shared resolver.
- `src/techniques/reflective_loading/stub_fragment.rs` — the original
  `fix_imports` this consolidates.
- `docs/techniques/indirect_syscalls.md` — the syscall layer the hollowing
  fragment calls through.
