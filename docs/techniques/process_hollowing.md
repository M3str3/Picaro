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

## Implemented follow-up (loader + DLLs)

The first two steps of the plan below are now implemented in
`src/techniques/process_hollowing/stub_fragment.rs`:

1. **Let the target's loader initialize.** `run_stage_two` patches the original
   entry point to `jmp $` (`EB FE`) after making the entry page writable
   (`nt_protect_vm`), resumes the thread, polls `GetThreadContext` until `Rip`
   reaches the spin loop (so the loader has finished and `PEB->Ldr` is
   populated), then suspends the thread again (`nt_suspend_thread`).
2. **Load each imported DLL in the target.** The fragment walks the payload's
   import descriptors for DLL names and, for each, writes the name into the
   target and runs `LoadLibraryA` there via a remote thread
   (`CreateRemoteThread`), so the target has every DLL's base mapped before the
   IAT is resolved and the image is written. `NtCreateThreadEx` was considered
   (to stay off the static IAT) but takes eleven arguments — more than the
   indirect-syscall trampoline currently shuffles — so `CreateRemoteThread` is
   used for now.

Both steps add two syscall helpers to the layer: `NtProtectVirtualMemory`
(`nt_protect_vm`) and `NtSuspendThread` (`nt_suspend_thread`).

## Remaining work (TLS)

Step 3 of the original plan is still open: the payload's **TLS directory** is
not provisioned. The OS TLS slot a module needs for `#[thread_local]`/CRT state
is allocated by the loader when the module is loaded, and neither hollowing nor
reflective loading creates one, nor are the payload's TLS callbacks run in the
target. A Rust payload that touches thread-local CRT state on entry can still
fast-fail with `STATUS_STACK_BUFFER_OVERRUN` (`0xC0000409`). The follow-up is
(1) run the payload's TLS callbacks with `DLL_PROCESS_ATTACH` on the main
thread, and (2) allocate a TLS index (`TlsAlloc`) and copy the `.tls` template
into the thread's TLS slots before handing off.

## References

- `src/engine/imports.rs` — the shared resolver.
- `src/techniques/reflective_loading/stub_fragment.rs` — the original
  `fix_imports` this consolidates.
- `docs/techniques/indirect_syscalls.md` — the syscall layer the hollowing
  fragment calls through.
