# Syscall layer — design

Operator reference: `src/features/syscalls/README.md`.
This page is the implementation and decision record behind it.

## Placement

`build.stub.syscalls` is a *loader* configuration, not a `runtime:` technique:
it changes how every `nt_*` helper reaches the kernel, so it applies to the
whole generated stub rather than to one ordered step. The registry entry is
metadata only (`src/features/syscalls/mod.rs`); the implementation is
`src/engine/syscalls/`, and each SSN resolver is a self-contained module under
`src/engine/syscalls/resolvers/<name>/`
(see the [syscalls feature](../features/ref/syscalls.md)).

## Phases

| Phase | Resolver | What it added |
| --- | --- | --- |
| 6a | [Hell's Gate](../features/ref/syscalls/hells_gate.md) | SSN read from the live `Nt*` export prologue; trampoline through the ntdll gadget |
| 6b | [Tartarus Gate](../features/ref/syscalls/tartarus_gate.md) | SSN read from a clean on-disk copy of ntdll, so live hooks do not hide it; gadget still from live ntdll |
| 6c | [API hashing](../features/ref/syscalls/api_hash.md) | Same clean copy, matched by FNV-1a 64-bit hash of the export name (no `GetProcAddress`, no name string) |
| 6d | [Halo's Gate](../features/ref/syscalls/halos_gate.md) | Live export table; a hooked stub's SSN is derived from the nearest intact 32-byte neighbour, with the clean copy as fallback |

## Design notes

- **Fragment contract.** Technique fragments always call the `nt_*` helpers;
  `$SYSCALLS_BLOCK$` gives each helper a `none` (Win32) and an `indirect`
  (syscall) implementation, so a technique is written once.
- **Union of requirements.** A technique declares its `Nt*` functions in
  `TechniqueDef::syscalls`; the packer resolves only the deduplicated union of
  the active pipeline's requirements, so unused SSNs are never resolved and
  their names never emitted.
- **Trampoline arity.** `nt_invoke` carries eleven argument slots (the widest
  call a technique needs is `NtCreateThreadEx`). `syscall` pushes no return
  address, so the kernel reads arguments 5+ from the slots the Windows x64 ABI
  already put them in; the shim only sets `r10`/`eax`/`r11`.
- **Clean-copy walk.** `$FILE_PE_HELPERS$` (`rva_to_offset`, `pe16_at`,
  `pe32_at`) is shared by the Tartarus Gate and API-hashing resolvers.
- **API hash sync.** The FNV-1a hash is mirrored between
  `engine::syscalls::api_hash` and the generated stub, and unit-tested.

## Related

- **Stack spoofing** (`build.stub.syscalls.stack_spoofing`) is a property of
  this layer: it rewrites the `nt_invoke` trampoline at load time, so it applies
  on top of `mode: indirect`. It has no position in `runtime:`.
- **ntdll unhooking** (`unhook_ntdll`) is a *technique* too; it restores the live
  ntdll's `.text` from disk and runs in pipeline order (see the advisory about
  running it before the patchers).
- **API resolution** (`build.stub.api_resolution`) builds its proxies on this
  layer; see [`api-resolution.md`](api-resolution.md).

## Measurements

Phase 6a baseline: artifact `517,632 B → 525,312 B`; suspicious imports `2 → 0`;
`NtUnmapViewOfSection` string gone; every `nt_*` call returns `STATUS_SUCCESS`.
See [Measurements](../measurements.md).

## Known limitations

- `mode: indirect` is x64-only; x86 indirect syscalls are a parked workstream
  ([x86 support](../x86.md)).
- Stack spoofing lives in the layer (`build.stub.syscalls.stack_spoofing`); ntdll
  unhooking is a separate technique.
- Direct syscalls (no ntdll gadget) are **not** implemented; the layer supports
  `none` and `indirect` only.

## References

- [Measurements](../measurements.md) — phase 6a numbers.
- [x86 support](../x86.md) — why indirect syscalls are x64-only.
