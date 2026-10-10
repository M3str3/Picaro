# Techniques overview

<p align="center">
  <img src="/jester-emblem-512.webp" alt="Picaro emblem: two stacked joker cards" height="130" />
</p>

A runtime is a list of technique steps applied in order. Techniques are split
into three categories (`TechniqueDef.category`):

- **Preparation** — modifies the current process state (e.g. patches AMSI) but
  never runs a payload.
- **Execution** — runs a decrypted payload; only these take `params.payload`.
- **Control** — orchestrates the chain (`living_off_the_land`, `network_stager`,
  `ppid_spoofing`, `sleep`).

A step only continues if the loader gets control back, so a **terminal** step
(`reflective_loading`/`process_ghosting` of a PE executable, `dotnet_hosting`)
must be the last one; `src/plan/validate.rs` enforces it. Everything else chains.

Every technique fragment calls the stub's `nt_*` helpers (`src/engine/syscalls/`:
`nt_alloc_vm`, `nt_write_vm`, `nt_read_vm`, `nt_protect_vm`,
`nt_create_thread_ex`, `nt_wait_for_single_object`, `nt_get_context_thread`,
…) for kernel-facing work, rather than the Win32 APIs directly (loader entry
points such as `CreateProcessA`, `LoadLibraryA`/`GetProcAddress` and
`TlsAlloc`/`TlsSetValue` stay Win32). See
[Syscall layer](../features/ref/syscalls.md).

The registry (`src/techniques/mod.rs`) is metadata-only; inspect it with
`picaro techniques list`, `picaro techniques show <name>` (a styled page that
pages long documents full-screen; `--raw` prints the Markdown verbatim) and
`picaro techniques validate`. Adding one:
[Adding a technique](adding-a-technique.md).

## Registered techniques

<!-- registry-table -->
