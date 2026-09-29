# Reflective loading

## Metadata

- **ATT&CK**: T1620 (Reflective Code Loading)
- **Stability**: Experimental
- **YAML key**: `reflective_loading`
- **Introduced in**: Phase 6

## What it does

Maps a PE image into the current process's memory (manual mapping): allocates
at the image's preferred base, copies headers and sections, resolves imports,
applies base relocations, fixes section memory protections, runs TLS callbacks
and then executes the payload's entry point in a separate thread. No external
target process is required.

For a `format: shellcode` payload there is no image to map: the decrypted bytes
are copied into an executable allocation and run on a thread instead (see
“Payload formats” below).

## YAML parameters

None. The payload format and, for a DLL, its exported entry point come from
`build.payloads.<name>` (`format`, `export`), and the command-line arguments from
`build.payloads.<name>.args` / `build.payloads.<name>.args_mode`.

## YAML example

```yaml
# A PE payload (default).
runtime:
  - technique: reflective_loading
```

```yaml
# A shellcode payload.
build:
  payload:
    source: ./beacon.bin
    format: shellcode
runtime:
  - technique: reflective_loading
```

```yaml
# A DLL payload with an exported entry point.
build:
  payload:
    source: ./payload.dll
    format: dll
    export: Run
runtime:
  - technique: reflective_loading
```

## How it works

1. Validate the image (MZ and PE signatures, x64 magic).
2. Allocate memory at the preferred image base (fall back to any address if it
   is taken) through `nt_alloc_vm`.
3. Copy the PE headers and each section's raw data into the allocation.
4. Resolve imports (`LoadLibraryA` + `GetProcAddress`), patching the import
   address table.
5. Apply base relocations if the image did not land at its preferred base.
6. Set each section's final memory protection (`nt_protect_vm`).
7. Run TLS callbacks, if present.
8. Run the entry point (`DllMain` for a DLL, `mainCRTStartup`-style for an EXE)
   on a new thread and return its exit code.

With `build.payloads.<name>.export` (DLLs only), step 8 changes: the entry point is
called once with `DLL_PROCESS_ATTACH` — the loader step a mapped DLL needs so
its CRT and global constructors initialize — and then the named export is called
with no arguments instead of running the entry point on a thread. The process
exits 0 once the export returns.

## Payload formats

The technique renders a different fragment per `build.payloads.<name>.format`:

- `pe` and `dll` map the image as above; the `is_dll` flag is read from the
  file-header characteristics.
- `shellcode` uses a runner fragment: there is no image, so the decrypted bytes
  are copied into a `PAGE_EXECUTE_READWRITE` allocation (`nt_alloc_vm`) and run
  on a thread whose entry is a `fn() -> u32`. The region is intentionally leaked,
  since the shellcode may have spawned work that outlives the wait.

`process_hollowing` cannot run these two formats; `plan::validate` requires
`reflective_loading` for them.

### Payload arguments

Before mapping, `execute_payload` calls `patch_command_line()` (shared, in
`src/engine/args.rs`, rendered as `$ARGS_BLOCK$`). The payload runs in *this*
process, so the stub's own command line has to be replaced with
`<exe> <yaml args> <runtime args>` (combined by `build.payloads.<name>.args_mode`).

Two places are updated (see `src/features/args/README.md`):

1. `PEB->ProcessParameters->CommandLine` (the `UNICODE_STRING` PEB-reading tools
   see), repointed at a new leaked UTF-16 buffer; and
2. the pointer `kernelbase` caches at process start and returns from
   `GetCommandLineW` — measured on Windows 11, patching only the PEB does **not**
   change what the payload's CRT reads. The cache is found by scanning
   `kernelbase` for the original buffer pointer, so no version-specific offset is
   hardcoded.

The line's token 0 is the executable name (the stub's own path), never an
argument, so the payload's `argv[0]` is the stub exe and the payload args start
at `argv[1]`.

## What it evades

- The payload never touches disk: it is decrypted in memory and mapped directly.
- No `CreateProcess` on the payload, no visible child process.
- No external process to hollow or inject into.

## What detects it

- **Userland hooks** on `VirtualAlloc`/`VirtualProtect` when a `PAGE_EXECUTE_*`
  region is created (RWX or RX transitions). These go through the syscall layer's
  `nt_alloc_vm`/`nt_protect_vm`, so `mode: indirect` bypasses the hooks and
  removes the Win32 imports.
- **ETW-TI** (`Microsoft-Windows-Threat-Intelligence`) for suspicious memory
  allocations.
- **Kernel callbacks** that flag executable private memory.
- **Memory scanning / YARA** over the in-memory image (the same static
  signatures that flag the file on disk apply in memory).
- High-entropy executable regions that do not map to a loaded module.

## Architectures

The mapper is shared by `x64` and `x86`: the NT headers, the TLS directory and
the entry-point call are selected by `#[cfg]`, and the 4-byte thunks / 32-bit
IAT slots come from the shared import resolver (`src/engine/imports.rs`). On x86
the entry point is called through the x86 ABI (arguments on the stack); the
mapper never uses a register hand-off.

## TLS provisioning

A manually mapped image gets a real TLS index, a private copy of its `.tls`
template and a slot on the calling thread, so a payload's `thread_local` state
starts at its image-initialized values. Two measured facts shape the code:

- The slot has to be written into the loader's array
  (`gs:[0x58]` / `fs:[0x2C]`), which is what a CRT reads through `_tls_index`.
  `TlsSetValue` writes a *different* array (`gs:[0x1480]` / `fs:[0xE10]`), and a
  payload provisioned that way reads another module's block.
- The index still comes from `TlsAlloc`, because the reservation it makes is
  what the thread's teardown expects: ntdll reads the block header of every
  unreserved entry when the thread exits and the process dies with an access
  violation or heap corruption. See `docs/measurements.md`.

Limitations: threads the payload creates itself have no slot for this index, the
index can coincide with a loaded module's (the module then sees the payload's
template bytes in that thread), and a module loaded later can be handed the same
index.

## Measurements

- TODO — pending a static/dynamic baseline (see `docs/measurements.md`).

## Implementation notes

- The entry point runs on a separate thread so the stub can wait for it and
  capture its exit code. If the payload calls `ExitProcess`, it terminates the
  whole stub process (and its thread).
- Payload arguments are rewritten into the PEB and `kernelbase`'s cached
  command-line pointer before the payload runs, so the payload's `argv` is what
  the operator configured (`build.payloads.<name>.args` + runtime args).
- Allocation and page protection go through the syscall layer
  (`nt_alloc_vm`/`nt_protect_vm`); `CreateThread` stays Win32 because
  `NtCreateThreadEx` takes eleven arguments, more stack arguments than the
  indirect-syscall trampoline currently shuffles.

## References

- MITRE ATT&CK T1620 — Reflective Code Loading.
- Manual mapping / reflective DLL injection papers (Stephen Fewer, Hasherezade).
