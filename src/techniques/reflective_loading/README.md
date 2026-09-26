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

## YAML parameters

None. Payload arguments are not per-technique: they come from
`build.payload.args` / `build.payload.args_mode` (see below).

## YAML example

```yaml
runtime:
  - technique: reflective_loading
```

## How it works

1. Validate the image (MZ and PE signatures, x64 magic).
2. Allocate memory at the preferred image base (fall back to any address if it
   is taken).
3. Copy the PE headers and each section's raw data into the allocation.
4. Resolve imports (`LoadLibraryA` + `GetProcAddress`), patching the import
   address table.
5. Apply base relocations if the image did not land at its preferred base.
6. Set each section's final memory protection (`VirtualProtect`).
7. Run TLS callbacks, if present.
8. Run the entry point (`DllMain` for a DLL, `mainCRTStartup`-style for an EXE)
   on a new thread and return its exit code.

### Payload arguments

Before mapping, `execute_payload` calls `patch_command_line()` (shared, in
`src/engine/args.rs`, rendered as `$ARGS_BLOCK$`). The payload runs in *this*
process, so the stub's own command line has to be replaced with
`<exe> <yaml args> <runtime args>` (combined by `build.payload.args_mode`).

Two places are updated (see `docs/techniques/process_argument_spoofing.md`):

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
  region is created (RWX or RX transitions).
- **ETW-TI** (`Microsoft-Windows-Threat-Intelligence`) for suspicious memory
  allocations.
- **Kernel callbacks** that flag executable private memory.
- **Memory scanning / YARA** over the in-memory image (the same static
  signatures that flag the file on disk apply in memory).
- High-entropy executable regions that do not map to a loaded module.

## Measurements

- TODO — pending a static/dynamic baseline (see `docs/measurements/`).

## Implementation notes

- The entry point runs on a separate thread so the stub can wait for it and
  capture its exit code. If the payload calls `ExitProcess`, it terminates the
  whole stub process (and its thread).
- Payload arguments are rewritten into the PEB and `kernelbase`'s cached
  command-line pointer before the payload runs, so the payload's `argv` is what
  the operator configured (`build.payload.args` + runtime args).

## References

- MITRE ATT&CK T1620 — Reflective Code Loading.
- Manual mapping / reflective DLL injection papers (Stephen Fewer, Hasherezade).
