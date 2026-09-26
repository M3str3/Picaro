# Process hollowing

## Metadata

- **ATT&CK**: T1055.012 (Process Injection: Process Hollowing)
- **Stability**: Experimental
- **YAML key**: `process_hollowing`
- **Introduced in**: Phase 4

## What it does

Runs the decrypted payload inside a legitimate, suspended process
(`svchost.exe` by default) by unmapping its original image and replacing it
with the payload's image, so the payload never executes from disk under its own
name.

## YAML parameters

| Parameter | Type   | Required | Default                          | Description                     |
|-----------|--------|----------|----------------------------------|---------------------------------|
| `target`  | string | no       | `C:\Windows\System32\svchost.exe` | Process to create, suspend and hollow |

## YAML example

```yaml
runtime:
  - technique: process_hollowing
    params:
      target: "C:\\Windows\\System32\\svchost.exe"
```

## How it works

1. Create a legitimate process (`svchost.exe`) suspended with
   `CreateProcessA(..., CREATE_SUSPENDED)`.
2. Read the suspended thread's context (`GetThreadContext`) to find the PEB
   (`Rdx` on x64) and, from it, the image base (`PEB + 0x10`).
3. Unmap the legitimate image with `NtUnmapViewOfSection` (resolved dynamically
   from `ntdll.dll`).
4. Allocate memory at the same base with `VirtualAllocEx`
   (`MEM_COMMIT | MEM_RESERVE`, `PAGE_EXECUTE_READWRITE`).
5. Fix up base relocations if the preferred image base changed.
6. Resolve the payload's import table and fill in its IAT (see below).
7. Write the payload's headers and sections with `WriteProcessMemory`.
8. Redirect the thread to the payload entry point (`SetThreadContext` → `Rcx`).
9. Resume the thread (`ResumeThread`).

### Import resolution

Step 6 walks the payload's import descriptors and, for every thunk, calls
`LoadLibraryA` + `GetProcAddress` and writes the resulting address into the
payload's IAT slot, before the image is written to the target. This is the same
walk reflective loading uses; both share the resolver injected as
`$IMPORTS_BLOCK$` (`src/engine/imports.rs`), so it is not duplicated between the
two execution fragments. Any import that cannot be resolved aborts the build of
the process *before* the thread is redirected, so a payload never starts with a
half-filled IAT.

The addresses are resolved in the packer stub's **current** process. Windows
assigns system DLLs one base per session (ASLR for system DLLs is session-wide,
not per-process), so a resolved address is valid in the target as long as the
target has that DLL mapped. API set names (`api-ms-win-*`) are virtual and are
resolved by the loader through the API set schema; `LoadLibraryA` therefore
returns the contract host's module (with a family-based fallback for the CRT
contracts).

> **Known limitation (open).** A process created with `CREATE_SUSPENDED` has
> **not run its loader yet** (`PEB->Ldr` is `NULL`; only `ntdll.dll` and the main
> image are mapped). Resolving the IAT is necessary but not yet sufficient: the
> payload's other imports (`kernel32.dll`, `user32.dll`, …) may be absent from
> the target, in which case the first import call jumps to unmapped memory. The
> Windows loader also refuses to initialize the swapped-in image (it exits with
> `STATUS_DLL_INIT_FAILED`), so the target's own loader cannot be used to load
> these DLLs either. See `docs/techniques/process_hollowing.md` for the measured
> evidence and the proposed follow-up.

### Payload arguments

The command line passed to `CreateProcessA` is built from `build.payload.args`
plus the args the operator passes to the packed binary, combined by
`build.payload.args_mode` (`join`/`override`). The shared helper lives in
`src/engine/args.rs` (`$ARGS_BLOCK$`); see
`docs/techniques/process_argument_spoofing.md`.

The line is `<target exe name> <args>`: **token 0 is the executable name, never
an argument**, so the payload's `argv[0]` is `svchost.exe` and the payload args
start at `argv[1]`. The suspended target's `RTL_USER_PROCESS_PARAMETERS` keeps
this line when the payload image is swapped in, and the target's CRT has already
built its `argv` from it, so `GetCommandLineW` inside the payload returns it.

> The command line is ANSI (`CreateProcessA`), so non-ASCII arguments are
> converted to the active code page; keep payload arguments ASCII.

## What it evades

- The payload never touches disk in cleartext (no drop, no `CreateProcess` on
  the payload itself), so file-based scanners never see the payload.
- The process tree shows a legitimate, signed `svchost.exe`, not the payload.

## What detects it

- **Kernel callbacks** (`PsSetCreateProcessNotifyRoutine` / `ObRegisterCallbacks`)
  see the suspend → write → resume sequence and the `PAGE_EXECUTE_READWRITE`
  allocation.
- **Userland hooks** on `VirtualAllocEx`/`WriteProcessMemory`/`ResumeThread`
  (the very APIs the technique depends on).
- **ETW-TI** (`Microsoft-Windows-Threat-Intelligence`) reports the cross-process
  memory write to a signed process.
- **Static**: the stub still statically imports `VirtualAllocEx` and
  `WriteProcessMemory`, and keeps `NtUnmapViewOfSection` as a cleartext string
  for `GetProcAddress` (this is what phase 5 measures).

## Measurements

- See `docs/measurements/crowdstrike.md`.

## Implementation notes

- Current implementation allocates `PAGE_EXECUTE_READWRITE` (RWX) directly; a
  later phase should switch to RW → write → RX via `VirtualProtectEx`.
- The PEB's `ImageBaseAddress` is not rewritten, so payloads that read it to
  locate themselves may misbehave. The current test payload does not.
- The IAT is patched in the local image buffer before it is written, so the
  target receives a complete image in one write sequence and a resolution
  failure cannot leave a half-patched IAT behind.
- `GetThreadContext`/`SetThreadContext` are given a 16-byte aligned `CONTEXT`
  (`AlignedContext`): x64 requires it, while the `windows` binding only
  guarantees 8.
- Import resolution is shared with reflective loading
  (`src/engine/imports.rs`); the fragment only supplies an RVA→file-offset
  mapper.
- The payload command line is shared with reflective loading
  (`src/engine/args.rs`, `$ARGS_BLOCK$`) and passed as `lpCommandLine`;
  `build_command_line` returns it with the target's file name as token 0.

## References

- MITRE ATT&CK T1055.012 — Process Injection: Process Hollowing.
