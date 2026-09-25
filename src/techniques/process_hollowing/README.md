# Process hollowing

## Metadata

- **ATT&CK**: T1055.012 (Process Injection: Process Hollowing)
- **Stability**: Stable
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
pipeline:
  - technique: process_hollowing
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
5. Write the payload's headers and sections with `WriteProcessMemory`.
6. Fix up base relocations if the preferred image base changed.
7. Redirect the thread to the payload entry point (`SetThreadContext` → `Rcx`).
8. Resume the thread (`ResumeThread`).

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

## References

- MITRE ATT&CK T1055.012 — Process Injection: Process Hollowing.
