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
2. Read the suspended thread's context to find the PEB (`Rdx` on x64) and, from
   it, the image base (`PEB + 0x10`). The context calls go through the syscall
   layer, so `Get`/`SetThreadContext` no longer appear in the stub's imports.
3. **Let the target's loader initialize.** Patch the original entry point to an
   infinite loop (`jmp $`), resume the thread, wait until it parks in the loop
   (so the loader has mapped the process's default DLLs and populated
   `PEB->Ldr`), then suspend it again. The original image is unmapped later, so
   the patched bytes never need restoring.
4. **Load the payload's imported DLLs in the target.** Each imported DLL name
   is written into the target and loaded there with a remote thread that calls
   `LoadLibraryA` (`NtCreateThreadEx` through the syscall layer), so the target
   has every DLL's base mapped. Loading an already-loaded DLL is a no-op.
5. Unmap the legitimate image with `NtUnmapViewOfSection`.
6. Allocate memory at the same base (`MEM_COMMIT | MEM_RESERVE`,
   `PAGE_EXECUTE_READWRITE`).
7. Fix up base relocations if the preferred image base changed.
8. Resolve the payload's import table and fill in its IAT (see below).
9. Write the payload's headers and sections.
10. **Provision the payload's TLS** (see below): a real TLS index allocated in
    the target, the index published where the payload reads `_tls_index`, and a
    per-thread copy of the `.tls` template pointed at by the main thread's TLS
    slot.
11. Redirect the thread to the payload entry point (`Rip` — and `Rcx`, the
    register a payload entry-point ABI may expect).
12. Resume the thread (`NtResumeThread`) and relay the target's exit code.

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
target has that DLL mapped — which step 4 guarantees. API set names
(`api-ms-win-*`) are virtual and are resolved by the loader through the API set
schema; `LoadLibraryA` therefore returns the contract host's module (with a
family-based fallback for the CRT contracts).

> **Known limitation (open).** The payload's **TLS callbacks** are not run yet.
> A callback has to run on a thread, and a freshly created (never started)
> thread has no TLS array in its TEB, so its slot cannot be provisioned the way
> the main thread's is. The TLS *index*, the per-thread template copy and the
> main thread's slot **are** provisioned (step 10), so a payload whose CRT reads
> thread-local state now runs; a payload that needs its `DLL_PROCESS_ATTACH`
> callback for something else still loses that init. Taking the callback thread
> through a started state first (or hand-building its TLS array) is the
> follow-up; evidence in `docs/techniques/process_hollowing.md`.

### Payload arguments

The command line passed to `CreateProcessA` is built from `build.payloads.<name>.args`
plus the args the operator passes to the packed binary, combined by
`build.payloads.<name>.args_mode` (`join`/`override`). The shared helper lives in
`src/engine/args.rs` (`$ARGS_BLOCK$`); see
`src/features/args/README.md`.

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
- **Userland hooks** on `VirtualAllocEx`/`WriteProcessMemory`/`ResumeThread`/
  `CreateRemoteThread` (the very APIs the technique depends on in
  `syscalls.mode: none`).
- **ETW-TI** (`Microsoft-Windows-Threat-Intelligence`) reports the cross-process
  memory write to a signed process.
- **Static**: the stub still statically imports `CreateProcessA`,
  `CreateRemoteThread`, `LoadLibraryA`, `GetProcAddress`, `GetThreadContext`,
  `SetThreadContext`, `WaitForSingleObject`, `GetExitCodeProcess` and
  `CloseHandle`. The Nt* calls (`NtUnmapViewOfSection`, `NtAllocateVirtualMemory`,
  `NtWriteVirtualMemory`, `NtReadVirtualMemory`, `NtResumeThread`,
  `NtProtectVirtualMemory`, `NtSuspendThread`) go through the syscall layer and
  never appear as imports or cleartext strings in `mode: indirect`.
- **Static (diagnostics)**: every error message the fragment can print is
  obfuscated as well — `MESSAGES` in `mod.rs` feeds `render_fragment`, which
  rebuilds each one at runtime — so no diagnostic text, and no technique keyword
  such as `loader`, reaches `.rdata`.

## Architectures

`process_hollowing` supports `x64` and `x86`, and the stub must match the
target's architecture: the technique replaces a *32-bit* process's image with a
32-bit payload, and a 64-bit one with a 64-bit payload. `arch: x86` builds a
32-bit stub, which runs under WOW64 and hollows the 32-bit `svchost.exe` (the
default `System32\svchost.exe` is redirected to `SysWOW64` for it).

What differs from the x64 path:

- the payload parser reads PE32 offsets (`ImageBase` is a `u32` at 28, the data
  directories start at 96);
- `Get`/`SetThreadContext` use the native `CONTEXT32` and the PEB's
  `ImageBaseAddress` is read from `Ebx` (the x64 path uses `Rdx`);
- the entry point is written to `Eip`; there is no register hand-off, because
  x86 passes arguments on the stack;
- the target thread's TLS array is `fs:[0x2C]` with 4-byte entries (x64:
  `gs:[0x58]`, 8-byte).

## Measurements

- See `docs/measurements.md`.

## Implementation notes

- The loader-init step (3) makes the entry page writable for the `jmp $` patch
  and leaves it `PAGE_EXECUTE_READWRITE`; the page is unmapped moments later, so
  the RWX window is tiny. The payload allocation itself is still
  `PAGE_EXECUTE_READWRITE` (RWX); a later phase should switch to RW → write → RX.
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
- `CreateRemoteThread` (remote `LoadLibraryA`) and
  `GetModuleHandleA`/`GetProcAddress` (to resolve its address) stay Win32
  imports: `NtCreateThreadEx` takes eleven arguments, more stack arguments than
  the indirect-syscall trampoline currently shuffles. Migrating them is a
  follow-up.
- The payload command line is shared with reflective loading
  (`src/engine/args.rs`, `$ARGS_BLOCK$`) and passed as `lpCommandLine`;
  `build_command_line` returns it with the target's file name as token 0.
- The payload's TLS is provisioned in the target before the thread is
  redirected: `TlsAlloc` runs there (on a throwaway thread, reading the index
  back from its exit status), the index is published where the payload's CRT
  reads `_tls_index`, and the main thread's TLS array slot is pointed at a
  private copy of the `.tls` template. The index has to be *reserved* through
  `TlsAlloc` — see `docs/measurements.md` for what ntdll does at thread exit to
  an unreserved entry. The TLS *callbacks* (`DLL_PROCESS_ATTACH`) are still not
  run (a never-started thread has no TLS array to point at; see the
  limitations in `AGENTS.md`).

## References

- MITRE ATT&CK T1055.012 — Process Injection: Process Hollowing.
