# Early Bird APC injection

## Metadata

- **ATT&CK**: T1055.004 (Process Injection: Asynchronous Procedure Call)
- **Stability**: Experimental
- **YAML key**: `early_bird`
- **Introduced in**: unreleased (Early Bird injection)

## What it does

Creates a legitimate process suspended, writes the payload into it and queues an
APC to its main thread before the process has run, so the payload executes
during the target's own initialization — before the target's entry point, and
before the anti-malware hooks placed around it.

## YAML parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `payload` | string | no | the only declared payload | Name of the payload in `build.payloads` to run |
| `target` | string | no | `C:\Windows\System32\svchost.exe` | Process to create, suspend and inject into |
| `wait_ms` | integer | no | `0` | Bounded wait, in milliseconds, for the *target* to exit; `0` does not wait |

The payload must be `format: shellcode`; `plan::validate` rejects a `pe`, `dll`
or `dotnet` payload for this technique at build time, and checks that the
target's architecture matches `build.output.arch`.

## YAML example

```yaml
runtime:
  - technique: early_bird
    params:
      target: "C:\\Windows\\System32\\svchost.exe"
      wait_ms: 0
```

## How it works

1. `CreateProcessA` the target with `CREATE_SUSPENDED`: its main thread is parked
   before ntdll's `LdrInitializeThunk` has run.
2. `nt_alloc_vm` a `PAGE_READWRITE` region in the target (never RWX),
   `nt_write_vm` the payload into it, then `nt_protect_vm` it to read+execute.
3. `nt_queue_apc` the payload as a user APC on the target's main thread while it
   is still suspended, so the APC is first in the queue.
4. `nt_resume_thread`. The target's loader flushes the APC queue during its own
   initialization (`LdrInitializeThunk` → `NtTestAlert`) and delivers the APC;
   the payload therefore runs before the target's entry point.

The last step is the technique's selling point: the payload runs *before* the
target's own code, and before the user-mode hooks that antivirus products place
around the entry point.

### Return value and `wait_ms`

The payload runs in another process, so the loader cannot read the payload's own
exit code back. `wait_ms` bounds how long the loader waits for the *target* to
exit, and the returned code follows this table:

| `wait_ms` | Target's fate | `execute_payload` returns |
|-----------|---------------|---------------------------|
| `0` (default) | not waited for | `259` (`STILL_ACTIVE`) |
| `> 0` | exits inside the window | the target's exit status (e.g. `0xC000001D` for a payload that crashed it) |
| `> 0` | still running when the window expires | `259` (`STILL_ACTIVE`) |

`259` therefore means "the target's exit was not observed": either the plan did
not ask for a wait, or the target is still alive — which is what a real payload
(a beacon) does. A target that genuinely exits with `259` is indistinguishable;
the debug log (`build.stub.debug: true`) prints the observed status, and is the
authority.

Not waiting by default is deliberate: it keeps the technique *chainable* (the
loader walks on to the next step) and never blocks on a target that a real
payload keeps alive forever. `on_success`/`on_fail` and the following steps
behave as for any other Execution technique.

### Caveats

- **The payload's `build.payloads.*.args` do not reach the target.** For
  in-process techniques the runner calls `patch_command_line()`, which patches
  the *loader's* PEB (and kernelbase's cached pointer); a process created by
  `CreateProcessA` has its own PEB. The target's command line is exactly what
  `CreateProcessA` was given — its own path — and the injected shellcode
  inherits that.
- **The APC carries no payload arguments.** All queued arguments are null, so a
  payload that expects a configuration block cannot be described by this
  technique (the same limitation the other shellcode runners have).
- **`syscalls.mode: none` maps `nt_queue_apc` to `QueueUserAPC`,** which takes a
  single pointer-sized argument; `mode: indirect` calls `NtQueueApcThread` with
  the three arguments the native call has. The payload is entered as the APC
  routine and ignores both shapes. `mode: indirect` is x64-only, like the rest
  of the syscall layer.

## What it evades

- The payload never touches disk in cleartext and never runs under its own image
  name.
- The APC is delivered by a legitimate process's own loader thread, before the
  target's entry point and before the hooks placed around it.
- The region is never RWX: it is written `PAGE_READWRITE` and only then made
  read+execute.

## What detects it

- Kernel callbacks (`PsSetCreateProcessNotifyRoutineEx` and the process/image
  callbacks) see the cross-process allocation, write, protection change and the
  APC queued against a thread that has never run.
- ETW-TI reports the cross-process write into a freshly created process
  (`NtWriteVirtualMemory` against a target-process handle).
- Static: `CreateProcessA` is always imported (a loader entry point), and
  `QueueUserAPC` is imported in `syscalls.mode: none` (the syscall layer removes
  it in `mode: indirect`).
- Queuing an APC to a suspended thread before its process has started is itself
  a behavioral signature.

## Measurements

- Measured end to end (x64 and x86): a two-byte `ud2` payload plus a bounded
  `wait_ms` makes the loader relay the target's `0xC000001D`, which only happens
  if the APC was delivered. The static baseline (362 KB x64) is in
  `docs/measurements.md`.
- **Target choice matters.** The 32-bit `notepad.exe` of a recent Windows build
  is a launcher shim: `QueueUserAPC` on its thread fails with
  `ERROR_INVALID_HANDLE` (`0x80070006`), while the 64-bit one and `cmd.exe` (both
  architectures) work. The default `svchost.exe` is a real image; when a run
  fails on an unusual target, suspect the target before the technique.

## Implementation notes

- The fragment (`stub_fragment.rs`) receives the target path, the wait bound and
  every diagnostic through `render_fragment_for`, all rebuilt from obfuscated
  bytes, so no target string and no message reaches the artifact's `.rdata` in
  cleartext.
- `CreateProcessA` and `GetExitCodeProcess` stay Win32: creating the target and
  reading its exit status are loader entry points, not kernel calls the stub
  issues. Everything kernel-facing goes through the `nt_*` helpers
  (`nt_alloc_vm`, `nt_write_vm`, `nt_protect_vm`, `nt_queue_apc`,
  `nt_resume_thread`, `nt_wait_for_single_object`, `nt_close`).
- On a failure after the target was created, the thread is resumed best-effort
  and both handles are closed, so a broken deployment cannot leave a suspended,
  payload-carrying process behind.
- The APC routine is the payload itself: it must be position-independent code
  that returns to the APC dispatcher, calls `ExitProcess`/`ExitThread`, or never
  returns. A payload that returns leaves the target running normally.

## References

- MITRE ATT&CK T1055.004 — Process Injection: Asynchronous Procedure Call.
- ired.team — "Early Bird APC Queue Code Injection".
