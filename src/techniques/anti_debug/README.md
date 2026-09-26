# Anti-Debug

## Metadata

- **ATT&CK**: T1622 (Debugger Evasion)
- **Stability**: Stable
- **Category**: Preparation
- **YAML key**: `anti_debug`
- **Introduced in**: Phase 7

## What it does

Checks the current process for signs of a debugger and, by default, aborts the
preparation so the payload never runs. It does not execute the payload, which is
why it is a Preparation technique. The goal is to stop interactive analysis of
the packed binary: a debugger that is attached when the stub starts makes the
stub fail closed instead of handing over a decrypted payload.

## YAML parameters

| Parameter | Type   | Required | Default | Description |
|-----------|--------|----------|---------|-------------|
| `action`  | string | no       | `abort` | `abort` fails the preparation; `continue` notes the detection and keeps going. |

## YAML example

```yaml
runtime:
  - technique: anti_debug
    params:
      action: abort
```

## How it works

Three independent signals are combined; a positive result from any of them is a
detection:

1. **PEB `BeingDebugged`** — `IsDebuggerPresent()` reads `PEB->BeingDebugged`,
   the flag the OS sets when a debugger attaches.
2. **Kernel debug port** — `CheckRemoteDebuggerPresent(GetCurrentProcess(), …)`
   queries `ProcessDebugPort`, which is also set for a debugger attached at
   creation time (e.g. `CreateProcess` with `DEBUG_PROCESS`).
3. **Hardware breakpoints** — `GetThreadContext` with
   `CONTEXT_DEBUG_REGISTERS_AMD64` reads DR0–DR3 of the current thread; a
   non-zero register means a debugger set a hardware breakpoint (typical for
   single-step / watchpoint based reversing).

A check that cannot be *read* (an error, rather than a positive hit) is treated
as "not detected", so an unavailable check never aborts the pipeline on its own.

With `action: abort`, a detection makes the preparation return an error, which
fails the run before the payload is executed. With `action: continue`, the run
proceeds regardless — useful when the packed binary is itself being tested under
a debugger.

## What it evades

- Interactive user-mode debugging (WinDbg, x64dbg, Visual Studio) of the packed
  stub, both attached at launch and attached after it starts.
- Automated sandboxes that run samples under a debugger for API tracing.

## What detects it

- A defensive analyst simply disabling the debugger sees the stub run normally;
  the technique is bypassable by patching out the checks. It raises cost, it does
  not prevent analysis.
- The imports it pulls in (`IsDebuggerPresent`, `CheckRemoteDebuggerPresent`,
  `GetThreadContext`) are classic anti-analysis indicators and are visible to any
  static scanner in the import table. Note that `IsDebuggerPresent` is already
  imported by the Rust standard library in the baseline stub, and the current
  `batesian audit` heuristic does not classify debugger APIs as suspicious, so
  they do not raise the tool's own risk summary.
- A detection with `action: abort` surfaces as a stub error before the payload
  runs (the error path prints the message to stderr and exits non-zero), which is
  itself an observable signal.

## Measurements

- See `docs/measurements/phase7_etw_anti_debug.md`.

## Implementation notes

- The techniques map to ATT&CK T1622; the sub-signals are the three checks above.
- The `windows` `CONTEXT` binding only guarantees 8-byte alignment, so the
  fragment wraps it in a `#[repr(align(16))]` struct, as x64 `GetThreadContext`
  requires. This mirrors the process-hollowing fragment.
- No string literals: every check is a direct import, so nothing needs to go
  through `StringsConfig`. That trade-off (no literals, but three tell-tale
  imports) is the main OPSEC cost of this technique.
- Resolving the checks dynamically (PEB walk / `GetProcAddress` with obfuscated
  names) or through `NtQueryInformationProcess` in the syscall layer is a later
  migration, exactly like the pending `patch_amsi` migration.
- `action: continue` still runs all checks (so the code path stays identical);
  it only changes whether a detection is turned into an error. A future
  parameter could add a delay action to defeat automated sandboxes.

## References

- Anti-debugging check catalogue (PEB flag, debug port, hardware breakpoints).
- MITRE ATT&CK T1622 — Debugger Evasion.
