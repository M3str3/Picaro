# Hardware breakpoints

*Emulates the AMSI scan exports and the ETW event writer with the CPU's debug
registers, so a trap returns clean without modifying a single byte of the target
module.*

## What it does

Arms a hardware breakpoint on each watched export and installs a vectored
exception handler that answers for it. When `AmsiScanBuffer` (or
`EtwEventWrite`, or the optional `AmsiScanString`/`AmsiOpenSession`) is about to
run, the CPU raises a debug exception *before* the first instruction; the
handler returns `S_OK` (and `AMSI_RESULT_CLEAN` for the scan exports) and
resumes at the caller, so the real function never executes and the module's
`.text` stays byte-identical to the copy on disk.

It does not run the payload; it only modifies process state (the debug registers
of the current thread and the vectored-handler list), which is why it is a
Preparation technique.

The default watches `AmsiScanBuffer` and `EtwEventWrite` — two of the four debug
registers. The optional `AmsiScanString` and `AmsiOpenSession` raise it to four.

## How it works

```mermaid
sequenceDiagram
    participant L as Loader (Preparation)
    participant K as Kernel
    participant H as Vectored handler
    participant T as amsi.dll / ntdll.dll
    L->>L: GetProcAddress the watched exports
    L->>K: AddVectoredExceptionHandler(breakpoint_handler)
    L->>K: NtGetContextThread(current thread)
    L->>K: NtSetContextThread(Dr0..Dr3 = exports, Dr7 = execute)
    Note over L,T: exports are untouched; only the CPU is armed
    T->>K: caller invokes AmsiScanBuffer
    K-->>H: EXCEPTION_SINGLE_STEP (Rip == watched address)
    H->>H: Rax = 0, [AMSI_RESULT*] = 0
    H->>K: resume at the caller's return address
    Note over T: AmsiScanBuffer never ran
```

### 1. Resolve the watches and pick the debug registers

1. Load `amsi.dll` (and `ntdll.dll` for `EtwEventWrite`) with `LoadLibraryA`.
2. Resolve each export with `GetProcAddress`; each takes one of the four debug
   registers `DR0`–`DR3`. `AmsiScanBuffer` and `EtwEventWrite` are load-bearing
   (a failure aborts the preparation); `AmsiScanString`/`AmsiOpenSession` are
   best effort.

### 2. Install the handler

3. Register the vectored handler with `AddVectoredExceptionHandler` *before*
   arming, so a trap cannot fire while the handler is missing.
4. Publish each watch (address + the stack offset of its out-parameter) for the
   handler in a process-global table.

### 3. Arm the debug registers

5. Read the current thread's `CONTEXT` with the syscall layer's
   `nt_get_context_thread`.
6. Set `Dr0`–`Dr3` to the watched addresses and `Dr7` to a local-enable bit per
   slot, with `R/W = 00` and `LEN = 00` (an *execute* breakpoint on the first
   byte). Write the context back with `nt_set_context_thread`.

### 4. Answer the trap

7. When a watched export is reached, the CPU raises `EXCEPTION_SINGLE_STEP` with
   `Rip` equal to the watched address.
8. The handler sets `Rax = 0`, stores `AMSI_RESULT_CLEAN` in the caller's
   out-parameter when the export has one, then pops the return address off the
   stack and resumes there. The export never runs and nothing in the module was
   written to.

## Integration

A **Preparation** step: the stub runs it before the Execution and it never
receives the payload. Its job overlaps `patch_amsi` and `patch_etw` — pick one
of the two shapes, not both. `plan::validate` accepts a
`hardware_breakpoints` step (with `amsi: true`) in place of `patch_amsi` before
`powershell_hosting`, so a plan that prefers the register-based bypass for the
in-process host does not draw the AMSI advisory.

The `AMSI_RESULT*` stack offsets are x64: `AmsiScanBuffer`'s sixth argument
(`[Rsp+0x30]`) and `AmsiScanString`'s fifth (`[Rsp+0x28]`), count including the
return address and the 32-byte shadow space — the same numbers the software
patch writes.

## What it evades

- AMSI scanning of scripts and .NET assemblies **in the current process**.
- ETW events from the user-mode writer **in the current process**.
- Memory-integrity checks that compare `amsi.dll`/`ntdll.dll` `.text` against the
  on-disk copy: there is no patch to find.
- Signatures/YARA hunting the classic patch bytes at the start of the scan
  exports.

## What detects it

- Reading the debug registers: a non-zero `DR0`–`DR3` on a thread that is not
  being debugged is itself the tell (an EDR can read `DR*` through
  `NtGetContextThread` from another process).
- A `#DB` (`EXCEPTION_SINGLE_STEP`) raised at `AmsiScanBuffer` entry.
- The `AddVectoredExceptionHandler` import and the `NtGet/SetContextThread`
  pair in the loader's IAT.
- ETW-TI and call-stack telemetry that see the handler on the stack at the
  moment AMSI was invoked.

## Measurements

- Measured end to end on Windows 11 26200 (2026-10-14): the trap answers
  `AmsiScanBuffer` at its entry — a call with a null context returns `S_OK` with
  `AMSI_RESULT_CLEAN` written to the caller's out-parameter, where the real
  `amsi.dll` returns `E_INVALIDARG` (`0x80070057`). That proves the real function
  body never ran; it is **not** a detection-bypass number: on the measurement host
  AMSI's provider is inert (Defender real-time protection off), and with real-time
  protection on the AMSI test sample runs unflagged, so a "blocked vs allowed"
  comparison is not available there. Numbers: `docs/measurements.md`.

## Implementation notes

- **Per-thread.** The debug registers belong to a thread, so only the thread
  that ran the Preparation is covered. A loader that calls AMSI/ETW from another
  thread (a hosted CLR's worker, for instance) is not protected there; the
  hardware-breakpoint check in `anti_debug` reads the same registers.
- **Four slots.** `DR0`–`DR3` are all the CPU has, so the four watched exports
  exactly fill the machine. A plan that also wants `anti_debug`'s
  hardware-breakpoint *detection* competes for the same four registers.
- **x64 only.** The handler resumes the caller by popping the x64 return address
  and writes the AMD64 `CONTEXT`; the x86 form (a `ret N` emulation) is future
  work, so `requires` is `windows-x64` and `plan::validate` rejects it on x86.
- `amsi.dll`, `ntdll.dll` and every export name are rebuilt at runtime through
  `StringsConfig` (`render_fragment`), so none reaches `.rdata`. Arming the
  registers goes through the syscall layer's `nt_get_context_thread` /
  `nt_set_context_thread`, so `mode: indirect` removes the
  `GetThreadContext`/`SetThreadContext` imports; `LoadLibraryA`/`GetProcAddress`
  stay Win32 (as in every technique).

## References

- Hardware-breakpoint AMSI bypasses (the debug-register + vectored-handler
  pattern, e.g. the "hardware breakpoint hooking" family).
- MITRE ATT&CK T1562.001 — Impair Defenses: Disable or Modify Tools.
- MITRE ATT&CK T1562.006 — Impair Defenses: Indicator Blocking.
