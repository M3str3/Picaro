# AMSI Patch

*Patches `AmsiScanBuffer` in the current process so every scan returns clean,
disabling in-process AMSI inspection of scripts and .NET content.*

## What it does

Patches AmsiScanBuffer in the current process so it always returns S_OK
(clean), disabling AMSI for any code that invokes it in-process: PowerShell,
WMI, VBScript, JScript, and .NET assembly loading. It does not run the payload;
it only modifies process state, which is why it is a Preparation technique.

## How it works

```mermaid
sequenceDiagram
    participant L as Loader
    participant A as amsi.dll
    L->>A: LoadLibraryA(amsi.dll)
    L->>A: GetProcAddress(AmsiScanBuffer)
    L->>A: nt_protect_vm(RWX)
    L->>A: write 29 C0 C3 (sub eax,eax; ret)
    L->>A: restore original protection
    Note over L,A: AmsiScanBuffer now returns S_OK
```

### 1. Resolve the target export

1. Load `amsi.dll` (`LoadLibraryA`, a no-op if already loaded).
2. Resolve `AmsiScanBuffer` with `GetProcAddress`.

### 2. Overwrite the prologue

3. Make the first three bytes of `AmsiScanBuffer` writable (`nt_protect_vm` →
   `PAGE_EXECUTE_READWRITE`).
4. Write `sub eax, eax; ret` (`29 C0 C3`): zero EAX (S_OK) and return.
5. Restore the original page protection.

If `amsi.dll` cannot be loaded (e.g. AMSI is unavailable), the preparation
returns a clear error and the pipeline fails with a useful message.

## Integration

A **Preparation** step: the stub runs it before the Execution and it never
receives the payload. Place it earlier in `runtime:` than the Execution step.

## What it evades

- AMSI scanning of scripts and .NET assemblies **in the current process**.

## What detects it

- Hooks on `NtProtectVirtualMemory` targeting `PAGE_EXECUTE_READWRITE` over
  `amsi.dll`.
- ETW-TI (`Microsoft-Windows-Threat-Intelligence`) on suspicious memory writes.
- Memory scanning / YARA looking for the `29 C0 C3` (or `B8 57 00 07 80 C3`)
  patch at the start of `AmsiScanBuffer`. Signatures vary per EDR.
- AMSI event log entries if the patch is applied only partially or too late.

## Measurements

- Pending — needs a .NET or script payload that actually invokes AMSI.

## Implementation notes

- The patch `29 C0 C3` is chosen because it is the shortest valid stub
  (`sub eax, eax; ret`). An alternative is `mov eax, 0x80070057; ret`
  (`B8 57 00 07 80 C3`), which returns `E_INVALIDARG`; `29 C0 C3` is shorter.
- Only affects the current process. If the payload runs in another process
  (e.g. process hollowing), that process's AMSI is not patched here; doing so
  will require a parameter on the corresponding execution technique.
- `amsi.dll` and `AmsiScanBuffer` are reconstructed at runtime through
  `StringsConfig` (`render_fragment`), so they never appear in cleartext in
  `.rdata`. The page protection change goes through the syscall layer's
  `nt_protect_vm`, so `mode: indirect` removes the `VirtualProtect` import;
  `LoadLibraryA`/`GetProcAddress` stay Win32 (as in every technique).

## References

- AMSI bypass / patch techniques (e.g. the classic `AmsiScanBuffer` byte patch).
- MITRE ATT&CK T1562.001 — Impair Defenses: Disable or Modify Tools.
