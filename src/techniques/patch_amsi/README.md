# AMSI Patch

## Metadata

- **ATT&CK**: T1562.001 (Impair Defenses: Disable or Modify Tools)
- **Stability**: Experimental
- **Category**: Preparation
- **YAML key**: `patch_amsi`
- **Introduced in**: Phase 7

## What it does

Patches AmsiScanBuffer in the current process so it always returns S_OK
(clean), disabling AMSI for any code that invokes it in-process: PowerShell,
WMI, VBScript, JScript, and .NET assembly loading. It does not run the payload;
it only modifies process state, which is why it is a Preparation technique.

## YAML parameters

None.

## YAML example

```yaml
pipeline:
  - technique: patch_amsi
```

## How it works

1. Load `amsi.dll` (`LoadLibraryA`, a no-op if already loaded).
2. Resolve `AmsiScanBuffer` with `GetProcAddress`.
3. Make the first three bytes of `AmsiScanBuffer` writable (`VirtualProtect` →
   `PAGE_EXECUTE_READWRITE`).
4. Write `sub eax, eax; ret` (`29 C0 C3`): zero EAX (S_OK) and return.
5. Restore the original page protection.

If `amsi.dll` cannot be loaded (e.g. AMSI is unavailable), the preparation
returns a clear error and the pipeline fails with a useful message.

## What it evades

- AMSI scanning of scripts and .NET assemblies **in the current process**.

## What detects it

- Hooks on `VirtualProtect` targeting `PAGE_EXECUTE_READWRITE` over `amsi.dll`.
- ETW-TI (`Microsoft-Windows-Threat-Intelligence`) on suspicious memory writes.
- Memory scanning / YARA looking for the `29 C0 C3` (or `B8 57 00 07 80 C3`)
  patch at the start of `AmsiScanBuffer`. Signatures vary per EDR.
- A static strings scan for the cleartext literals `AmsiScanBuffer` and
  `amsi.dll` in `.rdata` (these are not obfuscated yet).
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
- `amsi.dll` and `AmsiScanBuffer` are emitted as cleartext byte literals, so
  they appear in a static strings scan. Obfuscating them (or resolving AMSI via
  indirect syscalls) is left for a later phase.

## References

- AMSI bypass / patch techniques (e.g. the classic `AmsiScanBuffer` byte patch).
- MITRE ATT&CK T1562.001 — Impair Defenses: Disable or Modify Tools.
