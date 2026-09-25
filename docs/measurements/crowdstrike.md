# CrowdStrike — process hollowing

## EDR

- Product: CrowdStrike Falcon (tier-1)
- Version: <fill in>
- Configuration: default sensor policy

## Technique

- Name: process hollowing
- ATT&CK: T1055.012

## Config (YAML used)

```yaml
schema: 1
name: test-msgbox

input:
  path: ./examples/payloads/test_payload.exe

payload:
  crypto:
    algo: xchacha20poly1305
    key: random

pipeline:
  - technique: process_hollowing
    target: "C:\\Windows\\System32\\svchost.exe"

output:
  path: ./dist/test_packed.exe
  arch: x64
  strip: true
  trim_paths: all
```

## Result

- [ ] Blocked
- [ ] Allowed
- [x] Partial

The stub runs and shows its own `STUB_MARKER_<hex>` MessageBox, but the payload
is **not** executed inside `svchost.exe`: CrowdStrike detects the hollowing in
runtime and prevents the payload from running.

## Where it was blocked

Runtime (behavioral). The hollowing sequence itself (suspend → unmap → RWX
write → resume) is flagged, and the payload never runs in the target process.
This is the expected outcome for a tier-1 EDR: the phase 4/5 goal is *static*
evasion, not beating CrowdStrike at runtime.

## Evidence

- Screenshot: <path>
- Log: <path>

## Additional observation (static, on the packer binary)

CrowdStrike also blocks execution of the **packer/audit tool itself**
(`batesian.exe`) with `Access denied`. The audit module embeds malware-API
string literals (`NtUnmapViewOfSection`, `VirtualAllocEx`, `WriteProcessMemory`,
...) and technique keywords (`hollow`, `inject`, `loader`, `shellcode`) for its
string scan, so the measurement tool trips the same static heuristics it is
meant to measure. Something to keep in mind when running it on a hardened host.

## Date

- 2026-09-25
