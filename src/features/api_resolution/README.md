# API resolution

- ATT&CK: T1106 (Native API)
- YAML: `build.stub.api_resolution`
- Scope: loader-wide (configures the generated loader)

## What it does

In `mode: proxy` the loader serves selected payload imports from proxies
generated in the stub, instead of letting the payload reach the real export. A
proxy is rebuilt on the native `Nt*` call through the syscall layer, so the
shadowed functions never enter the loader's IAT and the payload's calls are
answered from loader code.

## YAML parameters

```yaml
build:
  stub:
    api_resolution:
      mode: none | proxy                 # default: none
      apis: ["kernel32!ReadProcessMemory"]  # catalogue selections
      unmatched: forward | abort         # default: forward
```

- `mode` — `none` leaves import resolution untouched; `proxy` rewrites the
  payload's IAT so catalogue hits land on the generated proxies.
- `apis` — the selected catalogue entries, written as `dll!function`. The module
  side is normalized on lookup.
- `unmatched` — what an import *outside* the catalogue does: `forward` (default)
  resolves it normally; `abort` fails the load on the first non-catalogue import
  (with an advisory printed at build time).

The catalogue is deliberately small — the `lsass` critical path of a
mimikatz-style payload:

| Selector | Strategy |
| --- | --- |
| `ntdll!NtReadVirtualMemory` | route to `NtReadVirtualMemory` |
| `ntdll!NtOpenProcess` | route to `NtOpenProcess` |
| `kernel32!ReadProcessMemory` | route to `NtReadVirtualMemory` |
| `kernel32!OpenProcess` | route to `NtOpenProcess` |
| `kernel32!GetProcAddress` | handler (answers catalogue hits with the matching proxy) |

## YAML example

```yaml
build:
  stub:
    syscalls:
      mode: indirect
    api_resolution:
      mode: proxy
      apis:
        - "kernel32!ReadProcessMemory"
        - "kernel32!OpenProcess"
      unmatched: abort
runtime:
  - technique: reflective_loading
    params:
      payload: implant
```

## How it works

1. The selected `Nt*` names are merged into the syscall block, so `Nt*` proxies
   call through the same `nt_*` helpers everything else uses.
2. After the payload's relocations are applied and before its imports are
   resolved, the shared `patch_imports` walk serves each catalogue hit with the
   matching proxy (RVA, not pointer).
3. Every non-catalogue import is forwarded (resolved against the real export) or,
   with `unmatched: abort`, refused, failing the load.
4. A build-time check (`verify_no_intercepted_imports`) confirms the shadowed
   names never entered the loader's IAT.

## What it evades

- Static IAT analysis of the loader: the shadowed names are not imported; the
  loader's import table never lists `ReadProcessMemory`/`OpenProcess` (or the
  `Nt*` pair) even though the payload uses them.
- Userland hooks on the shadowed Win32 APIs: the payload's calls reach the
  proxy, which re-implements them on the native call rather than through the
  hooked export.

## What detects it

- Kernel callbacks and ETW-TI: the proxy eventually calls the kernel, which sees
  a legitimate-looking `Nt*` call.
- A payload that reads its own IAT and checks where the pointers live (the
  proxies are in the loader image, not in `kernel32`/`ntdll`).

## Implementation notes

- The catalogue, the semantics and the phase/decision log live in
  `docs/design/api-resolution.md`; this page is the operator reference.
- `mode: proxy` requires `syscalls.mode: indirect` (the proxies are rebuilt on the
  syscall layer) and a `pe`/`dll` payload (there is no IAT to rewrite otherwise).
  It is rejected with `process_hollowing`, because the proxies live in the loader
  image, which is not mapped in the target.
- `Strategy::Forward` (call the original, resolved dynamically) exists in the
  catalogue vocabulary but no shipped entry uses it today; it is reserved for
  "thick" APIs that cannot be re-implemented on a syscall.

## References

- MITRE ATT&CK T1106 — Native API.
- `docs/design/api-resolution.md` — spike evidence, scope, phases and
  limitations.
