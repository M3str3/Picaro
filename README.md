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

A build is one YAML document: `build.payloads` maps name → your binary,
`build.output.path` is where the packed PE lands, and the `runtime` list is the
ordered chain of techniques:

```yaml
schema: 6
name: my-build

build:
  payloads:
    payload:
      source: ./my_payload.exe   # local path, or file:// / http(s)://
  output:
    path: ./dist/my_payload_packed.exe

runtime:
  - technique: process_hollowing
    params:
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
