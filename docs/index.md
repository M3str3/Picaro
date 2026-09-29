![picaro logo](assets/picaro_logo.png){ .picaro-logo }

# picaro

`picaro` is a declarative PE packer for authorized red team research. It takes
a PE (or a DLL, or raw shellcode) and a YAML plan, and emits a packed PE with
the selected evasion techniques baked into a freshly generated Rust stub. The
payload is authenticated-encrypted at build time and only ever exists decrypted
in memory at run time.

!!! warning "Authorized use only"

    This is a malware loader packer for **authorized red team engagements, lab
    environments and security research**. Packing and executing a binary you do
    not own, or do not have written permission to test, is out of scope. You are
    responsible for what you build with it.

## The docs in one screen

- **[Getting started](getting-started.md)** — requirements, a first plan, and
  the commands to build, run and measure it.
- **[Plan](plan.md)** — every block of a schema-6 document,
  plus the interactive wizard that writes one.
- **[Examples](examples/index.md)** — the runnable plans and recipes.
- **[Techniques](techniques/index.md)** — the Preparation/Execution model and
  one page per runtime technique.
- **[Loader features](features/index.md)** — the cross-cutting stub
  configuration (syscall layer, API resolution, string obfuscation, payload
  arguments).
- **[Architecture](architecture.md)** / **[Custom stubs](custom-stubs.md)** —
  how the packer and the stub fit together.
- **[Reference](measurements.md)** — phase measurements, hollowing evidence and
  the schema migration guides.

The Markdown under `docs/` is the single source of truth. The per-technique and
per-feature pages, the plan reference and the examples page are pulled from
`src/techniques/<name>/README.md`, `src/features/<name>/README.md`, `README.md`
and `examples/README.md` at build time, so they never drift.
