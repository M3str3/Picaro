---
title: Picaro
description: Declarative PE packer for authorized red team research
template: splash
hero:
  tagline: A declarative PE packer for authorized red team research — a PE, a DLL or raw shellcode plus a YAML plan becomes a packed binary with the evasion techniques you select.
  image:
    file: ../../assets/picaro_logo.png
    alt: Picaro logo
  actions:
    - text: Get started
      link: /getting-started/
      icon: right-arrow
      variant: primary
    - text: Browse techniques
      link: /techniques/
      icon: open-book
      variant: minimal
    - text: Create plan
      link: /plan-builder/
      icon: open-book
      variant: minimal
---

:::danger[Authorized use only]
This is a malware loader packer for **authorized red team engagements, lab
environments and security research**. Packing and executing a binary you do not
own, or do not have written permission to test, is out of scope. You are
responsible for what you build with it.
:::

The preferred way to run Picaro is its bundled Docker wrapper:
`python scripts/picaro.py` needs only Docker and Python and behaves the same on
Linux, macOS and Windows. See [Getting started](/getting-started/) for the full
loop; a from-source `cargo run -- …` build works too.

## The docs in one screen

- **[Getting started](/getting-started/)** — requirements, a first plan, and the
  build → run → measure loop.
- **[Plan](/plan/)** — every block of a schema-6 document, plus the interactive
  wizard that writes one.
- **[Examples](/examples/)** — the runnable plans and recipes.
- **[Techniques](/techniques/)** — the Preparation / Execution / Control model and
  one page per runtime technique.
- **[Loader features](/features/)** — the cross-cutting stub configuration:
  syscall layer, API resolution, string obfuscation and payload arguments.
- **[Hosts](/hosts/)** — loading a packed DLL from a JVM, CPython, .NET,
  `rundll32` and other host programs.
- **[Architecture](/architecture/)** — how the packer and the generated stub fit
  together, and custom stubs.
- **[Reference](/measurements/)** — measured evidence and per-technique deep
  dives.

The Markdown under `docs/` is the single source of truth. The per-technique and
per-feature pages, the plan reference and the examples page are pulled from
`src/techniques/<name>/README.md`, `src/features/<name>/README.md`, `README.md`
and `examples/README.md` at build time, so they never drift.
