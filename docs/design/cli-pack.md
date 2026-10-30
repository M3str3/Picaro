# CLI pack design

`picaro pack` builds a payload without a hand-written YAML plan. It is a
**frontend**, not a second build path: it composes a schema-6 plan in memory,
writes it into the build's bundle and feeds it through the same loader,
validator and build engine as `picaro build`.

## Why

The YAML is not hard to learn; the friction is elsewhere:

- three blocks that must agree (`build.payloads`, `build.stub`, `build.output`);
- an ordered `runtime:` chain whose order matters and whose limits
  (`requires_indirect_syscalls`, conflicts, terminal steps) are easy to trip;
- 30+ techniques with different categories and parameters;
- validation messages that speak in YAML keys.

`pack` lets an operator start with one command, then graduate to YAML when the
build outgrows the flags.

## Command

```bash
picaro pack mimikatz.exe
picaro pack mimikatz.exe --patch-amsi --erase-header --hollow
picaro pack beacon.bin --syscalls indirect --resolver tartarus-gate --stack-spoofing
picaro pack app.exe --print-plan > app.yaml
```

The payload format is detected before composition, so the execution technique
can be chosen from it:

| Detected format | Default execution |
| --- | --- |
| `pe`, `dll`, raw shellcode | `reflective_loading` |
| `dotnet` | `dotnet_hosting` |
| `powershell` | `powershell_hosting` |

Built-in loader defaults: `syscalls: indirect` with `hells_gate` on x64,
`strings: xor` with a random key, `strip: true`, `trim_paths: all`.

A `dll` payload needs a callable entry: `DllMain` only initializes the library.
`pack` reads the export table. With no `--export`, it selects the only callable
export (e.g. `DllRegisterServer`) and announces it; several exports are an error
that lists them for `--export <name>`. An explicit `--export` is checked against
the table, so a typo fails before the build instead of in `GetProcAddress`.

## Flags

Canonical flags cover the common surface:

- execution: `--exec <technique>` and the shortcuts `--reflective-loading` and
  `--hollow`;
- steps: `-t/--technique <name>` (repeatable, ordered) and `--step <file.yaml>`
  (one `RuntimeStep` document, the escape hatch for nested parameters);
- loader: `--syscalls`, `--resolver`, `--stack-spoofing`/`--no-stack-spoofing`,
  `--strings`;
- output: `--dir`, `-o/--out`, `--arch`, `--kind`, `--entry`, `--export`,
  `--sign` (with its sub-flags), `--icon`, `--strip`/`--no-strip`,
  `--gui`/`--console`;
- flow: `--dry-run`, `--print-plan`, `--plan-out`, `--no-save-plan`, `--debug`,
  `--seed`, `--allow-experimental`.

Preparation shortcuts (`--patch-amsi`, `--patch-etw`, `--erase-header`,
`--unhook`, `--hide-module`) are sugar for `-t <name>`. They never replace the
generic flag: anything with structured parameters uses `--step`.

## Ordering

The composed chain is deterministic:

1. `--step` documents, in order;
2. `-t` techniques, in order;
3. preparation shortcuts, in their canonical order;
4. `--sleep`, if given;
5. the execution step.

Steps 3 and 4 are inserted **before the first execution step**, so
`-t reflective_loading --patch-amsi` still runs the patch first. If `--step` or
`-t` already declares an execution step, `--exec` is rejected (pick one way to
declare it); otherwise the format default is appended last. `--target` applies
to the single execution step and is only understood by `process_hollowing`,
`early_bird`, `pe_injection` and `thread_hijacking`.

## Stability gate

Explicitly selected non-`Stable` techniques need `--allow-experimental`; the
error names the technique and its stability and points at
`picaro techniques show <name>`. With the flag, the build proceeds and prints a
warning.

Format defaults are different: otherwise zero-config could never work, because
the three default execution techniques are `Experimental`. A defaulted
non-`Stable` technique **builds**, but prints a warning suggesting
`--allow-experimental` (which silences it) or `--exec` (which chooses another
technique). The distinction is "the packer chose it" versus "the operator chose
it".

## Output layout

Every build writes **one self-contained bundle** under `packed/`. The bundle is
both the build's working directory and its archive: source, encrypted payloads,
compiler output, the delivered artifact and the provenance travel together, and
two builds never share a folder.

The root is `packed/` by default (`dir:` in the config, `--dir`, or
`PICARO_BUNDLE_ROOT`). The folder is `<plan>-<run>`, where `<run>` is
`--build-name <name>` when given, otherwise `<pid>-<nanos>`:

```text
packed/
└── mimikatz-12345-1764000000000000000/
    ├── plan.yaml                   # the generated plan, saved by default
    ├── build/                      # the compiler workspace
    │   ├── main.rs                 # the rendered Rust stub
    │   ├── payload_0.bin           # encrypted payload(s), one per Execution step
    │   ├── out.exe                 # the compiled stub
    │   └── out.pdb                 # with --debug
    ├── dist/
    │   └── mimikatz.exe            # the canonical artifact (signed, hashed)
    └── artifacts/
        ├── mimikatz.manifest.json  # provenance (the build manifest)
        ├── mimikatz.ca.cer         # only with --sign lab
        └── .picaro/lab/            # only with --sign lab: CA + leaf identity
```

`build/` keeps `main.rs` next to the `payload_N.bin` files it includes with
`include_bytes!`, so the rendered source stays compilable on its own. `dist/`
holds the canonical artifact: it is the file that gets signed and hashed, and
the delivered copy is byte-identical. `artifacts/` holds everything a replay or
an audit needs. `prepare()` recreates only those three subdirectories, so a
bundle reused with the same `--build-name` keeps its `plan.yaml`.

`output.path` (or `--out`) only decides where the delivered artifact goes; it
never changes the bundle:

| `output.path` | Delivered artifact |
| --- | --- |
| omitted | `<bundle>/dist/<plan>.<ext>` (inside the bundle) |
| a file | exactly that path |
| a directory (existing, or with a trailing separator) | `<dir>/<plan>.<ext>` |

The same layout is used by `picaro build`. The plan's own `output.path` is
never rewritten, so a saved plan stays portable: a plan without a `path`
delivers into whichever bundle builds it. A hand-written plan with
`path: ./dist/loader.exe` and `name: loader` still creates
`packed/loader-<run>/` and delivers to `./dist/loader.exe`.

`--build-name <name>` pins the bundle to `packed/<plan>-<name>/`, so
`packed/<plan>-debug/build/main.rs` is a stable path for a debugger (see
`--debug`). `--plan-out <path>` writes an extra copy of the plan outside the
bundle; `--no-save-plan` skips the bundled one (a reused bundle keeps the
`plan.yaml` a previous run wrote, since `prepare()` only touches `build/`,
`dist/` and `artifacts/`). `--print-plan` writes the canonical YAML to stdout
and exits without building (the banner is suppressed so the output stays
redirectable).

`picaro build` resolves the same layout: `--build-name` names the bundle,
`--out` overrides the delivered path, and `PICARO_BUNDLE_ROOT` moves the root.
The legacy `PICARO_BUILD_DIR` is deliberately ignored: it named the old
temporary scratch directory, and honoring it now would move the bundle — the
archive — out of a mounted directory (a container wrapper that still sets it
would lose every build with the container). A bundle that fails before the
artifact is written (a payload hash mismatch, say) may exist with only `build/`
populated — the tree is created before the payloads are read.

Saving the plan by default is part of the reproducibility contract: the manifest
records the plan hash, and the plan must exist somewhere to rebuild it.

## Configuration

`picaro.config.yaml` in the current directory (or `--config <path>`) holds the
defaults:

```yaml
pack:
  dir: packed
  exec: auto            # auto = choose from the payload format
  arch: x64
  kind: exe
  syscalls: indirect
  resolver: hells_gate
  stack_spoofing: false
  strings: xor
  sign: none
  strip: true
  gui: false
  plan: true            # save <dir>/<plan>-<run>/plan.yaml
  allow_experimental: false
```

Every key is optional and CLI flags always win. `exec: auto` keeps the
format-driven default. A missing implicit file means "use the built-in
defaults"; a missing `--config` path is an error.

## Implementation

`src/pack/mod.rs` composes a `Plan`, resolves the run's `BundleLayout` and
serializes the plan. `compose` then calls `plan::load_plan_str`, the in-memory
twin of `load_plan`, so the generated document gets the same `$arg`
substitution, format resolution and validation as a file. The validated plan is
serialized again and that is what gets written and, for `--print-plan`,
printed.

`cli/mod.rs` only maps clap fields to `PackArgs` and calls the existing `build` /
`dry_run` paths. `BuildOptions` carries the bundle `pack` already resolved (so
`build` does not re-derive it) plus a heading and a short prelude, so both
commands report the invocation the operator actually ran.

## Limits

`pack` composes one payload, registered under its file stem. Multi-payload plans,
`drop`/decoy assets, network stagers, `bouncer` policies with structured
requirements and other nested parameters use `--step` for individual steps, or
`--print-plan` and edit the YAML. A `--step` document that names
`params.payload` must use that file stem (or omit it: one payload is implicit).
That is intentional: the flags stay a short, learnable surface, and YAML remains
the full-power interface.
