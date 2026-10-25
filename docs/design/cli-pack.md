# CLI pack design

`picaro pack` builds a payload without a hand-written YAML plan. It is a
**frontend**, not a second build path: it composes a schema-6 plan in memory,
writes it next to the artifact and feeds it through the same loader, validator
and build engine as `picaro build`.

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

The default root is `packed/` (configurable with `dir` or `--dir`). Each payload
gets a folder named after its file stem, and the folder is the complete package —
the generated stub, the encrypted payloads and the artifact's provenance live
together:

```text
packed/
└── mimikatz/
    ├── main.rs                 # the rendered Rust stub
    ├── payload_0.bin           # encrypted payload(s), one per Execution step
    ├── mimikatz.exe            # the packed artifact
    ├── mimikatz.manifest.json  # provenance (the build manifest)
    ├── plan.yaml               # the generated plan, saved by default
    ├── mimikatz.ca.cer         # only with --sign lab
    └── .picaro/lab/            # only with --sign lab: CA + leaf identity
```

The same layout is used by `picaro build`: the package folder is named after the
plan and is created inside the directory of `build.output.path` (or under
`packed/` when the plan declares a bare filename). A hand-written plan with
`path: ./dist/loader.exe` and `name: loader` produces
`dist/loader/loader.exe` plus its sources and provenance.

`--out` selects the artifact name and its directory: the artifact name is kept
and the plan folder is created under the selected directory. The plan is written
beside it unless `--no-save-plan`; `--plan-out` overrides the path.
`--print-plan` writes the canonical YAML to stdout and exits without building
(the banner is suppressed so the output stays redirectable).

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
  plan: true            # save <dir>/<payload>/plan.yaml
  allow_experimental: false
```

Every key is optional and CLI flags always win. `exec: auto` keeps the
format-driven default. A missing implicit file means "use the built-in
defaults"; a missing `--config` path is an error.

## Implementation

`src/pack/mod.rs` composes a `Plan` and serializes it. `compose` then calls
`plan::load_plan_str`, the in-memory twin of `load_plan`, so the generated
document gets the same `$arg` substitution, format resolution and validation as
a file. The validated plan is serialized again and that is what gets written and,
for `--print-plan`, printed.

`cli/mod.rs` only maps clap fields to `PackArgs` and calls the existing `build` /
`dry_run` paths. `BuildOptions` gained a heading and a short prelude so both
commands report the invocation the operator actually ran.

## Limits

`pack` composes one payload, registered under its file stem. Multi-payload plans,
`drop`/decoy assets, network stagers, `bouncer` policies with structured
requirements and other nested parameters use `--step` for individual steps, or
`--print-plan` and edit the YAML. A `--step` document that names
`params.payload` must use that file stem (or omit it: one payload is implicit).
That is intentional: the flags stay a short, learnable surface, and YAML remains
the full-power interface.
