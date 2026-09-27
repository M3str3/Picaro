# Migrating a plan from schema 1 to schema 3

Schema 3 is a **syntax** change, not a behaviour change: the same build is
described with a different key layout. Schema 1 is no longer accepted — a YAML
that declares `schema: 1` fails at parse time with a migration hint, and there
is no compatibility mode.

If your plan declares `schema: 2`, it is much closer: only the `strings` move
described in `docs/migration-v2-v3.md` applies.

> Schema 3 was later superseded by schema 4 (runtime parameters moved under a
> nested `params:` mapping); see `docs/migration-v3-v4.md` for the second step.

## Why

Schema 1 scattered the build inputs across four top-level blocks (`input`,
`payload`, `loader`, `output`) plus a `pipeline`. That made it hard to see that
they all describe the same thing: *how to build the artifact*. Schemas 2 and 3
group them under a single `build` block (`payload`, `stub`, `output`) and
rename `pipeline` to `runtime`, so the two halves of a plan are explicit:
*what to build* (`build`) and *what to run at execution time* (`runtime`).
Schema 3 tightens this further: everything that describes the **stub** lives
in `build.stub`, so string obfuscation moves from `build.strings` to
`build.stub.strings` (it only ever affected the stub's literals). Schema 3 also
renames the build-argument placeholder from `$build.N$` (which would be
confusing inside the `build` block) to `$arg.N$`, making clear that it is an
argument external to the YAML.

## Field mapping

| Schema 1           | Schema 3                | Notes                                                          |
| ------------------ | ----------------------- | -------------------------------------------------------------- |
| `input.path`       | `build.payload.source`  | Now a plain string (path or URL).                              |
| `input.url`        | `build.payload.source`  | Same field; the packer detects the scheme.                     |
| `payload.crypto`   | `build.payload.crypto`  | Unchanged.                                                     |
| `payload.strings`  | `build.stub.strings`    | Applies to every stub literal, independent of the techniques.  |
| `loader.path`      | `build.stub.path`       | `null`/absent = builtin stub.                                  |
| `loader.syscalls`  | `build.stub.syscalls`   | Unchanged.                                                     |
| `output.path`      | `build.output.path`     | Unchanged.                                                     |
| `output.arch`      | `build.output.arch`     | Unchanged.                                                     |
| `output.strip`     | `build.output.strip`    | Unchanged.                                                     |
| `output.trim_paths`| `build.output.trim_paths`| Unchanged.                                                    |
| `pipeline`         | `runtime`               | The technique list (same `technique:` objects).                |
| `$build.N$`        | `$arg.N$` (YAML)        | Build-time substitution. `$arg.0$`, `$arg.1$`, `$arg.foo$`.    |
| `$ARG_<n>$`        | `$ARG_<n>$` (stub)      | Unchanged: the stub sees the already-resolved value.           |

## Example

Schema 1:

```yaml
schema: 1
name: peloader

input:
  path: "$build.0$"

payload:
  crypto:
    algo: xchacha20poly1305
    key: random
  strings:
    strategy: xor
    key: random

loader:
  syscalls:
    mode: indirect
    resolver: hells_gate

pipeline:
  - technique: reflective_loading

output:
  path: "$build.1$"
  arch: x64
  strip: true
  trim_paths: all
```

Schema 3 (equivalent):

```yaml
schema: 3
name: peloader

build:
  payload:
    source: "$arg.0$"
    crypto:
      algo: xchacha20poly1305
      key: random
  stub:
    path: null              # null = builtin; or a path to a custom .rs
    syscalls:
      mode: indirect
      resolver: hells_gate
    strings:
      strategy: xor
      key: random
  output:
    path: "$arg.1$"
    arch: x64
    strip: true
    trim_paths: all

runtime:
  - technique: reflective_loading
```

## Migrating existing YAMLs

The token renames are mechanical and can be done with `sed`:

```bash
# Build-argument placeholders.
sed -i 's/\$build\./\$arg./g' plan.yaml

# The technique list key.
sed -i 's/^pipeline:/runtime:/' plan.yaml
sed -i 's/^  pipeline:/  runtime:/' plan.yaml
```

The block moves are structural, so do them by hand (or with your editor's
find/replace) following the example above:

1. `schema: 1` → `schema: 3`.
2. Wrap `payload`, `output` (and the optional `loader` → `stub`) under a new
   `build:` key, indenting their contents by two spaces.
3. Collapse `input.path` / `input.url` into `build.payload.source` (a single
   string; URL detection happens at load time).
4. Move `payload.strings` into the `stub:` block as `build.stub.strings`.
5. Rename the top-level `loader:` block to `build.stub:`.
6. Rename the top-level `pipeline:` block to `runtime:`.

A YAML that still declares `schema: 1` will fail with the mapping above and a
pointer to this document:

```
error: invalid YAML in 'plan.yaml': schema 1 is no longer supported.
Migration:
  input.path      → build.payload.source
  payload.*       → build.payload.*
  payload.strings → build.stub.strings
  loader.path     → build.stub.path
  loader.syscalls → build.stub.syscalls
  output.*        → build.output.*
  pipeline        → runtime
  pipeline params → runtime[].params (nested)
  $build.N$       → $arg.N$
See docs/migration-v1-v3.md, then docs/migration-v3-v4.md for details.
```
