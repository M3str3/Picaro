# Migrating a config from schema 2 to schema 3

Schema 3 is a **syntax** change, not a behaviour change. Schema 2 is no longer
accepted — a YAML that declares `schema: 2` fails at parse time with a migration
hint, and there is no compatibility mode.

For a config that still declares `schema: 1`, see `docs/migration-v1-v3.md`.

> Schema 3 was later superseded by schema 4 (runtime parameters moved under a
> nested `params:` mapping); see `docs/migration-v3-v4.md` for the second step.

## Why

String obfuscation only ever affected the literals of the generated stub, so it
belongs with the rest of the stub configuration. Schema 3 moves it from
`build.strings` (a sibling of `payload`/`stub`/`output`) into `build.stub`, which
leaves `build` with exactly three blocks: `payload`, `stub`, `output`.

## Field mapping

| Schema 2               | Schema 3                | Notes                                       |
| ---------------------- | ----------------------- | ------------------------------------------- |
| `build.strings`        | `build.stub.strings`    | Contents unchanged.                         |
| everything else        | unchanged               | No other key moves.                         |

## Example

Schema 2:

```yaml
schema: 2
name: peloader

build:
  payload:
    source: "$arg.0$"
    crypto:
      algo: xchacha20poly1305
      key: random
  strings:
    strategy: xor
    key: random
  stub:
    syscalls:
      mode: indirect
      resolver: hells_gate
  output:
    path: "$arg.1$"
    arch: x64
    strip: true
    trim_paths: all

runtime:
  - technique: reflective_loading
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

1. `schema: 2` → `schema: 3`.
2. Move the `strings:` block (two spaces of indentation, under `build:`) inside
   the `stub:` block, adding two spaces of indentation to its contents. If the
   config has no `stub:` block yet, create one.

A YAML that still declares `schema: 2` will fail with:

```
error: invalid YAML in 'config.yaml': schema 2 is no longer supported.
Migration:
  build.strings → build.stub.strings
  runtime entries now nest parameters under `params:` (schema 3 → 4)
See docs/migration-v2-v3.md (then docs/migration-v3-v4.md) for details.
```
