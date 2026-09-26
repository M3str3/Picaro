# Migrating a config from schema 3 to schema 4

Schema 4 is a **syntax** change, not a behaviour change. Schema 3 is no longer
accepted — a YAML that declares `schema: 3` fails at parse time with a migration
hint, and there is no compatibility mode.

If your config still declares `schema: 1` or `schema: 2`, apply those steps
first: `docs/migration-v1-v3.md` and `docs/migration-v2-v3.md`.

## Why

In schema 3 the parameters of a technique sat next to `technique:` in the same
YAML object:

```yaml
runtime:
  - technique: process_hollowing
    target: "C:\\Windows\\System32\\svchost.exe"
```

That puts the technique key and its parameters in one namespace: a parameter can
never be named `technique`, and it is not obvious at a glance which keys belong
to the technique. Schema 4 nests the parameters under a `params:` mapping, so
every runtime entry has the same two-level shape — the technique name, and
optionally its parameters:

```yaml
runtime:
  - technique: process_hollowing
    params:
      target: "C:\\Windows\\System32\\svchost.exe"
```

## Field mapping

| Schema 3                                     | Schema 4                                        | Notes                                                         |
| -------------------------------------------- | ----------------------------------------------- | ------------------------------------------------------------- |
| `runtime[].<param>` (alongside `technique:`) | `runtime[].params.<param>`                      | The parameters move one level down; the values are unchanged. |
| `runtime[].technique`                        | `runtime[].technique`                           | Unchanged.                                                    |
| `runtime[]` entry with no parameters         | same, with `params` omitted                     | No `params:` block is needed.                                 |
| everything else                              | unchanged                                       | No other key moves.                                           |

## Example

Schema 3:

```yaml
schema: 3
name: test-hollowing

build:
  payload:
    source: ./examples/payloads/test_payload.exe
    crypto:
      algo: xchacha20poly1305
      key: random
  output:
    path: ./dist/test_packed.exe
    arch: x64
    strip: true
    trim_paths: all

runtime:
  - technique: process_hollowing
    target: "C:\\Windows\\System32\\svchost.exe"
```

Schema 4 (equivalent):

```yaml
schema: 4
name: test-hollowing

build:
  payload:
    source: ./examples/payloads/test_payload.exe
    crypto:
      algo: xchacha20poly1305
      key: random
  output:
    path: ./dist/test_packed.exe
    arch: x64
    strip: true
    trim_paths: all

runtime:
  - technique: process_hollowing
    params:
      target: "C:\\Windows\\System32\\svchost.exe"
```

## Migrating existing YAMLs

1. `schema: 3` → `schema: 4`.
2. For every `runtime:` entry that has parameter keys at the same level as
   `technique:`, move those keys under a new `params:` key, indented one level
   deeper. Entries with no parameters (e.g. `- technique: reflective_loading`)
   need no change.

> **Watch out:** the deserializer ignores unknown keys inside a runtime entry.
> A config where `schema: 3` was changed to `4` but the parameters were left
> flat will parse, and the parameters will be silently dropped — the technique
> then runs with its defaults (for `process_hollowing`, that means the payload
> is hollowed into `svchost.exe`). Always nest the parameters under `params:`.

A YAML that still declares `schema: 3` will fail with:

```
error: invalid YAML in 'config.yaml': schema 3 is no longer supported.
Migration: a runtime entry now nests the technique's parameters under a
`params:` mapping instead of putting them next to `technique:`.
  before (schema 3):
    - technique: process_hollowing
      target: "C:\\Windows\\System32\\svchost.exe"
  after (schema 4):
    - technique: process_hollowing
      params:
        target: "C:\\Windows\\System32\\svchost.exe"
A technique with no parameters omits `params:` entirely.
See docs/migration-v3-v4.md for details.
```
