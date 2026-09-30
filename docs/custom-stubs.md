# Custom stubs

A custom stub replaces the generated loader with your own Rust template. The
packer still fills it with the per-step technique fragments and the shared
blocks; you decide how to drive them.

Use it when the builtin stub's structure does not fit (a different loader shape,
an experimental flow before promoting it to a builtin technique). If you only
need different parameters, use build arguments — no custom stub required.

## How it works

```yaml
build:
  stub:
    path: ./my_stub.rs
```

- **Without** `path` (null or absent), the builtin template is used.
- **With** `path`, it must point to a readable `.rs` file that defines a
  `fn main()`. The file is a template: `$PLACEHOLDER$` tokens are substituted
  before compilation.

The same block also carries the syscall layer (`syscalls`), the API resolution
(`api_resolution`) and the string obfuscation (`strings`); all apply to custom
stubs. The packer compiles it with the builtin stub's dependency set
(`chacha20poly1305`, `hex`, `windows`); importing anything else fails with a
plain `rustc` "crate not found" error.

## Contract

Your template must define `fn main()`. Nothing else is imposed. (A
`build.output.kind: dll` build refuses a custom stub: a DLL has no `main`, and
its entry contract is `$ENTRY_BLOCK$`.)

| Placeholder              | Substituted with |
| ------------------------ | ---------------- |
| `$STUB_HELPERS$`         | The shared `dec_xor` / `decrypt_step` helpers |
| `$ENTRY_BLOCK$`          | The entry point: `fn main` (executable) or the DLL's exports (`build.output.kind`). Optional — a stub that defines its own `fn main` leaves it out |
| `$STEP_MODULES$`         | One `mod step_<i>` per runtime step (fragments + adapters) |
| `$STEP_RUNNER_BODY$`     | The generated straight-line runner (runs the steps in order) |
| `$SYSCALLS_BLOCK$`       | The syscall layer (from `build.stub.syscalls`) |
| `$ARGS_BLOCK$`           | The payload command-line builder |
| `$IMPORTS_BLOCK$`        | The shared payload import resolver |
| `$API_RESOLUTION_BLOCK$` | The API-resolution policy and proxies (from `build.stub.api_resolution`) |
| `$ARG_<key>$`            | A build argument (index or name), substituted literally |

Placeholders use the `$NAME$` delimiter. `$X$` is invalid Rust, so `rustfmt`
leaves it untouched; never go back to `{{X}}` (valid Rust — `rustfmt` rewrites it
into nested blocks and silently breaks substitution).

A template that pulls in `$STEP_RUNNER_BODY$` needs `$STUB_HELPERS$` (the
decryption helpers) and every module the runner calls. The simplest working
shape is exactly the builtin template with a different `main`; see
`examples/stubs/minimal.rs`.

You may ignore the step blocks. If you do while the YAML declares steps, the
packer emits a warning (not an error):

```
warning: loader stub does not reference $STEP_MODULES$; the declared techniques will have no effect
```

The builtin template requires every placeholder above (a missing one is an
error); a custom template may omit any of them.

## Build arguments

Positional arguments after the plan path are substituted into the YAML as
`$arg.N$` and into a custom stub as `$ARG_<key>$`. An argument of the form
`name=value` is available as `$arg.name$` (and `$ARG_name$`):

```bash
picaro build plan.yaml "C:\\Windows\\System32\\svchost.exe"
```

```yaml
runtime:
  - technique: process_hollowing
    params:
      target: "$arg.0$"
```

A referenced-but-missing argument is an error:
`the plan references '$arg.0$' but no build argument '0' was provided`.

## Examples

- `examples/stubs/minimal.rs` — a working custom stub that pulls in the step
  modules and runner, with its own `main`.
- `examples/stubs/runtime-key.rs` — takes a value from a `key=value` build
  argument, so nothing derived from it is embedded.
- `examples/plans/custom-stub.yaml` — end-to-end plan for `minimal.rs`.

## Limitations

- **Rust-only**, and **single file**: no separate modules, no custom
  dependencies beyond the builtin stub's set, no template inheritance.
- **The per-step payload keys are embedded by the runner.** Each Execution
  step's key and nonce live in the generated runner as hex literals, so a custom
  template that keeps the runner keeps that shape; a stub that wants a runtime
  key must decrypt the payloads itself.
