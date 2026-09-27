# Custom stubs

A custom stub replaces the generated loader with your own Rust template. The
packer still fills it with the encrypted payload and the selected technique
fragments; you decide how to load, decrypt and run the payload.

Use it when the builtin stub's structure does not fit (a different loader shape,
a key read at runtime, or an experimental execution flow before promoting it to a
builtin technique). If you only need different parameters, use build arguments —
no custom stub required.

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

The same block also carries the syscall layer (`syscalls`) and the string
obfuscation (`strings`); both apply to custom stubs. The packer compiles it with
the builtin stub's dependency set (`chacha20poly1305`, `hex`, `windows`);
importing anything else fails with a plain `rustc` "crate not found" error.

## Contract

Your template must define `fn main()`. Nothing else is imposed.

| Placeholder            | Substituted with |
| ---------------------- | ---------------- |
| `$PAYLOAD_BYTES$`      | The encrypted payload (ciphertext + tag) as a `[u8; N]` array literal |
| `$PAYLOAD_LEN$`        | The decrypted payload size (`usize`) |
| `$PAYLOAD_NONCE_DEF$`  | A `[u8; 24]` array literal rebuilding the nonce |
| `$PAYLOAD_KEY_DEF$`    | A `[u8; 32]` array literal rebuilding the key (only when referenced) |
| `$PREPARATION_BLOCKS$` | Preparation technique fragments (in runtime order) |
| `$SYSCALLS_BLOCK$`     | The syscall layer (from `build.stub.syscalls`) |
| `$IMPORTS_BLOCK$`      | The shared payload import resolver |
| `$EXECUTION_BLOCK$`    | The single Execution technique fragment |
| `$ARG_<key>$`          | A build argument (index or name), substituted literally |

Placeholders use the `$NAME$` delimiter. `$X$` is invalid Rust, so `rustfmt`
leaves it untouched; never go back to `{{X}}` (valid Rust — `rustfmt` rewrites it
into nested blocks and silently breaks substitution).

You may ignore `$PREPARATION_BLOCKS$` and `$EXECUTION_BLOCK$`. If you do while
the YAML declares techniques, the packer emits a warning (not an error):

```
warning: loader stub does not reference $PREPARATION_BLOCKS$; declared preparation techniques will have no effect
```

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

- `examples/stubs/minimal.rs` — prints the payload size; ignores the technique
  blocks. The smallest stub that verifies substitution works.
- `examples/stubs/runtime-key.rs` — reads the key from argv, so it is never
  embedded (the decryption body is left for you to write).
- `examples/plans/custom-stub.yaml` — end-to-end plan for `minimal.rs`.

## Limitations

- **Rust-only**, and **single file**: no separate modules, no custom
  dependencies beyond the builtin stub's set, no template inheritance.
- **Key/nonce are not obfuscated.** `$PAYLOAD_KEY_DEF$` / `$PAYLOAD_NONCE_DEF$`
  emit plain byte-array literals, so a stub that references them lands the key in
  `.rdata`. Read the key at runtime (see `examples/stubs/runtime-key.rs`).
