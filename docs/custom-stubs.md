# Custom loader stubs

A custom stub lets you replace the generated loader with your own Rust
template. The packer still fills it with the encrypted payload and the selected
technique fragments; you decide how to load, decrypt and run the payload.

This is the escape hatch for when the builtin stub's structure does not fit
your needs (e.g. you want to read the key from argv, or decrypt without
touching the technique pipeline).

## When to use it

- You need a different loader shape than `templates/stub/main.rs.tpl`.
- You want to receive a secret (e.g. the key) at runtime instead of embedding
  it in the binary.
- You are experimenting with a new execution flow before promoting it to a
  builtin technique.

If you only need different parameters (target, output path, …), use build
arguments instead (see below) — no custom stub required.

## How it works

Add a `loader` block to the YAML:

```yaml
loader:
  path: ./my_stub.rs
```

- **Without** `loader`, the builtin template is used (current behavior).
- **With** `loader`, `path` must point to a readable `.rs` file that defines a
  `fn main()`. The file is a template: `{{PLACEHOLDER}}` tokens are substituted
  before compilation.

The packer compiles it with the same dependency set as the builtin stub
(`chacha20poly1305`, `hex`, `windows`). Importing anything else fails with a
plain `rustc` "crate not found" error, which is surfaced verbatim.

## Contract

Your template must define `fn main()`. Nothing else is imposed.

Available placeholders:

| Placeholder              | Substituted with                                            |
| ------------------------ | ----------------------------------------------------------- |
| `{{PAYLOAD_BYTES}}`      | The encrypted payload (ciphertext + tag) as a `[u8; N]` array literal |
| `{{PAYLOAD_LEN}}`        | The decrypted payload size (`usize`)                        |
| `{{PAYLOAD_NONCE_DEF}}`  | A `[u8; 24]` array literal rebuilding the nonce             |
| `{{PAYLOAD_KEY_DEF}}`    | A `[u8; 32]` array literal rebuilding the key               |
| `{{PREPARATION_BLOCKS}}` | Preparation technique fragments (in pipeline order)         |
| `{{EXECUTION_BLOCK}}`    | The single Execution technique fragment                     |
| `{{ARG_<n>}}`            | A positional build argument, substituted literally          |

You may ignore `{{PREPARATION_BLOCKS}}` and `{{EXECUTION_BLOCK}}`. If you do
while the YAML declares techniques, the packer emits a warning (not an error):

```
warning: loader stub does not reference {{PREPARATION_BLOCKS}}; declared preparation techniques will have no effect
```

`{{PAYLOAD_KEY_DEF}}` is only embedded when the template references it, so a
stub that never mentions it does not get the key baked in (see
`examples/stubs/runtime-key.rs`).

## Build arguments

Positional arguments after the config path are substituted into the YAML as
`{{build.N}}` (0-based index) and into a custom stub as `{{ARG_N}}`:

```bash
packerman build config.yaml "C:\\Windows\\System32\\svchost.exe"
```

```yaml
# config.yaml
pipeline:
  - technique: process_hollowing
    target: "{{build.0}}"
```

A referenced-but-missing argument is an error:
`the config references '{{build.0}}' but no build argument #0 was provided`.

## Examples

- `examples/stubs/minimal.rs` — prints the payload size; ignores the technique
  blocks. The smallest stub that verifies substitution works.
- `examples/stubs/runtime-key.rs` — reads the key from argv (`./out.exe
  <hex_key>`), so the key is never embedded. Intentionally left incomplete (the
  decryption body is yours to write).
- `examples/configs/test-custom-stub.yaml` — end-to-end config for `minimal.rs`.

## Limitations

- **Rust-only.** No C/Nim/Zig stubs yet.
- **Single file.** No separate modules; everything lives in the one `.rs`.
- **No custom dependencies.** Only the builtin stub's dependency set is linked.
- **No template inheritance.** A custom stub fully replaces the builtin one.

## Roadmap

- Multi-language stubs (`.o` + linker) are a possible follow-up if there is
  demand; the render/compile steps are already generic and the compiler
  invocation is isolated, so the change would be localized.
