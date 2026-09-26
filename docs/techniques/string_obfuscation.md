# String obfuscation

A packer-level feature (not a pipeline technique): it obfuscates every sensitive
string literal the packer embeds into the generated stub and emits code that
rebuilds the string at runtime. Configurable in `build.stub.strings`.

## What it does

The stub contains a handful of sensitive literals: the per-build marker
(`STUB_MARKER_<hex>`) and, for process hollowing, the target path. Without
obfuscation these would appear as cleartext in `.rdata` and show up in
`strings <binary>`.

The packer intercepts each literal, obfuscates it according to the configured
strategy and substitutes the result into a placeholder
(`$STUB_MARKER_DEF$`, `HOLLOW_TARGET_DEF`) as a Rust expression; the stub binds
it at runtime and uses the reconstructed `String` normally. All obfuscation flows
through `src/engine/obfuscation.rs` (the old hardcoded XOR with `0x5A` is gone).

## YAML

```yaml
build:
  stub:
    strings:          # optional; omitted => xor + random key (with a warning)
      strategy: xor   # xor | stack
      key: random     # random | literal:<64 hex chars>  (xor only)
```

- `strategy` — `xor` (default) or `stack`.
- `key` — `random` (default) or `literal:<hex>` for a fixed 32-byte XOR key.

An unknown strategy, or a `literal:` key that is not valid hex or not exactly 32
bytes, is a clear error.

## Strategies

### `xor`

Each literal is XORed with a repeating 32-byte key and embedded as a byte-array
literal plus the key; the stub decodes it with a small runtime loop (`dec_xor`).

- **Pros**: fast; strong evasion ratio; each string gets its own fresh key.
- **Cons**: the decoder is a recognizable pattern, and the key and ciphertext
  sit together in `.rdata`.

### `stack`

The literal is emitted as one byte store per character into a local stack array,
then converted to a `String` at the point of use. No decoder, no key.

- **Pros**: no key, no decoder, and the bytes are never a contiguous `.rdata`
  literal (each store is wrapped in `std::hint::black_box` to stop LLVM folding
  them back into a constant).
- **Cons**: more code (one store per byte), slightly slower.

## What it evades / what detects it

- Evades static `strings` scans for the marker and target path (`system32`,
  `svchost.exe`, …).
- Entropy anomalies: `xor` raises `.rdata` entropy in theory, but the embedded
  XChaCha20 ciphertext already dominates it, so the marginal effect is
  negligible ([Measurements](../measurements.md)).
- Decoder patterns: `xor`'s `dec_xor` loop (byte array XORed with a key) is a
  classic tell a heuristic or ML classifier can flag.
- Runtime reconstruction: both strategies must materialize the string before
  use, so a hook on `LoadLibraryA`/`CreateProcessA` or a memory scan still sees
  it.

## References

- litcrypt / litcrypt2 — Rust crates that encrypt string literals at compile time
  and decrypt them lazily.
- Common string-obfuscation patterns: XOR with a key, stack construction and
  split/stacked fragments.
