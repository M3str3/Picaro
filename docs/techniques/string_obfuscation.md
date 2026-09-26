# String obfuscation

A packer-level feature (not a pipeline technique): it obfuscates every
sensitive string literal that the packer embeds into the generated stub, and
emits code that rebuilds the string at runtime. The strategy and key are
configurable in `build.stub.strings`.

## What it does

The stub contains a handful of sensitive literals: the per-build marker
(`STUB_MARKER_<hex>`) and, for process hollowing, the target path
(`C:\Windows\System32\svchost.exe`). Without obfuscation these would appear as
cleartext in `.rdata` and show up in `strings <binary>`.

The packer intercepts each literal, obfuscates it according to the configured
strategy, and substitutes the result into a placeholder (`$STUB_MARKER_DEF$`,
`HOLLOW_TARGET_DEF`) as a Rust expression. The stub binds that expression at
runtime (`let stub_marker = ...;`, `let hollow_target = ...;`) and uses the
reconstructed `String` normally. The old hardcoded XOR with `0x5A` is gone; all
obfuscation flows through `src/engine/obfuscation.rs`.

## YAML parameters

```yaml
build:
  stub:
    strings:          # optional; omitted => xor + random key (with a warning)
      strategy: xor   # xor | stack
      key: random     # random | literal:<hex>   (xor only; ignored by stack)
```

- `strategy` — `xor` (default) or `stack`.
- `key` — `random` (default) or `literal:<64-hex-chars>` for a fixed 32-byte
  XOR key.

Semantic validation: an unknown strategy is a clear error; a `literal:` key that
is not valid hex or not exactly 32 bytes is a clear error.

## YAML example

```yaml
build:
  payload:
    crypto:
      algo: xchacha20poly1305
      key: random
  stub:
    strings:
      strategy: xor
      key: random
```

## Strategies

### xor

Each literal is XORed with a repeating 32-byte key and embedded as a byte-array
literal plus the key. The stub decodes it with a small runtime loop
(`dec_xor`).

- **Pros**: fast; strong evasion ratio; each string gets its own fresh key.
- **Cons**: the decoder (`dec_xor`) is a recognizable pattern; the key and
  ciphertext sit together in `.rdata`.

Use for most strings.

### stack

The literal is emitted as one byte store per character into a local stack
array, then converted to a `String` at the point of use. No decoder, no key.

- **Pros**: no key; no decoder; the bytes are never a contiguous `.rdata`
  literal (each store is wrapped in `std::hint::black_box` to stop LLVM from
  folding them back into a constant).
- **Cons**: more code (one store per byte), slightly slower.

Use for short strings that must appear zero times in `.rdata`.

## What it evades

- Static `strings` scans for the marker and target path (`system32`,
  `svchost.exe`, ...).

## What detects it

- **Entropy anomalies** — the ciphertext/key in `xor` raise `.rdata` entropy;
  in practice the embedded XChaCha20 payload already dominates entropy, so the
  marginal effect is negligible (see Measurements).
- **Decoder patterns** — `xor`'s `dec_xor` loop (XOR of a byte array with a
  key) is a classic tell that a heuristic or ML classifier can flag.
- **Runtime reconstruction hooking** — both strategies must materialize the
  string before use, so a runtime hook on `LoadLibraryA`/`CreateProcessA` or a
  memory scan for the reconstructed value will still see it.

## Measurements

`docs/measurements/phase5_baseline_strings.md`,
`phase6_strings_xor.md`, `phase6_strings_stack.md`. The static strings scan
shows no difference across the three (all hide the marker and target), because
phase 5 already hardcoded a XOR. The feature makes that formal, per-string, and
configurable, and adds the no-decoder stack strategy.

| Strategy | STUB_MARKER in strings | HOLLOW_TARGET in strings | Entropy `.rdata` |
| -------- | ---------------------- | ------------------------ | ---------------- |
| none (phase 5, XOR 0x5A) | no | no | 6.81 |
| xor | no | no | 6.81 |
| stack | no | no | 6.81 |

`.rdata` size and entropy are identical across all three because the embedded
XChaCha20 payload ciphertext dominates `.rdata`; the obfuscated literals are a
rounding error by comparison.

## References

- litcrypt / litcrypt2 — Rust string-literal encryption crates (compile-time
  macro that encrypts literals and decrypts them lazily at runtime).
- Common string-obfuscation patterns: XOR with a key, stack construction, and
  split/stacked fragments.
