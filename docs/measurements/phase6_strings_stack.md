# String obfuscation — phase 6, strategy `stack`

Static audit of the phase 6 binary with the `stack` strategy active.

## Binary

- `dist/test_packed_stack.exe` (process hollowing, test payload)
- `build.strings: { strategy: stack }` (no key)

## Config (YAML)

```yaml
build:
  payload:
    crypto:
      algo: xchacha20poly1305
      key: random
  strings:
    strategy: stack
```

## Audit summary

- Size: `1600512` bytes
- `.rdata`: `339` KB, entropy `6.81`
- `STUB_MARKER` in strings: no
- `HOLLOW_TARGET` (`system32`) in strings: no
- Static risk: MEDIUM (2 suspicious imports, 3 flagged strings)

## Strings scan detail

- Paths (System32): 0
- APIs by name: 1 (`NtUnmapViewOfSection`)
- Technique names: 1 (a `windows-0.58.0` source path containing "loader")
- URLs/IPs: 1 (a `getrandom` doc URL)
- Total flagged: 3

Identical to `xor` and the baseline in the static strings scan. `.rdata` is
unchanged (the payload ciphertext dominates it); `stack` only grows `.text`
slightly (one `black_box` store per byte).

## Implementation note (honest caveat)

The first `stack` build leaked a *prefix* of each literal (`STUB_MARKER_` and
`C:\Windows\Syste`) into `.rdata`: LLVM constant-folded the byte stores back
into a contiguous constant. Wrapping each store in `std::hint::black_box`
prevents that folding, after which `grep`/`audit` find neither the marker nor
the target. See `src/engine/obfuscation.rs::render_stack_expr`.
