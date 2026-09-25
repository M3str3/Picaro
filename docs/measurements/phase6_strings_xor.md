# String obfuscation — phase 6, strategy `xor`

Static audit of the phase 6 binary with the formal `xor` strategy active.

## Binary

- `dist/test_packed.exe` (process hollowing, test payload)
- `build.strings: { strategy: xor, key: random }`

## Config (YAML)

```yaml
build:
  payload:
    crypto:
      algo: xchacha20poly1305
      key: random
  strings:
    strategy: xor
    key: random
```

## Audit summary

- Size: `1598464` bytes
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

Identical to the phase 5 baseline: the marker and target are XORed with a
per-build 32-byte key (instead of the old fixed `0x5A`) and decoded by a
`dec_xor` loop in the stub.
