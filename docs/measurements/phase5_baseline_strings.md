# String obfuscation — phase 5 baseline

Static audit of the phase 5 binary **before** formal string obfuscation. At this
point the stub hid its two sensitive literals (`STUB_MARKER_<hex>` and the
hollowing target) with a hardcoded XOR key `0x5A`.

## Binary

- `dist/test_packed.exe` (process hollowing, test payload)
- Built before the `build.strings` feature (hardcoded XOR `0x5A`).

## Config (YAML)

```yaml
schema: 2
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

## Audit summary

- Size: `1598976` bytes
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

The three flagged strings are unrelated to the obfuscated literals: they are
debug-info/path strings from the `windows` and `getrandom` crates.
