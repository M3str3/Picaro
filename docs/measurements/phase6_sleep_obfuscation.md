# Sleep obfuscation (ekko) — phase 6 static footprint

Static audit of the same stub with and without the new Preparation technique,
both built from `reflective_loading` and the same payload.

## Binaries

- Baseline: `dist/test_packed_reflective.exe`
  (`examples/configs/test-reflective.yaml`, `reflective_loading` only)
- With sleep: `dist/test_sleep.exe`
  (`examples/configs/test-sleep.yaml`, `sleep_obfuscation → reflective_loading`)

Both were produced in the same session from the same stub template and payload
(`examples/payloads/test_payload.exe`), so the comparison is apples-to-apples.

## Config (YAML delta)

```yaml
runtime:
  - technique: sleep_obfuscation
    variant: ekko
    sleep_ms: 5000
    encrypt_regions: [payload]
  - technique: reflective_loading
```

## Sizes and sections

| Section   | Baseline | With sleep | Delta   |
|-----------|----------|------------|---------|
| total     | 487 KB   | 505 KB     | +18 KB  |
| `.text`   | 263 KB   | 278 KB     | +15 KB  |
| `.rdata`  | 205 KB   | 208 KB     | +3 KB   |
| `.data`   | 3 KB     | 3 KB       | —       |
| `.pdata`  | 10 KB    | 11 KB      | +1 KB   |
| `.fptable`| 0 KB     | 0 KB       | —       |
| `.reloc`  | 3 KB     | 3 KB       | —       |

Entropy is unchanged (`.text` 6.27 → 6.25, `.rdata` 7.26 → 7.25): the RC4
timer-chain code adds ~15 KB of ordinary low-entropy `.text`, and the payload is
already encrypted at rest in `.rdata`, so no section becomes a new high-entropy
outlier.

## IAT delta

| Import            | Baseline | With sleep |
|-------------------|----------|------------|
| `CreateEventW`    | no       | yes        |
| `VirtualQuery`    | no       | yes        |
| DLLs / functions  | 3 / 96   | 3 / 98     |

- The only two new imports are `CreateEventW` (the completion event) and
  `VirtualQuery` (the image-run walk). Both are kernel32 and benign — no
  timer-queue, RC4, `NtContinue`, `RtlCaptureContext` or `SystemFunction032`
  name reaches the import table.
- `RtlCaptureContext` already appears in the *baseline* import list: it is a
  Rust-standard-library backtrace import, not the fragment's dynamic ntdll
  resolution (the fragment resolves ntdll's copy through `GetProcAddress` and
  obfuscates the name).
- The timer-queue family (`CreateTimerQueue`, `CreateTimerQueueTimer`,
  `DeleteTimerQueueEx`), `WaitForSingleObject`, `SetEvent`, `VirtualProtect`,
  `NtContinue`, `RtlCaptureContext` and `SystemFunction032` are all resolved at
  runtime, so none is statically linked.

## Strings scan

- `sensitive 0`, `technique names 0`, `paths 0`, `urls / ips 0` in both builds.
- `apis by name 1` in the sleep build (`NtTk`): a 4-byte substring coincidence
  in non-code data, not an NT API name and not a leak (the `Nt*` heuristic only
  flags camelCase candidates and `sensitive` stays 0).
- The three new sensitive literals (`SystemFunction032`, `RtlCaptureContext`,
  `NtContinue`) are covered by `SENSITIVE_LITERALS` and do not appear in
  cleartext. The `#[ignore]` guardrail
  `no_sensitive_literals_in_generated_stubs` passes for the fragment.

## Runtime

- Not statically observable: the value of the technique is that, during the
  `WaitForSingleObject` delay, the image region is RC4 ciphertext and the only
  active thread runs in system DLLs. Verification needs a debugger
  (`VirtualQuery` + a memory dump inside the sleep window).
- `cargo test -- --ignored no_sensitive_literals_in_generated_stubs` passes:
  the fragment compiles inside a generated stub and leaks no sensitive literal.
  A dedicated `compiles_sleep_obfuscation_stub_to_pe` e2e test (ignored, needs
  `rustc`) also compiles the full `sleep_obfuscation → reflective_loading`
  pipeline to a PE.

## Defender

`batesian audit` Defender scan unavailable in this session (`hr = 0x80508023`);
Windows Defender is disabled on the test machine. The YARA ruleset is empty, so
the `YARA` line is not meaningful yet.

## Date

- 2026-09-26
