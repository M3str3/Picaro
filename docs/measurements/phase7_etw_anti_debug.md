# ETW patch + anti-debug — phase 7 static footprint

Static audit of the same stub with and without the two new Preparation
techniques, both built from `reflective_loading` and the same payload.

## Binaries

- Baseline: `dist/test_packed_reflective.exe`
  (`examples/configs/test-reflective.yaml`, `reflective_loading` only)
- With preps: `dist/test_etw_anti_debug.exe`
  (`examples/configs/test-etw-anti-debug.yaml`,
  `anti_debug → patch_etw → reflective_loading`)

Both binaries were produced in the same session from the same stub template and
payload (`examples/payloads/test_payload.exe`), so the comparison is
apples-to-apples.

## Config (YAML delta)

```yaml
runtime:
  - technique: anti_debug
    action: abort
  - technique: patch_etw
    full: true
  - technique: reflective_loading
```

## Sizes and sections

| Section   | Baseline  | With preps | Delta    |
|-----------|-----------|------------|----------|
| total     | 498 688   | 505 344    | +6 656   |
| `.text`   | 263 KB    | 267 KB     | +4 KB    |
| `.rdata`  | 205 KB    | 207 KB     | +2 KB    |
| `.data`   | 3 KB      | 3 KB       | —        |
| `.pdata`  | 10 KB     | 11 KB      | +1 KB    |
| `.fptable`| 0 KB      | 0 KB       | —        |
| `.reloc`  | —         | 3 KB       | —        |

Entropy is unchanged (`.text` 6.27, `.rdata` ~7.2), i.e. the added code turns
neither section into a high-entropy outlier beyond the payload's existing
`.rdata` baseline.

## IAT delta

| Import                       | Baseline | With preps |
|------------------------------|----------|------------|
| `IsDebuggerPresent`          | yes      | yes        |
| `CheckRemoteDebuggerPresent` | no       | yes        |
| `GetThreadContext`           | no       | yes        |
| `GetCurrentProcess`          | yes      | yes        |
| `VirtualProtect`             | yes      | yes        |
| `LoadLibraryA`               | yes      | yes        |
| `GetProcAddress`             | yes      | yes        |
| DLLs / functions             | 3 / 96   | 3 / 98     |

- `IsDebuggerPresent` is already imported by the Rust standard library's panic
  machinery, so the anti-debug PEB check adds **no** import.
- The only two new imports are `CheckRemoteDebuggerPresent` (kernel32) and
  `GetThreadContext` (kernel32). `patch_etw` adds none: it reuses
  `VirtualProtect`/`LoadLibraryA`/`GetProcAddress`, already linked.
- No new DLL is linked.
- `SUSPICIOUS IMPORTS` still reports `✓ IAT looks minimal` in both builds: the
  audit's suspicious-API heuristic does not classify debugger APIs as
  suspicious. The tell-tale nature of `IsDebuggerPresent` /
  `CheckRemoteDebuggerPresent` is visible in the raw import listing, not in the
  suspicious summary.

## Strings scan

- Baseline and with-preps: `sensitive 0`, `apis by name 0`, `paths 0`,
  `technique names 0`, `total flagged 0`.
- `patch_etw` adds `ntdll.dll`, `EtwEventWrite` and `EtwEventWriteFull` as
  obfuscated runtime literals; none appears in cleartext. The `#[ignore]`
  guardrail `no_sensitive_literals_in_generated_stubs` covers the three names.
- `anti_debug` has no string literals at all (every check is a direct import).

## Runtime

- Not exercised here. With `action: abort`, the stub is expected to fail inside
  `run_preparations` whenever a debugger is attached; running the packed binary
  under a debugger on the test host is the follow-up verification.
- `cargo test -- --ignored no_sensitive_literals_in_generated_stubs` passes:
  both fragments compile inside a generated stub and leak no sensitive literal.

## Defender

`batesian audit` Defender scan unavailable in this session (`hr = 0x80508023`);
Windows Defender is disabled on the test machine. The YARA ruleset is empty, so
the `YARA` line is not meaningful yet.

## Date

- 2026-09-25
