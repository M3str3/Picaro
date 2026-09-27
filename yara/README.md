# YARA rules

This directory holds YARA rules used by `picaro audit` to tag known
signatures in a binary.

The YARA engine is **not wired yet** (there is no stable, ergonomic YARA crate
for Rust). `picaro audit` reports `✓ no matches (ruleset empty)` until a rule
file is added and the engine is integrated.

## Adding rules

Drop one or more `.yar` / `.yara` files here, e.g. `yara/picaro.yar`:

```yara
rule picaro_stub_marker {
    meta:
        description = "picaro packed stub"
    strings:
        $a = "STUB_MARKER_" ascii
    condition:
        $a
}
```

## Integrating the engine (TODO)

Pick one approach:

1. **libyara FFI** — add a `yara`/`yara-sys` crate and compile the rules in
   `yara/*.yar`, then scan the raw bytes. Requires libyara on the build machine.
2. **Subprocess** — invoke the `yara` CLI against a temp copy of the file and
   parse its output. No native dependency, but slower and needs `yara` in PATH.

Until then, `src/audit/yara.rs` is a stub that only reports whether rule files
exist.
