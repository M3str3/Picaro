# YARA rules

This directory holds YARA rules used by `batesian audit` to tag known
signatures in a binary.

The YARA engine is **not wired yet** (there is no stable, ergonomic YARA crate
for Rust). `batesian audit` reports `✓ no matches (ruleset empty)` until a rule
file is added and the engine is integrated.

## Adding rules

Drop one or more `.yar` / `.yara` files here, e.g. `yara/batesian.yar`:

```yara
rule batesian_stub_marker {
    meta:
        description = "batesian packed stub"
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
