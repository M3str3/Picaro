# YARA rules

This directory holds YARA rules used by `picaro audit` to tag known
signatures in a binary.

## Engine

`picaro audit` scans the binary through the **`yara` CLI as a subprocess** (see
`src/audit/yara/mod.rs`): the artifact bytes are written to a temporary file under
the system temp directory, `yara <rule-file> <temp-file>` is run once per rule
file, and the matching rule names are parsed from stdout. No native libyara
dependency is required.

The scan is strictly **best-effort**:

- No `.yar` / `.yara` file here → the report shows `ruleset empty`.
- Rules present but `yara` is not on `PATH` → the report shows
  `yara not found in PATH`, and the audit still completes (it is a soft note,
  not a failure).

The `yara` executable can be overridden with the `PICARO_YARA` environment
variable (empty or unset means `yara` on `PATH`).

## Adding rules

Drop one or more `.yar` / `.yara` files under `src/audit/yara/rules/`, e.g.
`src/audit/yara/rules/picaro.yar`:

```yara
rule picaro_stub_marker {
    meta:
        description = "Picaro packed stub"
    strings:
        $a = "STUB_MARKER_" ascii
    condition:
        $a
}
```

Rule files are discovered case-insensitively by extension and scanned in a
deterministic (sorted) order; a rule name is the first whitespace-delimited
token of each matching output line, deduplicated and sorted in the report.
