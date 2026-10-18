---
name: picaro-analysis
description: "Static, inert triage of binaries with the picaro-debugger MCP: hashes, PE facts (entry point, sections, entropy), export resolution, Intel disassembly via llvm-objdump, raw strings with file offsets, YARA scans, and audit baselines. Never executes the sample. Use when the user asks to analyze or triage a sample or artifact, compare builds for regressions, read assembly, or hunt for strings/rules."
---

# Static analysis with the picaro-debugger MCP

Load this skill for inert triage — nothing here executes a sample, so it is
safe on any host and does not need the lab gates. For live
breakpoints/stepping/attach use the `picaro-debugger` skill instead; for the
technique registry (what a build's techniques are meant to do) use
`picaro-techniques`. The server must be running
(`python .agents/mcp/server.py --lab`); the static tools also work without
`--lab`.

## The triage loop

```
hash_file(path=...)                    # sha256/sha1/md5 + size — the identity of the sample
pe_info(path=...)                      # machine, entry_point_va (OEP), image_base, sections
audit_file(path=...)                   # picaro audit --json: sections+entropy, imports/exports,
                                       #   string triage, YARA (stub rules), Defender verdict
audit_file(path=..., baseline="prev.json")  # regressions come back prefixed REGRESSION
export_lookup(module=..., name=...)    # export → RVA (+ address when a session is live)
disassemble_file(path=..., at="+0x<rva>")   # Intel assembly; at = VA | +RVA | export; default = entry
strings_file(path=..., min_length=6)   # ASCII + UTF-16LE with file offsets (the raw view)
yara_scan(path=..., rules=...)         # custom rules; default = the repo's rules (mimikatz byte patterns)
```

## What to reach for

- **Identify the sample**: `hash_file`, then the build provenance in
  `dist/<name>.manifest.json` (read it with your file tools).
- **Why does this PE look odd?** `audit_file` (high-entropy sections, thin
  imports, overlay), then `strings_file` for raw evidence and
  `disassemble_file` at the entry point.
- **Where does control go?** `pe_info` prints `entry_point_va`;
  `disassemble_file` (no `at`) starts there; follow `call` targets by
  disassembling at their VA.
- **Did a change regress a build?** `audit_file` with `baseline` against an
  earlier `--json` report; the tool returns the diff text prefixed
  `REGRESSION` (audit exited 3).
- **What are this build's techniques meant to do?** `audit_file`'s
  `strings.sensitive` flags the technique keys that leaked into the artifact;
  `techniques_list` / `technique_show(name=...)` then describe each one (the
  `picaro-techniques` skill covers the registry).
- **Rules**: `yara_scan` needs the `yara` CLI (`scoop install yara`); the
  repo's rules in `src/audit/yara/rules/` (byte-pattern signatures for known
  tools — currently a mimikatz pair) are the default and also feed the YARA
  section of `picaro audit`. Detection is best-effort: a rule can miss a
  different build of the same tool.

## Notes and traps

- `disassemble_file` addresses are absolute VAs (`image_base + RVA`); `pe_info`
  prints both. Symbol-level disassembly of a `--debug` stub (Rust names) needs
  the live session — switch to the `picaro-debugger` skill and use lldb's
  `disassemble`.
- `strings_file` offsets are file offsets, not RVAs.
- `run_artifact` and every `debug_*` tool execute: they belong to the debugger
  skill and the lab gates. Do not invoke them for pure triage.
- `audit_file`'s Defender line shells out to the OS scanner; in a container it
  reports `unavailable` (known limitation).
