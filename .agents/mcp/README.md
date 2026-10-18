# picaro-debugger MCP server

An MCP server that gives the Zed agent an **lldb-backed debugger** for packed
artifacts, a **static triage** toolbelt (PE facts, exports, Intel disassembly,
strings, YARA), the **project's technique registry** (list / show / validate) and
the minimum around it to prepare sessions (build a debug stub, run the artifact
once without a debugger).

It is an HTTP server on loopback, started by hand in a console:

```sh
python .agents/mcp/server.py --lab          # http://127.0.0.1:8787/mcp
```

The console is the live log of the session (every tool call, every stop). Zed
connects to it as a remote MCP server, so the server's lifetime is yours, not
Zed's.

## Zed registration

`settings.json` (Windows: `%APPDATA%\Zed\settings.json`):

```json
"context_servers": {
  "picaro-debugger": {
    "url": "http://127.0.0.1:8787/mcp"
  }
}
```

Check **Settings → AI → MCP Servers**: the indicator next to `picaro-debugger`
must be green (*Server is active*). Without `--lab` the server only exposes
the inert tools.

**Zed caches the tool list.** It reads `tools/list` once, when it connects, and
does not re-read it: a server that was down at connect time stays marked
*server shut down* for the whole session even after it is up, and a server
restarted after a `server.py` change keeps serving Zed's stale toolset (that is
how `disassemble_file`, `strings_file`, `yara_scan` and `activity_log` can be
missing from a session while the server reports 34 tools). Spend a second on the
fix: with the server running, toggle the `picaro-debugger` entry off and on in
**Settings → AI → MCP Servers** (or reload the window).

## Agent skills

- `.agents/skills/picaro-debugger/` — when and how to drive live sessions
  (breakpoints, stepping, attach, anti-debug comparisons).
- `.agents/skills/picaro-analysis/` — inert static triage (hashes, PE facts,
  disassembly, strings, YARA, baselines).
- `.agents/skills/picaro-techniques/` — inspect the technique registry and the
  checklist for adding or changing a technique.

## Requirements

- Python 3.10+ (3.14 here).
- **lldb with Python bindings.** Discovered from `lldb` on PATH (scoop's
  `<root>/bin/lldb.exe` + `<root>/lib/site-packages/lldb`) or from
  `PICARO_LLDB_HOME` pointing at the LLVM root.
- `llvm-objdump` (ships with the scoop llvm install) for `disassemble_file`;
  `pefile` (pip) for the PE tools.
- Optional: the `yara` CLI for `yara_scan`; Sysinternals, capa, … — see
  *Installing the optional tooling*.

## Tools

| group | tool | what |
| --- | --- | --- |
| static | `hash_file` | sha256, sha1, md5 + size. |
| static | `pe_info` | machine, entry point RVA/VA (payload OEP), image base, sections with flags. |
| static | `export_lookup` | resolve a module export to its RVA and, with a live session, to its address — the offline way to breakpoint system-DLL APIs. |
| static | `disassemble_file` | Intel disassembly via llvm-objdump: at the entry point, or `at` = VA / `+RVA` / export name. |
| static | `strings_file` | ASCII + UTF-16LE strings with file offsets (the raw view; `audit_file` is the curated one). |
| static | `yara_scan` | scan with the `yara` CLI (rule file or directory); `rules` defaults to the repo's rules under `src/audit/yara/rules/`. |
| static | `audit_file` | `picaro audit --json` (sections+entropy, imports/exports, string triage, YARA, Defender verdict); `baseline` diffs against an earlier report. |
| project | `techniques_list` | the technique registry (`picaro techniques list`): key, category, stability, ATT&CK id, summary. |
| project | `technique_show` | a technique's full README (`picaro techniques show <name> --raw`): what it does and its plan keys. |
| project | `techniques_validate` | validate the registry (keys, fragments, loader features); never fails, the verdict is the text. |
| prep | `build_plan` | `picaro build <plan>`; `debug=true` keeps symbols/source and returns `stub_exe` + `stub_source` (from `build/<name>/` when `name` is set, else `build/run-*/`). |
| prep | `defender_status` | AV state + this server's lab gate. |
| exec | `run_artifact` | run a PE **without** the debugger (control run for anti-debug comparisons). |
| debug | `debug_launch` / `debug_attach` / `debug_close` / `debug_status` | session lifecycle; stdout/stderr are captured into every stop. |
| debug | `bp_set` / `bp_list` / `bp_delete` / `bp_enable` | breakpoints: `module!symbol`, `symbol` (crate-qualified for Rust), `re:`, `file.rs:123`, `+0xRVA`, `@0xADDR`, `0xADDR`; software or hardware; conditions. |
| debug | `run_until_event` / `step` | continue with a timeout (watchdog interrupt) or step over/into/out/insn. Stops come back as `breakpoint`, `step`, `exception`, `signal`, `entry`, `exited`, `crashed` or `timeout`. |
| debug | `registers` / `read_memory` / `write_memory` / `memory_scan` | CPU and memory access; `memory_scan` finds `MZ` in anonymous mappings (mapped payloads). |
| debug | `stack` / `threads` / `select_thread` / `modules` / `disassemble` / `evaluate` | the usual inspection. |

## Recipes

**Static triage.** Inert everywhere.

```
hash_file(path="dist/x.exe"); pe_info(path="examples/payloads/test_payload.exe")
disassemble_file(path="dist/x.exe", at="+0x1000", count=32)
strings_file(path="dist/x.exe", min_length=8)
yara_scan(path="dist/x.exe")                  # needs `scoop install yara`
```

**Inspect the project (registry and plans).** Inert; no sample, no lab.

```
techniques_list()                            # the whole registry: stability, ATT&CK, summary
technique_show(name="reflective_loading")    # its README: what it does, its plan keys
techniques_validate()                        # keys, fragments, loader features (OK or the list)
build_plan(plan="examples/plans/x.yaml", dry_run=True)  # validate a plan, compile nothing
```

**Debug the generated stub (source level).** Pass `name="<dir>"` to
`build_plan(debug=true)` and the engine stages that build under `build/<dir>/`
— a stable path across runs, so a fixed breakpoint target survives a rebuild.
Without a `name` it uses a unique `build/run-<pid>-<timestamp>/`. Either way
`out.exe`, `out.pdb` and `main.rs` stay together and `build_plan` returns
`stub_exe` + `stub_source`. Launch **that intermediate**, not the `dist/` copy:
the PDB is referenced by bare name (`out.pdb`) and lldb only resolves it next to
the executable. (The same flag exists on the CLI: `picaro build <plan> --debug
--build-name <dir>`, and it prints a `scratch  <path>` line.)

```
build_plan(plan="examples/plans/reflective-loading.yaml", debug=true, name="dbg")
debug_launch(path="<stub_exe>")              # stops at entry
bp_set(spec="main::step_0::payload")         # crate-qualified; a Preparation exposes run()
bp_set(spec="<stub_source>:869")             # or a source line in the generated stub
run_until_event(timeout_s=15)                # breakpoint hit with file/line in the frame
registers(names=["rip", "rsp"]); stack(); read_memory(...)
bp_delete(id=<noisy breakpoint>)             # APIs hit many times; clean up before the long run
```

**Payload OEP after mapping** (reflective loading / hollowing): break on the
allocation, read the base back, then break at `base + OEP`.

```
pe_info(path="examples/payloads/test_payload.exe")              # OEP RVA
export_lookup(module="ntdll", name="NtAllocateVirtualMemory")   # offline: the export table
bp_set(spec="@<address>")                                       # break on the API
run_until_event(timeout_s=15)
stack(); read_memory(address="rsp", size=0x40)                   # args on the stack
# after the allocation returns, rax is the base; then:
memory_scan(pattern="MZ", max_results=8)                         # confirm the base
bp_set(spec="@0x<base+oep>")
```

**Does anti_debug work?** `run_artifact` (no debugger) against `debug_launch`
(with debugger): the difference in exit code / output *is* the answer. The
debugger is the adversary here; nothing bypasses the checks for you.

**Hollowing target**: `debug_attach(name="svchost.exe")` while the loader is
suspended, then `threads`, `stack`, `modules`.

## Installing the optional tooling

| tool | why | install |
| --- | --- | --- |
| `yara` CLI | `yara_scan` + the YARA section of `picaro audit` | `scoop install yara` |
| llvm | `llvm-objdump`, `llvm-readobj`, and lldb itself | already installed (`scoop install llvm`) |
| Sysinternals | Procmon/ProcExp next to a debug session | `scoop bucket add extras`, then `scoop install sysinternals` (it is not in the main bucket) |
| capa | capability detection for triage | `pip install flare-capa` (verified: resolves on Python 3.14) |
| floss | strings from obfuscated/encoded data | `pip install flare-floss` (verified: resolves on Python 3.14) |
| Wireshark/tshark | loopback traffic when testing network stagers | `scoop install wireshark` |

Already present and used: Python 3.14, `pefile`, `capstone`, gcc's `strings`,
`wpr` (ETW, for later), 7-Zip. `cdb`/`dumpbin` are not needed (lldb +
llvm-objdump cover debugging and disassembly).

## Safety gates

All execution/debugger tools only exist with `--lab` (or `PICARO_MCP_LAB=1`),
and launch paths additionally refuse while Windows Defender real-time
protection is on. One session at a time; a target that keeps running is
stopped by the watchdog and stays usable.

## Manual test

```sh
python .agents/mcp/test_smoke.py            # also launches benign targets under lldb
python .agents/mcp/test_smoke.py --quick    # analysis-only checks
```

## lldb quirks this server encodes (measured on LLDB 23.1.2, Windows)

- Sync mode only: async mode never delivered a usable stop context here.
- Timeouts are `SBProcess.SendAsyncInterrupt()` from a timer thread
  (`SBProcess.Stop()` does nothing from another thread).
- `SBLaunchInfo` argv must not include `argv[0]`: lldb prepends the image, so
  including it runs `app.exe app.exe ...` (which looks like instant crashes).
- stdin is `NUL` and stdout/stderr go to temp files (`picaro-mcp-*.out/.err`);
  debuggees otherwise die on their first write, and the files double as the
  captured output in every stop result.
- A `dist/` artifact has no PDB next to it (the reference is the bare name
  `out.pdb`), so debug builds are debugged from `build/run-*/out.exe`.
- Rust symbols are crate-qualified (`main::step_0::payload`) and `re:`
  breakpoints match the mangled name, so prefer plain names or `file:line`.
  System DLLs have no offline symbols at all: resolve exports with
  `export_lookup` and breakpoint the address.
- `step kind=insn` is lldb's *instruction step, over calls*. At a `call` it runs
  the callee to completion, so a step over `reflective_loading`/`dotnet_hosting`
  (their call never returns) runs the whole payload to the `exited` stop —
  expected, not a lost stop. Use `into` to enter a call.

## Roadmap

- Keep `out.pdb` reachable from `dist/` artifacts so the final copy is
  debuggable too.
- `symbols_load`: load the payload's symbols onto its mapped image so
  breakpoints can use its function names.
- Watchpoints (write on the still-empty OEP) and a batch `trace` mode.
- Remote deployment: run the same server on a separate lab host (Zed accepts
  remote `url` servers, so nothing else changes).
