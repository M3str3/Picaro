---
name: picaro-debugger
description: "Debug packed Picaro artifacts through the picaro-debugger MCP server: build a --debug stub, set breakpoints (crate-qualified Rust symbols, file:line in the generated stub, system-DLL exports via export_lookup), step, read registers and memory, attach to a target, and compare anti-debug behavior with and without a debugger. Use when the user asks to debug a stub or artifact, set breakpoints, inspect a running loader, or check what a technique does at runtime. For static-only triage (no execution) use the picaro-analysis skill instead."
---

# Driving the picaro-debugger MCP

Load this skill when the user wants to debug a built artifact or stub, set
breakpoints, step, inspect runtime state, attach to a process, or verify a
technique (including `anti_debug`). The server's full tool table and the
measured lldb quirks are in `.agents/mcp/README.md`. For inert static work
(hashes, PE facts, disassembly, strings, YARA) use the sibling
`picaro-analysis` skill — nothing in this one is safe without the lab gates.

## Preconditions

1. **The user runs the server in a console** — by design:
   `python .agents/mcp/server.py --lab` → `http://127.0.0.1:8787/mcp`.
   If the `debug_*` tools are not in your toolset, the server is down or was
   started without `--lab`: ask the user to start/restart it (start it
   yourself only if the user explicitly asks). Zed caches `tools/list` when it
   connects and never refreshes it: after a server restart (or a `server.py`
   change) the toolset stays stale until the entry is toggled in
   **Settings → AI → MCP Servers** (or the window is reloaded) with the server
   running.
2. When in doubt, call `defender_status`. Execution/debug tools refuse while
   Defender real-time protection is on — that is the lab gate from
   `AGENTS.md`, not a bug; relay it instead of retrying.
3. One session at a time. `debug_close` (kill by default) before switching
   targets. A debug session runs real loaders: lab host only.

## The loop

```
build_plan(plan="examples/plans/<plan>.yaml", debug=true, name="dbg")  # → stub_exe + stub_source (packed/<plan>-dbg/build/; omit name → unique packed/<plan>-<pid>-<nanos>/)
debug_launch(path=stub_exe)                                # stops at entry; every stop carries stdout/stderr tails
bp_set(spec="main::step_0::payload")                       # crate-qualified; Execution=payload(), Preparation=run()
bp_set(spec="<stub_source>:<line>")                        # or a source line of the generated stub
run_until_event(timeout_s=30)                              # kind: breakpoint | step | exception | signal | entry | exited | crashed | timeout
registers(names=["rip", "rsp", "rax"]); read_memory(address="rip", size=16); stack(); disassemble()
bp_delete(id=<noisy one>)                                  # API breakpoints repeat; clean up before long runs
run_until_event(...) until kind == "exited"                # then read stop["output"] and stop["exit_status"]
debug_close()
```

- The stub's crate is `main`: `main::step_0::payload` (step wrapper),
  `main::step_0::run_reflective` (technique helper), `main::run` (runner).
- Before breakpointing a technique, `technique_show(name=...)` shows what it is
  meant to do (the `picaro-techniques` skill covers the registry).
- `run_until_event` never hangs: on timeout the watchdog interrupts and the
  process stays stopped and usable.
- `re:` breakpoints match the mangled name — prefer plain names or `file:line`.
- System DLLs have no offline symbols, so `bp_set("ntdll!NtX")` stays pending:
  `export_lookup(module="ntdll", name="NtAllocateVirtualMemory")` then
  `bp_set(spec="@<address>")`.
- Debug the staged intermediate (`stub_exe`), not the `dist/` copy: the PDB is
  referenced by bare `out.pdb` and is only found next to the intermediate.
- Payload OEP work: `pe_info` on the payload for the entry RVA; after the
  allocation returns, `rax` is the base; `memory_scan(pattern="MZ")` locates
  mapped images; then `bp_set("@<base + oep>")`.
- Attach (e.g. hollowing targets): `debug_attach(pid=...)` or
  `debug_attach(name="svchost.exe")`, then `threads` / `stack` / `modules`.

## Anti-debug and verification

- Do **not** bypass detector techniques. To verify `anti_debug`, run the same
  artifact with `run_artifact` (no debugger) and `debug_launch` (debugger) and
  compare exit code and output — the difference is the answer.
- `write_memory` is for experiments the user explicitly asks for (patch a
  check, corrupt a value); it is not a default move.
- Report evidence: stop kinds, frame function/file/line, register values,
  output tails, exit code.

## Traps

- `tests/fixtures/minimal_*.exe` are `loop {}` parser fixtures — never launch
  them, they never exit.
- Windows paths in specs are fine (`C:\...\main.rs:238`); the tool splits on
  the last `:`.
- The first stop after launch is `kind: "entry"` (a SIGTRAP on top of the
  entry point) — normal.
- A `timeout` stop is left on purpose; `step`/`run_until_event` continue from
  it like from any other stop.
