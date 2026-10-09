# Host examples — `build.output.kind: dll`

One packed DLL, loaded from a host process instead of run as an `.exe`. A DLL is
not a program, so application-whitelisting *program* rules (SRP / AppLocker / a
GPO) never apply to it; the host has to be an allowed program (usually an
interpreter). Design: `docs/design/dll-output.md`; measured host matrix:
`docs/measurements.md`.

Two axes, worth keeping apart:

- **host** — the process that loads the DLL and calls the export (Python, Java,
  .NET, `rundll32`, Office/VBA, ...);
- **launch vector** — how that host is started when there is no shell (a macro
  document, a `.vbs`/`.js` launcher, a shortcut, a scheduled task, WMI, a
  ClickOnce/installer host, ...).

Every script below is a *host* driven from a shell ("`python …`", "`powershell
…`"). On a machine where `cmd.exe` **and** `powershell.exe` are both blocked —
a real WDAC/AppLocker/GPO case, and the reason `kind: dll` exists — the host
still works, but the *launcher* is the piece that has to be shell-free: see
[No shell at all](#6-no-shell-at-all) and `vba_host.bas`, `wsh_host.vbs`,
`wsh_host.js`, `scheduled_task.xml`.

The DLL runs **in the host's process**, so:

- its bitness must match the host's and the payload's;
- the host loads it with the normal image loader, so it is scanned on load and
  it appears in the host's module list;
- a process-scoped technique (`patch_etw`, `unhook_ntdll`, `patch_amsi`) patches
  the *host* — that is usually the point, but it is someone else's process.

## 1. Build the DLL

Three example plans, the first two `entry: auto` (the artifact exports
`DllMain`, `JNI_OnLoad` and `Run`, so one file works from every host):

| Plan | Payload | Behaviour |
|---|---|---|
| `examples/plans/dll-shellcode.yaml` | `demo_shellcode.bin` (`mov eax, 42; ret`) | the chain **returns 42**; every host below prints it |
| `examples/plans/dll.yaml` | `msgbox.exe` | the chain opens a **modal dialog** from the host process (the visible check); `Run` blocks until you dismiss it, then returns 0 |
| `examples/plans/dll-regsvr32.yaml` | `demo_shellcode.bin` | `entry: export:DllRegisterServer`, for the `regsvr32` launcher only |

```sh
cargo run -- build examples/plans/dll-shellcode.yaml   # dist/dll-shellcode.dll
cargo run -- build examples/plans/dll.yaml             # dist/dll-loader.dll
cargo run -- build examples/plans/dll-regsvr32.yaml    # dist/dll-regsvr32.dll
```

The examples below default to `dist/dll-shellcode.dll`; pass the other path to
try the visible payload.

## 2. Load it from a host

Measured on this repo's Windows host (Windows 11, x64):

| Host | Command | Expected |
|---|---|---|
| CPython | `python examples/hosts/ctypes_host.py` | `Run() -> 42` |
| PowerShell 5.1 | `powershell -ExecutionPolicy Bypass -File examples/hosts/pinvoke_host.ps1` | `Run() -> 42` + the DLL in the host's module list |
| .NET | `dotnet run --project examples/hosts/dotnet_host -- dist/dll-shellcode.dll Run` | `Run() -> 42` + the DLL in the host's module list |
| `rundll32` (PowerShell) | `powershell -ExecutionPolicy Bypass -File examples/hosts/rundll32_host.ps1` | a debug build's `STUB_MARKER_<hex>` on the captured stderr; `rundll32` exits 0 |
| `rundll32` (cmd) | `examples\hosts\rundll32_host.cmd` | a debug build's marker in cmd's console; `rundll32` exits 0 (the PowerShell-free path) |

The `rundll32` rows read the stub's marker, which only a debug build
(`build.stub.debug: true`) emits; a delivery build prints nothing.

Scripts committed but **not** run here (the runtime was not installed on this
host):

| Host | Command | Needs |
|---|---|---|
| Java (FFM) | `javac -d examples/hosts/java_host examples/hosts/java_host/FfmHost.java` then `java -cp examples/hosts/java_host FfmHost dist/dll-shellcode.dll Run` | JDK 22+ |
| Java (`JNI_OnLoad`) | `java -cp examples/hosts/java_host JavaHost dist/dll-shellcode.dll 10000` | any JDK |
| Perl | `perl examples/hosts/perl_host.pl` | Windows Perl with `Win32::API` (Strawberry bundles it) |
| Ruby | `ruby examples/hosts/ruby_host.rb` | Ruby (`Fiddle` is stdlib) |
| PHP | `php examples/hosts/php_host.php` | `extension=ffi` in `php.ini` |
| LuaJIT | `luajit examples/hosts/luajit_host.lua` | LuaJIT (not Lua 5.4) |
| Node.js | `npm install koffi` then `node examples/hosts/node_host.js` | the `koffi` package (Node has no stdlib FFI) |

The .NET row uses `dotnet run --project`, which needs the **SDK**; a locked-down
target usually has only the **runtime**, so publish a host once (`dotnet publish`)
and ship the executable instead.

Each script takes the DLL path and export name as arguments, e.g.
`python examples/hosts/ctypes_host.py dist/dll-loader.dll Run`.

### Launchers and the in-box hosts that are not interpreters

| Host / vector | Command | Notes |
|---|---|---|
| Office / VBA | import `examples/hosts/vba_host.bas`, then `?PicaroRun` | in-process macro host, **no shell at all**; the `Declare … Lib` path must be a literal |
| AutoIt | `AutoIt3.exe examples\hosts\autoit_host.au3` | in-box `DllCall`; third-party interpreter |
| AutoHotkey | `AutoHotkey.exe examples\hosts\autohotkey_host.ahk` | in-box `DllCall` (v2 file; v1 notes inside) |
| R | `Rscript examples/hosts/r_host.R` | `.C` returns the argument list, not the C code |
| Julia | `julia examples/hosts/julia_host.jl` | `ccall` reads the return code |
| Tcl | `tclsh examples/hosts/tcl_host.tcl` | needs `ffidl` (no core FFI) |
| `regsvr32` | `examples\hosts\regsvr32_host.cmd` | needs `examples/plans/dll-regsvr32.yaml` (`entry: export:DllRegisterServer`) |
| WSH (VBScript) | `wscript examples\hosts\wsh_host.vbs` | **launcher only** (no FFI): starts `rundll32` with no shell |
| WSH (JScript) | `cscript //nologo examples\hosts\wsh_host.js` | **launcher only** |
| Task Scheduler | import `examples\hosts\scheduled_task.xml` | **launcher only**: runs `rundll32` at logon, no shell |

`rundll32_host.cmd` is worth reading before you write your own: the DLL path must
**not** be quoted (measured: a quoted path makes rundll32 fail before the call,
leaving a process stuck on an invisible error dialog), and the script takes the
8.3 short name so paths with spaces still work unquoted. `regsvr32_host.cmd`
follows the same shape but targets a different exported name.

The per-runtime recipes, the whitelisting rationale, the calling-convention
details and what to do when PowerShell is not available are in the docs page
[`docs/hosts.md`](../../docs/hosts.md).

## 3. What to look at

- **The return value.** The plain export (`Run`) *blocks* and returns the
  chain's code, so `42` proves the chain ran, not that the module merely mapped.
  `rundll32` is the exception: it never relays the value, so its evidence is the
  marker on stderr.
- **The module list.** The DLL is a mapped module of the host
  (`dll-shellcode.dll @ 0x7FF…`), i.e. the child-process IoC is what this mode
  removes, not the file.
- **The exports.** `cargo run -- audit dist/dll-shellcode.dll` prints the
  `EXPORTS` section (`DllMain`, `JNI_OnLoad`, `Run`); the PE also records the
  delivered name (`strings dist/dll-shellcode.dll`).
- **The blocking entry.** `JNI_OnLoad` returns at once (the JVM keeps its own
  thread and owns the lifetime); `Run` waits, because `rundll32` exits the moment
  the export returns and would tear the payload thread down with it.

## 4. Calling shape

The plain export takes the four-argument shape `rundll32` calls natively:

```c
int Run(void *hwnd, void *hinst, const char *cmdline, int show);  /* arguments ignored */
```

On x64 a caller may pass none (extra argument slots are simply unused); the
declaration above is what a C#/FFI host should use, and on x86 `extern "system"`
is `stdcall`, so a callee that pops four arguments needs a caller that pushed
four — `rundll32` does.

## 5. Entry points

| `build.output.entry` | Exports | Use from |
|---|---|---|
| `auto` (default) | `DllMain`, `JNI_OnLoad`, `Run` | any host; the export table is a delivery tell |
| `jni_on_load` | `DllMain`, `JNI_OnLoad` | Java only |
| `export:Name` | `DllMain`, `Name` | CPython / .NET / `rundll32` / FFI |

`DllMain` is always emitted: it is the export an ordinary DLL has, and the only
place the host's per-thread notifications are dropped.

## 6. No shell at all

A machine where `cmd.exe` and `powershell.exe` are both blocked is the case this
whole mode is for. `kind: dll` solves the *host* (a DLL is not a program, so the
program rule that lets the interpreter run is the rule that runs the chain), but
the *launch vector* still has to exist without a shell. The examples above are
split accordingly:

- **In-process, no launcher needed**: `vba_host.bas` (an Office macro) loads the
  DLL straight from the document. This is the only entry here that needs no
  second process at all.
- **Shell-free launchers**: `wsh_host.vbs` / `wsh_host.js` (WSH has no FFI, so it
  cannot *host*, but `WScript.Shell.Run` / `Shell.Application.ShellExecute` /
  WMI `Win32_Process.Create` start `rundll32` with no `cmd`), and
  `scheduled_task.xml` (register it from the Task Scheduler GUI or the
  `Schedule.Service` COM object; `schtasks` would need `cmd`).
- **A host launched by any of those**: any interpreter above, or `rundll32` /
  `regsvr32`.

What the block actually is decides the outcome, and no launch vector changes it:

- a **scripting-host** block (ConstrainedLanguage, an AppLocker rule against
  `powershell.exe`/`wscript.exe`) leaves the other vectors untouched;
- a **program allow-list** is exactly what `kind: dll` sidesteps, as long as the
  host is allowed and `%WINDIR%`'s default rules cover `rundll32`/`regsvr32`;
- **DLL rules / WDAC code integrity** block the artifact itself at load, whoever
  loads it — the signature (`build.output.sign`) is the variable there, not the
  host or the launcher.

`regsvr32_host.cmd` needs `examples/plans/dll-regsvr32.yaml`, because regsvr32
calls `DllRegisterServer` and the default artifact does not export it; the
`entry: export:<name>` mechanism is what makes the artifact match its launcher.

## 7. Not supported for a DLL build

`subsystem: windows`, `resources.manifest`, `self_deletion`, `sleep_obfuscation`
(both act on the *running image* — the host, here), `bouncer` with
`on_fail: exit` (it would `ExitProcess` the host) and custom stubs. The build
rejects each one with a message naming the reason.
