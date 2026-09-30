# Host examples — `build.output.kind: dll`

One packed DLL, loaded from a host process instead of run as an `.exe`. A DLL is
not a program, so application-whitelisting *program* rules (SRP / AppLocker / a
GPO) never apply to it; the host has to be an allowed program (usually an
interpreter). Design: `docs/design/dll-output.md`; measured host matrix:
`docs/measurements.md`.

The DLL runs **in the host's process**, so:

- its bitness must match the host's and the payload's;
- the host loads it with the normal image loader, so it is scanned on load and
  it appears in the host's module list;
- a process-scoped technique (`patch_etw`, `unhook_ntdll`, `patch_amsi`) patches
  the *host* — that is usually the point, but it is someone else's process.

## 1. Build the DLL

Two example plans, both `entry: auto` (the artifact exports `DllMain`,
`JNI_OnLoad` and `Run`, so one file works from every host):

| Plan | Payload | Behaviour |
|---|---|---|
| `examples/plans/dll-shellcode.yaml` | `demo_shellcode.bin` (`mov eax, 42; ret`) | the chain **returns 42**; every host below prints it |
| `examples/plans/dll.yaml` | `msgbox.exe` | the chain opens a **modal dialog** from the host process (the visible check); `Run` blocks until you dismiss it, then returns 0 |

```sh
cargo run -- build examples/plans/dll-shellcode.yaml   # dist/dll-shellcode.dll
cargo run -- build examples/plans/dll.yaml             # dist/dll-loader.dll
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
| `rundll32` (PowerShell) | `powershell -ExecutionPolicy Bypass -File examples/hosts/rundll32_host.ps1` | the stub's `STUB_MARKER_<hex>` on the captured stderr; `rundll32` exits 0 |
| `rundll32` (cmd) | `examples\hosts\rundll32_host.cmd` | the stub's marker in cmd's console; `rundll32` exits 0 (the PowerShell-free path) |

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

Each script takes the DLL path and export name as arguments, e.g.
`python examples/hosts/ctypes_host.py dist/dll-loader.dll Run`.

`rundll32_host.cmd` is worth reading before you write your own: the DLL path must
**not** be quoted (measured: a quoted path makes rundll32 fail before the call,
leaving a process stuck on an invisible error dialog), and the script takes the
8.3 short name so paths with spaces still work unquoted.

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

## 6. Not supported for a DLL build

`subsystem: windows`, `resources.manifest`, `self_deletion`, `sleep_obfuscation`
(both act on the *running image* — the host, here), `bouncer` with
`on_fail: exit` (it would `ExitProcess` the host) and custom stubs. The build
rejects each one with a message naming the reason.
