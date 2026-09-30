// A .NET host for a `kind: dll` artifact.
//
// `NativeLibrary.Load` maps the packed DLL into *this* process (the CLR's own
// image loader path, so `DllMain` runs and `JNI_OnLoad` does not) and
// `NativeLibrary.GetExport` finds the entry point. Unlike `[DllImport]`, the
// library path is a runtime value here, so the host can be pointed at any
// artifact.
//
// Usage:
//   dotnet run --project examples/hosts/dotnet_host -- [dll] [export]

using System.Diagnostics;
using System.Runtime.InteropServices;

string dll = args.Length > 0 ? args[0] : @"dist\dll-shellcode.dll";
string export = args.Length > 1 ? args[1] : "Run";

string full = Path.GetFullPath(dll);
Console.WriteLine($"[*] NativeLibrary.Load({full})");

// A missing file or a wrong bitness fails here, which is itself the check that
// the DLL matches the host's architecture.
IntPtr module = NativeLibrary.Load(full);
Console.WriteLine($"[*] module handle: 0x{module:X}");

IntPtr address = NativeLibrary.GetExport(module, export);
var call = Marshal.GetDelegateForFunctionPointer<PlainExport>(address);
// The plain export has the rundll32 shape: four arguments, ignored. On x64 the
// extra slots are unused; the declaration is what keeps the x86 `stdcall`
// balance right.
int code = call(IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 0);
Console.WriteLine($"[+] {export}() -> {code}");

// The DLL is now a module of this process: the child-process IoC is what a DLL
// build removes, not the fact that the module is mapped.
string stem = Path.GetFileName(full);
foreach (ProcessModule m in Process.GetCurrentProcess().Modules)
{
    if (string.Equals(m.ModuleName, stem, StringComparison.OrdinalIgnoreCase))
    {
        Console.WriteLine($"[+] host module list: {m.ModuleName} @ 0x{m.BaseAddress:X}");
    }
}

/// The four-argument `extern "system"` shape the export is declared with.
[UnmanagedFunctionPointer(CallingConvention.Winapi)]
internal delegate int PlainExport(IntPtr hwnd, IntPtr hinst, IntPtr cmdline, int show);
