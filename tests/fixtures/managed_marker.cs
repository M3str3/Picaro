// Managed fixture for the `dotnet_hosting` tests.
//
// It prints a fixed marker (plus the process bitness, so a test can tell which
// CLR ran it) and returns a distinctive exit code. Build it with the framework
// compiler that ships with Windows:
//
//   csc /nologo /target:exe /platform:x86     /out:managed_x86.exe     managed_marker.cs
//   csc /nologo /target:exe /platform:anycpu  /out:managed_anycpu.exe  managed_marker.cs
//
// (`csc` lives in `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\`.)

using System;

internal static class Marker
{
    private static int Main(string[] args)
    {
        Console.WriteLine(
            "MANAGED_MARKER_7f3a9c2e args={0} x64={1}",
            args.Length,
            Environment.Is64BitProcess);
        return 42;
    }
}
