# Loads a packed DLL through .NET P/Invoke: Add-Type compiles a C# host into
# powershell.exe, so the interpreter is the loading process. Prints the value the
# export returns and checks that the module shows up in the host's module list
# (the image-load telemetry a DLL build does *not* hide).
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File examples/hosts/pinvoke_host.ps1 `
#       [-Dll dist\dll-shellcode.dll] [-Export Run]
#
# The C# declaration uses the rundll32 four-argument shape, which is what
# `rundll32` calls natively and what the x86 export requires.

param(
    [string]$Dll = "dist\dll-shellcode.dll",
    [string]$Export = "Run"
)

$full = (Resolve-Path $Dll).Path
Write-Output "[*] loading $full (export $Export)"

$source = @"
using System;
using System.Runtime.InteropServices;

public static class PicaroHost
{
    [DllImport(@"$full", EntryPoint = "$Export")]
    public static extern int Call(IntPtr hwnd, IntPtr hinst, IntPtr cmd, int show);
}
"@

Add-Type -TypeDefinition $source
# Blocking export: this call holds the thread for the payload's lifetime, which
# is the point for rundll32 and visible from a .NET caller.
$code = [PicaroHost]::Call([IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, 0)
Write-Output "[+] $Export() -> $code"

$stem = [System.IO.Path]::GetFileName($full)
$mods = [System.Diagnostics.Process]::GetCurrentProcess().Modules |
    Where-Object { $_.ModuleName -eq $stem }
if ($mods) {
    foreach ($m in $mods) {
        Write-Output ("[+] host module list: {0} @ {1}" -f $m.ModuleName, $m.BaseAddress)
    }
} else {
    Write-Output "[!] $stem is not in the host's module list"
}
