# Loads a packed DLL through rundll32 and makes its output observable.
#
# rundll32.exe is a GUI-subsystem binary, so neither cmd nor PowerShell hands it
# the parent's console (and `AttachConsole(ATTACH_PARENT_PROCESS)` in the DLL
# cannot attach a console that was never there). `Start-Process -Redirect...`
# is what captures the chain's stderr — the stub's per-build marker.
#
# rundll32 does not relay the export's return value: it always exits 0, so use
# the marker (or ctypes/P-Invoke) as the evidence that the chain ran.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File examples/hosts/rundll32_host.ps1 `
#       [-Dll dist\dll-shellcode.dll] [-Export Run]

param(
    [string]$Dll = "dist\dll-shellcode.dll",
    [string]$Export = "Run"
)

# Temp file is deliberate: the repository stays clean.
$err = Join-Path $env:TEMP "picaro_rundll_stderr.txt"
Remove-Item -ErrorAction SilentlyContinue $err

Write-Output "[*] rundll32 $Dll,$Export"
$p = Start-Process -FilePath "rundll32.exe" `
    -ArgumentList "$Dll,$Export" `
    -Wait -PassThru -NoNewWindow `
    -RedirectStandardError $err

Write-Output ("[+] rundll32 exit code: " + $p.ExitCode + " (always 0: it does not relay the export's code)")
if (Test-Path $err) {
    Get-Content $err | ForEach-Object { Write-Output "[+] stderr: $_" }
}
