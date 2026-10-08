@echo off
rem Loads a packed DLL through regsvr32.exe: another signed, in-box Windows
rem binary that maps a DLL with the OS loader and calls a well-known export, so
rem the chain runs with no cmd script of its own and no PowerShell.
rem
rem Difference from rundll32: regsvr32 calls `DllRegisterServer` (and
rem `DllUnregisterServer` under /u), not the artifact's plain export. The default
rem artifact does NOT export it, so pair this launcher with a plan built as
rem `entry: export:DllRegisterServer` -- see examples\plans\dll-regsvr32.yaml.
rem
rem Measured caveat (docs/hosts.md): a default `dll-shellcode.dll` loaded with
rem `/s` did not run the chain and the process still exited 0, so under /s the
rem exit code is not evidence. Use a payload with an observable side effect.
rem
rem Usage: examples\hosts\regsvr32_host.cmd [dll]

setlocal
set "DLLFULL=%~f1"
if "%DLLFULL%"=="" set "DLLFULL=%CD%\dist\dll-regsvr32.dll"

rem 8.3 short name: no spaces, so the path stays a single unquoted argument
rem (the quoting trap is measured for rundll32 -- see rundll32_host.cmd -- and
rem this keeps the same form here).
for %%I in ("%DLLFULL%") do set "DLL=%%~sI"

echo [*] regsvr32 /s %DLL%
regsvr32.exe /s %DLL%
rem /s suppresses regsvr32's own result dialog; do not read the exit code as
rem proof the chain ran.
echo [+] regsvr32 exit code %ERRORLEVEL%
endlocal
