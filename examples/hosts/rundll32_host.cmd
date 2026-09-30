@echo off
rem Loads a packed DLL from cmd.exe.
rem
rem Batch has no FFI: cmd cannot call an export itself, and its only path is to
rem launch a host. rundll32 ships with Windows and calls the export in the
rem four-argument shape natively, so it is the in-box host.
rem
rem Two cmd/rundll32 details that cost real time when they bite:
rem
rem   - the DLL path must NOT be quoted. `rundll32 "x.dll",Run`, `rundll32
rem     "x.dll,Run"` and the same with an absolute path were all measured to
rem     fail before the export was called, while the unquoted form works. The
rem     path is taken from the 8.3 short name below, which has no spaces, so
rem     long paths with spaces are safe without quotes;
rem   - rundll32 is a GUI-subsystem program: cmd does not wait for it, and a
rem     failure (a missing export, a bad path) is a modal *dialog*, not an error
rem     code -- in an automated context that is a process blocked forever with
rem     no message. The ping below keeps this console alive briefly so the chain
rem     output lands, and a payload with a side effect is the reliable evidence.
rem
rem Usage: examples\hosts\rundll32_host.cmd [dll] [export]

setlocal
set "DLLFULL=%~f1"
if "%DLLFULL%"=="" set "DLLFULL=%CD%\dist\dll-shellcode.dll"
set "EXPORT=%~2"
if "%EXPORT%"=="" set "EXPORT=Run"

rem 8.3 short name: no spaces, so the unquoted form stays one argument.
for %%I in ("%DLLFULL%") do set "DLL=%%~sI"
set "TARGET=%DLL%,%EXPORT%"

echo [*] rundll32 %TARGET%
rundll32.exe %TARGET%
rem A portable sleep (~2s); `timeout` needs a console that this script may not have.
ping -n 3 127.0.0.1 > nul
echo [+] rundll32 exit code %ERRORLEVEL% (always 0: it does not relay the export's code)
endlocal
