; AutoIt3 host for a `kind: dll` artifact.
;
; AutoIt ships `DllCall`, so the interpreter loads the DLL in-process: no shell
; and no child process are involved. AutoIt is a third-party, but very common,
; managed-workstation interpreter -- whether it is *allowed* is the policy's
; call, not the artifact's.
;
; NOT run on this repository's measurement host (no AutoIt there). Documented
; recipe; verify on the target.
;
; Usage:
;   AutoIt3.exe examples\hosts\autoit_host.au3 [dll] [export]
; or open it in SciTE and press F5.

Local $dll = "dist\dll-shellcode.dll"
If $CmdLine[0] >= 1 Then $dll = $CmdLine[1]

Local $export = "Run"
If $CmdLine[0] >= 2 Then $export = $CmdLine[2]

ConsoleWrite("[*] loading " & $dll & " (export " & $export & ")" & @CRLF)

; DllCall returns an array: element [0] is the function's return value and the
; remaining elements are the by-reference arguments (none here). The type
; strings are "ptr" for the three ignored pointers and "int" for `show`; the
; return type is declared first ("int").
Local $result = DllCall($dll, "int", $export, "ptr", 0, "ptr", 0, "str", "", "int", 0)

If @error Then
    ConsoleWrite("[!] DllCall failed (@error " & @error & ", @extended " & @extended & ")" & @CRLF)
    Exit 1
EndIf

ConsoleWrite("[+] " & $export & "() -> " & $result[0] & @CRLF)
