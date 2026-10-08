#Requires AutoHotkey v2.0
; AutoHotkey host for a `kind: dll` artifact.
;
; `DllCall` is built in, so AutoHotkey loads the DLL in-process: no shell and no
; child process. Like AutoIt it is a third-party interpreter that is common on
; managed workstations; whether it is allowed is the policy's call.
;
; NOT run on this repository's measurement host (no AutoHotkey there).
; Documented recipe; verify on the target.
;
; Usage:
;   AutoHotkey.exe examples\hosts\autohotkey_host.ahk [dll] [export]
;
; This file is AutoHotkey v2. In v1 (1.1) `DllCall` has no trailing return type
; -- the call is `DllCall(A_ScriptDir "\loader.dll\Run", "Ptr", 0, "Ptr", 0,
; "Ptr", 0, "Int", 0)`, and the result is the value itself rather than being
; typed last. `A_Args` also exists only from 1.1.27; older builds use `%1%`/`%2%`.

dll := A_Args.Length >= 1 ? A_Args[1] : "dist\dll-shellcode.dll"
export := A_Args.Length >= 2 ? A_Args[2] : "Run"

FileAppend("[*] loading " dll " (export " export ")`n", "*")

; The function is named as "path\function". The last argument is the return
; type; "Ptr" covers the three ignored pointers and "Int" the `show` flag.
code := DllCall(dll "\" export, "Ptr", 0, "Ptr", 0, "Ptr", 0, "Int", 0, "Int")

FileAppend("[+] " export "() -> " code "`n", "*")
