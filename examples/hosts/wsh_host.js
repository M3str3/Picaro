// JScript (cscript/wscript) is a *launcher*, not a host: Windows Script Host
// has no FFI, so it cannot call the export -- but it starts a program that can
// with no cmd.exe and no powershell.exe. The JScript twin of wsh_host.vbs.
//
// NOT run on this repository's measurement host (documented recipe). A
// scripting-host block refuses this file outright; check it first.
//
// Usage: cscript //nologo examples\hosts\wsh_host.js [dll] [export]

var args = WScript.Arguments;
var dll = args.length >= 1 ? args[0] : "dist\\dll-shellcode.dll";
var exp = args.length >= 2 ? args[1] : "Run";

var target = "rundll32.exe " + dll + "," + exp;
WScript.Echo("[*] " + target);

// rundll32 returns at once and never relays the export's code; observe the
// chain through its output or a side effect. The shell alternative is
//   new ActiveXObject("Shell.Application").ShellExecute( \
//       "rundll32.exe", dll + "," + exp, "", "open", 1);
var sh = new ActiveXObject("WScript.Shell");
sh.Run(target, 1, true);
WScript.Echo("[+] WScript.Shell.Run returned");
