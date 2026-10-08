// Loads a packed DLL from Node.js.
//
// Node has no FFI in the standard library: `process.dlopen` loads a *native
// Node addon* (`.node`), not an arbitrary DLL. A package is required, and the
// maintained one is `koffi` (`npm install koffi`); the older `ffi-napi` is
// unmaintained.
//
// NOT run on this repository's measurement host (koffi is not installed).
//
// Usage:
//   npm install koffi
//   node examples/hosts/node_host.js [dll] [export]

const path = require('path');
const koffi = require('koffi');

const dll = path.resolve(process.argv[2] || 'dist/dll-shellcode.dll');
const exportName = process.argv[3] || 'Run';

console.log(`[*] loading ${dll} (export ${exportName})`);

const lib = koffi.load(dll);
// Koffi defaults to cdecl; `__stdcall` is what `extern "system"` is on x86 and
// is ignored on x64. The parameters mirror the rundll32 shape and are ignored.
const fn = lib.func(`int __stdcall ${exportName}(void *hwnd, void *hinst, const char *cmdline, int show)`);
const code = fn(null, null, null, 0);

console.log(`[+] ${exportName}() -> ${code}`);
