-- Loads a packed DLL from LuaJIT. The `ffi` module is built into LuaJIT (it is
-- NOT available in standard Lua 5.4, where it needs `alien`).
--
-- NOT run on this repository's measurement host (no LuaJIT installed).
--
-- Usage:
--   luajit examples/hosts/luajit_host.lua [dll] [export]

local ffi = require("ffi")

local dll = arg[1] or "dist\\dll-shellcode.dll"
local export = arg[2] or "Run"

print("[*] loading " .. dll .. " (export " .. export .. ")")

-- Declare the prototype before resolving the symbol: the rundll32 shape (four
-- arguments, ignored) returning int. On x86 add `__stdcall` to match
-- `extern "system"`; LuaJIT's cdecl default is only correct on x64.
ffi.cdef(string.format(
    "int %s(void *hwnd, void *hinst, const char *cmdline, int show);", export))

local lib = ffi.load(dll)
local code = lib[export](nil, nil, nil, 0)

print(string.format("[+] %s() -> %d", export, code))
