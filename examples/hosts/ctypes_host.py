#!/usr/bin/env python3
"""Loads a packed DLL with CPython's ``ctypes``: the interpreter is the host.

The DLL runs in *this* process, so ``GetModuleHandle``/``EnumProcessModules``
would list it, and the export's return value is the chain's exit code.

Usage:
    python examples/hosts/ctypes_host.py [dll] [export]

Defaults to the non-blocking example (``dist/dll-shellcode.dll``, export
``Run``), whose chain returns 42. With ``examples/plans/dll.yaml`` the payload
opens a modal dialog: the export blocks until you dismiss it and then returns 0.
"""

import ctypes
import sys

dll = sys.argv[1] if len(sys.argv) > 1 else r"dist\dll-shellcode.dll"
export = sys.argv[2] if len(sys.argv) > 2 else "Run"

print(f"[*] loading {dll} (export {export})")
lib = ctypes.CDLL(dll)
print(f"[*] module handle: {lib._handle:#x}")

func = getattr(lib, export)
# The plain export takes the rundll32 shape (four arguments, ignored). On x64
# the caller may pass none, so a zero-argument call is correct.
code = func()
print(f"[+] {export}() -> {code}")
