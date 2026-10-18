#!/usr/bin/env python3
"""Rebuild sRDI's embedded x64 reflective loader from C source.

The upstream ``ShellcodeRDI.py`` ships a stale, prebuilt x64 blob and a bootstrap
whose 5th/6th argument slots are swapped, which makes the loader read a bogus
``dwFlags`` (the shellcode base address) and then ``Sleep`` for thousands of
seconds after resolving imports. This script recompiles ``ShellcodeRDI.c`` with
MinGW-w64, extracts the position-independent ``.text`` as the loader blob and
emits a corrected ``ShellcodeRDI.py`` (right bootstrap offsets, fresh blob).

Only the x64 blob is produced: Picaro's ``kind: shellcode`` output is x64-only.
"""

from __future__ import annotations

import argparse
import os
import shutil
import struct
import subprocess
import sys
import tempfile

BOOTSTRAP_SIZE = 69

ROR = lambda val, r_bits, max_bits: (
    ((val & (2**max_bits - 1)) >> r_bits % max_bits)
    | (val << (max_bits - (r_bits % max_bits)) & (2**max_bits - 1))
)


def which(*names: str) -> str:
    """Return the first executable found on PATH, or raise."""
    for name in names:
        path = shutil.which(name)
        if path:
            return path
    raise SystemExit(f"none of {', '.join(names)} found on PATH")


def run(cmd: list[str]) -> None:
    print("+", " ".join(cmd), flush=True)
    subprocess.run(cmd, check=True)


def hash_function_name(name: str) -> int:
    function = name.encode() + b"\x00"
    h = 0
    for b in function:
        h = ROR(h, 13, 32)
        h += b
    return h


def build_blob(c_source: str, workdir: str, cc: str, objcopy: str, ld: str) -> bytes:
    """Compile ``ShellcodeRDI.c`` and return the raw position-independent .text."""
    obj = os.path.join(workdir, "ShellcodeRDI.o")
    renamed = os.path.join(workdir, "ShellcodeRDI.renamed.o")
    exe = os.path.join(workdir, "ShellcodeRDI.exe")
    binpath = os.path.join(workdir, "ShellcodeRDI_x64.bin")

    common = [
        "-Os",
        "-fno-stack-protector",
        "-fno-asynchronous-unwind-tables",
        "-fno-unwind-tables",
        "-fno-ident",
        "-fno-builtin",
        "-fomit-frame-pointer",
        "-ffunction-sections",
        "-fdata-sections",
        "-m64",
    ]
    run([cc, "-c", c_source, "-o", obj] + common)
    # GNU ld sorts `.text$*` subsections by the string after `$`
    # (GetProcAddressWithHash < LoadDLL); the loader is entered at offset 0, so
    # LoadDLL must sort first. Rename its subsection to sort ahead of everything.
    run([objcopy, "--rename-section", ".text$LoadDLL=.text$000LoadDLL", obj, renamed])
    run([ld, "-o", exe, renamed, "--entry=LoadDLL", "--subsystem=console"])
    run([objcopy, "-O", "binary", "-j", ".text", exe, binpath])

    with open(binpath, "rb") as f:
        blob = f.read()
    if not blob:
        raise SystemExit(f"{binpath} is empty")
    return blob


def emit_module(blob: bytes, out_path: str) -> None:
    """Write ``ShellcodeRDI.py`` with the corrected bootstrap and fresh blob."""
    blob_hex = "".join("\\x{:02x}".format(b) for b in blob)
    module = '''\
import struct
from struct import pack

MACHINE_IA64 = 512
MACHINE_AMD64 = 34404


def is64BitDLL(bytes_):
    header_offset = struct.unpack("<L", bytes_[60:64])[0]
    machine = struct.unpack("<H", bytes_[header_offset + 4:header_offset + 4 + 2])[0]
    return machine in (MACHINE_IA64, MACHINE_AMD64)


ror = lambda val, r_bits, max_bits: (
    ((val & (2**max_bits - 1)) >> r_bits % max_bits)
    | (val << (max_bits - (r_bits % max_bits)) & (2**max_bits - 1))
)


def HashFunctionName(name, module=None):
    function = name.encode() + b"\\x00"

    if module:
        module = module.upper().encode("UTF-16LE") + b"\\x00\\x00"
        functionHash = 0
        for b in function:
            functionHash = ror(functionHash, 13, 32)
            functionHash += b
        moduleHash = 0
        for b in module:
            moduleHash = ror(moduleHash, 13, 32)
            moduleHash += b
        functionHash += moduleHash
        if functionHash > 0xFFFFFFFF:
            functionHash -= 0x100000000
    else:
        functionHash = 0
        for b in function:
            functionHash = ror(functionHash, 13, 32)
            functionHash += b
    return functionHash


def ConvertToShellcode(dllBytes, functionHash=0x10, userData=b"None", flags=0):
    if not is64BitDLL(dllBytes):
        raise ValueError("sRDI in Picaro is x64-only; a 32-bit DLL cannot be wrapped")

    rdiShellcode64 = b'{blob_hex}'

    bootstrap = b""
    bootstrapSize = {bootstrap_size}

    # call next instruction (pushes the next instruction address)
    bootstrap += b"\\xe8\\x00\\x00\\x00\\x00"
    dllOffset = bootstrapSize - len(bootstrap) + len(rdiShellcode64)

    # pop rcx - capture our current location
    bootstrap += b"\\x59"
    # mov r8, rcx - copy before rcx is modified
    bootstrap += b"\\x49\\x89\\xc8"
    # mov edx, <Hash of function>
    bootstrap += b"\\xba"
    bootstrap += pack("I", functionHash)
    # add r8, <Offset of the DLL> + <Length of DLL> (user data location)
    bootstrap += b"\\x49\\x81\\xc0"
    bootstrap += pack("I", dllOffset + len(dllBytes))
    # mov r9d, <Length of User Data>
    bootstrap += b"\\x41\\xb9"
    bootstrap += pack("I", len(userData))

    # push rsi; mov rsi, rsp (save the caller's stack)
    bootstrap += b"\\x56"
    bootstrap += b"\\x48\\x89\\xe6"
    # and rsp, -16 (align the stack)
    bootstrap += b"\\x48\\x83\\xe4\\xf0"
    # sub rsp, 0x30 (shadow space + two stack arguments)
    bootstrap += b"\\x48\\x83\\xec\\x30"

    # mov [rsp+0x20], rcx (arg5 = shellcode base). Upstream put this at +0x28,
    # which the x64 ABI reads as arg6; the swap fed a pointer into dwFlags.
    bootstrap += b"\\x48\\x89\\x4c\\x24\\x20"
    # add rcx, <Offset of the DLL>
    bootstrap += b"\\x48\\x81\\xc1"
    bootstrap += pack("I", dllOffset)
    # mov dword [rsp+0x28], <Flags> (arg6).
    bootstrap += b"\\xc7\\x44\\x24\\x28"
    bootstrap += pack("I", flags)

    # call the reflective loader
    bootstrap += b"\\xe8"
    bootstrap += pack("b", bootstrapSize - len(bootstrap) - 4)
    bootstrap += b"\\x00\\x00\\x00"

    # mov rsp, rsi; pop rsi; ret
    bootstrap += b"\\x48\\x89\\xf4"
    bootstrap += b"\\x5e"
    bootstrap += b"\\xc3"

    if len(bootstrap) != bootstrapSize:
        raise ValueError(
            "x64 bootstrap length: %d != bootstrapSize: %d"
            % (len(bootstrap), bootstrapSize)
        )

    return bootstrap + rdiShellcode64 + dllBytes + userData
'''.format(blob_hex=blob_hex, bootstrap_size=BOOTSTRAP_SIZE)

    with open(out_path, "w", newline="\n") as f:
        f.write(module)
    print("wrote", out_path, f"({len(blob)}-byte loader blob)", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("c_source", help="path to ShellcodeRDI.c")
    parser.add_argument("-o", "--output", required=True, help="output ShellcodeRDI.py")
    args = parser.parse_args()

    cc = which("x86_64-w64-mingw32-gcc", "gcc")
    objcopy = which("x86_64-w64-mingw32-objcopy", "objcopy")
    ld = which("x86_64-w64-mingw32-ld", "ld")

    workdir = tempfile.mkdtemp(prefix="srdi-build-")
    try:
        blob = build_blob(os.path.abspath(args.c_source), workdir, cc, objcopy, ld)
        emit_module(blob, args.output)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
