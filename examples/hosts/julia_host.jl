# Julia host for a `kind: dll` artifact.
#
# `ccall` names the exported symbol and the library together and maps the four
# ignored arguments directly, so Julia loads the DLL in-process with no shell and
# no child process.
#
# NOT run on this repository's measurement host (no Julia there). Documented
# recipe; verify on the target.
#
# Usage:
#   julia examples/hosts/julia_host.jl [dll] [export]

dll = length(ARGS) >= 1 ? ARGS[1] : "dist/dll-shellcode.dll"
export = length(ARGS) >= 2 ? ARGS[2] : "Run"

println("[*] loading $dll (export $export)")

# `ccall`'s first argument is the (symbol, library) pair; the argument types are
# the rundll32 shape (four arguments, ignored) and the return type is Cint.
code = ccall((Symbol(export), dll), Cint,
             (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{UInt8}, Cint),
             C_NULL, C_NULL, C_NULL, 0)

println("[+] $export() -> $code")
