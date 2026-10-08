# R host for a `kind: dll` artifact.
#
# `dyn.load` maps the DLL into the R process and `.C` calls the export, so no
# shell and no child process are involved.
#
# NOT run on this repository's measurement host (no R there). Documented recipe;
# verify on the target.
#
# Usage:
#   Rscript examples/hosts/r_host.R [dll] [export]

args <- commandArgs(trailingOnly = TRUE)
dll <- if (length(args) >= 1) args[[1]] else "dist/dll-shellcode.dll"
export <- if (length(args) >= 2) args[[2]] else "Run"

cat(sprintf("[*] loading %s (export %s)\n", dll, export))

dyn.load(dll)

# `.C` uses the C calling convention. On x64 there is a single convention; on a
# 32-bit R the export is stdcall and `.C`'s cdecl would unbalance the stack, so
# keep R (and the artifact) on x64.
#
# `.C` returns the (possibly modified) *argument list*, NOT the C return value,
# so the chain's exit code is not readable this way. Use a payload with an
# observable side effect, or `.External` with a wrapper to read the value.
invisible(.C(export))
cat("[+] chain invoked (R cannot read the C return value -- see the comment)\n")
