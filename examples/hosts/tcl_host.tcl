# Tcl host for a `kind: dll` artifact.
#
# Tcl has no FFI in its core: the `load` command is for Tcl extension packages,
# not arbitrary DLLs. This script needs the `ffidl` package (or `critcl`, which
# compiles a C wrapper and therefore needs a compiler). No shell and no child
# process are involved once ffidl is present.
#
# NOT run on this repository's measurement host (no Tcl/ffidl there). The exact
# `ffidl::callout` argument list has changed between ffidl versions -- check the
# package's own docs on the target before relying on this.
#
# Usage:
#   tclsh examples/hosts/tcl_host.tcl [dll] [export]

package require Ffidl

set dll    [expr {$argc > 0 ? [lindex $argv 0] : "dist/dll-shellcode.dll"}]
set export [expr {$argc > 1 ? [lindex $argv 1] : "Run"}]

puts "[*] loading $dll (export $export)"

# `ffidl::symbol` binds the export and `ffidl::callout` declares the Tcl command
# that calls it. Argument types are the rundll32 shape (four arguments, ignored)
# and the return type is int.
set sym [ffidl::symbol $dll $export]
ffidl::callout $export {pointer pointer pointer int} int $sym

puts "[+] $export() -> [$export 0 0 0 0]"
