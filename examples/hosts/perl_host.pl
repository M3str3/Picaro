# Loads a packed DLL from Perl. Windows Perl (Strawberry bundles Win32::API; it
# is also on CPAN) can call an export with no C compiler and no XS extension.
#
# NOT run on this repository's measurement host (the only Perl here is the MSYS
# one, which has no Win32::API and cannot load Win32 DLLs). The type handling is
# from the module's own documentation: the prototype form is the one to use,
# because an `undef` argument becomes a C NULL.
#
# Usage:
#   perl examples/hosts/perl_host.pl [dll] [export]

use strict;
use warnings;
use Win32::API;

my $dll    = $ARGV[0] // 'dist\\dll-shellcode.dll';
my $export = $ARGV[1] // 'Run';

print "[*] loading $dll (export $export)\n";

# The prototype form: `void *` for the three ignored pointers, `int` for the
# shape `rundll32` calls with. Win32::API defaults to __stdcall, which is what
# `extern "system"` means on x86 -- pass '_cdecl' as a fourth argument on a
# 32-bit Perl only if the export were cdecl (it is not).
my $fn = Win32::API::More->new(
    $dll,
    "int $export(void *hwnd, void *hinst, const char *cmdline, int show)"
) or die "Win32::API: " . Win32::GetLastError() . "\n";

# `undef` becomes NULL for a pointer parameter.
my $code = $fn->Call(undef, undef, undef, 0);
print "[+] $export() -> $code\n";
