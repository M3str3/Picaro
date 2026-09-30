# Loads a packed DLL from Ruby. `Fiddle` is in the standard library, so no gem
# and no C compiler are needed.
#
# NOT run on this repository's measurement host (no Ruby installed). The API
# used here is Fiddle's stable core: dlopen, the export lookup and
# Fiddle::Function.
#
# Usage:
#   ruby examples/hosts/ruby_host.rb [dll] [export]

require 'fiddle'

dll    = ARGV[0] || 'dist/dll-shellcode.dll'
export = ARGV[1] || 'Run'

puts "[*] loading #{dll} (export #{export})"

lib = Fiddle.dlopen(dll)
address = lib[export]
raise "export '#{export}' not found in #{dll}" if address.nil?

# Fiddle::TYPE_VOIDP for the three ignored pointers, TYPE_INT for the show flag;
# the export returns int. On x64 the calling convention is a single one; on x86
# Fiddle uses stdcall for Fiddle::Function by default, which matches
# `extern "system"`.
func = Fiddle::Function.new(
  address,
  [Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP, Fiddle::TYPE_INT],
  Fiddle::TYPE_INT
)

puts "[+] #{export}() -> #{func.call(0, 0, 0, 0)}"
