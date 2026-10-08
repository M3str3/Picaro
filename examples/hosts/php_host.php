<?php
// Loads a packed DLL from PHP. The `FFI` extension is bundled with the official
// Windows builds; it has to be enabled in php.ini (`extension=ffi`) and cannot
// be enabled at runtime (`ffi.enable` is INI_SYSTEM). Its default value,
// `preload`, still allows the CLI SAPI, so `php examples/hosts/php_host.php`
// works once the extension is loaded.
//
// NOT run on this repository's measurement host (no PHP installed).
//
// Usage:
//   php examples/hosts/php_host.php [dll] [export]

if (!extension_loaded('ffi')) {
    fwrite(STDERR, "[!] the FFI extension is not loaded (add `extension=ffi` to php.ini)\n");
    exit(1);
}

$dll    = $argv[1] ?? 'dist\\dll-shellcode.dll';
$export = $argv[2] ?? 'Run';

echo "[*] loading $dll (export $export)\n";

// FFI::cdef takes C declarations, so the export's prototype is built from the
// name: the rundll32 shape (four arguments, ignored) returning int.
$ffi = FFI::cdef(
    "int $export(void *hwnd, void *hinst, const char *cmdline, int show);",
    $dll
);

$code = $ffi->$export(null, null, null, 0);
echo "[+] $export() -> $code\n";
