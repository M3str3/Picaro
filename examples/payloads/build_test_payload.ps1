# Regenerates a test payload from test_payload.rs.
# Usage: powershell -ExecutionPolicy Bypass -File examples/payloads/build_test_payload.ps1 [-Arch x64|x86]
#   x64 -> test_payload.exe, x86 -> test_payload_x86.exe
param(
    [ValidateSet("x64", "x86")]
    [string]$Arch = "x64"
)
$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectRoot = Resolve-Path (Join-Path $scriptDir "..\..")

# The x86 payload is the same source cross-compiled; the 32-bit target keeps
# `examples/plans/x86.yaml` reproducible.
switch ($Arch) {
    "x64" { $target = $null; $outName = "test_payload.exe" }
    "x86" { $target = "i686-pc-windows-msvc"; $outName = "test_payload_x86.exe" }
}

$src = Join-Path $scriptDir "test_payload.rs"
$out = Join-Path $scriptDir $outName

Push-Location $projectRoot
try {
    if ($target) {
        rustc $src --target $target -O -C strip=symbols -o $out
    } else {
        rustc $src -O -C strip=symbols -o $out
    }
    Write-Host "OK: $out"
}
finally {
    Pop-Location
}
