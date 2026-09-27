# Regenerates examples/payloads/test_payload.exe from test_payload.rs.
# Usage: powershell -ExecutionPolicy Bypass -File examples/payloads/build_test_payload.ps1
$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectRoot = Resolve-Path (Join-Path $scriptDir "..\..")
$src = Join-Path $scriptDir "test_payload.rs"
$out = Join-Path $scriptDir "test_payload.exe"

Push-Location $projectRoot
try {
    rustc $src -O -C strip=symbols -o $out
    Write-Host "OK: $out"
}
finally {
    Pop-Location
}
