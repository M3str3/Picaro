# Regenerates examples/payloads/hello_world.exe from hello_world.rs.
# Usage: powershell -ExecutionPolicy Bypass -File examples/payloads/build_hello_world.ps1
$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectRoot = Resolve-Path (Join-Path $scriptDir "..\..")
$src = Join-Path $scriptDir "hello_world.rs"
$out = Join-Path $scriptDir "hello_world.exe"

Push-Location $projectRoot
try {
    # `-O` is rustc's release opt level; the payload has no Cargo profile to pick.
    rustc $src -O -C strip=symbols -o $out
    Write-Host "OK: $out"
}
finally {
    Pop-Location
}
