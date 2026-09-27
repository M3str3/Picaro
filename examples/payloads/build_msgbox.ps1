# Regenerates examples/payloads/msgbox.exe from msgbox.rs.
# Usage: powershell -ExecutionPolicy Bypass -File examples/payloads/build_msgbox.ps1
$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectRoot = Resolve-Path (Join-Path $scriptDir "..\..")
$src = Join-Path $scriptDir "msgbox.rs"
$out = Join-Path $scriptDir "msgbox.exe"

Push-Location $projectRoot
try {
    rustc $src -O -C strip=symbols -o $out
    Write-Host "OK: $out"
}
finally {
    Pop-Location
}
