# Convenience wrapper for Windows (PowerShell 5.1+ / pwsh 7+).
# Builds the batesian image on first use and runs it against the current
# directory, passing every argument through unchanged.
#
# Usage:
#   .\scripts\docker-batesian.ps1 build .\examples\configs\test-reflective.yaml
#   .\scripts\docker-batesian.ps1 audit .\dist\test_packed_reflective.exe
#   .\scripts\docker-batesian.ps1 techniques list
#   .\scripts\docker-batesian.ps1 --build build ...

$Image = if ($env:BATESIAN_IMAGE) { $env:BATESIAN_IMAGE } else { 'batesian:latest' }

# Repo root = the parent of this script's directory.
$Root = Split-Path -Parent $PSScriptRoot
# The current directory is mounted at /work inside the container.
$Cwd = (Get-Location).Path

# Rewrite a Windows-style argument into the form the Linux container sees.
#
# The container is Linux, so backslashes are not path separators there. This
# turns a relative path (".\examples\x.yaml", "dist\y.exe") into a POSIX one
# ("examples/x.yaml"), and an absolute path that lives under the mounted
# directory into "/work/...". Any other absolute path is left untouched: a
# value like "C:\Windows\System32\svchost.exe" is an opaque `$arg.N$` the stub
# uses at runtime on Windows, not a path the container resolves.
function Convert-ToContainerPath {
    param([string]$Arg)

    if ($Arg -notmatch '\\') { return $Arg }

    $normalized = $Arg -replace '\\', '/'

    if ($normalized -match '^[A-Za-z]:/' -or $normalized -match '^//') {
        $mount = ($Cwd -replace '\\', '/').TrimEnd('/')
        if ($normalized.Length -gt $mount.Length -and
            $normalized.Substring(0, $mount.Length) -ieq $mount -and
            $normalized.Substring($mount.Length, 1) -eq '/') {
            return '/work' + $normalized.Substring($mount.Length)
        }
        return $Arg
    }

    return $normalized
}

# A leading --build forces a rebuild; everything else passes through.
$rebuild = $false
$restArgs = @()
if ($args.Count -gt 0 -and $args[0] -eq '--build') {
    $rebuild = $true
    if ($args.Count -gt 1) {
        $restArgs = $args[1..($args.Count - 1)]
    }
} else {
    $restArgs = $args
}

if ($rebuild) {
    & docker build -t $Image $Root
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
} else {
    # Suppress both streams: the JSON on success and the error when absent.
    & docker image inspect $Image *> $null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "batesian: building image $Image (first run)..."
        & docker build -t $Image $Root
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    }
}

# Allocate a TTY only when stdout is a real console, so color auto-detection
# keeps working and piping still succeeds.
$interactive = $false
try {
    $interactive = -not [Console]::IsOutputRedirected
} catch {
    $interactive = $false
}

$runArgs = @('run', '--rm')
if ($interactive) {
    $runArgs += '-it'
}
$runArgs += @('-v', "${Cwd}:/work", '-w', '/work', $Image)

$translated = @($restArgs | ForEach-Object { Convert-ToContainerPath $_ })

& docker @runArgs @translated
exit $LASTEXITCODE
