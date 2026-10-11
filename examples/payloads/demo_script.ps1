# Deterministic fixture for the `powershell_hosting` end-to-end test.
#
# The loader embeds this script, hosts the PowerShell engine in its own process
# and runs the configured command (`Get-PicaroMarker`). Kept tiny and offline so
# `tests/cli.rs` can assert the packed artifact's output without a domain.

function Get-PicaroMarker {
    'picaro-ok'
}
