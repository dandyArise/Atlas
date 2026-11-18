param([switch]$Udp)
$ErrorActionPreference = 'Stop'
$baseUrl = 'http://127.0.0.1:47831'
$exe = Join-Path $PSScriptRoot 'atlas-reseau.exe'
if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { throw 'Extract the release ZIP first: atlas-reseau.exe is missing.' }
$existing = $null
try { $existing = Invoke-RestMethod "$baseUrl/api/connections" -TimeoutSec 2 } catch { }
if ($existing) {
    if ($Udp -and -not $existing.health.udp.available) {
        throw 'Atlas is already running without UDP. Run Stop-Atlas.cmd, then Start-Atlas-UDP.cmd.'
    }
    Start-Process $baseUrl
    exit 0
}
if ($Udp) {
    # Elevate only the collector; the browser retains the current user's privileges.
    Start-Process -FilePath $exe -WorkingDirectory $PSScriptRoot -Verb RunAs -WindowStyle Hidden
} else {
    Start-Process -FilePath $exe -WorkingDirectory $PSScriptRoot -WindowStyle Hidden
}
for ($attempt = 0; $attempt -lt 30; $attempt++) {
    Start-Sleep -Milliseconds 500
    try {
        $ready = Invoke-RestMethod "$baseUrl/api/connections" -TimeoutSec 2
        if ($ready.health.last -gt 0) {
            if ($Udp -and -not $ready.health.udp.available) { throw 'UDP capture unavailable; inspect the status in Atlas.' }
            Start-Process $baseUrl
            exit 0
        }
    } catch { if ($_.Exception.Message -like 'UDP capture*') { throw } }
}
throw 'Atlas did not become ready. Check whether port 47831 is occupied.'
