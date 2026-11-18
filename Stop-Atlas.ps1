$ErrorActionPreference = 'Stop'
Invoke-RestMethod -Method Post -Uri 'http://127.0.0.1:47831/api/shutdown' -Headers @{'X-Atlas-Local'='1'} -TimeoutSec 5 | Out-Null
Write-Host 'Atlas stopped / Atlas arrete.'
