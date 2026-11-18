$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')
$version = (Select-String -Path Cargo.toml -Pattern '^version = "([^"]+)"').Matches[0].Groups[1].Value
if ($env:GITHUB_REF_TYPE -eq 'tag' -and $env:GITHUB_REF_NAME -ne "v$version") { throw 'Tag must match Cargo.toml version.' }
$stage = Join-Path 'dist' "Atlas-$version-windows-x64"
if (Test-Path -LiteralPath $stage) { throw 'Package staging directory already exists; choose a clean build directory.' }
New-Item -ItemType Directory -Path $stage -Force | Out-Null
Copy-Item -LiteralPath 'target/release/atlas-reseau.exe' -Destination $stage
foreach ($file in @('Start-Atlas.cmd','Start-Atlas-UDP.cmd','Start-Atlas.ps1','Stop-Atlas.cmd','Stop-Atlas.ps1','README.md','README.fr.md','LICENSE','THIRD_PARTY_NOTICES.md')) {
    Copy-Item -LiteralPath $file -Destination $stage
}
New-Item -ItemType Directory -Path "$stage/docs" | Out-Null
Copy-Item -LiteralPath 'docs/PRIVACY.md' -Destination "$stage/docs"
Copy-Item -LiteralPath 'web/vendor/Leaflet-LICENSE.txt' -Destination "$stage/Leaflet-LICENSE.txt"
python scripts/licenses.py "$stage/THIRD-PARTY-LICENSES.txt"
if ($LASTEXITCODE -ne 0) { throw 'Dependency license collection failed.' }
$zip = "dist/Atlas-$version-windows-x64.zip"
Compress-Archive -Path "$stage/*" -DestinationPath $zip
$hash = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant()
"$hash  $([IO.Path]::GetFileName($zip))" | Set-Content -LiteralPath 'dist/SHA256SUMS.txt' -Encoding ascii
Write-Host "Created $zip and dist/SHA256SUMS.txt"
