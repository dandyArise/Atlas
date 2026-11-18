# Atlas

[Français](README.fr.md) · [Download for Windows](https://github.com/dandyArise/Atlas/releases/latest) · [Builds](https://github.com/dandyArise/Atlas/actions)

**See where your Windows applications connect.** Atlas is a Rust network monitor with a world map, application icons, local connection history and reputation alerts. Inspired by the visibility offered by Little Snitch, it is an independent project, with no affiliation.

Atlas currently **observes connections**. It does not block traffic or replace a firewall. The interface is currently in French; documentation is available in English and French.

## Features

- Live TCP connections attributed to Windows processes.
- UDP activity captured through Windows ETW when started as administrator.
- UDP port 443 marked **“QUIC possible”**: a heuristic, not protocol confirmation.
- World map with destination markers, schematic connection lines and application icons extracted locally.
- Group by application, country, possible DNS name or server; search and filter by protocol, country, alerts and date.
- SQLite history stored locally; inactive records retained for 30 days.
- Local reputation matching against Spamhaus DROP IPv4/IPv6 and StevenBlack domain lists, with source-labelled alerts.
- Embedded offline map; optional IP geolocation and OpenStreetMap tiles.

## Download and run

Requires Windows 10/11 x64 and a modern browser. Download `Atlas-<version>-windows-x64.zip` and `SHA256SUMS.txt` from [Releases](https://github.com/dandyArise/Atlas/releases), then extract the ZIP to a folder you own. No Rust installation is needed for a release.

1. Double-click **Start-Atlas.cmd** for TCP monitoring.
2. For UDP, use **Start-Atlas-UDP.cmd** and accept the Windows UAC prompt. Stop an existing non-elevated Atlas instance first with **Stop-Atlas.cmd**.
3. The browser opens at **http://127.0.0.1:47831/**. Enable geolocation in the interface if you want public destinations placed on the map.
4. Use **Stop-Atlas.cmd** to stop the local collector. Closing the browser alone does not stop it.

Double-click `.cmd` launchers in Explorer; do not paste their batch contents into PowerShell. Binaries are not code-signed, so Windows may show an unknown-publisher warning. Compare the downloaded ZIP with the published checksum:

```powershell
Get-FileHash .\Atlas-0.2.1-windows-x64.zip -Algorithm SHA256
```

## Privacy and network access

History lives in `%LOCALAPPDATA%\AtlasReseau\history.sqlite`, including process names/paths, endpoint addresses and timestamps. It is not uploaded by Atlas. The HTTP service binds to localhost and validates local request origins. Treat the database, exports and screenshots as private.

Optional geolocation sends public destination IPs to **ipwho.is**. Optional map tiles contact **OpenStreetMap**. Reputation lists are downloaded on startup when needed and refreshed daily; matching is local. These services see the IP address making requests. Geolocation starts disabled after each restart. See [privacy details](docs/PRIVACY.md) and [third-party notices](THIRD_PARTY_NOTICES.md).

## Limits

- IP geolocation is approximate; a map line is not the route packets took. Private/local addresses are not geolocated. The origin marker can be set manually.
- UDP endpoints require elevated ETW collection; UDP entries remain active for about 30 seconds after an observed event. No packet payload is stored.
- QUIC can use other ports; UDP/443 can carry other protocols.
- DNS names are inferred from the Windows DNS cache and may be ambiguous or absent, especially with shared IPs or encrypted DNS.
- The map displays the current page of connections (up to 200); summary counts can cover the full filtered result.
- Lists produce indicators, not proof of malicious activity. Domain matches depend on available DNS observations. No automatic blocking, retroactive history rescanning or desktop notification is implemented.

## Build and verify

Install Rust with the MSVC toolchain and Visual Studio Build Tools (Desktop development with C++), Python 3.11+ and Node.js (JavaScript syntax check only).

```powershell
cargo fmt --check
cargo clippy --locked -- -D warnings
cargo test --locked
node --check web/app.js
cargo build --release --locked
python verify.py target/release/atlas-reseau.exe
powershell -NoProfile -File scripts/package.ps1
```

`verify.py` uses a temporary database and an available localhost port, disables list downloads, and checks TCP capture, local API access controls, assets, icons, persistence and shutdown. It does not prove live UDP/QUIC capture or third-party service availability. One live geolocation unit test is ignored by default.

The Windows workflow runs these checks on pushes and pull requests and uploads a portable ZIP plus SHA-256 checksums. A `v<version>` tag matching `Cargo.toml` additionally publishes a GitHub release after checks pass. Releases are built on GitHub, never packaged from a user's history directory.

Advanced options: `atlas-reseau.exe --port 47832 --data-dir <folder>`; `--offline-lists` disables list downloads. The default map is embedded, but enable neither geolocation nor online tiles for offline use.

## Contribute and license

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md). Please do not post real connection histories, personal paths or unredacted screenshots in public issues.

Atlas source is [MIT licensed](LICENSE). Dependencies, map data and external lists retain their own licenses. Release archives contain third-party license notices.
