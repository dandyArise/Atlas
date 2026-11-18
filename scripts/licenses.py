"""Collect license notices from locked dependencies without publishing local paths."""
import json
import pathlib
import subprocess
import sys

metadata = json.loads(subprocess.check_output([
    'cargo', 'metadata', '--locked', '--format-version', '1',
    '--filter-platform', 'x86_64-pc-windows-msvc',
], text=True))
resolved = {node['id'] for node in metadata['resolve']['nodes']}
parts = ['Third-party Rust dependency notices\nSQLite: https://www.sqlite.org/copyright.html (public domain)\n']
missing = []
for package in sorted(metadata['packages'], key=lambda p: (p['name'], p['version'])):
    if package['id'] not in resolved or package['id'] in metadata['workspace_members']:
        continue
    directory = pathlib.Path(package['manifest_path']).parent
    files = {p for p in directory.iterdir() if p.is_file() and p.name.upper().startswith(('LICENSE', 'LICENCE', 'COPYING', 'NOTICE'))}
    if package.get('license_file'):
        files.add(directory / package['license_file'])
    if not files:
        missing.append(f"{package['name']} {package['version']}")
    parts.append(f"\n{'=' * 72}\n{package['name']} {package['version']}\nDeclared license: {package.get('license') or 'see notice'}\n")
    for file in sorted(files):
        parts.append(f"\n--- {file.name} ---\n{file.read_text(encoding='utf-8', errors='replace')}\n")
if missing:
    sys.exit('Missing license files: ' + ', '.join(missing))
output = pathlib.Path(sys.argv[1])
output.parent.mkdir(parents=True, exist_ok=True)
output.write_text('\n'.join(parts), encoding='utf-8')
print(f'Collected dependency notices: {len(resolved) - len(metadata["workspace_members"])} packages')
