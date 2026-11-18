"""Fail closed on unexpected tracked files and common private data patterns."""
import pathlib
import re
import subprocess
import sys

names = subprocess.check_output(['git', 'ls-files', '-z'], text=True).split('\0')
allowed_top = {
    '.gitattributes', '.gitignore', 'Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml',
    'LICENSE', 'README.md', 'README.fr.md', 'THIRD_PARTY_NOTICES.md',
    'CONTRIBUTING.md', 'SECURITY.md', 'verify.py', 'Start-Atlas.cmd',
    'Start-Atlas-UDP.cmd', 'Start-Atlas.ps1', 'Stop-Atlas.cmd', 'Stop-Atlas.ps1',
}
patterns = {
    'personal home path': re.compile(r'(?i)[a-z]:[\\/]+(?:Users|Documents and Settings)[\\/]+[^\\/\s<>]+'),
    'GitHub credential': re.compile(r'(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})'),
    'private key': re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),
    'AWS access key': re.compile(r'AKIA[A-Z0-9]{16}'),
}
failures = []
for name in filter(None, names):
    path = pathlib.Path(name)
    allowed = name in allowed_top or (
        path.parts[0] in {'src', 'web', 'scripts', 'docs', '.github'}
        and path.suffix in {'.rs', '.js', '.css', '.html', '.json', '.txt', '.py', '.ps1', '.md', '.yml'}
    )
    if not allowed:
        failures.append(f'{name}: unexpected tracked file')
        continue
    content = subprocess.check_output(['git', 'show', ':' + name]).decode('utf-8')
    for label, pattern in patterns.items():
        if pattern.search(content):
            failures.append(f'{name}: {label}')
if failures:
    sys.exit('\n'.join(failures))
print(f'Public source audit passed: {len(list(filter(None, names)))} tracked files; no disallowed files or detected private patterns.')
print('Pattern checks supplement review; they cannot prove absence of every kind of secret.')
