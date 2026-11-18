"""Integration checks: real IPv4/IPv6 sockets, persistence, HTTP isolation.
Uses a disposable database and never enables external geolocation.
Run: python verify.py path/to/atlas-reseau.exe
"""
import http.client
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import time
import urllib.request

exe = Path(sys.argv[1]).resolve()
with socket.socket() as reservation:
    reservation.bind(('127.0.0.1', 0))
    port = reservation.getsockname()[1]
base = f'http://127.0.0.1:{port}'

def get(path='/api/connections?mode=history'):
    with urllib.request.urlopen(base + path, timeout=3) as r:
        return json.load(r)

def eventually(check, message):
    for _ in range(24):
        try:
            result = check()
            if result:
                return result
        except (OSError, ValueError):
            pass
        time.sleep(.5)
    raise AssertionError(message)

def status(path, headers=None, method='GET'):
    c = http.client.HTTPConnection('127.0.0.1', port, timeout=3)
    c.request(method, path, headers=headers or {})
    r = c.getresponse()
    code = r.status
    r.read()
    c.close()
    return code

with tempfile.TemporaryDirectory(prefix='atlas-verification-') as directory:
    def start():
        p = subprocess.Popen([str(exe), '--port', str(port), '--data-dir', directory, '--offline-lists'],
                             stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                             creationflags=subprocess.CREATE_NO_WINDOW)
        eventually(lambda: get()['health']['last'], 'server did not collect')
        return p
    p = start()
    try:
        ids = []
        for family, address in [(socket.AF_INET, '127.0.0.1'), (socket.AF_INET6, '::1')]:
            with socket.socket(family) as listener, socket.socket(family) as client:
                listener.bind((address, 0))
                listener.listen(1)
                client.connect(listener.getsockname())
                peer, _ = listener.accept()
                local_port = client.getsockname()[1]
                def find():
                    return next((r for r in get('/api/connections?q='+address)['rows']
                                 if r['pid'] == os.getpid() and r['local_port'] == local_port
                                 and r['state'] == 'Établie'), None)
                row = eventually(find, 'controlled socket not observed')
                assert row['remote'] == address and not row['public']
                assert row['app'].lower().startswith('python'), row['app']
                ids.append(row['id'])
                client.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('hh', 1, 0))
                peer.close()
            eventually(lambda: any(r['id'] == row['id'] and not r['active']
                                   for r in get('/api/connections?mode=history&q='+address)['rows']),
                       'closed connection not retained')
        assert status('/', {'Host': 'evil.example'}) == 403
        assert status('/api/connections', {'Origin': 'https://evil.example'}) == 403
        assert status('/api/geo?enabled=true', method='POST') == 404
        assert not get()['health']['geo_enabled']
        assert get('/api/connections?q=__no_such_application__')['total'] == 0
        assert status('/world.json') == 200 and status('/app.js') == 200
        assert status('/country-names.json') == 200
        icons = eventually(lambda: get('/api/icons'), 'native application icons unavailable')
        import base64
        for value in icons.values():
            assert value.startswith('data:image/png;base64,')
            assert base64.b64decode(value.split(',', 1)[1]).startswith(b'\x89PNG\r\n\x1a\n')
        assert status('/api/shutdown', {'X-Atlas-Local': '1'}, 'POST') == 200
        p.wait(timeout=5)
        p = start()
        all_rows = get('/api/connections?mode=history&q=python')['rows']
        assert all(any(r['id'] == i for r in all_rows) for i in ids)
        assert not get()['health']['geo_enabled']
        print('PASS: TCP IPv4 + IPv6, PID/application, closure, SQLite restart, filters, assets, Host/Origin, consent default.')
    finally:
        if p.poll() is None:
            status('/api/shutdown', {'X-Atlas-Local': '1'}, 'POST')
        p.wait(timeout=5)
