#!/usr/bin/env python3
"""Websocket check for an Entrixy server.

Why not curl or websocat: over HTTPS those clients negotiate HTTP/2 on their
own, and HTTP/2 forbids the Upgrade and Connection headers, so the upgrade is
impossible and everything looks like broken proxying. Here ALPN is pinned to
http/1.1.

    python3 ws_check.py wss://gate.example.com/ws
    python3 ws_check.py ws://127.0.0.1:8095/ws
"""
import base64, json, os, socket, ssl, sys
from urllib.parse import urlparse

url = urlparse(sys.argv[1] if len(sys.argv) > 1 else 'ws://127.0.0.1:8095/ws')
secure = url.scheme == 'wss'
host, port = url.hostname, url.port or (443 if secure else 80)
path = url.path or '/'

sock = socket.create_connection((host, port), timeout=10)
if secure:
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(['http/1.1'])          # without this h2 gets negotiated
    sock = ctx.wrap_socket(sock, server_hostname=host)

key = base64.b64encode(os.urandom(16)).decode()
sock.sendall((
    f'GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\n'
    f'Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n'
    f'Sec-WebSocket-Version: 13\r\n\r\n'
).encode())

head = b''
while b'\r\n\r\n' not in head:
    chunk = sock.recv(4096)
    if not chunk:
        sys.exit('connection closed before any reply')
    head += chunk
status = head.split(b'\r\n')[0].decode()
print('handshake:', status)
if '101' not in status:
    sys.exit('no upgrade happened - check the proxy config')

# A 101 alone is not enough. Some panel configurations hide response headers,
# and the answer arrives without `Upgrade: websocket`. Browsers and Android
# clients reject exactly that, while a lenient checker would call it healthy —
# so the header is verified here explicitly.
head_lines = [l.decode(errors='replace').lower() for l in head.split(b'\r\n')]
if not any(l.startswith('upgrade:') and 'websocket' in l for l in head_lines):
    print('handshake headers:')
    for l in head.decode(errors='replace').split('\r\n')[1:]:
        if l.strip():
            print('   ', l)
    sys.exit('the 101 came without the Upgrade header: the proxy is hiding it. '
             'Add `proxy_pass_header Upgrade;` to the /ws location, or remove '
             'whatever clears response headers there. Clients refuse such a '
             'handshake and reconnect forever.')

# masked frame: {"type":"ping"}
payload = json.dumps({'type': 'ping'}).encode()
mask = os.urandom(4)
frame = bytes([0x81, 0x80 | len(payload)]) + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
sock.sendall(frame)

data = sock.recv(4096)
if not data:
    sys.exit('no reply')
length = data[1] & 0x7F
print('worker replied:', data[2:2 + length].decode(errors='replace'))
