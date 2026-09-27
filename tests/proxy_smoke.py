#!/usr/bin/env python3
"""Check both shipped proxies with bounded synthetic metadata on an internal network.

Requires Docker; no real messages, credentials or public listener are used.
"""
from pathlib import Path
import re
import subprocess
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[1]


def run(*args, timeout=120):
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f'{args[:3]} failed: {result.stderr[-2000:]} {result.stdout[-2000:]}')
    return result.stdout


def main():
    images = {'python': 'python:3.11-alpine', 'nginx': 'nginx:1.28-alpine', 'caddy': 'caddy:2.10-alpine'}
    for image in images.values():
        run('docker', 'pull', image)
    prefix = 'nf-proxy-test-' + uuid.uuid4().hex[:10]
    containers = []
    network = prefix + '-network'
    with tempfile.TemporaryDirectory(prefix='nf-proxy-') as directory:
        root = Path(directory)
        nginx = (ROOT / 'deploy/nginx.conf').read_text()
        # Keep the complete HTTPS server's locations and limits; use HTTP only
        # on the isolated test network. Certificate handling is tested separately.
        nginx = nginx[nginx.index('server {', nginx.index('server {') + 1):]
        nginx = re.sub(r'^\s*(listen|ssl_)[^\n]*\n', '', nginx, flags=re.M)
        nginx = nginx.replace('server {', 'server {\n listen 8080;', 1)
        nginx = nginx.replace('127.0.0.1:18080', 'backend:18080')
        nginx = ('events {}\nhttp {\nlimit_req_zone $binary_remote_addr '
                 'zone=noisefence_login:10m rate=5r/m;\n' + nginx + '\n}\n')
        (root / 'nginx.conf').write_text(nginx)
        caddy = (ROOT / 'deploy/Caddyfile').read_text().replace('noisefence.example.org {', ':8080 {')
        (root / 'Caddyfile').write_text(caddy.replace('127.0.0.1:8080', 'backend:18080'))
        (root / 'backend.py').write_text('''from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        size = int(self.headers['Content-Length'])
        body = self.rfile.read(size)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(str(len(body)).encode())
    def log_message(self, *args): pass
ThreadingHTTPServer(('0.0.0.0', 18080), Handler).serve_forever()
''')
        (root / 'client.py').write_text('''import http.client, time
# Container creation is not listener readiness, particularly on shared CI hosts.
for host in ('backend', 'nginx', 'caddy'):
    deadline = time.monotonic() + 20
    while True:
        try:
            connection = http.client.HTTPConnection(host, 18080 if host == 'backend' else 8080, timeout=2)
            connection.request('POST', '/health', b'ready')
            response = connection.getresponse()
            ready = response.status == 200 and response.read() == b'5'
            connection.close()
            if ready: break
        except (OSError, http.client.HTTPException):
            pass
        if time.monotonic() >= deadline: raise RuntimeError(host + ' did not become ready')
        time.sleep(0.2)
for proxy in ('nginx', 'caddy'):
    for path, size, expected in [('/api/v1/cluster/v1/sync', 262144, 200),
                                 ('/api/v1/cluster/v2/sync', 262144, 200),
                                 ('/api/v1/cluster/v2/sync', 5*1024*1024, 413),
                                 ('/api/v1/cluster/v3/history', 3*1024*1024, 200),
                                 ('/api/v1/cluster/v3/logs', 3*1024*1024, 200),
                                 ('/api/v1/cluster/v3/history', 5*1024*1024, 413),
                                 ('/api/v1/settings', 262144, 413)]:
        deadline = time.monotonic() + 15
        while True:
            try:
                connection = http.client.HTTPConnection(proxy, 8080, timeout=5)
                # Send a prefix first so an early 413 cannot cause a broken pipe.
                connection.putrequest('POST', path)
                connection.putheader('Content-Length', str(size))
                connection.endheaders()
                if expected == 200:
                    connection.send(b'x' * size)
                elif proxy == 'caddy':
                    # Caddy enforces while the upstream reads the body.
                    try: connection.send(b'x' * size)
                    except BrokenPipeError: pass
                response = connection.getresponse()
                body = response.read()
                assert response.status == expected, (proxy, path, response.status, body[:100])
                if expected == 200: assert body == str(size).encode()
                connection.close()
                break
            except (ConnectionRefusedError, OSError):
                if time.monotonic() >= deadline: raise
                time.sleep(0.2)
        print(proxy, path, size, expected, flush=True)
''')
        mounts = ('-v', f'{root}:/test:ro')
        try:
            run('docker', 'network', 'create', '--internal', network)
            for kind, alias, command in [
                ('python', 'backend', ('python', '/test/backend.py')),
                ('nginx', 'nginx', ('nginx', '-g', 'daemon off;', '-c', '/test/nginx.conf')),
                ('caddy', 'caddy', ('caddy', 'run', '--config', '/test/Caddyfile', '--adapter', 'caddyfile')),
            ]:
                name = prefix + '-' + alias
                containers.append(name)
                run('docker', 'run', '-d', '--name', name, '--network', network,
                    '--network-alias', alias, '--memory', '128m', '--cpus', '0.5',
                    *mounts, images[kind], *command)
            print(run('docker', 'run', '--rm', '--network', network, *mounts,
                      images['python'], 'python', '/test/client.py'))
        except Exception:
            for container in containers:
                logs = subprocess.run(['docker', 'logs', '--tail', '30', container], capture_output=True, text=True)
                print(container, logs.stdout, logs.stderr, flush=True)
            raise
        finally:
            for container in containers:
                subprocess.run(['docker', 'rm', '-f', container], capture_output=True)
            subprocess.run(['docker', 'network', 'rm', network], capture_output=True)


if __name__ == '__main__':
    main()
