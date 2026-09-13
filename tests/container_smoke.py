#!/usr/bin/env python3
"""Isolated Docker acceptance/persistence test. Never sends mail outside loopback."""
import argparse
import http.cookiejar
import http.client
import json
import math
import os
from pathlib import Path
import pty
import re
import select
import smtplib
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import uuid


def docker(*args, **kwargs):
    return subprocess.check_output(['docker', *args], text=True, timeout=kwargs.pop('timeout', 45), **kwargs).strip()


def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def administrator(container, password):
    master, slave = pty.openpty()
    process = subprocess.Popen(['docker', 'exec', '-it', container, 'noisefence', '--config', '/etc/noisefence/config.toml', 'user-add', 'smoke-admin', '--admin'], stdin=slave, stdout=slave, stderr=slave)
    os.close(slave)
    sent = 0
    received = b''
    deadline = time.monotonic() + 30
    try:
        while time.monotonic() < deadline:
            if select.select([master], [], [], .2)[0]:
                try:
                    received += os.read(master, 4096)
                except OSError:
                    break
                expected = [b'Console password', b'Repeat password'][min(sent, 1)]
                if sent < 2 and expected in received:
                    os.write(master, password.encode() + b'\n')
                    sent += 1
                    received = b''
            if process.poll() is not None:
                break
        if process.poll() is None:
            process.terminate()
        if process.wait(timeout=5) != 0 or sent != 2 or b'User created.' not in received:
            raise RuntimeError('Interactive container account bootstrap failed')
    finally:
        os.close(master)
        if process.poll() is None:
            process.kill()


def privileged_port(image):
    """Do not rely on Docker's relaxed default privileged-port sysctl."""
    name = 'noisefence-port-test-' + uuid.uuid4().hex[:12]
    volume = name + '-data'
    sample = Path(__file__).resolve().parents[1] / 'config/docker.example.toml'
    with tempfile.TemporaryDirectory(prefix='noisefence-port-test-') as temporary:
        config = Path(temporary) / 'config.toml'
        config.write_text(sample.read_text().replace('127.0.0.1:2525', '127.0.0.1:25'))
        config.chmod(0o644)
        docker('volume', 'create', volume)
        try:
            docker('run', '-d', '--name', name, '--network=none',
                   '--sysctl=net.ipv4.ip_unprivileged_port_start=1024', '--read-only',
                   '--user=0:0', '--cap-drop=ALL', '--cap-add=NET_BIND_SERVICE',
                   '--cap-add=SETUID', '--cap-add=SETGID', '--cap-add=SETPCAP',
                   '--security-opt=no-new-privileges:true', '--pids-limit=256', '--memory=2g',
                   '--tmpfs=/tmp:rw,nosuid,nodev,noexec,size=128m',
                   '-v', f'{volume}:/var/lib/noisefence',
                   '-v', f'{config}:/etc/noisefence/config.toml:ro', image)
            for _ in range(60):
                assert docker('inspect', name, '--format', '{{.State.Running}}') == 'true', 'Port-25 runtime stopped'
                response = subprocess.run(['docker', 'exec', name, 'curl', '--silent', '--fail',
                                           'http://127.0.0.1:18080/healthz'], capture_output=True, text=True, timeout=5)
                if response.returncode == 0 and json.loads(response.stdout)['smtp_ready']:
                    break
                time.sleep(.25)
            else:
                raise AssertionError('Port-25 runtime did not become ready')
            status = dict(line.split(':', 1) for line in docker('exec', name, 'cat', '/proc/1/status').splitlines() if ':' in line)
            assert status['Uid'].split() == ['10001'] * 4
            assert status['Gid'].split() == ['10001'] * 4
            assert status['NoNewPrivs'].strip() == '1'
            assert all(int(status[k], 16) == 1 << 10 for k in ['CapEff', 'CapPrm', 'CapBnd', 'CapAmb']), status
            # EHLO + NOOP + QUIT only, inside a network namespace with no external interface.
            response = subprocess.run(['docker', 'exec', name, 'curl', '--verbose', '--silent', '--show-error',
                                       '--fail', '--request', 'NOOP', '--max-time', '5', 'smtp://127.0.0.1:25'],
                                      capture_output=True, text=True, timeout=10)
            assert response.returncode == 0 and 'PIPELINING' in response.stderr, response.stderr
        except Exception:
            print(docker('logs', '--tail', '30', name), flush=True)
            raise
        finally:
            subprocess.run(['docker', 'rm', '-f', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20, check=False)
            subprocess.run(['docker', 'volume', 'rm', volume], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20, check=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', default='noisefence:local')
    args = parser.parse_args()
    name = 'noisefence-smoke-' + uuid.uuid4().hex[:12]
    volume = name + '-data'
    web_port, smtp_port = free_port(), free_port()
    origin = f'http://127.0.0.1:{web_port}'
    password = uuid.uuid4().hex
    cookies = http.cookiejar.CookieJar()
    client = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(cookies))

    def request(path, body=None):
        data = None if body is None else json.dumps(body).encode()
        headers = {'Origin': origin}
        if data is not None:
            headers['Content-Type'] = 'application/json'
        with client.open(urllib.request.Request(origin + path, data=data, headers=headers), timeout=5) as response:
            return response.read(), response.headers

    def ready():
        for _ in range(60):
            try:
                body, _ = request('/healthz')
                assert json.loads(body)['smtp_ready'] is True
                return
            except (urllib.error.URLError, http.client.HTTPException, OSError, AssertionError):
                time.sleep(.25)
        raise RuntimeError('Container did not become SMTP-ready')

    with tempfile.TemporaryDirectory(prefix='noisefence-container-test-') as temporary:
        config = Path(temporary) / 'config.toml'
        sample = Path(__file__).resolve().parents[1] / 'config/docker.example.toml'
        config.write_text(sample.read_text().replace('http://127.0.0.1:18080', origin).replace('127.0.0.1:18080\"', f'127.0.0.1:{web_port}\"').replace('127.0.0.1:2525\"', f'127.0.0.1:{smtp_port}\"'))
        config.chmod(0o644)  # Synthetic configuration only; allow non-root container reads.
        docker('volume', 'create', volume)
        try:
            docker('run', '-d', '--name', name, '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges:true', '--pids-limit=256', '--memory=2g', '--tmpfs=/tmp:rw,nosuid,nodev,noexec,size=128m', '--network=host', '-e', f'NOISEFENCE_HEALTH_URL={origin}/healthz', '-v', f'{volume}:/var/lib/noisefence', '-v', f'{config}:/etc/noisefence/config.toml:ro', args.image)
            ready()
            assert docker('exec', name, 'id', '-u') == '10001'
            html, _ = request('/')
            assert b'lang="en"' in html and b'NoiseFence' in html
            assets = set(re.findall(rb'(?:src|href)="(/_next/static/[^"?]+)', html))
            assert assets, 'Missing built console assets'
            for asset in assets:
                body, headers = request(asset.decode())
                assert body and 'text/html' not in headers.get('Content-Type', '')
            try:
                request('/api/v1/admin/config')
                raise AssertionError('Anonymous administration must fail')
            except urllib.error.HTTPError as error:
                assert error.code == 401
            administrator(name, password)
            request('/api/v1/login', {'username': 'smoke-admin', 'password': password})
            with smtplib.SMTP('127.0.0.1', smtp_port, timeout=20) as smtp:
                smtp.ehlo('client.example.test')
                smtp.mail('sender@example.test')
                code, _ = smtp.rcpt('outside@unrelated.test')
                assert code == 550, f'Unexpected open-relay response: {code}'
                smtp.rset()
                smtp.mail('sender@example.test')
                for address in ['alice@example.test', 'bob@example.test']:
                    code, _ = smtp.rcpt(address)
                    assert code == 250
                code, reply = smtp.data('From: sender@example.test\r\nTo: alice@example.test\r\nSubject: Container persistence check\r\nMessage-ID: <container-smoke@example.test>\r\n\r\nSynthetic loopback-only message.\r\n')
                assert code == 250, reply
                found = re.search(rb'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', reply)
                assert found, 'No durable queue identifier'
                message_id = found[0].decode()
            def retained():
                body, _ = request('/api/v1/search/messages?id=' + message_id)
                page = json.loads(body)
                assert page['total'] == 1
                mail = page['messages'][0]
                assessment = mail['assessment']
                assert assessment['version'] == 1 and assessment['score']['scale'] == 100
                assert math.isfinite(assessment['score']['value']) and 0 <= assessment['score']['value'] <= 100
                assert assessment['category'] == mail['category']
                assert mail['tagged'] is False and mail['pub_tagged'] is False
                assert len(mail['recipients']) == 2
                return assessment
            before = retained()
            docker('restart', '--time', '20', name)
            ready()
            assert retained() == before, 'Accepted evidence changed after restart'
        except Exception:
            print(docker('logs', '--tail', '50', name), flush=True)
            raise
        finally:
            subprocess.run(['docker', 'rm', '-f', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20, check=False)
            subprocess.run(['docker', 'volume', 'rm', volume], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20, check=False)
    privileged_port(args.image)
    print(json.dumps({'status': 'passed', 'checks': ['non-root runtime', 'English console and assets', 'admin authentication', 'open-relay refusal', 'two-recipient durable acceptance', 'shared score assessment', 'restart persistence', 'privileged SMTP port with reduced capabilities'], 'delivered_externally': False}))


if __name__ == '__main__':
    main()
