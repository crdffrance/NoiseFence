#!/usr/bin/env python3
"""External, content-free SMTP STARTTLS/admission and HTTPS checks."""
import argparse
import concurrent.futures
import datetime
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import smtplib
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.parse


class PinnedSMTP(smtplib.SMTP):
    def __init__(self, host, address, port):
        self.address = address
        super().__init__(host, port, timeout=5)

    def _get_socket(self, host, port, timeout):
        return socket.create_connection((self.address, port), timeout=timeout)


class PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host, address, context, port):
        self.address = address
        super().__init__(host, port=port, timeout=5, context=context)

    def connect(self):
        sock = socket.create_connection((self.address, self.port), timeout=self.timeout)
        try:
            self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
        except BaseException:
            sock.close()
            raise


def host_name(value):
    return (isinstance(value, str) and len(value) <= 253
            and all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
                    for label in value.split('.')))


def load_config(path):
    with Path(path).open('rb') as source:
        data = source.read(16385)
    if len(data) > 16384:
        raise ValueError('Configuration exceeds 16 KiB')
    config = json.loads(data)
    if set(config) != {'schema', 'nodes'} or config['schema'] != 1:
        raise ValueError('Unsupported monitor configuration')
    nodes = config['nodes']
    if not isinstance(nodes, list) or not 1 <= len(nodes) <= 8:
        raise ValueError('Configure between one and eight MX nodes')
    names = set()
    for node in nodes:
        if not isinstance(node, dict) or set(node) != {'host', 'expected_addresses', 'console_redirect_hosts'}:
            raise ValueError('Invalid node configuration')
        if not host_name(node['host']) or node['host'] in names:
            raise ValueError('Hostnames must be unique lowercase DNS names')
        names.add(node['host'])
        if not isinstance(node['expected_addresses'], list) or len(node['expected_addresses']) > 16:
            raise ValueError('Invalid expected DNS addresses')
        for address in node['expected_addresses']:
            if not isinstance(address, str) or not ipaddress.ip_address(address).is_global:
                raise ValueError('Expected addresses must be public IP addresses')
        targets = node['console_redirect_hosts']
        if not isinstance(targets, list) or len(targets) > 8 or not all(host_name(h) for h in targets):
            raise ValueError('Invalid console redirect hosts')
    return nodes


def certificate_days(certificate, now=None):
    expiry = ssl.cert_time_to_seconds(certificate['notAfter'])
    return int((expiry - (time.time() if now is None else now)) // 86400)


def smtp_check(host, address, context, port=25):
    with PinnedSMTP(host, address, port) as client:
        if client.ehlo('probe.invalid')[0] != 250 or not client.has_extn('starttls'):
            raise ValueError('SMTP STARTTLS unavailable')
        client.starttls(context=context)
        days = certificate_days(client.sock.getpeercert())
        for command, args in ((client.ehlo, ('probe.invalid',)), (client.mail, ('',)), (client.rset, ())):
            reply = command(*args)
            if reply[0] != 250:
                raise smtplib.SMTPResponseException(reply[0], b'admission probe')
        # Never send RCPT, DATA or an authenticated transaction.
        return {'status': 'ok' if days >= 14 else 'attention',
                'certificate_days_remaining': days, 'tls': client.sock.version(),
                'admission': True, 'message_submitted': False}


def https_check(host, address, redirect_hosts, context, port=443):
    client = PinnedHTTPS(host, address, context, port)
    try:
        client.connect()
        days = certificate_days(client.sock.getpeercert())
        client.request('GET', '/', headers={'User-Agent': 'NoiseFence-external-probe/1'})
        response = client.getresponse()
        result = {'status': 'ok' if days >= 14 else 'attention',
                  'http_status': response.status, 'certificate_days_remaining': days,
                  'redirect_followed': False}
        if response.status in (301, 302, 303, 307, 308):
            location = response.getheader('Location', '')
            target = urllib.parse.urlsplit(urllib.parse.urljoin('https://' + host + '/', location))
            if (not location or target.scheme != 'https'
                    or target.hostname not in [host, *redirect_hosts]
                    or target.username is not None or target.password is not None
                    or target.port not in (None, 443)):
                raise ValueError('Unexpected console redirect')
            result['redirect_host'] = target.hostname
        elif response.status != 200:
            result['status'] = 'failed'
        if response.status == 200:
            response.read(1024)  # Never retain or log the response body.
        return result
    finally:
        client.close()


def failure(error):
    # SMTP banners, response text, URLs and exception strings can contain secrets.
    result = {'status': 'failed', 'error': type(error).__name__}
    if isinstance(error, smtplib.SMTPResponseException):
        result['smtp_code'] = error.smtp_code
    return result


def probe_node(node):
    host = node['host']
    result = {'host': host, 'status': 'failed', 'checks': {}}
    try:
        addresses = sorted({entry[4][0] for entry in socket.getaddrinfo(host, 25,
            type=socket.SOCK_STREAM)})
        if not addresses or len(addresses) > 16 or not all(ipaddress.ip_address(a).is_global for a in addresses):
            raise ValueError('MX did not resolve exclusively to public addresses')
        expected = {str(ipaddress.ip_address(a)) for a in node['expected_addresses']}
        if expected and {str(ipaddress.ip_address(a)) for a in addresses} != expected:
            raise ValueError('MX DNS addresses differ from configuration')
        result['checks']['dns'] = {'status': 'ok', 'addresses': addresses}
    except Exception as error:
        result['checks']['dns'] = failure(error)
        return result
    address = addresses[0]
    result['checked_address'] = address
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    for name, check in [('smtp', lambda: smtp_check(host, address, context)),
                         ('https', lambda: https_check(host, address, node['console_redirect_hosts'], context))]:
        try:
            result['checks'][name] = check()
        except Exception as error:
            result['checks'][name] = failure(error)
    result['status'] = 'ok' if all(c['status'] == 'ok' for c in result['checks'].values()) else 'attention'
    return result


def bounded_node(node, timeout=25):
    started = time.monotonic()
    try:
        run = subprocess.run([sys.executable, str(Path(__file__).resolve()), '--node'],
            input=json.dumps(node), capture_output=True, text=True, timeout=timeout)
        if run.returncode:
            raise RuntimeError('Probe child failed')
        result = json.loads(run.stdout)
    except Exception as error:
        result = {'host': node['host'], 'status': 'failed', 'checks': {},
                  'error': 'deadline_exceeded' if isinstance(error, subprocess.TimeoutExpired)
                           else type(error).__name__}
    result['elapsed_ms'] = round((time.monotonic() - started) * 1000)
    return result


def write_report(path, report):
    path = Path(path)
    # The installer creates a private StateDirectory; never create parents blindly.
    fd, temporary = tempfile.mkstemp(prefix='.external-monitor-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as output:
            json.dump(report, output, allow_nan=False)
            output.write('\n'); output.flush(); os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--node', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    os.umask(0o077)
    if args.node:
        print(json.dumps(probe_node(json.loads(sys.stdin.read(16385)))))
        return 0
    try:
        if args.config is None:
            raise ValueError('A configuration file is required')
        nodes = load_config(args.config)
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(bounded_node, nodes))
        report = {'schema': 'noisefence-external-health-1',
                  'checked_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  'status': 'ok' if all(n['status'] == 'ok' for n in results) else 'attention',
                  'nodes': results, 'messages_submitted': 0}
        if args.output:
            write_report(args.output, report)
        print(json.dumps(report, allow_nan=False))
        return 0 if report['status'] == 'ok' else 1
    except Exception as error:
        print(json.dumps({'schema': 'noisefence-external-health-1', 'status': 'failed',
                          'error': type(error).__name__}), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
