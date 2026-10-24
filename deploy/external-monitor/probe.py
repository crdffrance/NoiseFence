#!/usr/bin/env python3
"""External, content-free SMTP STARTTLS/admission and HTTPS checks."""
import argparse
import concurrent.futures
import datetime
import http.client
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import smtplib
import socket
import ssl
import stat
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


def config_digest(nodes):
    # Bind the report to this monitored set, independent of JSON whitespace.
    value = json.dumps({'schema': 1, 'nodes': nodes}, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(value.encode()).hexdigest()


def read_report(path):
    # A missing/partial/oversized report is unavailable, never a healthy cache.
    # Do not block on a FIFO or follow a replacement symlink.
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as source:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError('Report must be a regular file')
        raw = source.read(131073)
    if len(raw) > 131072:
        raise ValueError('Report exceeds 128 KiB')

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('Duplicate report key')
            result[key] = value
        return result

    def invalid_constant(value):
        raise ValueError('Nonfinite report number')

    return json.loads(raw, object_pairs_hook=unique, parse_constant=invalid_constant)


def healthy_node(result, node):
    if result.get('status') != 'ok':
        return False
    checks = result.get('checks', {})
    if not isinstance(checks, dict) or set(checks) != {'dns', 'smtp', 'https'}:
        return False
    if any(not isinstance(value, dict) or value.get('status') != 'ok'
           for value in checks.values()):
        return False
    addresses = checks['dns'].get('addresses')
    if not isinstance(addresses, list) or not 1 <= len(addresses) <= 16:
        return False
    if any(not isinstance(a, str) or not ipaddress.ip_address(a).is_global for a in addresses):
        return False
    actual = {str(ipaddress.ip_address(a)) for a in addresses}
    expected = {str(ipaddress.ip_address(a)) for a in node['expected_addresses']}
    if expected and actual != expected:
        return False
    if result.get('checked_address') not in addresses:
        return False
    smtp, https = checks['smtp'], checks['https']
    if (smtp.get('admission') is not True or smtp.get('message_submitted') is not False
            or smtp.get('tls') not in ('TLSv1.2', 'TLSv1.3')
            or https.get('redirect_followed') is not False):
        return False
    for check in (smtp, https):
        days = check.get('certificate_days_remaining')
        if type(days) is not int or days < 14:
            return False
    code = https.get('http_status')
    return type(code) is int and (code == 200 or (
        code in (301, 302, 303, 307, 308)
        and https.get('redirect_host') in [node['host'], *node['console_redirect_hosts']]))


def check_report(path, nodes, max_age=180, now=None):
    """Consume a private report without networking, authentication or writes."""
    if type(max_age) is not int or not 30 <= max_age <= 3600:
        raise ValueError('Maximum age must be 30..3600 seconds')
    now = time.time() if now is None else now
    result = {'schema': 'noisefence-external-consumption-1', 'status': 'attention',
              'max_age_seconds': max_age, 'network_used': False,
              'scope': 'one_address_per_host', 'reasons': []}
    try:
        report = read_report(path)
    except (OSError, ValueError, UnicodeError):
        result['reasons'] = ['report_unavailable']
        return result
    try:
        if not isinstance(report, dict) or report.get('schema') != 'noisefence-external-health-1':
            raise ValueError('Invalid report schema')
        timestamp = datetime.datetime.fromisoformat(report['checked_at'])
        if timestamp.tzinfo is None or timestamp.utcoffset() is None:
            raise ValueError('Timestamp must include its time zone')
        age = now - timestamp.timestamp()
        result['age_seconds'] = round(age, 3)
        if age < -30:
            result['reasons'].append('clock_skew')
        elif age > max_age:
            result['reasons'].append('stale_report')
        if report.get('config_sha256') != config_digest(nodes):
            result['reasons'].append('configuration_changed')
        rows = report.get('nodes')
        if not isinstance(rows, list) or not 1 <= len(rows) <= 8:
            raise ValueError('Missing node results')
        by_host = {row['host']: row for row in rows}
        if len(by_host) != len(rows) or set(by_host) != {n['host'] for n in nodes}:
            result['reasons'].append('node_set_mismatch')
        elif any(not healthy_node(by_host[node['host']], node) for node in nodes):
            result['reasons'].append('incomplete_or_failed_checks')
        if report.get('status') != 'ok' or type(report.get('messages_submitted')) is not int or report['messages_submitted'] != 0:
            result['reasons'].append('probe_attention')
    except (KeyError, TypeError, ValueError, OverflowError, OSError):
        result['reasons'].append('invalid_report')
    if not result['reasons']:
        result['status'] = 'ok'
    return result


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
    parser.add_argument('--check-report', type=Path,
                        help='Check a saved report against the configuration without network access')
    parser.add_argument('--max-age', type=int, default=180,
                        help='Maximum saved report age in seconds (30..3600, default 180)')
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
        if args.check_report is not None:
            if args.output is not None:
                raise ValueError('Report checking is read-only; --output is not supported')
            result = check_report(args.check_report, nodes, args.max_age)
            print(json.dumps(result, allow_nan=False))
            return 0 if result['status'] == 'ok' else 1
        checked_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(bounded_node, nodes))
        report = {'schema': 'noisefence-external-health-1',
                  'checked_at': checked_at, 'config_sha256': config_digest(nodes),
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
