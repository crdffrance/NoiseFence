"""Local synthetic servers exercise the actual SMTP/TLS/HTTP probe."""
import contextlib
import copy
import datetime
import io
import os
import http.server
import importlib.util
import json
from pathlib import Path
import shutil
import socketserver
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('external_probe', ROOT/'deploy/external-monitor/probe.py')
probe = importlib.util.module_from_spec(spec); spec.loader.exec_module(probe)


class SMTPHandler(socketserver.StreamRequestHandler):
    def finish(self):
        try:
            super().finish()
        finally:
            self.connection.close()

    def handle(self):
        self.wfile.write(b'220 synthetic.example ESMTP\r\n'); self.wfile.flush()
        while True:
            line = self.rfile.readline(2048)
            if not line:
                return
            self.server.commands.append(line.decode().strip())
            command = line.split()[0].upper()
            if command == b'EHLO':
                self.wfile.write(b'250-synthetic.example\r\n250 STARTTLS\r\n')
            elif command == b'STARTTLS':
                self.wfile.write(b'220 Ready\r\n'); self.wfile.flush()
                self.rfile.close(); self.wfile.close()
                try:
                    self.connection = self.server.tls.wrap_socket(self.connection, server_side=True)
                except ssl.SSLError:
                    return
                self.rfile = self.connection.makefile('rb')
                self.wfile = self.connection.makefile('wb')
            elif command == b'MAIL':
                self.wfile.write(b'451 synthetic private response\r\n' if self.server.defer else b'250 OK\r\n')
            elif command == b'RSET':
                self.wfile.write(b'250 OK\r\n')
            elif command == b'QUIT':
                self.wfile.write(b'221 Bye\r\n'); self.wfile.flush(); return
            else:
                self.wfile.write(b'500 Unexpected command\r\n')
            self.wfile.flush()


class HTTPHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.paths.append(self.path)
        self.send_response(self.server.reply_status)
        if self.server.location:
            self.send_header('Location', self.server.location)
        self.send_header('Content-Length', '2'); self.end_headers()
        self.wfile.write(b'OK')

    def log_message(self, *args):
        pass


@unittest.skipUnless(shutil.which('openssl'), 'openssl is needed for local TLS fixtures')
class ExternalMonitorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(); cls.root = Path(cls.temp.name)
        cls.cert, cls.key = cls.root/'cert.pem', cls.root/'key.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
            '-keyout', str(cls.key), '-out', str(cls.cert), '-days', '30',
            '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'],
            check=True, capture_output=True)
        cls.server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        cls.server_context.load_cert_chain(cls.cert, cls.key)
        cls.client_context = ssl.create_default_context(cafile=str(cls.cert))

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    @contextlib.contextmanager
    def server(self, kind='smtp', defer=False, status=200, location=None):
        if kind == 'smtp':
            server = socketserver.ThreadingTCPServer(('127.0.0.1', 0), SMTPHandler)
            server.commands = []; server.tls = self.server_context; server.defer = defer
        else:
            server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), HTTPHandler)
            server.paths = []; server.reply_status = status; server.location = location
            server.socket = self.server_context.wrap_socket(server.socket, server_side=True)
        server.daemon_threads = True
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        try:
            yield server
        finally:
            server.shutdown(); server.server_close(); thread.join(timeout=2)

    def test_real_starttls_checks_admission_without_submitting_mail(self):
        with self.server() as server:
            result = probe.smtp_check('localhost', '127.0.0.1', self.client_context, server.server_address[1])
        self.assertEqual(result['status'], 'ok')
        self.assertFalse(result['message_submitted'])
        self.assertEqual(server.commands, ['ehlo probe.invalid', 'STARTTLS', 'ehlo probe.invalid', 'mail FROM:<>', 'rset', 'QUIT'])
        self.assertGreaterEqual(result['certificate_days_remaining'], 28)

    def test_untrusted_certificate_is_not_accepted(self):
        with self.server() as server, self.assertRaises(ssl.SSLCertVerificationError):
            probe.smtp_check('localhost', '127.0.0.1', ssl.create_default_context(), server.server_address[1])

    def test_hostname_is_verified_even_when_connection_is_pinned(self):
        with self.server() as server, self.assertRaises(ssl.SSLCertVerificationError):
            probe.smtp_check('wrong.example', '127.0.0.1', self.client_context, server.server_address[1])

    def test_temporary_smtp_failure_is_visible_without_remote_text(self):
        with self.server(defer=True) as server:
            try:
                probe.smtp_check('localhost', '127.0.0.1', self.client_context, server.server_address[1])
            except Exception as error:
                result = probe.failure(error)
        self.assertEqual(result['smtp_code'], 451)
        self.assertNotIn('private', json.dumps(result))
        self.assertFalse(any(c.startswith(('RCPT', 'DATA', 'rset')) for c in server.commands))

    def test_https_uses_tls_and_never_follows_redirects(self):
        with self.server('https', status=302, location='https://coordinator.example/login') as server:
            result = probe.https_check('localhost', '127.0.0.1', ['coordinator.example'], self.client_context, server.server_address[1])
        self.assertEqual(result['status'], 'ok')
        self.assertFalse(result['redirect_followed'])
        self.assertEqual(server.paths, ['/'])
        with self.server('https', status=302, location='http://127.0.0.1/private') as server, self.assertRaises(ValueError):
            probe.https_check('localhost', '127.0.0.1', [], self.client_context, server.server_address[1])

    def test_console_error_does_not_count_as_healthy(self):
        with self.server('https', status=503) as server:
            result = probe.https_check('localhost', '127.0.0.1', [], self.client_context, server.server_address[1])
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(result['http_status'], 503)

    def test_private_dns_and_mismatched_expected_addresses_stop_before_connections(self):
        node = {'host':'mx.example', 'expected_addresses':[], 'console_redirect_hosts':[]}
        for resolved, expected in [('127.0.0.1', []), ('8.8.8.8', ['1.1.1.1'])]:
            with patch.object(probe.socket, 'getaddrinfo', return_value=[(2, 1, 6, '', (resolved, 25))]), patch.object(probe, 'smtp_check') as smtp:
                result = probe.probe_node({**node, 'expected_addresses':expected})
                self.assertEqual(result['checks']['dns']['status'], 'failed'); smtp.assert_not_called()

    def test_child_deadline_surfaces_failure_without_stderr(self):
        with patch.object(probe.subprocess, 'run', side_effect=subprocess.TimeoutExpired('probe', 25, stderr='sensitive')):
            result = probe.bounded_node({'host':'mx.example'})
        self.assertEqual(result['error'], 'deadline_exceeded')
        self.assertNotIn('sensitive', json.dumps(result))

    def test_config_is_bounded_and_report_is_private(self):
        node = {'host':'mx.example', 'expected_addresses':[], 'console_redirect_hosts':[]}
        config = self.root/'config.json'; config.write_text(json.dumps({'schema':1, 'nodes':[node]}))
        self.assertEqual(probe.load_config(config), [node])
        config.write_text(' ' * 16385)
        with self.assertRaises(ValueError): probe.load_config(config)
        output = self.root/'report.json'; probe.write_report(output, {'status':'ok'})
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        self.assertEqual(json.loads(output.read_text()), {'status':'ok'})

    def test_certificate_warning_uses_actual_expiry(self):
        self.assertEqual(probe.certificate_days({'notAfter':'Jan 15 00:00:00 2030 GMT'},
            ssl.cert_time_to_seconds('Jan 02 00:00:00 2030 GMT')), 13)


class ReportConsumerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.path = self.root / 'report.json'
        self.nodes = [{'host': 'mx.example', 'expected_addresses': ['8.8.8.8'],
                       'console_redirect_hosts': ['coordinator.example']}]
        self.now = float(int(time.time()))
        self.report = {
            'schema': 'noisefence-external-health-1',
            'checked_at': datetime.datetime.fromtimestamp(self.now - 10, datetime.timezone.utc).isoformat(),
            'config_sha256': probe.config_digest(self.nodes), 'status': 'ok',
            'messages_submitted': 0,
            'nodes': [{'host': 'mx.example', 'status': 'ok', 'checked_address': '8.8.8.8',
                       'checks': {
                           'dns': {'status': 'ok', 'addresses': ['8.8.8.8']},
                           'smtp': {'status': 'ok', 'admission': True, 'message_submitted': False,
                                    'tls': 'TLSv1.3', 'certificate_days_remaining': 29},
                           'https': {'status': 'ok', 'http_status': 200, 'redirect_followed': False,
                                     'certificate_days_remaining': 29}}}]}

    def check(self, report=None, **kwargs):
        self.path.write_text(json.dumps(self.report if report is None else report))
        with patch.object(probe.socket, 'getaddrinfo', side_effect=AssertionError('Unexpected DNS')), \
             patch.object(probe.socket, 'create_connection', side_effect=AssertionError('Unexpected connection')):
            return probe.check_report(self.path, self.nodes, now=self.now, **kwargs)

    def test_current_complete_report_is_healthy_without_network_or_writes(self):
        self.assertEqual(self.check()['status'], 'ok')
        before = self.path.stat()
        result = probe.check_report(self.path, self.nodes, now=self.now)
        self.assertEqual(result['age_seconds'], 10)
        self.assertFalse(result['network_used'])
        self.assertEqual(result['scope'], 'one_address_per_host')
        self.assertEqual(self.path.stat().st_mtime_ns, before.st_mtime_ns)
        self.assertEqual(json.loads(self.path.read_text()), self.report)

    def test_age_boundary_clock_skew_timezone_and_operator_bound(self):
        for offset, reason in [(-180, None), (-181, 'stale_report'), (31, 'clock_skew')]:
            self.report['checked_at'] = datetime.datetime.fromtimestamp(
                self.now + offset, datetime.timezone.utc).isoformat()
            result = self.check()
            self.assertEqual(result['status'], 'attention' if reason else 'ok')
            if reason:
                self.assertIn(reason, result['reasons'])
        self.report['checked_at'] = '2026-01-01T00:00:00'
        self.assertIn('invalid_report', self.check()['reasons'])
        for maximum in [0, 29, 3601, True]:
            with self.assertRaises(ValueError):
                self.check(max_age=maximum)

    def test_missing_special_partial_oversized_and_ambiguous_reports_fail_closed(self):
        def unavailable():
            result = probe.check_report(self.path, self.nodes, now=self.now)
            self.assertEqual(result['status'], 'attention')
            self.assertEqual(result['reasons'], ['report_unavailable'])
        unavailable()
        for content in ['{', ' ' * 131073, '{"status":"failed","status":"ok"}', '{"status":NaN}']:
            self.path.write_text(content)
            unavailable()
        self.path.unlink()
        os.mkfifo(self.path)
        started = time.monotonic()
        unavailable()
        self.assertLess(time.monotonic() - started, 1)
        self.path.unlink()
        target = self.root / 'target'; target.write_text(json.dumps(self.report))
        self.path.symlink_to(target)
        unavailable()
        self.path.unlink(); self.path.mkdir()
        unavailable()

    def test_changed_configuration_and_duplicate_or_missing_nodes_are_not_healthy(self):
        changed = copy.deepcopy(self.report)
        changed.pop('config_sha256')  # Earlier schema-1 reports need a new probe.
        self.assertIn('configuration_changed', self.check(changed)['reasons'])
        changed['config_sha256'] = '0' * 64
        self.assertIn('configuration_changed', self.check(changed)['reasons'])
        for rows in [[], self.report['nodes'] * 2, [{'host': 'other.example'}], [None]]:
            changed = {**self.report, 'nodes': rows}
            self.assertEqual(self.check(changed)['status'], 'attention')
        self.nodes[0]['console_redirect_hosts'] = []
        self.assertIn('configuration_changed', self.check()['reasons'])

    def test_top_level_ok_cannot_hide_failed_or_missing_checks(self):
        mutations = [
            ('dns', 'status', 'failed'), ('dns', 'addresses', ['127.0.0.1']),
            ('dns', 'addresses', ['1.1.1.1']), ('dns', 'addresses', []),
            ('smtp', 'admission', False), ('smtp', 'admission', 1),
            ('smtp', 'message_submitted', True), ('smtp', 'tls', 'TLSv1.1'),
            ('smtp', 'certificate_days_remaining', 13),
            ('https', 'certificate_days_remaining', True),
            ('https', 'http_status', 503), ('https', 'redirect_followed', True)]
        for check, field, value in mutations:
            with self.subTest(check=check, field=field):
                changed = copy.deepcopy(self.report)
                changed['nodes'][0]['checks'][check][field] = value
                self.assertIn('incomplete_or_failed_checks', self.check(changed)['reasons'])
        changed = copy.deepcopy(self.report)
        del changed['nodes'][0]['checks']['https']
        self.assertEqual(self.check(changed)['status'], 'attention')
        for submitted in [1, False, None]:
            self.assertIn('probe_attention', self.check({**self.report, 'messages_submitted': submitted})['reasons'])

    def test_allowed_redirect_is_checked_without_using_a_remote_location(self):
        self.report['nodes'][0]['checks']['https'].update(http_status=302, redirect_host='coordinator.example')
        self.assertEqual(self.check()['status'], 'ok')
        self.report['nodes'][0]['checks']['https']['redirect_host'] = 'unexpected.example'
        self.report['nodes'][0]['checks']['https']['remote_text'] = 'PRIVATE CONTENT'
        result = self.check()
        self.assertEqual(result['status'], 'attention')
        self.assertNotIn('PRIVATE', json.dumps(result))

    def test_cli_checks_without_replacing_or_creating_output(self):
        config = self.root / 'config.json'
        config.write_text(json.dumps({'schema': 1, 'nodes': self.nodes}, indent=4))
        self.check()
        command = [sys.executable, str(ROOT/'deploy/external-monitor/probe.py'),
                   '--config', str(config), '--check-report', str(self.path)]
        run = subprocess.run(command, capture_output=True, text=True, timeout=5)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertFalse(json.loads(run.stdout)['network_used'])
        self.report['checked_at'] = '2020-01-01T00:00:00+00:00'
        self.path.write_text(json.dumps(self.report))
        run = subprocess.run(command, capture_output=True, text=True, timeout=5)
        self.assertEqual(run.returncode, 1, run.stderr)
        self.assertIn('stale_report', json.loads(run.stdout)['reasons'])
        other = self.root / 'output.json'
        run = subprocess.run(command + ['--output', str(other)], capture_output=True, text=True, timeout=5)
        self.assertEqual(run.returncode, 2)
        self.assertFalse(other.exists())

    def test_producer_binds_configuration_and_timestamps_before_slow_checks(self):
        config = self.root / 'config.json'
        config.write_text(json.dumps({'schema': 1, 'nodes': self.nodes}))
        def slow_node(node):
            time.sleep(0.05)
            return self.report['nodes'][0]
        output = io.StringIO()
        before = time.time()
        with patch.object(sys, 'argv', ['probe', '--config', str(config), '--output', str(self.path)]), \
             patch.object(probe, 'bounded_node', side_effect=slow_node), contextlib.redirect_stdout(output):
            self.assertEqual(probe.main(), 0)
        result = json.loads(self.path.read_text())
        observed = datetime.datetime.fromisoformat(result['checked_at']).timestamp()
        self.assertGreaterEqual(observed, before)
        self.assertLess(observed, time.time() - 0.04)
        self.assertEqual(result['config_sha256'], probe.config_digest(self.nodes))
        self.assertEqual(probe.check_report(self.path, self.nodes)['status'], 'ok')
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)


if __name__ == '__main__':
    unittest.main()
