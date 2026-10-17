"""Local synthetic servers exercise the actual SMTP/TLS/HTTP probe."""
import contextlib
import http.server
import importlib.util
import json
from pathlib import Path
import shutil
import socketserver
import ssl
import subprocess
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


if __name__ == '__main__':
    unittest.main()
