"""Actual read-only SQLite/WAL checks, bounded HTTP health and immutable operator receipts."""
import contextlib
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('upgrade_check', ROOT / 'deploy/upgrade-check.py')
check = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(check)


class UpgradeCheck(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.config = self.root / 'config.toml'
        self.base = f'data_dir={json.dumps(str(self.root))}\n[web]\nlisten="127.0.0.1:18080"\n'
        self.config.write_text(self.base)
        self.manifest = dict(project='NoiseFence', version='0.31.9', storage_schema=7,
                             commit='a' * 40, source_sha256='b' * 64)
        self.release = self.root / 'release'
        self.release.mkdir()
        self.save_manifest()
        self.database = self.root / 'state.sqlite3'

    def save_manifest(self):
        (self.release / 'build.json').write_text(json.dumps(self.manifest))

    @contextlib.contextmanager
    def db(self, version=5):
        db = sqlite3.connect(self.database)
        try:
            with db:
                db.execute(f'PRAGMA user_version={version}')
                db.execute('CREATE TABLE IF NOT EXISTS cluster_state(key TEXT PRIMARY KEY,value TEXT)')
                yield db
        finally:
            db.close()

    def inspect(self, **kwargs):
        return check.inspect(self.config, self.release, now=1000, **kwargs)

    def test_fresh_install_does_not_create_database_or_invent_live_readiness(self):
        before = sorted(self.root.iterdir())
        report = self.inspect()
        self.assertTrue(report['local_install_supported'])
        self.assertFalse(report['storage']['exists'])
        self.assertEqual(report['live'], {'status': 'not_checked'})
        self.assertEqual(report['rollback'], 'not_qualified')
        self.assertFalse(report['candidate']['artifact_checksums_verified'])
        self.assertEqual(sorted(self.root.iterdir()), before)
        self.assertEqual(self.inspect(expect_existing=True)['local_install_blockers'], ['existing_local_storage_missing'])

    def test_existing_wal_is_read_without_rewinding_or_using_an_immutable_snapshot(self):
        with self.db() as db:
            db.execute('PRAGMA journal_mode=WAL')
            db.execute('INSERT INTO cluster_state VALUES(?,?)', ('management_transport', 'private-value'))
            db.commit()
            before = db.execute('SELECT * FROM cluster_state').fetchall()
            with patch.object(check, 'readiness', side_effect=AssertionError('not requested')):
                report = self.inspect()
            self.assertFalse(report['local_install_supported'])
            self.assertEqual(report['storage']['management_markers'], ['management_transport'])
            self.assertNotIn('private-value', json.dumps(report))
            self.assertEqual(db.execute('SELECT * FROM cluster_state').fetchall(), before)
            self.assertEqual(db.execute('PRAGMA user_version').fetchone()[0], 5)

    def test_every_selected_or_partial_management_marker_refuses_local_install(self):
        for marker in check.MARKERS:
            with self.subTest(marker=marker), self.db(6) as db:
                db.execute('DELETE FROM cluster_state')
                db.execute('INSERT INTO cluster_state VALUES(?,?)', (marker, '{}'))
            report = self.inspect()
            self.assertEqual(report['local_install_blockers'], ['coordinated_management_required'])
        with self.db(7) as db:
            db.execute('DELETE FROM cluster_state')
        self.assertFalse(self.inspect()['local_install_supported'])
        self.database.unlink()
        for declaration in ('[management]\nbackend="postgresql"', '[management]\nbackend="coordinator"', '[management]'):
            self.config.write_text(self.base + declaration)
            self.assertFalse(self.inspect()['local_install_supported'])

    def test_old_candidate_and_unknown_or_broken_storage_fail_closed(self):
        with self.db(5):
            pass
        self.manifest['storage_schema'] = 4
        self.save_manifest()
        self.assertEqual(self.inspect()['local_install_blockers'], ['candidate_storage_format_too_old'])
        for version in (0, 8):
            with self.db(version):
                pass
            with self.assertRaises(ValueError):
                self.inspect()
        self.database.unlink()
        self.database.symlink_to(self.root / 'missing')
        with self.assertRaises(sqlite3.Error):
            self.inspect()
        self.database.unlink()
        Path(str(self.database) + '-wal').write_bytes(b'sidecar')
        with self.assertRaisesRegex(ValueError, 'sidecars'):
            self.inspect()

    def replication(self, generation=3, acked=3, heartbeat=995):
        with self.db() as db:
            db.execute('CREATE TABLE IF NOT EXISTS ha_local(message_id,generation,acked)')
            db.execute('DELETE FROM ha_local')
            db.execute('INSERT INTO ha_local VALUES(?,?,?)', ('synthetic', generation, acked))
            db.execute("INSERT OR REPLACE INTO cluster_state VALUES('ha_required','1')")
            db.execute("INSERT OR REPLACE INTO cluster_state VALUES('ha_last_success',?)", (str(heartbeat),))

    def test_two_copy_requirement_cannot_be_removed_by_configuration(self):
        self.replication()
        self.assertEqual(self.inspect()['local_install_blockers'], ['mandatory_replication_missing_from_configuration'])
        self.config.write_text(self.base + '[replication]\npeer_id="mx2"\n')
        self.assertTrue(self.inspect()['local_install_supported'])
        for acked, expected in [(0, 'replica_initial_acknowledgements_pending'), (2, 'replica_updates_pending')]:
            self.replication(acked=acked)
            with patch.object(check, 'readiness', return_value={'status': 'observed', 'smtp_ready': True}):
                report = self.inspect(live=True)
            self.assertIn(expected, report['operational_blockers'])
        for generation, acked in [(3, 4), (3, None), (None, 0), (3, '3'), (1.5, 1)]:
            self.replication(generation=generation, acked=acked)
            with self.subTest(generation=generation, acked=acked), self.assertRaisesRegex(ValueError, 'generation'):
                self.inspect()

    def test_heartbeat_future_and_stale_never_count_as_healthy(self):
        self.config.write_text(self.base + '[replication]\npeer_id="mx2"\n')
        for at, good in [(985, True), (1000, True), (984, False), (1001, False)]:
            self.replication(heartbeat=at)
            with patch.object(check, 'readiness', return_value={'status': 'observed', 'smtp_ready': True}):
                report = self.inspect(live=True)
            self.assertEqual('replica_heartbeat_not_fresh' not in report['operational_blockers'], good)

    def test_http_unavailable_and_admission_false_are_distinct(self):
        for result in (False, True):
            with patch.object(check, 'readiness', return_value={'status': 'observed', 'smtp_ready': result}):
                report = self.inspect(live=True)
            self.assertEqual('smtp_not_ready' in report['operational_blockers'], not result)
        with patch.object(check, 'readiness', side_effect=OSError('private server content')):
            report = self.inspect(live=True)
        self.assertEqual(report['live'], {'status': 'unavailable'})
        self.assertNotIn('private server', json.dumps(report))
        with patch.object(check, 'readiness', side_effect=check.DeadlineExceeded):
            with self.assertRaises(check.DeadlineExceeded):
                self.inspect(live=True)

    def test_http_requires_numeric_loopback_and_strict_bounded_readiness(self):
        for address in ('example.org:80', '192.0.2.1:80', '127.0.0.1:65536', '127.0.0.1:0'):
            with self.assertRaises(ValueError):
                check.readiness(address)
        self.assertIsNone(check.NoRedirect().redirect_request(None, None, 302, '', {}, 'https://example.org'))
        for payload in ([], {}, {'status': 'ok', 'smtp_ready': 'true'}, {'status': 'ok', 'smtp_ready': 1}, {'status': 'ok', 'smtp_ready': True}):
            response = Mock(status=200)
            response.read.return_value = json.dumps(payload).encode()
            opener = Mock()
            opener.open.return_value.__enter__ = Mock(return_value=response)
            opener.open.return_value.__exit__ = Mock(return_value=False)
            with patch.object(check.urllib.request, 'build_opener', return_value=opener):
                if payload == {'status': 'ok', 'smtp_ready': True} and type(payload['smtp_ready']) is bool:
                    self.assertTrue(check.readiness('[::1]:18080')['smtp_ready'])
                else:
                    with self.assertRaises(ValueError):
                        check.readiness('127.0.0.1:18080')
            response.read.assert_called_once_with(4097)

    def test_real_http_probe_refuses_redirects_errors_oversize_and_coerced_readiness(self):
        requests = []
        reply = [200, b'{"status":"ok","smtp_ready":true}']
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                requests.append(self.path)
                self.send_response(reply[0])
                if reply[0] == 302:
                    self.send_header('Location', '/must-not-follow')
                self.send_header('Content-Length', str(len(reply[1])))
                self.end_headers()
                self.wfile.write(reply[1])

            def log_message(self, *_args):
                pass
        # The fixture has a numeric loopback address; avoid the stdlib server's
        # unrelated reverse-DNS lookup while retaining real client/server HTTP.
        with patch('http.server.socket.getfqdn', return_value='localhost'):
            server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        with server:
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            try:
                address = f'127.0.0.1:{server.server_port}'
                self.assertTrue(check.readiness(address)['smtp_ready'])
                for status, body in [(302, b''), (503, b'private body'), (200, b'x' * 4097),
                                     (200, b'{"status":"ok","smtp_ready":"true"}')]:
                    reply[:] = status, body
                    with self.subTest(status=status, body_length=len(body)), self.assertRaises((OSError, ValueError)):
                        check.readiness(address)
                self.assertEqual(requests, ['/healthz'] * 5)
            finally:
                server.shutdown()
                worker.join(timeout=3)

    @unittest.skipUnless(hasattr(os, 'mkfifo'), 'Unix CLI deadline')
    def test_cli_total_deadline_bounds_even_a_blocked_configuration_read(self):
        fifo = self.root / 'blocked-config'
        os.mkfifo(fifo, 0o600)
        start = time.monotonic()
        result = subprocess.run([sys.executable, str(ROOT / 'deploy/upgrade-check.py'), '--config', str(fifo),
                                 '--candidate', str(self.release)], capture_output=True, text=True, timeout=18)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn('No installation was authorized', result.stderr)
        self.assertLess(time.monotonic() - start, 16)
        self.assertFalse(self.database.exists())

    def test_receipts_are_private_durable_and_never_replace_existing_history(self):
        output = self.root / 'receipt.json'
        value = self.inspect()
        check.write_receipt(output, value)
        original = output.read_bytes()
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(FileExistsError):
            check.write_receipt(output, {'replacement': True})
        self.assertEqual(output.read_bytes(), original)
        self.assertEqual(list(self.root.glob('.upgrade-check-*')), [])
        with patch.object(check.os, 'link', side_effect=OSError('disk error')):
            with self.assertRaises(OSError):
                check.write_receipt(self.root / 'failed.json', value)
        self.assertFalse((self.root / 'failed.json').exists())

    def test_cli_refuses_selected_authority_without_printing_configuration_or_mutating_storage(self):
        self.config.write_text(self.base + '[management]\nbackend="postgresql"\npassword="SYNTHETIC-PRIVATE"\n')
        digest = hashlib.sha256(self.config.read_bytes()).hexdigest()
        result = subprocess.run([sys.executable, str(ROOT / 'deploy/upgrade-check.py'), '--config', str(self.config),
                                 '--candidate', str(self.release), '--require-local-install'], capture_output=True, text=True, timeout=12)
        self.assertEqual(result.returncode, 1)
        self.assertIn('coordinated_management_required', result.stderr)
        self.assertNotIn('SYNTHETIC-PRIVATE', result.stdout + result.stderr)
        self.assertEqual(hashlib.sha256(self.config.read_bytes()).hexdigest(), digest)
        self.assertFalse(self.database.exists())

    def test_relative_data_path_uses_explicit_runtime_working_directory(self):
        self.config.write_text('data_dir="data"\n')
        (self.root / 'data').mkdir()
        with contextlib.closing(sqlite3.connect(self.root / 'data/state.sqlite3')) as db:
            db.execute('PRAGMA user_version=7')
        self.assertFalse(self.inspect(working_directory=self.root)['local_install_supported'])

    def test_oversized_and_malformed_metadata_never_passes(self):
        for changes in ({'storage_schema': True}, {'version': '../bad'}, {'commit': '123'}, {'source_sha256': 'bad'}):
            (self.release / 'build.json').write_text(json.dumps(self.manifest | changes))
            with self.assertRaises(ValueError):
                self.inspect()
        self.config.write_bytes(b'x' * (check.MAX_CONFIG + 1))
        with self.assertRaises(ValueError):
            self.inspect()


if __name__ == '__main__':
    unittest.main()
