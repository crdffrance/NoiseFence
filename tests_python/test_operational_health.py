"""Admission and replication must remain observable despite a healthy HTTP server."""
import importlib.util
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('health', ROOT / 'deploy/health-check.py')
health = importlib.util.module_from_spec(spec)
spec.loader.exec_module(health)


class OperationalHealth(unittest.TestCase):
    def readiness(self, payload):
        response = Mock(status=200)
        response.read.return_value = json.dumps(payload).encode()
        opener = Mock()
        opener.open.return_value.__enter__ = Mock(return_value=response)
        opener.open.return_value.__exit__ = Mock(return_value=False)
        return opener

    def test_http_200_does_not_imply_smtp_ready(self):
        for value in (False, None, 1, 'true'):
            with patch.object(health.urllib.request, 'build_opener',
                              return_value=self.readiness({'status': 'ok', 'smtp_ready': value})):
                with self.assertRaisesRegex(ValueError, 'not ready'):
                    health.web_readiness('127.0.0.1:18080')
        with patch.object(health.urllib.request, 'build_opener',
                          return_value=self.readiness({'status': 'ok', 'smtp_ready': True})):
            self.assertTrue(health.web_readiness('[::1]:18080')['smtp_ready'])

    def test_no_redirect_or_nonlocal_health_target(self):
        self.assertIsNone(health.NoRedirect().redirect_request(None, None, 302, '', {}, 'https://example.org'))
        with self.assertRaises(ValueError):
            health.web_readiness('example.org:80')

    def test_admission_checks_without_delivering_mail(self):
        with patch.object(health.smtplib, 'SMTP') as factory:
            client = factory.return_value.__enter__.return_value
            client.ehlo.return_value = (250, b'ok')
            client.mail.return_value = (451, b'private detail')
            client.rset.return_value = (250, b'ok')
            with self.assertRaisesRegex(ValueError, '^SMTP MAIL returned 451$'):
                health.smtp_probe('0.0.0.0:25')
            client.rcpt.assert_not_called()
            client.data.assert_not_called()
            client.sendmail.assert_not_called()

    def test_stale_ha_and_worker_policy(self):
        with sqlite3.connect(':memory:') as db:
            db.executescript("CREATE TABLE cluster_state(key TEXT,value TEXT);"
                             "CREATE TABLE ha_local(generation INTEGER,acked INTEGER);"
                             "INSERT INTO ha_local VALUES(3,1);"
                             "INSERT INTO cluster_state VALUES('ha_required','1'),"
                             "('ha_last_success','980'),('role','worker'),('last_sync','100');")
            metrics, issues = health.replication_status(db, {'cluster': {'max_stale_seconds': 60}}, 1000)
            self.assertEqual(metrics['pending_updates'], 1)
            self.assertEqual(metrics['unprotected'], 0)
            self.assertEqual(len(issues), 2)
            db.execute("UPDATE cluster_state SET value='999' WHERE key IN ('ha_last_success','last_sync')")
            self.assertEqual(health.replication_status(db, {}, 1000)[1], [])
            with patch.object(health.time, 'time', return_value=1000):
                self.assertEqual(health.replication_status(db, {})[1], [])

    def test_memory_events_are_deltas_and_reset_after_restart(self):
        def sample(at, count, boot='a'):
            return {'checked_at': at, 'memory': {'current_bytes': 10, 'high_bytes': 20,
                    'events': {'high': count}, 'boot_id': boot, 'cgroup_id': 1}}
        self.assertEqual(health.sample_warnings(sample(100, 500), sample(40, 500)), [])
        self.assertEqual(health.sample_warnings(sample(100, 501), sample(40, 500)), ['new memory high events'])
        self.assertEqual(health.sample_warnings(sample(100, 501, 'b'), sample(40, 500)), [])
        self.assertEqual(health.sample_warnings(sample(100, 2), sample(40, 500)), [])

    def test_transient_replication_backlog_is_not_persistent(self):
        now = {'checked_at': 100, 'replication': {'pending_updates': 1}}
        self.assertEqual(health.sample_warnings(now, {}), [])
        self.assertTrue(health.sample_warnings(now, {**now, 'checked_at': 40}))
        self.assertEqual(health.sample_warnings(now, {**now, 'checked_at': -100}), [])

    def test_history_is_bounded_private_and_excludes_old_future_samples(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'history.json'
            health.write_json(path, [{'checked_at': i} for i in range(4000)])
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            history = health.load_history(path, 3998)
            self.assertEqual(len(history), health.HISTORY_LIMIT)
            self.assertEqual(history[-1]['checked_at'], 3998)
            self.assertEqual(health.load_history(path, 4000 + health.HISTORY_SECONDS), [])

    def test_database_is_read_only(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'state.sqlite3'
            with sqlite3.connect(path) as db:
                db.execute('CREATE TABLE t(x)')
            with health.readonly_db(path) as db:
                with self.assertRaises(sqlite3.OperationalError):
                    db.execute('INSERT INTO t VALUES(1)')


if __name__ == '__main__':
    unittest.main()
