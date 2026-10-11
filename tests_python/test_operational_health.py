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
    def test_selected_postgres_never_reads_obsolete_sqlite_workers(self):
        with sqlite3.connect(':memory:') as db:
            db.executescript("CREATE TABLE cluster_state(key,value);"
                             "INSERT INTO cluster_state VALUES('role','coordinator');")
            cfg = {'management': {'backend': 'postgresql'}}
            report = {'backend': 'postgresql', 'workers': 1, 'stale_workers': 0}
            metrics, issues = health.replication_status(db, cfg, 1000, report)
            self.assertEqual(metrics['stale_workers'], 0)
            self.assertEqual(issues, [])
            report['stale_workers'] = 1
            self.assertEqual(len(health.replication_status(db, cfg, 1000, report)[1]), 1)
            with self.assertRaisesRegex(ValueError, 'no SQLite fallback'):
                health.replication_status(db, cfg, 1000)

    def test_management_probe_is_bounded_and_rejects_wrong_or_stale_authority(self):
        good = {'backend': 'postgresql', 'checked_at': 1000, 'workers': 1, 'stale_workers': 0}
        with patch.object(health.time, 'time', return_value=1000), patch.object(health.subprocess, 'run') as run:
            run.return_value = Mock(returncode=0, stdout=json.dumps(good).encode())
            self.assertEqual(health.management_status('/etc/private.toml'), good)
            self.assertEqual(run.call_args.kwargs['timeout'], 8)
            for changes in ({'backend': 'sqlite'}, {'checked_at': 0}, {'workers': True}, {'stale_workers': 2}):
                run.return_value.stdout = json.dumps({**good, **changes}).encode()
                with self.assertRaises(ValueError):
                    health.management_status('/etc/private.toml')
            run.return_value = Mock(returncode=1, stdout=b'', stderr=b'private connection data')
            with self.assertRaisesRegex(ValueError, '^selected management health unavailable; no SQLite fallback$'):
                health.management_status('/etc/private.toml')

    def test_queue_excludes_history_mirrors_and_uses_quarantine_release_age(self):
        with sqlite3.connect(':memory:') as db:
            db.executescript("CREATE TABLE messages(id,created,is_dsn);"
                             "CREATE TABLE deliveries(id,message_id,status);"
                             "CREATE TABLE cluster_origin(message_id);"
                             "CREATE TABLE delivery_policy(delivery_id,released_at);"
                             "INSERT INTO messages VALUES('mirror',1,1),('local',990,1),('released',1,0);"
                             "INSERT INTO deliveries VALUES(1,'mirror','pending'),(2,'local','pending'),(3,'released','sending');"
                             "INSERT INTO cluster_origin VALUES('mirror');"
                             "INSERT INTO delivery_policy VALUES(3,995);")
            self.assertEqual(health.queue_status(db, 1000), {
                'dsn': {'pending': 1, 'oldest_age_seconds': 10},
                'mail': {'pending': 1, 'oldest_age_seconds': 5}})

    def test_llm_suspension_requires_explicit_operator_intent_and_keeps_other_alerts(self):
        cfg = {'pricing_checked_at': 0, 'monthly_budget_micro_eur': 20_000_000}
        now = 31 * 86400
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            with self.assertRaisesRegex(ValueError, 'pricing'):
                health.llm_status(cfg, root, now)
            self.assertEqual(health.llm_status(cfg, root, now, True),
                             {'status': 'suspended', 'reason': 'pricing_expired', 'expected': True})
            self.assertEqual(list(root.iterdir()), [])
            with self.assertRaisesRegex(ValueError, 'pricing'):
                health.llm_status(cfg, root, 29 * 86400, True)
            cfg['pricing_checked_at'] = now
            with sqlite3.connect(root / 'llm-budget.sqlite3') as db:
                db.executescript("CREATE TABLE llm_months(month,accounted,requests);"
                                 "INSERT INTO llm_months VALUES(strftime('%Y-%m','now'),19000000,99);")
            with self.assertRaisesRegex(ValueError, '90 percent'):
                health.llm_status(cfg, root, now, True)

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
