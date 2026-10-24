"""Backup verification uses a complete, bound node set; all producers are synthetic."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('hardening_central', ROOT/'deploy/hardening/central.py')
central = importlib.util.module_from_spec(spec); spec.loader.exec_module(central)


class CentralVerificationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.patch = patch.object(central, 'ROOT', self.root)
        self.patch.start(); self.addCleanup(self.patch.stop)
        self.config = {'nodes': {'mx1': {}, 'mx2': {}}, 'backup_mode': 'metadata',
                       'repository': '/synthetic/repository', 'password_file': '/synthetic/password'}
        self.status = {'time': int(time.time()) - 100, 'status': 'complete', 'snapshots': [
            {'node': 'mx1', 'snapshot_id': 'a'*64, 'mode': 'metadata'},
            {'node': 'mx2', 'snapshot_id': 'b'*64, 'mode': 'metadata'}]}
        self.result = {'status': 'verified', 'mode': 'metadata', 'files': 2,
                       'databases': ['data/state.sqlite3'], 'postgresql_restore_required': False,
                       'network_used': False, 'services_started': False}
        self.status_path = self.root/'backup-status.json'
        self.status_path.write_text(json.dumps(self.status))
        self.restore_path = self.root/'restore-status.json'
        self.restore_path.write_text('{"previous":"result"}')

    def test_empty_missing_duplicate_unknown_or_mismatched_snapshot_sets_refuse_before_restore(self):
        cases = []
        for rows in [[], self.status['snapshots'][:1], self.status['snapshots'][:1]*2,
                     [None, None], self.status['snapshots'] + [self.status['snapshots'][0]]]:
            cases.append({**self.status, 'snapshots': rows})
        for field, value in [('node', 'unknown'), ('snapshot_id', '../private'), ('mode', 'full')]:
            changed = copy.deepcopy(self.status)
            changed['snapshots'][0][field] = value; cases.append(changed)
        cases.extend([{**self.status, 'status': 'failed'}, {**self.status, 'time': True},
                      {**self.status, 'time': int(time.time()) + 900}])
        with patch.object(central.subprocess, 'run') as run, patch.object(central, 'execute') as execute:
            for status in cases:
                self.status_path.write_text(json.dumps(status))
                with self.subTest(status=status), self.assertRaises(ValueError):
                    central.verify(self.config)
                self.assertEqual(json.loads(self.restore_path.read_text()), {'previous': 'result'})
            run.assert_not_called(); execute.assert_not_called()
        with self.assertRaises(ValueError):
            central.verified_snapshot_set({**self.status, 'snapshots': []}, {**self.config, 'nodes': {}})

    def test_archive_result_requires_real_checks_and_preserves_prior_status_on_partial_failure(self):
        for field, value in [('status', 'unknown'), ('postgresql_restore_required', 0),
                             ('postgresql_restore_required', True), ('mode', 'full'),
                             ('network_used', True), ('services_started', True),
                             ('files', 0), ('files', True), ('databases', [])]:
            changed = {**self.result, field: value}
            with self.subTest(field=field, value=value), patch.object(central.subprocess, 'run'), \
                 patch.object(central, 'execute', side_effect=[json.dumps(self.result), json.dumps(changed)]), \
                 self.assertRaises(ValueError):
                central.verify(self.config)
            self.assertEqual(json.loads(self.restore_path.read_text()), {'previous': 'result'})
            self.assertEqual(list(self.root.glob('restore-test-*')), [])

    def test_verified_set_keeps_metadata_scope_snapshot_identity_and_backup_age(self):
        with patch.object(central.subprocess, 'run') as run, \
             patch.object(central, 'execute', return_value=json.dumps(self.result)) as execute:
            central.verify(self.config)
        self.assertEqual(run.call_count, 2)
        self.assertEqual(execute.call_count, 2)
        for call in execute.call_args_list:
            self.assertEqual(call.args[0][:3], ['/usr/bin/unshare', '--net', '--'])
        result = json.loads(self.restore_path.read_text())
        self.assertEqual(result['restoration'], 'verified')
        self.assertEqual(result['backup_time'], self.status['time'])
        self.assertEqual(result['recovery_scope'], 'metadata_only_not_a_queue_restore')
        self.assertEqual({r['snapshot_id'] for r in result['results']}, {'a'*64, 'b'*64})
        self.assertEqual(self.restore_path.stat().st_mode & 0o777, 0o600)

    def test_postgres_archive_never_becomes_a_completed_database_restore(self):
        pg = {**self.result, 'postgresql_restore_required': True, 'status': 'requires_postgresql_restore'}
        with patch.object(central.subprocess, 'run'), \
             patch.object(central, 'execute', side_effect=[json.dumps(pg), json.dumps(self.result)]):
            central.verify(self.config)
        result = json.loads(self.restore_path.read_text())
        self.assertEqual(result['restoration'], 'requires_postgresql_restore')
        self.assertTrue(result['results'][0]['postgresql_restore_required'])

    def test_failed_dump_or_archive_check_never_replaces_success_receipt(self):
        with patch.object(central.subprocess, 'run', side_effect=subprocess.CalledProcessError(1, 'synthetic')), \
             patch.object(central, 'execute') as execute, self.assertRaises(subprocess.CalledProcessError):
            central.verify(self.config)
        execute.assert_not_called()
        self.assertEqual(json.loads(self.restore_path.read_text()), {'previous': 'result'})
        self.assertEqual(list(self.root.glob('restore-test-*')), [])
        with patch.object(central.subprocess, 'run'), \
             patch.object(central, 'execute', side_effect=RuntimeError('Synthetic failure')), \
             self.assertRaises(RuntimeError):
            central.verify(self.config)
        self.assertEqual(json.loads(self.restore_path.read_text()), {'previous': 'result'})

    def test_backup_rejects_invalid_sources_before_tools_and_bad_receipts_before_pruning(self):
        for change in [{'nodes': {}}, {'nodes': {'mx1': None}}, {'retention_days': True}]:
            with patch.object(central, 'restic') as restic, self.assertRaises(ValueError):
                central.backup({**self.config, **change})
            restic.assert_not_called()
        responses = [json.dumps({'message_type': 'summary', 'snapshot_id': 'a'*64}),
                     json.dumps({'message_type': 'summary', 'snapshot_id': 'invalid'})]
        with patch.object(central, 'restic', side_effect=responses) as restic, self.assertRaises(ValueError):
            central.backup(self.config)
        self.assertEqual([call.args[1] for call in restic.call_args_list], ['backup', 'backup'])
        self.assertEqual(json.loads(self.status_path.read_text()), self.status)

    def test_atomic_status_failure_keeps_existing_report_and_cleans_temporary(self):
        with patch.object(central.os, 'replace', side_effect=OSError('synthetic disk error')), self.assertRaises(OSError):
            central.write_status('restore-status.json', {'new': True})
        self.assertEqual(json.loads(self.restore_path.read_text()), {'previous': 'result'})
        self.assertEqual(list(self.root.glob('.backup-status-*')), [])


if __name__ == '__main__':
    unittest.main()
