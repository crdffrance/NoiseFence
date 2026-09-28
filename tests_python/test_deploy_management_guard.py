"""Simple release-pointer changes must not bypass selected management authority."""
import importlib.util
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('deploy_management_guard', ROOT/'deploy/hardening/deploy-control.py')
deploy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(deploy)


class ManagementDeploymentGuard(unittest.TestCase):
    def test_refuses_before_commands_or_release_pointer_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = root/'config.toml'
            database = root/'state.sqlite3'
            config.write_text('[management]\nbackend="postgresql"\n')
            with patch.object(deploy, 'CONFIG', config), patch.object(deploy, 'release', return_value=(root, {'storage_schema': 99})), patch.object(deploy, 'run') as run, patch.object(deploy.os, 'replace') as replace:
                with self.assertRaisesRegex(ValueError, 'coordinated'):
                    deploy.activate('0.29.0')
                run.assert_not_called()
                replace.assert_not_called()
            config.write_text('hostname="mx.example.test"\n')
            with sqlite3.connect(database) as db:
                db.execute('PRAGMA user_version=7')
            with self.assertRaisesRegex(ValueError, 'coordinated'):
                deploy.local_activation_allowed(config, database)
            with sqlite3.connect(database) as db:
                db.execute('PRAGMA user_version=6')
                db.execute('CREATE TABLE cluster_state(key TEXT PRIMARY KEY,value TEXT)')
            self.assertEqual(deploy.local_activation_allowed(config, database), 6)
            for marker in ('management_transport', 'runtime_history_protocol'):
                with sqlite3.connect(database) as db:
                    db.execute('DELETE FROM cluster_state')
                    db.execute('INSERT INTO cluster_state VALUES(?,?)', (marker, 'present'))
                with self.assertRaisesRegex(ValueError, 'coordinated'):
                    deploy.local_activation_allowed(config, database)
            with sqlite3.connect(database) as db:
                self.assertEqual(db.execute('PRAGMA user_version').fetchone()[0], 6)
