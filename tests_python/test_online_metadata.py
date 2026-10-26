import importlib.util
import hashlib
import io
import json
from pathlib import Path
import sqlite3
import tarfile
import tempfile
import types
import unittest
from unittest.mock import patch
from tests_python import test_ha_standby

ROOT = Path(__file__).resolve().parents[1]
def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
online = load('online_metadata_test', 'deploy/hardening/online_metadata.py')
snapshot = load('metadata_snapshot_test', 'deploy/hardening/snapshot.py')


class OnlineMetadataTests(unittest.TestCase):
    def fixture(self, root, worker=False):
        source, manifest = test_ha_standby.StandbyTests().selected_fixture(root)
        if worker:
            path = source / 'data/state.sqlite3'
            with sqlite3.connect(path) as db:
                state = dict(db.execute('SELECT key,value FROM cluster_state'))
                selection = json.loads(state['management_selection'])
                local = json.loads(state['activation_participant'])
                selection.update(role='worker', mfa_key_sha256=None)
                selection['node']['node'] = 'mx2'
                local['node'] = 'mx2'
                local['authority']['rollout']['participants'] = {'mx1': 'applied', 'mx2': 'applied'}
                for key, value in [('management_selection', selection), ('activation_participant', local)]:
                    db.execute('UPDATE cluster_state SET value=? WHERE key=?', (json.dumps(value), key))
            (source / 'config/config.toml').write_text('[cluster]\nrole="worker"\nnode_id="mx2"\n[management]\nbackend="coordinator"\n')
        for directory, key in [('directory-vault', b'v'*32), ('contact-memory', b'm'*32)]:
            folder = source / 'data' / directory
            folder.mkdir(mode=0o700)
            (folder / 'key').write_bytes(key)
            (folder / 'key').chmod(0o600)
            if directory == 'contact-memory':
                (folder / 'key-id').write_text(hashlib.sha256(key).hexdigest())
                (folder / 'key-id').chmod(0o600)
        for name in ['spool', 'incoming', 'replicas', 'research-archive']:
            folder = source / 'data' / name
            folder.mkdir()
            (folder / 'never-export.eml').write_bytes(b'private body')
        return source, manifest

    def run_export(self, root, worker=False, change=False, symlink=False, key_change=False):
        source, manifest = self.fixture(root, worker)
        cfg = source / 'config'
        if symlink:
            (cfg / 'redirected-file').symlink_to(source / 'data/spool/never-export.eml')
        tools = online.checkpoint_tools()
        identity = snapshot.identity_tools()
        backup = types.SimpleNamespace(identity_tools=lambda: identity, DATA=source / 'data', ROOT=root,
            verify_management_selection=snapshot.verify_management_selection,
            manifest=snapshot.manifest, postgres_target=lambda _: None if worker else {},
            postgres_bytes=lambda _: 10,
            dump_postgres=lambda target,path,timeout:path.write_bytes(b'PGDMPsynthetic'))
        output = io.BytesIO()
        calls = []
        def sqlite_backup(args, **kwargs):
            calls.append(args)
            self.assertEqual(args[1], 'ha-snapshot')
            with sqlite3.connect(args[2]) as a, sqlite3.connect(args[3]) as b:
                a.backup(b)
            if change:
                with sqlite3.connect(source / 'data/state.sqlite3') as db:
                    local = json.loads(db.execute("SELECT value FROM cluster_state WHERE key='activation_participant'").fetchone()[0])
                    local['authority']['sequence'] += 1
                    db.execute("UPDATE cluster_state SET value=? WHERE key='activation_participant'", (json.dumps(local),))
        with patch.object(identity, 'postgres_keys', side_effect=[[hashlib.sha256(b'v'*32).hexdigest()], ['f'*64] if key_change else [hashlib.sha256(b'v'*32).hexdigest()]]), \
             patch.object(online, 'checkpoint_tools', return_value=tools), \
             patch.object(tools, 'postgres_state', return_value=manifest['management']), \
             patch.object(online.subprocess, 'run', side_effect=sqlite_backup), \
             patch('sys.stdout', types.SimpleNamespace(buffer=output)):
            if change or symlink or key_change:
                with self.assertRaisesRegex(ValueError, 'symlink refused' if symlink else 'Directory keys changed' if key_change else 'Policy changed'):
                    online.export(backup, cfg)
                self.assertEqual(output.getvalue(), b'')
                return
            online.export(backup, cfg)
        self.assertTrue(calls)
        output.seek(0)
        with tarfile.open(fileobj=output) as archive:
            names = archive.getnames()
            self.assertFalse(any('never-export.eml' in n for n in names))
            self.assertEqual('data/management.postgresql.dump' in names, not worker)
            m = json.load(archive.extractfile('manifest.json'))
            for name in identity.KEY_FILES:
                self.assertIn('data/' + name, names)
            self.assertEqual(m['identity_recovery']['keys']['contact-memory'], hashlib.sha256(b'm'*32).hexdigest())
            self.assertTrue(m['online'])
            self.assertEqual(m['pause_and_copy_seconds'], 0)
            self.assertEqual(m['mode'], 'metadata')
            self.assertEqual(m['recovery_scope'], 'metadata_only_not_a_queue_restore')

    def test_live_coordinator_and_worker_export_without_any_service_operation(self):
        for worker in [False, True]:
            with self.subTest(worker=worker), tempfile.TemporaryDirectory() as tmp:
                self.run_export(Path(tmp), worker)

    def test_policy_change_refuses_the_archive_before_streaming(self):
        for worker in [False, True]:
            with self.subTest(worker=worker), tempfile.TemporaryDirectory() as tmp:
                self.run_export(Path(tmp), worker, change=True)

    def test_preparing_worker_policy_fails_closed(self):
        import tomllib
        with tempfile.TemporaryDirectory() as tmp:
            source, _ = self.fixture(Path(tmp), worker=True)
            cfg = tomllib.loads((source / 'config/config.toml').read_text())
            db_path = source / 'data/state.sqlite3'
            with sqlite3.connect(db_path) as db:
                local = json.loads(db.execute("SELECT value FROM cluster_state WHERE key='activation_participant'").fetchone()[0])
                local['authority']['rollout']['phase'] = 'preparing'
                db.execute("UPDATE cluster_state SET value=? WHERE key='activation_participant'", (json.dumps(local),))
            with self.assertRaisesRegex(ValueError, 'stable installed policy'):
                online.authority(db_path, cfg)

    def test_redirected_configuration_cannot_include_private_bodies(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.run_export(Path(tmp), symlink=True)

    def test_vault_key_binding_change_refuses_output_before_streaming(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.run_export(Path(tmp), key_change=True)
