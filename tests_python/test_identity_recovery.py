"""Synthetic installation keys only; never read a gateway or contact a provider."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import io
import shutil
import tarfile
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]

def load(name):
    spec = importlib.util.spec_from_file_location('test_' + name, ROOT / 'deploy/hardening' / name)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

identity = load('identity_recovery.py')
snapshot = load('snapshot.py')
restore = load('restore-check.py')


class IdentityRecoveryTests(unittest.TestCase):
    def fixture(self, root):
        data = root / 'data'
        data.mkdir(mode=0o700)
        ids = {}
        for directory, key in [('directory-vault', b'v'*32), ('contact-memory', b'm'*32)]:
            folder = data / directory
            folder.mkdir(mode=0o700)
            (folder / 'key').write_bytes(key)
            (folder / 'key').chmod(0o600)
            ids[directory] = hashlib.sha256(key).hexdigest()
        marker = data / 'contact-memory/key-id'
        marker.write_text(ids['contact-memory'])
        marker.chmod(0o600)
        config = {'contact_learning': {'enabled': True, 'key_id': ids['contact-memory']}}
        with sqlite3.connect(data / 'state.sqlite3') as db:
            db.execute('CREATE TABLE identity_connections(record TEXT)')
            db.execute('INSERT INTO identity_connections VALUES(?)', (json.dumps({'metadata': {'key_id': ids['directory-vault']}, 'revoked_at': 1234}),))
        (root / 'config').mkdir()
        (root / 'config/config.toml').write_text('[contact_learning]\nenabled=true\nkey_id="' + ids['contact-memory'] + '"\n')
        return data, config, ids

    def archive(self, root, path, receipt):
        (root / 'manifest.json').unlink(missing_ok=True)
        manifest = snapshot.manifest(root, 'metadata')
        manifest['identity_recovery'] = receipt
        (root / 'manifest.json').write_text(json.dumps(manifest))
        with tarfile.open(path, 'w') as output:
            for file in root.iterdir():
                output.add(file, arcname=file.name)

    def test_private_archive_recovers_exact_keys_and_requires_revoked_record_key(self):
        # The archive transport is protected by the existing restic pipeline;
        # this fixture checks its plaintext inner archive entirely offline.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'source'; root.mkdir()
            data, config, ids = self.fixture(root)
            receipt = identity.inspect(data, config, private=True)
            self.assertEqual(receipt['keys'], ids)
            archive = Path(tmp) / 'snapshot.tar'
            self.archive(root, archive, receipt)
            result = restore.verify(archive)
            self.assertEqual(result['status'], 'verified')
            self.assertFalse(result['network_used'])
            self.assertFalse(result['services_started'])
            (data / 'directory-vault/key').unlink()
            self.archive(root, archive, receipt)
            with self.assertRaisesRegex(ValueError, 'recovery key missing'):
                restore.verify(archive)
            (data / 'directory-vault/key').write_bytes(b'x'*32)
            self.archive(root, archive, receipt)
            with self.assertRaisesRegex(ValueError, 'vault recovery key'):
                restore.verify(archive)

    def test_memory_key_marker_policy_and_receipt_must_agree(self):
        with tempfile.TemporaryDirectory() as tmp:
            data, config, _ = self.fixture(Path(tmp))
            receipt = identity.inspect(data, config)
            key = data / 'contact-memory/key'
            key.write_bytes(b'x'*32)
            with self.assertRaisesRegex(ValueError, 'memory recovery key mismatch'):
                identity.inspect(data, config)
            (data / 'contact-memory/key-id').write_text(hashlib.sha256(b'x'*32).hexdigest())
            with self.assertRaisesRegex(ValueError, 'Installed contact memory'):
                identity.inspect(data, config)
            with self.assertRaisesRegex(ValueError, 'receipt mismatch'):
                identity.inspect(data, {}, expected=receipt)
            config['contact_learning']['enabled'] = False
            with self.assertRaisesRegex(ValueError, 'Installed contact memory'):
                identity.inspect(data, config)
            key.unlink()
            with self.assertRaisesRegex(ValueError, 'recovery key missing'):
                identity.inspect(data, {})

    def test_selected_central_does_not_read_shadow_and_cannot_claim_database_restore(self):
        with tempfile.TemporaryDirectory() as tmp:
            data, config, ids = self.fixture(Path(tmp))
            with sqlite3.connect(data / 'state.sqlite3') as db:
                db.execute('UPDATE identity_connections SET record=?', (json.dumps({'metadata': {'key_id': 'e'*64}}),))
            config['management'] = {'backend': 'postgresql'}
            receipt = identity.inspect(data, config, [ids['directory-vault']])
            # Offline verification checks the recorded key binding, not PG SQL.
            identity.inspect(data, config, expected=receipt)
            (data / 'directory-vault/key').write_bytes(b'z'*32)
            with self.assertRaisesRegex(ValueError, 'receipt mismatch'):
                identity.inspect(data, config, expected=receipt)

    def test_current_policy_overrides_bootstrap_and_reads_local_revision(self):
        with tempfile.TemporaryDirectory() as tmp:
            data, config, ids = self.fixture(Path(tmp))
            with sqlite3.connect(data / 'state.sqlite3') as db:
                db.execute('CREATE TABLE cluster_state(key TEXT,value TEXT)')
                db.execute('CREATE TABLE console_revisions(id INTEGER,settings TEXT)')
                db.execute('INSERT INTO console_revisions VALUES(1,?)', (json.dumps(config),))
            identity.inspect(data, {})
            with sqlite3.connect(data / 'state.sqlite3') as db:
                settings = {'contact_learning': {'enabled': True, 'key_id': 'f'*64}}
                db.execute('INSERT INTO cluster_state VALUES(?,?)', ('activation_participant', json.dumps({'installed': {'settings': settings}})))
            with self.assertRaisesRegex(ValueError, 'Installed contact memory'):
                identity.inspect(data, config)

    def test_key_paths_and_catalogs_refuse_links_permissions_and_partial_writes(self):
        with tempfile.TemporaryDirectory() as tmp:
            data, _, _ = self.fixture(Path(tmp))
            self.assertEqual(len(identity.files(data)), 3)
            key = data / 'directory-vault/key'
            key.chmod(0o644)
            with self.assertRaisesRegex(ValueError, 'Unsafe'):
                identity.files(data)
            key.chmod(0o600)
            other = data / 'duplicate'; os.link(key, other)
            with self.assertRaisesRegex(ValueError, 'Unsafe'):
                identity.files(data)
            other.unlink()
            original = key.read_bytes(); key.unlink(); key.symlink_to('/dev/zero')
            with self.assertRaises(OSError):
                identity.files(data)
            key.unlink(); key.write_bytes(original); key.chmod(0o600)
            prepared = data / 'identity/prepared'; prepared.mkdir(mode=0o700, parents=True)
            prepared.parent.chmod(0o700)
            content = b'{"synthetic":true}'
            catalog = prepared / (hashlib.sha256(content).hexdigest() + '.json')
            catalog.write_bytes(content); catalog.chmod(0o600)
            self.assertEqual(len(identity.files(data)), 4)
            catalog.write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError, 'catalog mismatch'):
                identity.files(data)
            catalog.unlink(); (prepared / '.prepare-interrupted').write_bytes(content)
            with self.assertRaisesRegex(ValueError, 'Unstable'):
                identity.files(data)

    def test_full_backup_preserves_keys_catalog_and_restarts_service_before_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / 'source'; source.mkdir()
            data, _, ids = self.fixture(source)
            prepared = data / 'identity/prepared'; prepared.mkdir(mode=0o700, parents=True)
            prepared.parent.chmod(0o700)
            content = b'{"synthetic":true}'
            catalog = prepared / (hashlib.sha256(content).hexdigest() + '.json')
            catalog.write_bytes(content); catalog.chmod(0o600)
            backup = root / 'backup'; backup.mkdir()
            output = io.BytesIO(); calls = []
            def command(*args, **kwargs):
                calls.append(args)
                if args[0] == 'cp':
                    src, dest = Path(args[-2]), Path(args[-1])
                    if src.is_dir():
                        shutil.copytree(src, dest)
                    else:
                        shutil.copy2(src, dest)
                if args[:3] == ('systemctl', 'is-active', '--quiet'):
                    return types.SimpleNamespace(returncode=0 if args[3] == 'noisefence' else 3, stdout='')
                return types.SimpleNamespace(returncode=0, stdout='inactive')
            with patch.object(snapshot, 'DATA', data), patch.object(snapshot, 'CONFIG', source / 'config'), \
                 patch.object(snapshot, 'ROOT', backup), patch.object(snapshot, 'run', side_effect=command), \
                 patch.object(snapshot.sys, 'stdout', types.SimpleNamespace(buffer=output)):
                old_umask = os.umask(0o077)
                try:
                    snapshot.export('full')
                finally:
                    os.umask(old_umask)
            self.assertIn(('systemctl', 'stop', 'noisefence'), calls)
            self.assertIn(('systemctl', 'start', 'noisefence'), calls)
            archive = root / 'snapshot.tar'; archive.write_bytes(output.getvalue())
            self.assertEqual(restore.verify(archive)['status'], 'verified')
            with tarfile.open(archive) as tar:
                manifest = json.load(tar.extractfile('manifest.json'))
                self.assertEqual(manifest['identity_recovery']['keys'], ids)
                self.assertIn('data/identity/prepared/' + catalog.name, tar.getnames())

    def test_postgres_only_requests_public_bounded_ids_and_retains_tombstones(self):
        key = 'a'*64
        runner = Mock(side_effect=[types.SimpleNamespace(stdout='t\n'), types.SimpleNamespace(stdout=json.dumps([key]))])
        tools = types.SimpleNamespace(run=runner, postgres_command=lambda target, tool: [tool])
        self.assertEqual(identity.postgres_keys(tools, {}), [key])
        query = runner.call_args.args[-1]
        self.assertIn("record#>>'{metadata,key_id}'", query)
        self.assertNotIn('revoked_at', query)
        self.assertIn('LIMIT 17', query)
        runner.side_effect = [types.SimpleNamespace(stdout='f\n')]
        self.assertEqual(identity.postgres_keys(tools, {}), [])
        runner.side_effect = [types.SimpleNamespace(stdout='t'), types.SimpleNamespace(stdout='[null]')]
        with self.assertRaisesRegex(ValueError, 'Invalid identity'):
            identity.postgres_keys(tools, {})
