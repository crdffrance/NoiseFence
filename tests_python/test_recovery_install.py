"""Recovery installer contract tests; systemd and root ownership use local substitutes."""
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import stat
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'deploy/postgresql'))
import recovery_install as install
from migration_protocol import atomic, canonical
from test_management_migration import selection


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory())).resolve()
        self.account = pwd.getpwuid(os.getuid())
        self.data = self.root / 'data'
        self.data.mkdir(mode=0o700)
        (self.data / 'calibration').mkdir(mode=0o700)
        for path in [self.data / 'daemon.lock', self.data / 'calibration/worker.lock']:
            atomic(path, b'')
        self.worker = self.root / 'config.toml'
        self.key = self.root / 'worker.key'
        atomic(self.key, b'1'*64)
        self.original = (f'data_dir="{self.data}"\n[management]\nbackend="coordinator"\n'
                         f'[cluster]\nrole="worker"\nnode_id="mx2"\ncredential_file="{self.key}"\n'
                         'coordinator_url = "https://old.example.test"\n').encode()
        atomic(self.worker, self.original)
        self.selected = selection()
        self.selected['role'] = 'worker'
        self.selected['node']['node'] = 'mx2'
        self.selected['mfa_key_sha256'] = None
        self.op = '00000000-0000-4000-8000-000000000003'
        self.bundle = self.root / 'keys.json'
        self.keys = {'protocol':'noisefence-recovery-worker-credentials-1', 'operation':self.op,
                     'database':self.selected['database'], 'workers':{'mx2':{'epoch':self.selected['node']['epoch'], 'token':'2'*64}}}
        atomic(self.bundle, canonical(self.keys))
        self.auth = self.root / 'authorization.json'
        self.plan = {'protocol':'noisefence-recovery-install-1', 'operation':self.op, 'selection':self.selected,
                     'config':str(self.worker), 'config_sha256':hashlib.sha256(self.original).hexdigest(),
                     'bundle_sha256':hashlib.sha256(self.bundle.read_bytes()).hexdigest(),
                     'coordinator_url':'https://new.example.test', 'user':self.account.pw_name,
                     'expires_at':int(time.time())+600}
        self.write_plan()
        self.state = self.root / 'state'
        self.units = self.root / 'units'
        self.units.mkdir(mode=0o700)
        self.commands = []
        self.stack.enter_context(patch.object(install, 'STATE', self.state))
        self.stack.enter_context(patch.object(install, 'UNITS', self.units))
        self.stack.enter_context(patch.object(install, 'protected', self.protected_fixture))
        self.stack.enter_context(patch.object(install, 'read_selection', return_value=self.selected))
        self.stack.enter_context(patch.object(install, 'unit_state', return_value='inactive'))
        self.stack.enter_context(patch.object(install, 'execute', self.execute))

    def write_plan(self):
        atomic(self.auth, canonical(self.plan))

    def protected_fixture(self, path, directory=False):
        path = Path(path)
        install.require(path.resolve() == path and self.root in (path, *path.parents), 'fixture physical path')
        info = path.lstat()
        install.require(not info.st_mode & 0o022 and (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)), 'fixture protected file')
        return info

    def execute(self, arguments, **kwargs):
        self.commands.append(arguments)
        if 'show' in arguments:
            return (f'User={self.account.pw_name}\nExecStart={{ path=/opt/noisefence/noisefence ; argv[]=/opt/noisefence/noisefence --config {self.worker} serve ; ignore_errors=no ; }}\n').encode()
        return b''

    def run_install(self):
        return install.install(self.auth, self.bundle)

    def test_installs_only_configured_key_and_origin_idempotently_without_starting(self):
        first = self.run_install()
        self.assertEqual(first, self.run_install())
        self.assertEqual(self.key.read_bytes(), b'2'*64)
        self.assertEqual(self.worker.read_bytes(), install.rewrite(self.original, self.plan['coordinator_url']))
        self.assertTrue((self.state / 'hold.json').exists())
        self.assertTrue(first['native_verification_required'])
        self.assertFalse(first['queue_replaced'])
        self.assertFalse(first['services_started'])
        self.assertNotIn('2'*64, json.dumps(first))
        self.assertTrue(all('start' not in command and 'restart' not in command for command in self.commands))
        self.assertEqual(stat.S_IMODE(self.key.stat().st_mode), 0o600)
        for service in install.SERVICES:
            self.assertIn(str(self.state / 'hold.json'), (self.units / (service+'.d') / install.DROPIN).read_text())
        for name in install.RECOVERED_JOBS:
            for suffix in ('.timer', '.service'):
                self.assertIn(['/usr/bin/systemctl', 'stop', name+suffix], self.commands)

    def test_bundle_hash_and_authority_are_both_required(self):
        self.keys['operation'] = '00000000-0000-4000-8000-000000000004'
        atomic(self.bundle, canonical(self.keys))
        with self.assertRaisesRegex(ValueError, 'checksum'):
            self.run_install()
        self.plan['bundle_sha256'] = hashlib.sha256(self.bundle.read_bytes()).hexdigest()
        self.write_plan()
        with self.assertRaisesRegex(ValueError, 'another recovery'):
            self.run_install()
        self.assertEqual(self.key.read_bytes(), b'1'*64)
        self.assertEqual(self.worker.read_bytes(), self.original)

    def test_actual_selected_queue_must_match_after_fencing(self):
        with patch.object(install, 'read_selection', return_value=None):
            with self.assertRaisesRegex(ValueError, 'Actual worker queue'):
                self.run_install()
        self.assertTrue((self.state / 'hold.json').exists())
        self.assertEqual(self.key.read_bytes(), b'1'*64)

    def test_retry_after_key_install_and_configuration_failure(self):
        def failing(path, raw, **kwargs):
            if path == self.worker:
                raise OSError('simulated configuration publication failure')
            return atomic(path, raw, **kwargs)
        with patch.object(install, 'atomic', failing):
            with self.assertRaises(OSError):
                self.run_install()
        self.assertEqual(self.key.read_bytes(), b'2'*64)
        self.assertEqual(self.worker.read_bytes(), self.original)
        self.assertTrue((self.state / 'hold.json').exists())
        self.assertEqual(self.run_install()['status'], 'installed_services_fenced')

    def test_running_source_lock_refuses_install_and_preserves_fence(self):
        with (self.data / 'daemon.lock').open('r+b') as held:
            fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(BlockingIOError):
                self.run_install()
        self.assertEqual(self.key.read_bytes(), b'1'*64)
        self.assertTrue((self.state / 'hold.json').exists())

    def test_symlink_key_cannot_redirect_privileged_write(self):
        target = self.root / 'other'
        atomic(target, b'keep')
        self.key.unlink()
        self.key.symlink_to(target)
        with self.assertRaisesRegex(ValueError, 'credential destination'):
            self.run_install()
        self.assertEqual(target.read_bytes(), b'keep')

    def test_systemd_must_use_this_exact_configuration(self):
        def wrong(arguments, **kwargs):
            return self.execute(arguments).replace(str(self.worker).encode(), b'/etc/other.toml')
        with patch.object(install, 'execute', wrong):
            with self.assertRaisesRegex(ValueError, 'another configuration'):
                self.run_install()
        self.assertEqual(self.key.read_bytes(), b'1'*64)

    def test_retry_cannot_change_authorization_or_overwrite_unexpected_config(self):
        self.run_install()
        self.plan['coordinator_url'] = 'https://unapproved.example.test'
        self.write_plan()
        with self.assertRaisesRegex(ValueError, 'authorization changed'):
            self.run_install()

    def test_expired_authorization_fails_before_mutation(self):
        self.plan['expires_at'] = int(time.time())-1
        self.write_plan()
        with self.assertRaisesRegex(ValueError, 'expired'):
            self.run_install()
        self.assertFalse(self.state.exists())

    def test_plaintext_or_url_credentials_are_refused(self):
        for url in ['http://mx.example.test', 'https://a:b@mx.example.test', 'https://mx.example.test/path', 'https://mx.example.test/?x=1']:
            with self.subTest(url=url), self.assertRaises(ValueError):
                install.origin(url)


if __name__ == '__main__':
    unittest.main()
