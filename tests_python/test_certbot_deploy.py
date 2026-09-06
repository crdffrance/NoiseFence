import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    'certbot_deploy', Path(__file__).resolve().parents[1] / 'deploy/certbot-deploy.py')
hook = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hook)


class CertificateDeploymentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixtures = tempfile.TemporaryDirectory()
        cls.root = Path(cls.fixtures.name)
        for name in ('first', 'second'):
            directory = cls.root / name
            directory.mkdir()
            subprocess.run([
                'openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2',
                '-subj', '/CN=mx.example.test', '-addext', 'subjectAltName=DNS:mx.example.test',
                '-keyout', str(directory / 'privkey.pem'),
                '-out', str(directory / 'fullchain.pem'),
            ], check=True, capture_output=True)
        trust = cls.root / 'trust.pem'
        trust.write_bytes(b''.join((cls.root / name / 'fullchain.pem').read_bytes()
                                  for name in ('first', 'second')))
        cls.trust = patch.dict(os.environ, {'SSL_CERT_FILE': str(trust)})
        cls.trust.start()

    @classmethod
    def tearDownClass(cls):
        cls.trust.stop()
        cls.fixtures.cleanup()

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name) / 'tls'
        self.addCleanup(self.temporary.cleanup)

    def install(self, name='first', hostname='mx.example.test', restart=lambda: None):
        hook.deploy(self.root / name, hostname, self.base, os.getuid(), os.getgid(), restart)

    def test_deploy_and_repeat_preserve_private_permissions(self):
        calls = []
        self.install(restart=lambda: calls.append(True))
        target = os.readlink(self.base / 'current')
        self.install(restart=lambda: calls.append(True))
        self.assertEqual(target, os.readlink(self.base / 'current'))
        self.assertEqual(len(calls), 2)
        self.assertEqual((self.base / 'current/key.pem').stat().st_mode & 0o777, 0o640)
        self.assertEqual(self.base.stat().st_mode & 0o777, 0o750)
        self.assertFalse(list((self.base / 'versions').glob('.pending-*')))

    def test_wrong_hostname_keeps_previous_certificate(self):
        self.install()
        previous = os.readlink(self.base / 'current')
        with self.assertRaises(subprocess.CalledProcessError):
            self.install('second', 'wrong.example.test')
        self.assertEqual(previous, os.readlink(self.base / 'current'))

    def test_mismatched_key_keeps_previous_certificate(self):
        self.install()
        previous = os.readlink(self.base / 'current')
        mixed = Path(self.temporary.name) / 'mixed'
        mixed.mkdir()
        (mixed / 'fullchain.pem').write_bytes((self.root / 'first/fullchain.pem').read_bytes())
        (mixed / 'privkey.pem').write_bytes((self.root / 'second/privkey.pem').read_bytes())
        with self.assertRaisesRegex(ValueError, 'do not match'):
            hook.deploy(mixed, 'mx.example.test', self.base, os.getuid(), os.getgid(), lambda: None)
        self.assertEqual(previous, os.readlink(self.base / 'current'))

    def test_restart_failure_rolls_back_before_retry(self):
        self.install()
        previous = os.readlink(self.base / 'current')
        observed = []

        def restart():
            observed.append(os.readlink(self.base / 'current'))
            if len(observed) == 1:
                raise RuntimeError('simulated restart failure')

        with self.assertRaisesRegex(RuntimeError, 'simulated restart failure'):
            self.install('second', restart=restart)
        self.assertNotEqual(observed[0], previous)
        self.assertEqual(observed[1], previous)
        self.assertEqual(os.readlink(self.base / 'current'), previous)


if __name__ == '__main__':
    unittest.main()
