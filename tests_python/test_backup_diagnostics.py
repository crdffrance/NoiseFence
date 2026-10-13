import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('nf_central_diagnostics', Path(__file__).resolve().parents[1] / 'deploy/hardening/central.py')
central = importlib.util.module_from_spec(spec)
spec.loader.exec_module(central)


class BackupDiagnosticsTests(unittest.TestCase):
    def test_failure_is_private_bounded_and_never_echoes_arguments(self):
        for error in [subprocess.CalledProcessError(1, ['SECRET argument'], stderr='x' * 40000),
                      subprocess.TimeoutExpired(['SECRET argument'], 3, stderr=b'bounded diagnostic')]:
            with self.subTest(kind=type(error).__name__), tempfile.TemporaryDirectory() as tmp:
                with patch.object(central, 'ROOT', Path(tmp)), patch.object(central.subprocess, 'run', side_effect=error):
                    with self.assertRaisesRegex(RuntimeError, 'private last-tool-error.log') as raised:
                        central.execute(['SECRET argument'])
                self.assertNotIn('SECRET', str(raised.exception))
                path = Path(tmp) / 'last-tool-error.log'
                self.assertLessEqual(len(path.read_text()), 32768)
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
