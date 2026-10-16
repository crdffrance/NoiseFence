"""Deployment metadata must not mutate a release or replace a valid receipt on failure."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('deployment_receipt', ROOT / 'deploy/record-deployment.py')
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class DeploymentReceiptTests(unittest.TestCase):
    def test_overlay_identity_and_atomic_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            (base / 'web').mkdir()
            console = base / 'web/version.json'
            console.write_text(json.dumps(dict(schema='noisefence-console-1', version='0.32.0', source_sha256='a'*64)))
            engine = json.dumps(dict(version='0.31.9', engine_build='b'*64)).encode()
            before = console.read_bytes()
            with patch.object(MODULE.subprocess, 'check_output', return_value=engine), patch.object(MODULE.time, 'time', return_value=12345):
                MODULE.record(base)
                receipt = (base / 'deployment.json').read_bytes()
                self.assertEqual(json.loads(receipt)['deployed_at'], 12345)
                self.assertEqual(json.loads(receipt)['console_source_sha256'], 'a'*64)
                self.assertEqual(console.read_bytes(), before)
                with patch.object(MODULE.os, 'replace', side_effect=OSError('disk failure')):
                    with self.assertRaises(OSError): MODULE.record(base)
                self.assertEqual((base / 'deployment.json').read_bytes(), receipt)
                self.assertEqual(list(base.glob('.deployment-*')), [])
                console.write_text('{}')
                with self.assertRaises(KeyError): MODULE.record(base)
                self.assertEqual((base / 'deployment.json').read_bytes(), receipt)
