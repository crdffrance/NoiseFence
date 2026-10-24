"""Failed CI must be diagnosable without publishing private fixture state."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('diagnostics', ROOT/'scripts/rehearsal_diagnostics.py')
diag = importlib.util.module_from_spec(spec); spec.loader.exec_module(diag)


class DiagnosticsTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def test_nested_failure_references_source_without_values_paths_or_credentials(self):
        folder = self.root/'paired';folder.mkdir()
        (folder/'failure-command.log').write_text(
            '  File "/home/PRIVATE-USER/source/tests/fixtures/paired_node.py", line 132, in readiness\n'
            'RuntimeError: Synthetic gateway readiness deadline exceeded\n'
            'Command=[secret-password, private-message@example.test]\n'
            '  File "/SECRET/private.py", line 23, in SECRET\n'
            '  File "/root/paired_node.py", line 999999, in SECRET\n')
        result = diag.diagnose(self.root, 'paired')
        log = result['logs']['paired/failure-command.log']
        self.assertEqual(log['frames'], [{'source':'tests/fixtures/paired_node.py','line':132}])
        self.assertIn('RuntimeError', log['error_types'])
        self.assertTrue(any(row['source']=='tests/fixtures/paired_node.py' for row in log['assertions']))
        text = json.dumps(result)
        for forbidden in ('PRIVATE', 'SECRET', 'password', 'example.test', 'deadline exceeded'):
            self.assertNotIn(forbidden, text)
        self.assertEqual(result['status'], 'failed');self.assertFalse(result['raw_data_included'])

    def test_denials_only_expose_fixed_operation_and_resource_categories(self):
        folder=self.root/'apparmor';folder.mkdir()
        (folder/'denials.log').write_text(
            'apparmor="DENIED" profile="private-profile" operation="open" name="/etc/noisefence/secret.key"\n'
            'apparmor="DENIED" operation="open" name="/etc/noisefence/other.key"\n'
            'apparmor="DENIED" operation="exec" name="/not-public"\n'
            'apparmor="DENIED" operation="open" name="/etc/noisefence-blocked-fixture.toml"\n'
            'apparmor="DENIED" operation="SECRET-OPERATION" name="/etc/noisefence/secret.key"\n'
            'apparmor="ALLOWED" operation="connect" name="/run/postgresql/socket"\n')
        result=diag.diagnose(self.root,'paired')
        self.assertEqual(result['logs']['apparmor/denials.log']['denials'],
            [{'operation':'open','resource':'configuration'},{'operation':'exec','resource':'other'},
             {'operation':'open','resource':'intentional_canary'}])
        for word in ('secret.key','other.key','private-profile','SECRET-OPERATION','/not-public'):
            self.assertNotIn(word,json.dumps(result))

    def test_postgresql_capacity_errors_publish_only_fixed_categories(self):
        result=diag.describe('Central policy capacity unavailable PRIVATE-DB\nCentral ingestion capacity unavailable PRIVATE-USER',{},[])
        self.assertEqual(result['indicators'],['central_policy_capacity_unavailable','central_ingestion_capacity_unavailable'])
        self.assertNotIn('PRIVATE',json.dumps(result))

    def test_missing_truncated_malformed_and_unrecognized_logs_are_not_passes(self):
        self.assertEqual(diag.diagnose(self.root/'missing','paired')['logs'],{})
        (self.root/'paired.log').write_bytes(b'\xff' * (diag.LIMIT+10) + b'Permission denied\n')
        self.assertEqual(len(diag.tail(self.root,'paired.log')),diag.LIMIT)
        result=diag.diagnose(self.root,'paired')
        self.assertEqual(result['logs']['paired.log']['indicators'],['permission_denied'])
        self.assertEqual(result['status'],'failed')
        with self.assertRaises(ValueError):diag.diagnose(self.root,'private-phase')

    def test_links_fifo_directories_and_unlisted_logs_are_not_read(self):
        secret=self.root/'unlisted.log';secret.write_text('Permission denied')
        (self.root/'paired.log').symlink_to(secret)
        (self.root/'paired').symlink_to(self.root, target_is_directory=True)
        os.mkfifo(self.root/'standalone.log')
        self.assertEqual(diag.diagnose(self.root,'paired')['logs'],{})
        (self.root/'paired.log').unlink();(self.root/'paired.log').mkdir()
        self.assertIsNone(diag.tail(self.root,'paired.log'))
        (self.root/'paired').unlink();(self.root/'paired').mkdir()
        os.link(secret,self.root/'paired/failure-command.log')
        self.assertIsNone(diag.tail(self.root,'paired/failure-command.log'))

    def test_wrapper_preserves_failure_status_when_diagnostic_itself_fails(self):
        # Execute the actual EXIT trap with disposable command stubs. No Docker,
        # application binary or external command is invoked by this fixture.
        wrapper=(ROOT/'scripts/check_release_lifecycle.sh').read_text()
        cleanup=wrapper[wrapper.index('cleanup() {'):wrapper.index('phase=paired-image')]
        stub=self.root/'bin';stub.mkdir()
        for name in ('python3','docker'):
            path=stub/name;path.write_text('#!/bin/sh\nexit 91\n');path.chmod(0o755)
        result=subprocess.run(['/bin/sh','-c','set -eu\nname=test\nphase=paired\noutput=unused\n'+cleanup+'exit 7\n'],
            capture_output=True,timeout=5,env={'PATH':str(stub),'HOME':str(self.root),'TMPDIR':str(self.root)})
        self.assertEqual(result.returncode,7)
        self.assertIn(b'phase=paired exit=7', result.stderr)


if __name__ == '__main__':unittest.main()
