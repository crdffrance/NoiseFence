"""A second native operation must not reuse the first one's SSH authorization."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'deploy/postgresql'))
spec = importlib.util.spec_from_file_location('exchange_fixture', ROOT/'tests/fixtures/exchange_node.py')
fixture = importlib.util.module_from_spec(spec); spec.loader.exec_module(fixture)
sys.path.pop(0)
OP = 'aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa'
NEXT = 'bbbbbbbb-bbbb-4bbb-bbbb-bbbbbbbbbbbb'


class FixtureExchangeLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.folder = root/'authorization'; self.folder.mkdir(mode=0o700)
        self.private = root/'private'; self.private.mkdir()
        self.auth = {'protocol':fixture.exchange.PROTOCOL,'operation':OP,'node':'mx1'}
        (self.folder/'exchange.json').write_text(json.dumps(self.auth))
        (self.folder/'host').write_text('synthetic private host key')
        self.report = {'node':'mx1','phase':'complete'}
        for name,value in [('FOLDER',self.folder),('PRIVATE',self.private)]:
            p=patch.object(fixture,name,value);p.start();self.addCleanup(p.stop)
        p=patch.object(fixture.activation,'Activation');self.activation=p.start();self.addCleanup(p.stop)
        self.activation.return_value.report.side_effect=lambda: self.report
        p=patch.object(fixture,'command');self.command=p.start();self.addCleanup(p.stop)

    def test_retire_preserves_previous_files_and_allows_fresh_operation(self):
        self.assertEqual(fixture.retire('mx1',OP),{'node':'mx1','operation':OP,'phase':'retired'})
        self.command.assert_called_once_with('systemctl','stop','paired-upgrade-ssh.service')
        kept=self.private/('completed-exchange-'+OP)
        self.assertEqual(json.loads((kept/'exchange.json').read_text()),self.auth)
        self.assertEqual((kept/'host').read_text(),'synthetic private host key')
        self.assertFalse(self.folder.exists())
        self.report={'node':'mx1','phase':'started','proposal':[]}
        def keygen(*args):
            self.assertEqual(args[0],'ssh-keygen')
            path=Path(args[-1]);path.write_text('new synthetic key');Path(str(path)+'.pub').write_text('ssh-ed25519 synthetic')
        self.command.side_effect=keygen
        with patch.object(fixture.activation,'checked_proposal',return_value='a'*64):
            new=fixture.prepare('mx1',NEXT)
        self.assertEqual(new['authorization']['operation'],NEXT)
        self.assertEqual(json.loads((kept/'exchange.json').read_text())['operation'],OP)

    def test_cannot_retire_unfinished_or_foreign_operation(self):
        for phase,node,operation in [('started','mx1',OP),('complete','mx2',OP),('complete','mx1',NEXT)]:
            self.report={'node':node,'phase':phase}
            with self.subTest(phase=phase,node=node,operation=operation),self.assertRaises(ValueError):
                fixture.retire('mx1',operation)
            self.assertTrue(self.folder.exists())
        self.command.assert_not_called()

    def test_stop_failure_preserves_authorization(self):
        self.command.side_effect=OSError('synthetic stop failure')
        with self.assertRaises(OSError):fixture.retire('mx1',OP)
        self.assertEqual(json.loads((self.folder/'exchange.json').read_text()),self.auth)

    def test_refuses_pending_fault_or_existing_retired_directory(self):
        (self.private/'drop-next-completion').write_text('pending synthetic fault')
        with self.assertRaises(ValueError):fixture.retire('mx1',OP)
        (self.private/'drop-next-completion').unlink()
        (self.private/('completed-exchange-'+OP)).mkdir()
        with self.assertRaises(ValueError):fixture.retire('mx1',OP)
        self.command.assert_not_called()
