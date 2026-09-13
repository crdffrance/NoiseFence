import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('network_hardening', ROOT/'deploy/hardening/network.py')
network = importlib.util.module_from_spec(spec)
spec.loader.exec_module(network)


class NetworkHardening(unittest.TestCase):
    def test_rules_do_not_flush_foreign_firewalls(self):
        text = network.firewall(999)
        self.assertNotIn('flush ruleset', text)
        self.assertIn('flush table inet noisefence_host', text)
        self.assertIn('type filter hook input priority 10; policy drop', text)
        self.assertIn('udp sport 67 udp dport 68 accept', text)
        self.assertIn('ipv6-icmp', text)
        self.assertIn('meta skuid 999 ip daddr', text)
        self.assertNotIn('type filter hook output priority 10; policy drop', text)
        self.assertLess(text.index('oifname "lo" accept'), text.index('meta skuid 999'))

    def test_administrators_cannot_inject_ssh_directives(self):
        for admins in [[], ['debian\nPermitRootLogin yes'], ['root *'], ['debian', 'debian']]:
            with self.assertRaises(ValueError):
                network.desired_files(admins, 999)
        for uid in [0, -1, '999\nflush ruleset', True]:
            with self.assertRaises(ValueError):
                network.firewall(uid)

    def test_commit_rejects_file_changed_after_probe(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            managed = directory/'setting';managed.write_text('unexpected mutation')
            ident = 'a'*32
            state = {'id':ident,'status':'pending','deadline':network.time.time()+100,
                     'applied_hashes':{str(managed):'0'*64}}
            (directory/(ident+'.json')).write_text(json.dumps(state))
            with patch.object(network,'STATE',directory), patch.object(network,'run') as run:
                with self.assertRaises(ValueError):network.commit(ident)
                run.assert_not_called()
                self.assertEqual(network.read_state(ident)['status'],'pending')

    def test_rollback_cannot_undo_committed_transaction(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp);ident='b'*32
            (directory/(ident+'.json')).write_text(json.dumps({'id':ident,'status':'committed'}))
            with patch.object(network,'STATE',directory), patch.object(network,'run') as run:
                self.assertEqual(network.rollback(ident)['status'],'committed')
                run.assert_not_called()

    def test_transaction_id_cannot_escape_private_state(self):
        for ident in ['../config', '/etc/shadow', 'a'*33, '']:
            with self.assertRaises(ValueError):network.read_state(ident)

    def test_atomic_write_rejects_symlinks(self):
        with tempfile.TemporaryDirectory() as tmp:
            link=Path(tmp)/'managed';target=Path(tmp)/'original';target.write_text('keep')
            link.symlink_to(target)
            with self.assertRaises(ValueError):network.atomic(link,b'overwrite')
            self.assertEqual(target.read_text(),'keep')

    def test_service_can_traverse_new_config_directory_with_private_umask(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'dropins'/'security.conf'
            previous=os.umask(0o077)
            try:
                with patch.object(network.os,'fchown'):
                    network.atomic(path,b'LLMNR=no\n')
            finally:os.umask(previous)
            self.assertEqual(path.parent.stat().st_mode&0o777,0o755)
            self.assertEqual(path.stat().st_mode&0o777,0o644)


if __name__=='__main__':unittest.main()

class StatusIsolation(unittest.TestCase):
    def test_reports_are_not_interpreted_as_transactions(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'monitor.json').write_text('{}');(root/'backup-status.json').write_text('{"status":"complete"}')
            (root/('a'*32+'.json')).write_text('{"id":"a","status":"committed"}')
            with patch.object(network,'STATE',root):self.assertEqual(len(network.transaction_states()),1)
