import importlib.util
import io
import json
from pathlib import Path
import sqlite3
import tarfile
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1]
def module(name):
    spec=importlib.util.spec_from_file_location(name,ROOT/'deploy/hardening'/name);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
restore=module('restore-check.py');snapshot=module('snapshot.py')
class RestoreTests(unittest.TestCase):
    def test_queue_and_mfa_recovery_require_their_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'source';(root/'data/spool').mkdir(parents=True)
            message_id='12345678-1234-1234-1234-123456789012'
            with sqlite3.connect(root/'data/state.sqlite3') as db:
                db.execute('CREATE TABLE messages(id TEXT,raw_present INTEGER)')
                db.execute('INSERT INTO messages VALUES(?,1)',(message_id,))
                db.execute('CREATE TABLE mfa_credentials(username TEXT)')
            arc=Path(tmp)/'snapshot.tar'
            def write(mode):
                (root/'manifest.json').unlink(missing_ok=True)
                (root/'manifest.json').write_text(json.dumps(snapshot.manifest(root,mode)))
                with tarfile.open(arc,'w') as a:
                    for p in root.iterdir():a.add(p,arcname=p.name)
            write('metadata');self.assertEqual(restore.verify(arc)['status'],'verified')
            write('full')
            with self.assertRaisesRegex(ValueError,'Queued message'):restore.verify(arc)
            (root/'data/spool'/(message_id+'.eml')).write_bytes(b'Subject: synthetic\r\n\r\nfixture')
            write('full');self.assertEqual(restore.verify(arc)['status'],'verified')
            write('metadata')
            with self.assertRaisesRegex(ValueError,'Metadata snapshot'):restore.verify(arc)
            with sqlite3.connect(root/'data/state.sqlite3') as db:db.execute("INSERT INTO mfa_credentials VALUES('synthetic')")
            write('full')
            with self.assertRaisesRegex(ValueError,'MFA recovery key'):restore.verify(arc)
            (root/'data/mfa.key').write_bytes(b'x'*32)
            write('full');self.assertEqual(restore.verify(arc)['status'],'verified')
    def test_valid_snapshot_detects_tamper_and_never_follows_links(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'source';(root/'data').mkdir(parents=True);(root/'config').mkdir()
            with sqlite3.connect(root/'data/state.sqlite3') as db:db.execute('CREATE TABLE probe (value TEXT)')
            (root/'config/test').write_text('synthetic');(root/'config/link').symlink_to('/etc/shadow')
            (root/'manifest.json').write_text(json.dumps(snapshot.manifest(root,'metadata')))
            arc=Path(tmp)/'snapshot.tar'
            def write():
                with tarfile.open(arc,'w') as a:
                    for p in root.iterdir():a.add(p,arcname=p.name)
            write();self.assertEqual(restore.verify(arc)['status'],'verified')
            (root/'config/test').write_text('tampered');write()
            with self.assertRaisesRegex(ValueError,'Checksum'):restore.verify(arc)
    def test_path_traversal_and_device_rejected(self):
        for name in ['/etc/shadow','../shadow','data/../../shadow','data\\shadow','other/file']:
            with self.assertRaises(ValueError):restore.safe_name(name)
        with tempfile.TemporaryDirectory() as tmp:
            arc=Path(tmp)/'bad.tar'
            with tarfile.open(arc,'w') as a:
                info=tarfile.TarInfo('data/device');info.type=tarfile.CHRTYPE;a.addfile(info)
            with self.assertRaisesRegex(ValueError,'Unsupported'):restore.verify(arc)
