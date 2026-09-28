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

    def test_selected_postgres_requires_dump_and_original_mfa_key_but_not_claimed_restore(self):
        import hashlib
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'source';(root/'data').mkdir(parents=True);(root/'config').mkdir()
            key=b'k'*32
            selection={'role':'coordinator','mfa_key_sha256':hashlib.sha256(key).hexdigest()}
            with sqlite3.connect(root/'data/state.sqlite3') as db:
                db.execute('CREATE TABLE cluster_state(key TEXT PRIMARY KEY,value TEXT)')
                db.execute('INSERT INTO cluster_state VALUES(?,?)',('management_selection',json.dumps(selection)))
                db.execute('PRAGMA user_version=7')
            (root/'config/config.toml').write_text('[management]\nbackend="postgresql"\n')
            archive=Path(tmp)/'snapshot.tar'
            def write():
                (root/'manifest.json').unlink(missing_ok=True)
                (root/'manifest.json').write_text(json.dumps(snapshot.manifest(root,'metadata')))
                with tarfile.open(archive,'w') as a:
                    for p in root.iterdir():a.add(p,arcname=p.name)
            write()
            with self.assertRaisesRegex(ValueError,'PostgreSQL management backup missing'):restore.verify(archive)
            (root/'data/management.postgresql.dump').write_bytes(b'PGDMPsynthetic-not-restorable')
            write()
            with self.assertRaisesRegex(ValueError,'Selected MFA recovery key'):restore.verify(archive)
            (root/'data/mfa.key').write_bytes(key);write()
            result=restore.verify(archive)
            self.assertEqual(result['status'],'requires_postgresql_restore')
            self.assertTrue(result['postgresql_restore_required'])
            (root/'data/mfa.key').write_bytes(b'x'*32);write()
            with self.assertRaisesRegex(ValueError,'Selected MFA recovery key'):restore.verify(archive)

    def test_full_restore_preserves_legacy_dsn_body_and_rejects_false_notification_ids(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'source';(root/'data/spool').mkdir(parents=True)
            database=root/'data/state.sqlite3'
            with sqlite3.connect(database) as db:
                db.execute('CREATE TABLE messages(id TEXT PRIMARY KEY,raw_present INTEGER,is_dsn INTEGER,sender TEXT)')
                db.execute("INSERT INTO messages VALUES('dsn-7',1,1,'')")
            body=root/'data/spool/dsn-7.eml'
            body.write_bytes(b'Subject: Delivery failure\r\n\r\nSynthetic notification')
            archive=Path(tmp)/'snapshot.tar'
            def write():
                (root/'manifest.json').unlink(missing_ok=True)
                (root/'manifest.json').write_text(json.dumps(snapshot.manifest(root,'full')))
                with tarfile.open(archive,'w') as a:
                    for p in root.iterdir():a.add(p,arcname=p.name)
            write();self.assertEqual(restore.verify(archive)['status'],'verified')
            for ident,flag,sender in [('dsn-0',1,''),('dsn-07',1,''),('dsn-9223372036854775808',1,''),('dsn-7/../outside',1,''),('dsn-7',0,''),('dsn-7',1,'sender@example.test')]:
                with sqlite3.connect(database) as db:db.execute('UPDATE messages SET id=?,is_dsn=?,sender=?',(ident,flag,sender))
                write()
                with self.assertRaisesRegex(ValueError,'Invalid queued message identifier'):restore.verify(archive)
            with sqlite3.connect(database) as db:db.execute("UPDATE messages SET id='dsn-7',is_dsn=1,sender=''")
            body.unlink();write()
            with self.assertRaisesRegex(ValueError,'Queued message body missing'):restore.verify(archive)
