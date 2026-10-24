import contextlib
import importlib.util
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('rollback_schema', Path(__file__).resolve().parents[1] / 'deploy/can-rollback.py')
rollback = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rollback)


class RollbackSchemaTest(unittest.TestCase):
    def test_old_release_cannot_read_migrated_queue(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = root / 'config.toml'
            config.write_text(f'data_dir = {json.dumps(str(root))}\n')
            manifest = root / 'build.json'
            manifest.write_text('{}')
            with contextlib.closing(sqlite3.connect(root / 'state.sqlite3')) as db, db:
                db.execute('PRAGMA user_version=1')
            self.assertTrue(rollback.compatible(config, root))
            with contextlib.closing(sqlite3.connect(root / 'state.sqlite3')) as db, db:
                db.execute('PRAGMA user_version=2')
            self.assertFalse(rollback.compatible(config, root))
            manifest.write_text('{"storage_schema":2}')
            self.assertTrue(rollback.compatible(config, root))
            with contextlib.closing(sqlite3.connect(root / 'state.sqlite3')) as db, db:
                self.assertEqual(db.execute('PRAGMA user_version').fetchone()[0], 2)
            manifest.write_text('{"storage_schema":true}')
            self.assertFalse(rollback.compatible(config, root))

    def test_central_authority_cannot_be_rolled_back_by_schema_number_alone(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);config=root/'config.toml'
            local='data_dir = '+json.dumps(str(root))+'\n'
            config.write_text(local+'[management]\nbackend="postgresql"\n')
            (root/'build.json').write_text('{"storage_schema":99}')
            self.assertFalse(rollback.compatible(config,root))
            config.write_text(local+'[management]\n')
            self.assertFalse(rollback.compatible(config,root))
            (root/'build.json').write_text('{"storage_schema":7}')
            config.write_text(local)
            with contextlib.closing(sqlite3.connect(root/'state.sqlite3')) as db, db:
                db.execute('PRAGMA user_version=7')
            self.assertFalse(rollback.compatible(config,root))
            with contextlib.closing(sqlite3.connect(root/'state.sqlite3')) as db, db:
                db.execute('PRAGMA user_version=6')
                db.execute('CREATE TABLE cluster_state(key TEXT PRIMARY KEY,value TEXT)')
            for marker in ('management_selection','management_transport','runtime_history_protocol','management_recovery_required','management_worker_release'):
                with contextlib.closing(sqlite3.connect(root/'state.sqlite3')) as db, db:
                    db.execute('DELETE FROM cluster_state')
                    db.execute('INSERT INTO cluster_state VALUES(?,?)',(marker,'unknown'))
                self.assertFalse(rollback.compatible(config,root))

    def test_unknown_broken_and_replication_stripped_state_cannot_authorize_rollback(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); config=root/'config.toml'; database=root/'state.sqlite3'
            config.write_text('data_dir='+json.dumps(str(root))+'\n')
            (root/'build.json').write_text('{"storage_schema":7}')
            for schema in (0, 8):
                with contextlib.closing(sqlite3.connect(database)) as db:
                    db.execute(f'PRAGMA user_version={schema}')
                self.assertFalse(rollback.compatible(config,root))
            with contextlib.closing(sqlite3.connect(database)) as db, db:
                db.executescript("PRAGMA user_version=5; CREATE TABLE cluster_state(key TEXT PRIMARY KEY,value TEXT);")
                db.execute("INSERT INTO cluster_state VALUES('ha_required','1')")
            self.assertFalse(rollback.compatible(config,root))
            database.unlink()
            self.assertFalse(rollback.compatible(config,root))
            Path(str(database)+'-wal').write_bytes(b'stale')
            self.assertFalse(rollback.compatible(config,root))
            database.symlink_to(root/'missing')
            with self.assertRaises(sqlite3.Error):
                rollback.compatible(config,root)
