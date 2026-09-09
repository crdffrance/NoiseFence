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
            with sqlite3.connect(root / 'state.sqlite3') as db:
                db.execute('PRAGMA user_version=1')
            self.assertTrue(rollback.compatible(config, root))
            with sqlite3.connect(root / 'state.sqlite3') as db:
                db.execute('PRAGMA user_version=2')
            self.assertFalse(rollback.compatible(config, root))
            manifest.write_text('{"storage_schema":2}')
            self.assertTrue(rollback.compatible(config, root))
            with sqlite3.connect(root / 'state.sqlite3') as db:
                self.assertEqual(db.execute('PRAGMA user_version').fetchone()[0], 2)
            manifest.write_text('{"storage_schema":true}')
            self.assertFalse(rollback.compatible(config, root))
