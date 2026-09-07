"""Scheduler chooses the matching trainer and never alters active artifacts."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
try:
    import tomllib
except ImportError:
    tomllib = None


@unittest.skipIf(tomllib is None, 'The Linux scheduler requires Python 3.11+')
class SchedulerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location('feedback_service', ROOT/'deploy/train-feedback.py')
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    def test_schema_three_and_hybrid_never_reach_the_legacy_trainer(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            model = root/'model.json'
            config = root/'config.toml'
            model.write_text(json.dumps({'feature_version': 3}))
            config.write_text('[filter]\nmodel = '+json.dumps(str(model))+'\n[filter.semantic]\ncombination="x"\n')
            export, train, family = self.module.commands(root/'noisefence', config, root/'python', root/'candidate', root/'snapshot')
            self.assertIn('export-learning', export)
            self.assertIn('--require-semantic', export)
            self.assertIn('--hybrid', train)
            self.assertEqual(family, 'schema-3-hybrid')
            self.assertNotIn('train', train)
            model.write_text(json.dumps({'feature_version': 1}))
            with self.assertRaises(ValueError):
                self.module.commands(root/'noisefence', config, root/'python', root/'candidate', root/'snapshot')

    def test_failed_training_preserves_latest_and_deletes_temporary_features(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root/'config.toml'
            config.write_text('[filter]\n')
            latest = root/'latest-candidate.json'
            latest.write_text('previous candidate')
            active = root/'active.json'
            active.write_text('active weights')

            def run(command, **kwargs):
                if 'export-feedback' in command:
                    Path(command[-1]).write_text('private temporary features')
                else:
                    raise subprocess.CalledProcessError(1, command)

            with patch.object(sys, 'argv', ['train-feedback', '--directory', str(root), '--config', str(config)]), \
                    patch.object(self.module.subprocess, 'run', side_effect=run):
                with self.assertRaises(subprocess.CalledProcessError):
                    self.module.main()
            self.assertEqual(latest.read_text(), 'previous candidate')
            self.assertEqual(active.read_text(), 'active weights')
            self.assertEqual(list((root/'candidates').iterdir()), [])
            self.assertFalse(list(root.glob('.training-*')))


if __name__ == '__main__':
    unittest.main()
