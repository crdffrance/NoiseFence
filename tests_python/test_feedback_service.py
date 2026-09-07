"""Scheduler chooses the matching trainer and never alters active artifacts."""
import importlib.util
import contextlib
import io
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
            self.assertIn('--aggregate-only', train)
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
            self.assertEqual(json.loads((root/'last-training.json').read_text())['status'], 'failed')

    def test_insufficient_feedback_preserves_latest_and_cleans_separate_scratch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            model, config = root/'model.json', root/'config.toml'
            model.write_text(json.dumps({'feature_version': 3}))
            config.write_text('[filter]\nmodel = '+json.dumps(str(model))+'\n')
            latest = root/'latest-candidate.json'
            latest.write_text('previous candidate')
            scratch = root/'runtime'
            scratch.mkdir(mode=0o700)

            def run(command, **kwargs):
                if 'export-learning' in command:
                    path = Path(command[-1])
                    self.assertTrue(path.is_relative_to(scratch))
                    path.write_text('private per-message features')
                    return subprocess.CompletedProcess(command, 0, '{"exported":0}')
                return subprocess.CompletedProcess(command, 3, '{"status":"insufficient_feedback"}')

            with patch.object(sys, 'argv', ['train-feedback', '--directory', str(root), '--config', str(config),
                                          '--scratch-directory', str(scratch)]), \
                    patch.object(self.module.subprocess, 'run', side_effect=run), contextlib.redirect_stdout(io.StringIO()):
                self.module.main()
            self.assertEqual(latest.read_text(), 'previous candidate')
            self.assertEqual(list(scratch.iterdir()), [])
            self.assertFalse(list(root.glob('.candidate-stage-*')))
            result = json.loads((root/'last-training.json').read_text())
            self.assertEqual(result['status'], 'insufficient_feedback')
            self.assertFalse(result['activated'])
            self.assertNotIn('private per-message', (root/'last-training.json').read_text())

    def test_success_keeps_predictions_out_of_durable_candidates_and_pins_binary(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            model, config = root/'model.json', root/'config.toml'
            model.write_text(json.dumps({'feature_version': 3}))
            config.write_text('[filter]\nmodel = '+json.dumps(str(model))+'\n')
            release = root/'release'
            release.mkdir()
            (release/'noisefence').touch()
            link = root/'noisefence'
            link.symlink_to(release/'noisefence')
            scratch = root/'runtime'
            scratch.mkdir(mode=0o700)

            def run(command, **kwargs):
                if 'export-learning' in command:
                    self.assertEqual(Path(command[0]), (release/'noisefence').resolve())
                    Path(command[-1]).write_text('private per-message features')
                    return subprocess.CompletedProcess(command, 0, '{"exported":120}')
                self.assertEqual(Path(command[1]), (release/'research/train_feedback.py').resolve())
                self.assertIn('--aggregate-only', command)
                candidate = Path(command[3])
                self.assertFalse(candidate.is_relative_to(scratch))
                candidate.mkdir()
                (candidate/'model.json').write_text('aggregate weights')
                return subprocess.CompletedProcess(command, 0, '{}')

            with patch.object(sys, 'argv', ['train-feedback', '--binary', str(link), '--directory', str(root),
                                          '--config', str(config), '--scratch-directory', str(scratch)]), \
                    patch.object(self.module.subprocess, 'run', side_effect=run), contextlib.redirect_stdout(io.StringIO()):
                self.module.main()
            result = json.loads((root/'latest-candidate.json').read_text())
            self.assertEqual(result['status'], 'candidate_prepared')
            self.assertFalse(result['activated'])
            self.assertEqual((Path(result['candidate'])/'model.json').read_text(), 'aggregate weights')
            self.assertEqual(list(scratch.iterdir()), [])
            self.assertFalse(list(root.glob('.candidate-stage-*')))

    def test_shared_or_symlinked_work_directory_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            public = root/'public'
            public.mkdir(mode=0o755)
            public.chmod(0o755)
            with self.assertRaises(ValueError):
                self.module.private_directory(public)
            link = root/'link'
            link.symlink_to(root, target_is_directory=True)
            with self.assertRaises(ValueError):
                self.module.private_directory(link)


if __name__ == '__main__':
    unittest.main()
