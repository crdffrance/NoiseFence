"""Private-feedback protocol, leakage controls and candidate publication."""
import copy
import hashlib
import json
import math
import os
from pathlib import Path
import sys
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'research'))
try:
    import train_feedback as training
except ImportError:
    training = None


def sample(i, spam=None):
    spam = bool(i % 2) if spam is None else spam
    sha = hashlib.sha256(f'synthetic-{i}'.encode()).hexdigest()
    vector = [0.] * 384
    vector[0] = 1. if spam else -1.
    return {'schema': 'noisefence-learning-1', 'source': 'local_human_feedback',
            'id': sha, 'fingerprint': sha, 'simhash': sha[:16], 'feature_version': 3,
            'observed_at': 1788740000, 'labelled_at': 1788740001, 'spam': spam,
            'features': [[1 if spam else 2, 1.]],
            'semantic': {'protocol': copy.deepcopy(training.PROTOCOL), 'features': vector}}


@unittest.skipIf(training is None, 'Install research/requirements.txt for training tests')
class FeedbackTests(unittest.TestCase):
    def read(self, rows, hybrid=True):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'feedback.jsonl'
            path.write_text(''.join(json.dumps(r)+'\n' for r in rows))
            return training.read_rows(path, hybrid)

    def test_schema_encoder_revision_and_vector_bounds_cannot_be_silently_mixed(self):
        self.assertEqual(len(self.read([sample(0), sample(1)])[0]), 2)
        for mutate in [lambda r: r.update(feature_version=1),
                       lambda r: r['semantic']['protocol'].update(revision='unpinned'),
                       lambda r: r['semantic']['features'].__setitem__(0, 0.1),
                       lambda r: r.update(features=[[1, float('nan')]]),
                       lambda r: r.update(features=[[True, 1.]]),
                       lambda r: r.update(features=[[1, 1.], [1, 1.]]),
                       lambda r: r.update(semantic=None)]:
            row = sample(0)
            mutate(row)
            with self.assertRaises(ValueError):
                self.read([row])
        with self.assertRaises(ValueError):
            self.read([sample(0), sample(0)])
        row = sample(0)
        row['semantic'] = None
        self.assertEqual(len(self.read([row], hybrid=False)[0]), 1)

    def test_group_conflicts_excluded_and_transitive_duplicates_cannot_cross_splits(self):
        rows = [sample(i, True) for i in range(5)]
        for row, h in zip(rows[:3], ('0000000000000000', '0000000000000007', '000000000000003f')):
            row['simhash'] = h
        rows[3]['simhash'] = rows[4]['simhash'] = 'ffffffffffffffff'
        rows[4]['spam'] = False
        grouped, counts = training.group_rows(rows)
        self.assertEqual(len(grouped), 1)
        self.assertEqual(counts['conflicting_messages'], 2)
        self.assertEqual(counts['duplicates_removed'], 2)
        self.assertEqual(grouped[0]['group'], min(r['fingerprint'] for r in rows[:3]))

    def test_holdouts_do_not_fit_weights_idf_or_select_hyperparameters(self):
        rows, _ = training.group_rows([sample(i) for i in range(200)])
        parts = training.partition(rows)
        model, combo, report, predictions = training.train(rows, True, 'synthetic-test')
        modified = copy.deepcopy(rows)
        for i in list(parts['test']) + list(parts['calibration']):
            modified[i]['features'] = [[999, 1.]]
        m2, c2, r2, _ = training.train(modified, True, 'synthetic-test')
        self.assertEqual(model['weights'], m2['weights'])
        self.assertEqual(model['idf'], m2['idf'])
        self.assertEqual(combo['head_weights'], c2['head_weights'])
        self.assertEqual(report['selected'], r2['selected'])
        self.assertFalse(report['eligible'])
        self.assertEqual(len(predictions), 200)
        self.assertTrue(all(math.isfinite(row['combined_logit']) for row in predictions))

    def test_bundle_is_bound_to_lexical_bytes_and_existing_artifact_is_preserved(self):
        rows, _ = training.group_rows([sample(i) for i in range(120)])
        model, combo, report, predictions = training.train(rows, True, 'synthetic-test')
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)/'candidate'
            old_mask = os.umask(0o077)
            try:
                training.publish(output, model, combo, report, predictions)
            finally:
                os.umask(old_mask)
            digest = hashlib.sha256((output/'model.json').read_bytes()).hexdigest()
            manifest = json.loads((output/'native-combination.json').read_text())
            self.assertEqual(manifest['lexical_model_sha256'], digest)
            self.assertEqual(output.stat().st_mode & 0o777, 0o700)
            self.assertEqual((output/'model.json').stat().st_mode & 0o777, 0o600)
            with self.assertRaises(ValueError):
                training.publish(output, {}, {}, {}, [])
            self.assertEqual(hashlib.sha256((output/'model.json').read_bytes()).hexdigest(), digest)
            aggregate = Path(directory)/'aggregate'
            training.publish(aggregate, model, combo, report, predictions, aggregate_only=True)
            self.assertFalse((aggregate/'predictions.json').exists())
            aggregate_report = json.loads((aggregate/'report.json').read_text())
            self.assertNotIn('predictions_sha256', aggregate_report)
            self.assertEqual(aggregate_report['per_message_predictions'], 'not_written')
            self.assertEqual((aggregate/'model.json').read_bytes(), (output/'model.json').read_bytes())
            self.assertFalse(any(row['id'] in p.read_text() for p in aggregate.iterdir() for row in predictions))

    def test_insufficient_human_labels_cannot_publish_a_candidate(self):
        rows, _ = training.group_rows([sample(i, True) for i in range(100)])
        with self.assertRaisesRegex(ValueError, 'both classes'):
            training.train(rows, True, 'insufficient')

    def test_cli_distinguishes_missing_labels_from_corrupt_data(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root/'feedback.jsonl'
            destination = root/'candidate'
            command = [sys.executable, str(ROOT/'research/train_feedback.py'),
                       str(source), str(destination), '--hybrid', '--aggregate-only']
            source.write_text('')
            result = subprocess.run(command, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 3, result.stderr)
            self.assertEqual(json.loads(result.stdout)['status'], 'insufficient_feedback')
            self.assertFalse(destination.exists())
            source.write_text('{"invalid":"export"}\n')
            result = subprocess.run(command, capture_output=True, text=True, timeout=30)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotEqual(result.returncode, 3)
            self.assertFalse(destination.exists())


if __name__ == '__main__':
    unittest.main()
