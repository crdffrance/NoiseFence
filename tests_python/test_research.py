"""Research invariants: prevent leakage, label conflicts and unsafe calibration."""
import importlib.util
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class GroupingTests(unittest.TestCase):
    def test_encoder_manifest_excludes_test_calibration_and_external_groups(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            rows, manifest, wanted = [], [], set()
            for i in range(100):
                group = f'{i:064x}'
                external = i % 7 == 0
                bucket = int(hashlib.sha256(group.encode()).hexdigest()[:8], 16) % 10
                if not external and bucket >= 3:
                    wanted.add(group)
                rows.append({'fingerprint': group, 'group': group, 'raw_sha256': group,
                             'external_test': external, 'spam': i % 2 == 0, 'source': 'synthetic'})
                manifest.append({'path': f'synthetic/{group}.eml'})
            source, index = root / 'features.jsonl', root / 'manifest.jsonl'
            source.write_text(''.join(json.dumps(row) + '\n' for row in rows))
            index.write_text(''.join(json.dumps(row) + '\n' for row in manifest))
            subprocess.run([sys.executable, str(ROOT / 'research/prepare_semantic.py'),
                            str(source), str(index), str(root / 'output')], check=True, capture_output=True)
            actual = [json.loads(line) for line in (root / 'output/rows.jsonl').read_text().splitlines()]
            self.assertEqual({row['raw_sha256'] for row in actual}, wanted)
            self.assertEqual({row['partition'] for row in actual}, {'train', 'development'})

    def test_encoder_download_checks_pinned_git_blob_and_lfs_hashes(self):
        spec = importlib.util.spec_from_file_location('fetch_encoder', ROOT / 'research/fetch_encoder.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'artifact'
            payload = b'bounded data-only weights'
            path.write_bytes(payload)
            lfs = {'size': len(payload), 'sha256': hashlib.sha256(payload).hexdigest()}
            git = {'size': len(payload), 'sha256': None,
                   'git_blob': hashlib.sha1(f'blob {len(payload)}\0'.encode() + payload).hexdigest()}
            self.assertTrue(module.verified(path, lfs))
            self.assertTrue(module.verified(path, git))
            path.write_bytes(b'X' + payload[1:])
            self.assertFalse(module.verified(path, lfs))
            self.assertFalse(module.verified(path, git))

    def test_campaign_overlap_is_withheld_and_conflicting_labels_are_excluded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            rows = []
            for i, (spam, external, campaign, simhash) in enumerate([
                (True, False, 'a', '0000000000000000'),
                (True, True, 'a', '0000000000000000'),
                (True, False, 'b', 'ffffffffffffffff'),
                (False, False, 'b', 'ffffffffffffffff'),
                (False, False, 'c', 'aaaaaaaaaaaaaaaa'),
            ]):
                rows.append({'fingerprint': f'{i:064x}', 'campaign': campaign * 64,
                             'simhash': simhash, 'raw_sha256': f'{i:064x}', 'spam': spam,
                             'external_test': external, 'features': [[1, 0.5]], 'source': str(i)})
            source, output = root / 'source.jsonl', root / 'grouped.jsonl'
            source.write_text(''.join(json.dumps(row) + '\n' for row in rows))
            subprocess.run([sys.executable, str(ROOT / 'research/group_campaigns.py'), str(source), str(output)],
                           check=True, capture_output=True)
            actual = [json.loads(line) for line in output.read_text().splitlines()]
            self.assertEqual(len(actual), 2)
            self.assertTrue(next(row for row in actual if row['spam'])['external_test'])
            report = json.loads(output.with_suffix('.groups.json').read_text())
            self.assertEqual(report['counts']['conflicting_groups'], 1)
            self.assertEqual(report['counts']['older_messages_withheld_by_external_overlap'], 1)


try:
    import numpy as np
    import sklearn
except ImportError:
    np = None


@unittest.skipIf(np is None, 'Install research/requirements.txt for model-training tests')
class CalibrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location('train_linear', ROOT / 'research/train_linear.py')
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    def test_tied_calibration_scores_do_not_exceed_false_positive_allowance(self):
        labels = np.array([False] * 1000 + [True] * 3)
        logits = np.array([2., 2.] + [0.] * 998 + [10., 11., 12.])
        threshold = self.module.cutoff(labels, logits)
        report = self.module.metrics(labels, logits, threshold)
        self.assertEqual(report['false_positive'], 0)
        self.assertEqual(report['true_positive'], 3)
        self.assertGreater(report['fpr_ci95'][1], 0.001)

    def test_partitions_depend_on_group_and_provenance_never_labels(self):
        examples = [{'fingerprint': f'{i:064x}', 'spam': i % 2 == 0, 'group': str(i // 2)} for i in range(100)]
        a = self.module.partition(examples)
        for row in examples:
            row['spam'] = not row['spam']
        b = self.module.partition(examples)
        for name in a:
            self.assertEqual(a[name].tolist(), b[name].tolist())
            self.assertTrue(all((i ^ 1) in a[name] for i in a[name]))
        examples[0]['external_test'] = True
        self.assertEqual(self.module.partition(examples)['external'].tolist(), [0])

    def test_spam_only_external_set_cannot_measure_false_positive_rate(self):
        report = self.module.metrics(np.array([True, True]), np.array([1., 2.]), 0.)
        self.assertIsNone(report['false_positive_rate'])
        self.assertEqual(report['fpr_ci95'], [0.0, 1.0])


if __name__ == '__main__':
    unittest.main()
