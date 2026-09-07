"""Content experiment isolation and shared false-positive decision boundary."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
try:
    import numpy as np
    import sklearn
except ImportError:
    np = None


@unittest.skipIf(np is None, 'Install research/requirements.txt')
class ContentAdaptationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, str(ROOT/'research'))
        spec = importlib.util.spec_from_file_location('adapt_content', ROOT/'research/adapt_content.py')
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    def rows(self):
        rows = []
        for i in range(200):
            key = hashlib.sha256(str(i).encode()).hexdigest()
            bucket = int(hashlib.sha256(key.encode()).hexdigest()[:8], 16) % 10
            if bucket < 3:
                continue
            rows.append({'raw_sha256': key, 'fingerprint': key, 'group': key,
                         'feature_version': 3, 'spam': bool(i % 2),
                         'partition': 'development' if bucket == 3 else 'train',
                         'stratum': 'source-a' if i < 100 else 'source-b'})
        return rows

    def test_reserved_groups_and_forged_split_are_rejected(self):
        rows = self.rows()
        self.module.validate_rows(rows)
        reserved = hashlib.sha256(b'reserved').hexdigest()
        while int(hashlib.sha256(reserved.encode()).hexdigest()[:8], 16) % 10 >= 3:
            reserved = hashlib.sha256(reserved.encode()).hexdigest()
        rows[0]['group'] = reserved
        with self.assertRaisesRegex(ValueError, 'holdout'):
            self.module.validate_rows(rows)
        rows = self.rows()
        rows[0]['partition'] = 'development' if rows[0]['partition'] == 'train' else 'train'
        with self.assertRaisesRegex(ValueError, 'Declared partition'):
            self.module.validate_rows(rows)

    def test_duplicate_campaigns_and_external_sources_cannot_enter_fitting(self):
        rows = self.rows()
        rows.append(dict(rows[0]))
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            self.module.validate_rows(rows)
        rows = self.rows()
        rows[0]['external_test'] = True
        with self.assertRaisesRegex(ValueError, 'holdout'):
            self.module.validate_rows(rows)

    def test_one_threshold_preserves_each_stratum_budget_with_ties(self):
        labels = np.array([False]*1000+[True]*2+[False]*10+[True]*2)
        logits = np.array([0.]*999+[1.]+[3., 6.]+[5.]*2+[0.]*8+[6., 7.])
        strata = np.array(['large']*1002+['small']*12)
        result = self.module.evaluate(labels, logits, strata, .001)
        self.assertGreater(result['threshold_logit'], 5.)
        self.assertEqual(result['by_stratum']['small']['false_positive'], 0)
        self.assertEqual(result['by_stratum']['large']['false_positive'], 0)
        self.assertEqual(result['by_stratum']['large']['true_positive'], 1)
        self.assertGreater(result['by_stratum']['small']['fpr_ci95'][1], .001)

    def test_vectors_require_exact_ids_protocol_hash_and_norm(self):
        rows = self.rows()
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            ids = [row['raw_sha256'] for row in rows][::-1]
            (directory/'ids.json').write_text(json.dumps(ids))
            vectors = np.zeros((len(rows), 384), dtype=np.float32)
            for index in range(len(rows)):
                vectors[index, index % 384] = 1.
            np.save(directory/'embeddings.npy', vectors, allow_pickle=False)
            protocol = {**self.module.PROTOCOL, 'complete': True,
                        'ids_sha256': self.module.digest(directory/'ids.json'),
                        'embeddings_sha256': self.module.digest(directory/'embeddings.npy')}
            (directory/'protocol.json').write_text(json.dumps(protocol))
            actual = self.module.load_vectors(directory, rows)
            np.testing.assert_array_equal(actual, vectors[::-1])
            protocol['revision'] = 'untrusted'
            (directory/'protocol.json').write_text(json.dumps(protocol))
            with self.assertRaisesRegex(ValueError, 'incompatible'):
                self.module.load_vectors(directory, rows)
            protocol['revision'] = self.module.PROTOCOL['revision']
            vectors[0] *= .5
            np.save(directory/'embeddings.npy', vectors, allow_pickle=False)
            protocol['embeddings_sha256'] = self.module.digest(directory/'embeddings.npy')
            (directory/'protocol.json').write_text(json.dumps(protocol))
            with self.assertRaisesRegex(ValueError, 'Invalid encoder'):
                self.module.load_vectors(directory, rows)

    def test_grid_rejects_relaxed_fp_budget_and_unbounded_fits(self):
        grid = {'augmentation_strata': ['source-b'], 'sample_weights': [1, 5],
                'lexical_C': [1, 10], 'semantic_C': [1], 'semantic_weights': [0, .1],
                'lexical_families': ['nb_logistic'], 'target_fpr': .001}
        self.module.validate_grid(grid, {'source-a', 'source-b'})
        grid['target_fpr'] = .01
        with self.assertRaisesRegex(ValueError, 'FPR'):
            self.module.validate_grid(grid, {'source-a', 'source-b'})
        grid['target_fpr'] = .001
        grid['sample_weights'] = list(range(1, 11))
        grid['lexical_C'] = list(range(1, 11))
        with self.assertRaisesRegex(ValueError, 'budget'):
            self.module.validate_grid(grid, {'source-a', 'source-b'})


if __name__ == '__main__':
    unittest.main()
