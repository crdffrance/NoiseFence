"""Fusion isolation, calibration and fail-open decision tests. Synthetic only."""
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
class FusionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location('train_fusion', ROOT/'research/train_fusion.py')
        cls.f = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.f)

    def fixture(self, root):
        f = self.f
        digest = lambda text: hashlib.sha256(text.encode()).hexdigest()
        artifacts = {'application': 'fixture', 'dependency_lock_sha256': digest('lock'), 'policy_sha256': digest('policy'),
                     'lexical_model_sha256': digest('lexical'), 'semantic_model_sha256': None, 'semantic_protocol': None,
                     'llm_prompt_sha256': None, 'antivirus_database_sha256': None, 'signatures_database_sha256': None,
                     'llm_model_revision': None}
        data = [{'type': 'header', 'schema': 'noisefence-fusion-vectors-1', 'protocol_sha256': f.PROTOCOL_HASH, 'artifacts': artifacts}]
        annotations = []
        for i in range(200):
            values = [0.] * len(f.PROTOCOL['features'])
            values[next(j for j, v in enumerate(f.PROTOCOL['features']) if v['name'] == 'lexical.logit_clipped_32')] = .7 if i % 2 else -.7
            key = digest('row-'+str(i))
            data.append({'type': 'row', 'id': key, 'fingerprint': key, 'simhash': key[:16], 'observed_at': 100+i,
                         'labelled_at': 1000+i, 'source': 'local_human_feedback', 'spam': bool(i % 2), 'values': values,
                         'availability_profile': 'complete', 'tag_eligible': i % 19 != 0, 'legacy_score': 50.})
            annotations.append({'id': key, 'campaign': key, 'split': f.SPLITS[i//40], 'label': 'unwanted_binary' if i % 2 else 'legit',
                                'language': 'fr', 'kind': 'unit-fixture'})
        data.append({'type': 'footer', 'counts': {'considered': 200, 'exported': 200, 'missing_evidence': 0,
                                                  'non_smtp_evidence': 0, 'ineligible_to_tag': len(range(0,200,19))}})
        history = {'schema': 'noisefence-base-history-1', 'lexical_model_sha256': artifacts['lexical_model_sha256'],
                   'semantic_model_sha256': None, 'complete_for': f.BASE_USES,
                   'rows': [{'fingerprint': digest('base'), 'campaign': digest('base'), 'simhash': digest('base')[:16]}]}
        (root/'vectors.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in data))
        (root/'annotations.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in annotations))
        (root/'history.json').write_text(json.dumps(history))
        manifest = {'schema': 'noisefence-fusion-experiment-1', 'version': 'unit', 'purpose': 'research', 'protocol_sha256': f.PROTOCOL_HASH,
                    **{k: {'path': path, 'sha256': hashlib.sha256((root/path).read_bytes()).hexdigest()}
                       for k, path in [('vectors','vectors.jsonl'), ('annotations','annotations.jsonl'), ('base_history','history.json')]},
                    'sampling': {'kind': 'synthetic', 'description': 'Unit fixtures', 'authorization': 'No private data', 'start_at':100,'end_at':299}}
        path = root/'manifest.json'
        path.write_text(json.dumps(manifest))
        return path, data

    def test_threshold_ties_and_incomplete_checks_do_not_escape_fpr_constraint(self):
        f = self.f
        y, score, eligible = np.array([False, True, True]), np.array([2.,2.,100.]), np.array([True,True,False])
        threshold = f.choose_cutoff(y, score, eligible)
        result = f.metrics(y, eligible & (score >= threshold))
        self.assertEqual((result['tp'], result['fp']), (0,0))
        self.assertGreater(f.wilson(0,97)[1], .03)
        y = np.array([False]*1000 + [True]*20)
        score = np.arange(len(y), dtype=float)
        point = f.choose_cutoff(y, score, np.ones(len(y),bool))
        result = f.metrics(y, score >= point)
        self.assertEqual(result['tp'], 20)
        self.assertLessEqual(result['fp'], 1)

    def test_monotone_calibration_handles_reversed_predictions_and_reports_mixture(self):
        cal = self.f.calibrate(np.array([-2.,-1.,1.,2.]), np.array([True,True,False,False]))
        self.assertGreaterEqual(cal['slope'], 0.)
        self.assertLess(cal['slope'], 1e-6)
        self.assertEqual(cal['positive_fraction'], .5)
        self.assertEqual(cal['messages'], 4)

    def test_transitive_campaigns_cannot_cross_splits_or_base_training(self):
        rows = [{'id': str(i), 'fingerprint': str(i)*64, 'campaign': str(i)*64,
                 'simhash': f'{s:016x}', 'split': split, 'label': 'legit', 'spam': False}
                for i,s,split in [(1,0,'train'),(2,7,'train'),(3,63,'test')]]
        self.assertEqual(len(self.f.components(rows)), 1)
        with self.assertRaisesRegex(ValueError, 'crosses'):
            self.f.audit_groups(rows, [])
        with self.assertRaisesRegex(ValueError, 'base-model'):
            self.f.audit_groups(rows[:2], [rows[2]])
        rows[1]['spam'] = True
        with self.assertRaisesRegex(ValueError, 'Conflicting'):
            self.f.audit_groups(rows[:2], [])

    def test_test_predictions_cannot_change_fit_and_frozen_models_cannot_be_replaced(self):
        f = self.f
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest, data = self.fixture(root)
            f.fit(manifest, root/'first')
            original = json.loads((root/'first/full.json').read_text())
            for row in data[161:201]:
                row['values'] = [-x for x in row['values']]
            (root/'vectors.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in data))
            m = json.loads(manifest.read_text())
            m['vectors']['sha256'] = hashlib.sha256((root/'vectors.jsonl').read_bytes()).hexdigest()
            manifest.write_text(json.dumps(m))
            f.fit(manifest, root/'second')
            changed = json.loads((root/'second/full.json').read_text())
            for field in ('weights','bias','cutoff','calibration','supported_profiles'):
                self.assertEqual(original[field], changed[field])
            report = f.evaluate(manifest, root/'second')
            self.assertFalse(report['production_eligible'])
            self.assertFalse(report['target_supported_on_this_test'])
            self.assertEqual(report['variants']['full']['metrics']['tp'], 0)
            with self.assertRaisesRegex(ValueError, 'consumed'):
                f.evaluate(manifest, root/'second')
            with self.assertRaisesRegex(ValueError, 'mismatch'):
                f.evaluate(manifest, root/'first')

    def test_hashes_protocol_and_export_footer_prevent_silent_dataset_changes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest, _ = self.fixture(root)
            (root/'vectors.jsonl').write_text('{}\n')
            with self.assertRaisesRegex(ValueError, 'hash mismatch'):
                self.f.load_experiment(manifest)
        with self.assertRaisesRegex(ValueError, 'Duplicate JSON'):
            self.f.decode('{"x":1,"x":2}')
        with self.assertRaisesRegex(ValueError, 'Non-finite'):
            self.f.decode('{"x":NaN}')


if __name__ == '__main__':
    unittest.main()
