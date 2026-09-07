"""Population denominators and campaign isolation; synthetic software tests only."""
import importlib.util
from pathlib import Path
import sys
import unittest

try:
    import numpy
    import sklearn
except ImportError:
    numpy = None


@unittest.skipIf(numpy is None, 'Install research/requirements.txt')
class PopulationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(__file__).resolve().parents[1] / 'research'
        sys.path.insert(0, str(root))
        try:
            spec = importlib.util.spec_from_file_location('evaluate_population', root / 'evaluate_population.py')
            cls.p = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(cls.p)
        finally:
            sys.path.pop(0)

    def test_unknown_is_not_a_true_negative_and_known_fail_open_is_a_miss(self):
        p = self.p
        rows = [{'spam': False}, {'spam': True}, {'spam': True}, {'spam': None}]
        m = p.outcome_metrics(rows, [None, None, False, True], [[0], [1], [2], [3]])
        self.assertEqual(m['conditional_on_assessed_and_labelled']['fn'], 1)
        self.assertEqual(m['conditional_on_assessed_and_labelled']['tn'], 0)
        self.assertEqual(m['conservative_on_known_truth']['fp'], 1)
        self.assertEqual(m['conservative_on_known_truth']['fn'], 2)
        self.assertEqual((m['unknown_truth'], m['unassessable']), (1, 2))
        self.assertFalse(p.target_supported(m, rows, {'kind': 'representative'},
                                           {'blinded': True, 'independent_campaigns': True}))

    def test_campaign_copies_cannot_multiply_independent_successes(self):
        rows = [{'spam': False}]*10 + [{'spam': True}]*10
        predictions = [False]*9+[True] + [True]*9+[False]
        m = self.p.outcome_metrics(rows, predictions, [list(range(10)), list(range(10,20))])
        self.assertEqual(m['conditional_on_assessed_and_labelled']['tp'], 9)
        campaigns = m['campaigns']['conservative_stability']
        self.assertEqual((campaigns['tp'], campaigns['tn'], campaigns['fp'], campaigns['fn']), (0,0,1,1))
        m = self.p.outcome_metrics([{'spam': False}, {'spam': True}], [False, True], [[0,1]])
        self.assertEqual(m['campaigns']['mixed_truth'], 1)

    def test_missing_hashes_stay_distinct_but_real_provenance_connects_transitively(self):
        rows = [{'fingerprint': None, 'simhash': None, 'campaign': None},
                {'fingerprint': None, 'simhash': None, 'campaign': None}]
        self.assertEqual(self.p.groups(rows), [[0], [1]])
        rows = [{'fingerprint': 'a'*64, 'simhash': None, 'campaign': 'b'*64},
                {'fingerprint': 'a'*64, 'simhash': '123456789abcdef0', 'campaign': None},
                {'fingerprint': None, 'simhash': '123456789abcdef1', 'campaign': 'c'*64},
                {'fingerprint': None, 'simhash': None, 'campaign': 'c'*64}]
        self.assertEqual(self.p.groups(rows), [[0,1,2,3]])
        with self.assertRaisesRegex(ValueError, 'overlaps'):
            self.p.independent_groups(rows[:3], rows[3:])

    def test_raw_body_or_identity_overlap_is_rejected_without_simhash(self):
        for key in ('raw_sha256', 'id'):
            with self.assertRaisesRegex(ValueError, 'overlaps'):
                self.p.independent_groups([{key: 'a'*64}], [{key: 'a'*64}])

    def test_labels_require_human_review_and_conflicts_require_adjudication(self):
        p = self.p
        row = {'id': 'a'*64, 'observed_at': 100,
               'label': {'status': 'conflicting', 'unwanted': None, 'labelled_at': 101}}
        a = {'id': row['id'], 'label': 'legit', 'campaign': None, 'language': 'fr', 'kind': 'fixture',
             'basis': 'reviewed', 'review_reference': 'Synthetic human-review fixture', 'reviewed_at': 102}
        with self.assertRaisesRegex(ValueError, 'adjudication'):
            p.annotate([row], [a], 102)
        a['basis'] = 'adjudicated'
        self.assertFalse(p.annotate([row], [a], 102)[0]['spam'])
        a.update(label='uncertain', basis='unresolved', review_reference=None, reviewed_at=None)
        self.assertIsNone(p.annotate([row], [a], 102)[0]['spam'])
        a.update(label='spam', basis='reviewed')
        with self.assertRaisesRegex(ValueError, 'provenance'):
            p.annotate([row], [a], 102)

    def test_support_needs_complete_independent_review_and_conservative_intervals(self):
        p = self.p
        rows = [{'spam': False, 'campaign': 'a', 'fingerprint': 'b', 'simhash': 'c'}]*10000
        rows += [{'spam': True, 'campaign': 'd', 'fingerprint': 'e', 'simhash': 'f'}]*2000
        # Artificial singleton groups exercise the gate, never a quality claim.
        m = p.outcome_metrics(rows, [r['spam'] for r in rows], [[i] for i in range(len(rows))])
        sampling, review = {'kind': 'representative'}, {'blinded': True, 'independent_campaigns': True}
        self.assertTrue(p.target_supported(m, rows, sampling, review))
        self.assertFalse(p.target_supported(m, rows, {'kind':'synthetic'}, review))
        self.assertFalse(p.target_supported(m, rows, sampling, {**review, 'blinded':False}))
        self.assertFalse(p.target_supported(m, [{**rows[0], 'campaign':None}]+rows[1:], sampling, review))


if __name__ == '__main__':
    unittest.main()
