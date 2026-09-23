"""Synthetic checks: receipt semantics and privacy, never accuracy qualification."""
import copy
import json
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'research'))
from recorded_decisions import (SCHEMA, validate_snapshot, engine_outcome,
                                policy_outcome, raw_score, policy_report)


def receipt():
    return json.loads((Path(__file__).resolve().parents[1] / 'tests/fixtures/recorded-decisions.json').read_text())


class RecordedDecisionTests(unittest.TestCase):
    def test_receipt_has_priority_over_legacy_fields_without_erasing_partial_verdict(self):
        row = {'decision_snapshot': receipt(), 'baseline_complete': True,
               'legacy_decision': {'outcome': 'legitimate'}, 'legacy_score': 1.,
               'delivery_classification': 'spam'}
        self.assertEqual(engine_outcome(row), 'spam')
        self.assertEqual(policy_outcome(row), 'legitimate')
        self.assertEqual(raw_score(row), 99.)

    def test_present_invalid_or_unknown_contract_never_falls_back(self):
        base = receipt()
        variants = [None, {}, {**base, 'schema': 'future'}, {**base, 'private': 'secret'},
                    {**base, 'engine': {**base['engine'], 'raw_score': float('nan')}},
                    {**base, 'action': {**base['action'], 'reason': 'PRIVATE'}},
                    {**base, 'final': {**base['final'], 'category': 'spam'}},
                    {**base, 'final': {**base['final'], 'classification': None}}]
        for snapshot in variants:
            with self.subTest(snapshot=snapshot), self.assertRaises(ValueError):
                engine_outcome({'decision_snapshot': snapshot, 'legacy_decision': {'outcome': 'unwanted'}})
        with self.assertRaises(ValueError): validate_snapshot({}, required=True)
        self.assertIsNone(validate_snapshot({}))

    def test_unavailable_and_invalid_results_stay_unknown(self):
        s = receipt(); s['final'].update(classification='unassessed', category='legitimate', score=None)
        s['engine'].update(outcome='undetermined', raw_score=None)
        row = {'decision_snapshot': s}
        self.assertEqual(policy_outcome(row), 'review')
        self.assertIsNone(raw_score(row))
        invalid = {'schema': SCHEMA, 'provenance': 'invalid', 'engine': None, 'final': None, 'action': None}
        row = {'decision_snapshot': invalid, 'legacy_decision': {'outcome': 'unwanted'}, 'legacy_score': 99}
        self.assertEqual(engine_outcome(row), 'review')
        self.assertEqual(policy_outcome(row), 'review')
        self.assertIsNone(raw_score(row))

    def test_legacy_explicit_verdict_survives_partial_analysis_without_new_threshold(self):
        self.assertEqual(engine_outcome({'legacy_decision': {'outcome': 'unwanted'}, 'baseline_complete': False}), 'spam')
        self.assertEqual(engine_outcome({'legacy_score': 100}), 'review')
        self.assertEqual(policy_outcome({'legacy_score': 100}), 'review')

    def test_policy_and_observation_actions_do_not_change_engine_metrics(self):
        s = receipt()
        rows = [{'risk': 'legitimate', 'decision_snapshot': s},
                {'risk': 'spam', 'legacy_decision': {'outcome': 'unwanted'}},
                {'risk': 'spam', 'decision_snapshot': {'schema': SCHEMA, 'provenance': 'invalid',
                                                     'engine': None, 'final': None, 'action': None}}]
        frozen = copy.deepcopy(rows)
        report = policy_report(rows)
        self.assertEqual(report['classification']['tn'], 1)
        self.assertEqual(report['classification']['tp'], 1)
        self.assertEqual(report['classification']['spam_to_review'], 1)
        self.assertEqual(report['requested_actions']['legitimate'], {'tag': 1})
        self.assertEqual(report['effective_actions']['legitimate'], {'deliver': 1})
        self.assertEqual(report['effective_actions']['spam'], {'not_recorded': 2})
        self.assertEqual((report['snapshots'], report['legacy_without_snapshot'], report['invalid_snapshots']), (1, 1, 1))
        self.assertFalse(report['independent_validation'])
        self.assertEqual(rows, frozen)


if __name__ == '__main__': unittest.main()
