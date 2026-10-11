"""Synthetic score diagnostics; these fixtures do not demonstrate filter accuracy."""
import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'research'))
try:
    from score_tradeoffs import score_tradeoffs
except ImportError:
    score_tradeoffs = None


@unittest.skipIf(score_tradeoffs is None, 'Install research requirements')
class ScoreTradeoffsTests(unittest.TestCase):
    protocol = {'features': [{'name': 'llm.state.' + s} for s in
                            ('complete', 'disabled', 'pricing_expired')]}

    def row(self, identifier, risk, score, state=2, cohort='a'):
        return {'id': identifier, 'risk': risk, 'legacy_score': score,
                'quality': {'artifacts_sha256': cohort,
                            'values': [int(i == state) for i in range(3)]}}

    def test_saturation_cannot_be_fixed_by_raising_threshold(self):
        rows = [self.row('ham', 'legitimate', 99.99), self.row('spam', 'spam', 98.)]
        report = score_tradeoffs(rows, rows, self.protocol)
        profile = report['profiles'][0]
        self.assertFalse(profile['empirical_target_possible'])
        self.assertEqual(profile['saturated'], 1)
        self.assertEqual(profile['points'][3]['metrics']['fp'], 1)
        self.assertFalse(report['may_activate'])

    def test_missing_class_and_missing_score_never_certify_a_threshold(self):
        rows = [self.row('ham', 'legitimate', 20.), self.row('missing', 'spam', None)]
        report = score_tradeoffs(rows, rows, self.protocol)
        self.assertIsNone(report['profiles'][0]['empirical_target_possible'])
        self.assertEqual(report['excluded']['missing_score'], 1)

    def test_cohorts_and_actual_llm_states_remain_separate(self):
        rows = [self.row(str(i), 'spam', 98., state=i) for i in range(3)]
        rows.append(self.row('other', 'spam', 98., cohort='b'))
        report = score_tradeoffs(rows, rows, self.protocol)
        self.assertEqual(len(report['profiles']), 4)
        self.assertEqual({p['llm_state'] for p in report['profiles']},
                         {'complete', 'disabled', 'pricing_expired'})

    def test_unknown_availability_and_exclusions_are_explicit(self):
        rows = [self.row('unknown', 'legitimate', 5., state=9),
                self.row('bad', 'spam', 99.), self.row('unlabelled', None, 20.)]
        report = score_tradeoffs(rows, rows[:1], self.protocol)
        self.assertEqual(report['profiles'][0]['llm_state'], 'not_recorded')
        self.assertEqual(report['excluded'], {'incompatible_or_unusable_observation': 1,
                                             'unlabelled_or_uncertain': 1})

    def test_report_size_is_bounded_without_hiding_excluded_profiles(self):
        rows = [self.row(str(i), 'spam', 98., cohort=str(i)) for i in range(20)]
        report = score_tradeoffs(rows, rows, self.protocol)
        self.assertEqual(len(report['profiles']), 16)
        self.assertEqual(report['excluded']['profile_display_limit'], 4)
