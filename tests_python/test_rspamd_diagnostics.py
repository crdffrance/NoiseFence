import copy
import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'research'))
from rspamd_diagnostics import diagnose


def row(risk=None, native='legitimate', action='no action'):
    return dict(risk=risk, legacy_decision=dict(outcome=native),
                quality=dict(artifacts_sha256='native-a'),
                rspamd=dict(status='complete', action=action, settings_sha256='rspamd-a',
                            symbols=[dict(name='EXAMPLE', score=1.0)]))


class DiagnosticsTests(unittest.TestCase):
    def test_unlabelled_disagreement_never_becomes_an_error(self):
        rows = [row(native='unwanted'), row('spam'), row('legitimate', 'unwanted')]
        before = copy.deepcopy(rows)
        r = diagnose(rows)
        self.assertEqual(rows, before)
        self.assertEqual(r['confirmed_errors']['native_false_positive'], 1)
        self.assertEqual(r['confirmed_errors']['native_missed_spam'], 1)
        self.assertEqual(r['symbol_slices'][0]['unlabelled'], 1)
        self.assertFalse(r['may_activate'])
        self.assertFalse(r['independent_validation'])

    def test_nonfinal_and_unavailable_cannot_supply_a_spam_verdict(self):
        a = row('spam', action='greylist')
        a['rspamd']['score'] = 1000
        b = row('legitimate', action='reject'); b['rspamd']['status'] = 'unavailable'
        c = row('spam', action='custom')
        r = diagnose([a, b, c])
        self.assertEqual(r['confirmed_errors']['rspamd_false_positive'], 0)
        self.assertEqual(r['confirmed_errors']['rspamd_missed_spam'], 0)
        self.assertEqual(r['cohorts'][0]['nonfinal'], 2)
        self.assertEqual(r['symbol_slices'][0]['messages'], 2)

    def test_symbols_are_deduplicated_and_cohorts_remain_separate(self):
        a = row('legitimate'); a['rspamd']['symbols'] *= 2
        a['rspamd']['symbols'] += [dict(name='NEGATIVE', score=-1), dict(name='BAD', score=float('nan'))]
        b = row('spam'); b['quality']['artifacts_sha256'] = 'native-b'
        c = row('spam'); c['rspamd']['settings_sha256'] = 'rspamd-b'
        r = diagnose([a, b, c])
        self.assertEqual(len(r['cohorts']), 3)
        self.assertEqual(len(r['symbol_slices']), 4)
        self.assertTrue(all(s['messages'] == 1 for s in r['symbol_slices']))
        self.assertEqual(next(s for s in r['symbol_slices'] if s['symbol'] == 'NEGATIVE')['negative'], 1)

    def test_policy_category_does_not_replace_recorded_engine(self):
        a = row('legitimate', 'unwanted'); a['delivery_classification'] = 'legitimate'
        self.assertEqual(diagnose([a])['confirmed_errors']['native_false_positive'], 1)


if __name__ == '__main__':
    unittest.main()
