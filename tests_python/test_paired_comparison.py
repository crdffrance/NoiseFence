"""Regression checks for matched engine metrics, not detection quality claims."""
import copy
import hashlib
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'research'))
try:
    from compare_quality import paired_comparison
    from evaluate_quality import baseline
    from recorded_decisions import policy_outcome
except ImportError:
    paired_comparison = None


@unittest.skipIf(paired_comparison is None, 'Install research/requirements.txt')
class PairedComparisonTests(unittest.TestCase):
    def row(self, ident, truth='legitimate', native='legitimate', action='no action'):
        digest = hashlib.sha256(ident.encode()).hexdigest()
        return dict(id=ident, risk=truth, observed_at=100,
                    fingerprint=digest, simhash=digest[:16], baseline_complete=True,
                    legacy_decision=dict(source='legacy', outcome=native),
                    rspamd=dict(status='complete', action=action, settings_sha256='a'*64))

    def test_missing_analyses_are_excluded_but_abstentions_and_greylisting_remain(self):
        good=self.row('good')
        spam=self.row('spam', 'spam', 'undetermined', 'greylist')
        missing=self.row('missing', 'spam', 'unwanted', 'reject')
        missing['rspamd']['status']='unavailable'
        no_native=self.row('no-native'); no_native['legacy_decision']=None
        report=paired_comparison([good,spam,missing,no_native])
        self.assertEqual(report['messages'],2)
        self.assertEqual(report['baseline']['tn'],1)
        self.assertEqual(report['rspamd']['spam_to_review'],1)
        self.assertEqual(report['rspamd']['tp'],0)
        self.assertEqual(report['coverage']['native_missing'],1)
        self.assertEqual(report['coverage']['rspamd_missing'],1)
        self.assertEqual(report['coverage']['paired_spam'],1)
        self.assertFalse(report['capture_comparison_supported'])
        self.assertFalse(report['independent_validation'])

    def test_observed_threat_survives_incomplete_coverage_and_policy_is_separate(self):
        row=self.row('observed-threat','spam','unwanted','reject')
        row['baseline_complete']=False
        self.assertEqual(baseline(row),'spam')  # Coverage cannot erase a recorded verdict.
        report=paired_comparison([row])
        self.assertEqual(report['baseline']['tp'],1)
        self.assertEqual(report['coverage']['paired_core_incomplete'],1)
        row['delivery_classification']='legitimate'
        row['baseline_complete']=True
        self.assertEqual(baseline(row),'spam')
        self.assertEqual(policy_outcome(row),'legitimate')
        self.assertEqual(paired_comparison([row])['baseline']['tp'],1)

    def test_missing_is_not_zero_false_positive_evidence(self):
        row=self.row('never-run'); row['rspamd']=None
        report=paired_comparison([row])
        self.assertEqual(report['messages'],0)
        self.assertIsNone(report['rspamd']['recall'])
        self.assertIsNone(report['rspamd']['fpr'])

    def test_conflicting_campaign_label_is_not_hidden_by_missing_rspamd(self):
        a=self.row('campaign-a')
        b=copy.deepcopy(a); b.update(id='campaign-b',risk='spam',rspamd=None)
        report=paired_comparison([a,b])
        self.assertEqual(report['messages'],1)
        self.assertEqual(report['campaigns']['count'],0)
        self.assertEqual(report['campaigns']['conflicting'],1)

    def test_both_engines_use_the_same_campaign_representative(self):
        a=self.row('a','spam','unwanted','no action')
        b=copy.deepcopy(a); b.update(id='b',observed_at=101)
        b['legacy_decision']['outcome']='legitimate';b['rspamd']['action']='reject'
        report=paired_comparison([b,a])
        self.assertEqual(report['campaigns']['count'],1)
        self.assertEqual(report['campaigns']['baseline']['tp'],1)
        self.assertEqual(report['campaigns']['rspamd']['fn'],1)


if __name__=='__main__': unittest.main()
