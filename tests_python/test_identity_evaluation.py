import copy
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('identity_eval', Path(__file__).resolve().parents[1]/'research/evaluate_identity.py')
evaluation = importlib.util.module_from_spec(spec); spec.loader.exec_module(evaluation)


def row(ident, at, group, candidate=False, phase='evaluation', seen=False):
    return {'id': ident, 'received_at': at, 'phase': phase, 'campaign_group': group,
            'campaign_seen_in_history': seen, 'observation': {'applied_weight': 0},
            'contribution': {'corroborated': candidate, 'applied_weight': int(candidate), 'status': 'complete'}}


def fixture(rows, cases):
    result = {'protocol': 'identity-replay-result-1', 'scope': 'identity_corroboration_not_message_verdict',
              'mode': 'walk_forward', 'provenance': 'synthetic', 'evaluation_labels_used': False,
              'network_used': False, 'production_changed': False, 'rows': rows,
              'evaluation_after': min((r['received_at'] for r in rows if r['phase']=='evaluation'), default=10)}
    labels = {'protocol': 'identity-evaluation-labels-1', 'provenance': 'synthetic_fixture',
              'cases': [{'id': ident, 'label': label, 'family': 'fixture'} for ident, label in cases]}
    return result, labels


class IdentityEvaluationTests(unittest.TestCase):
    def test_wanted_publicity_counts_as_wanted_and_unknown_rates_are_not_zero(self):
        data = fixture([row('ham', 1, 0), row('pub', 2, 1, True), row('spam', 3, 2, True)],
                       [('ham', 'ham'), ('pub', 'pub'), ('spam', 'spam')])
        report = evaluation.evaluate(*data)
        self.assertEqual(report['candidate_rate_on_wanted']['rate'], .5)
        self.assertEqual(report['candidate_precision']['rate'], .5)
        self.assertEqual(report['wanted_candidate_ids'], ['pub'])
        self.assertFalse(report['efficacy_qualified'])
        self.assertIsNone(evaluation.interval(0, 0)['rate'])
        self.assertGreater(evaluation.interval(0, 10)['wilson_95'][1], .2)

    def test_overlap_conflicts_and_duplicates_are_not_optimistic_examples(self):
        rows = [row('history', 1, 0, phase='history'), row('overlap', 2, 0, seen=True),
                row('first', 3, 1, False), row('copy', 4, 1, True),
                row('mixed-a', 5, 2), row('mixed-b', 6, 2, True), row('unlabelled', 7, 3)]
        labels = [('overlap', 'ham'), ('first', 'spam'), ('copy', 'spam'), ('mixed-a', 'ham'), ('mixed-b', 'spam')]
        report = evaluation.evaluate(*fixture(rows, labels))
        self.assertEqual(report['evaluated_campaigns'], 1)
        self.assertEqual(report['candidate_rate_on_unwanted']['rate'], 0.)
        self.assertEqual(report['excluded'], {'history_campaign_overlap': 1, 'unlabelled_evaluation': 1,
                         'duplicate_campaign_copies': 1, 'campaigns_with_differing_candidate_results': 1,
                         'conflicting_campaign_labels': 2})

    def test_malformed_or_leaking_evaluations_are_refused(self):
        result, labels = fixture([row('a', 1, 0)], [('a', 'ham')])
        for mutate in [lambda r,l:r.update(evaluation_labels_used=True),
                       lambda r,l:r.update(provenance='unknown'),
                       lambda r,l:l.update(provenance='human_confirmed'),
                       lambda r,l:l['cases'].append(l['cases'][0]),
                       lambda r,l:l['cases'][0].update(label='rspamd-ham'),
                       lambda r,l:r['rows'][0].update(campaign_seen_in_history=True),
                       lambda r,l:r['rows'][0]['observation'].update(applied_weight=1),
                       lambda r,l:r['rows'][0]['contribution'].update(applied_weight=float('nan'))]:
            r,l=copy.deepcopy(result),copy.deepcopy(labels); mutate(r,l)
            with self.assertRaises(ValueError):evaluation.evaluate(r,l)
        with self.assertRaises(ValueError):
            evaluation.evaluate(*fixture([row('history',1,0,phase='history')],[('history','ham')]))

    def test_unavailable_evidence_stays_in_denominator(self):
        r,l=fixture([row('a',1,0)],[('a','spam')]);r['rows'][0]['contribution']['status']='unavailable'
        out=evaluation.evaluate(r,l)
        self.assertEqual(out['candidate_rate_on_unwanted']['denominator'],1)
        self.assertEqual(out['counts']['unavailable_correlation'],1)

    def test_recorded_inputs_bind_labels_to_the_exact_receipt_history(self):
        r, labels = fixture([row('a', 5, 0)], [('a', 'ham')])
        r.update(provenance='gateway_recorded', input_sha256='a'*64)
        labels.update(provenance='human_confirmed')
        with self.assertRaises(ValueError):
            evaluation.evaluate(r, labels)
        labels['input_sha256'] = 'b'*64
        with self.assertRaises(ValueError):
            evaluation.evaluate(r, labels)
        labels['input_sha256'] = r['input_sha256']
        self.assertEqual(evaluation.evaluate(r, labels)['evaluated_campaigns'], 1)
        r['evaluation_after'] = 6
        with self.assertRaises(ValueError):
            evaluation.evaluate(r, labels)
