"""Recorded policy results are distinct from engine predictions and delivery completion."""
import math
from collections import Counter

SCHEMA = 'noisefence-quality-decisions-1'
OUTCOMES = {'unwanted', 'legitimate', 'undetermined'}
CATEGORIES = {'spam', 'publicity', 'legitimate', 'undetermined'}
ACTIONS = {'deliver', 'tag', 'quarantine'}


def validate_snapshot(row, required=False):
    if 'decision_snapshot' not in row:
        if required:
            raise ValueError('Missing recorded decision contract')
        return None
    s = row['decision_snapshot']
    if not isinstance(s, dict) or s.get('schema') != SCHEMA or s.get('provenance') not in {
        'recipient_receipt', 'analysis_receipt', 'legacy', 'invalid'
    } or set(s) != {'schema', 'provenance', 'engine', 'final', 'action'}:
        raise ValueError('Invalid recorded decision contract')
    if s['provenance'] == 'invalid':
        if any(s[k] is not None for k in ('engine', 'final', 'action')):
            raise ValueError('Invalid recorded decision cannot supply results')
        return s
    def score(v):
        return v is None or type(v) in (int, float) and math.isfinite(v) and 0 <= v <= 100
    e, f, a = s['engine'], s['final'], s['action']
    if e is not None and (not isinstance(e, dict) or set(e) != {'source', 'outcome', 'complete', 'raw_score'} or e.get('outcome') not in OUTCOMES
        or e.get('source') not in {'legacy', 'fusion', 'antivirus'}
        or type(e.get('complete')) is not bool or 'raw_score' not in e or not score(e['raw_score'])):
        raise ValueError('Invalid recorded engine result')
    if not isinstance(f, dict) or set(f) != {'category', 'classification', 'classification_source', 'complete', 'score'} or f.get('category') not in CATEGORIES or f.get('classification') not in {
        None, 'legitimate', 'publicity', 'spam', 'phishing', 'malware', 'unassessed'
    } or f.get('classification_source') not in {
        'score_threshold', 'recipient_policy', 'recorded_decision', 'historical_fallback'
    } or type(f.get('complete')) is not bool or 'score' not in f or not score(f['score']):
        raise ValueError('Invalid recorded policy result')
    if a is not None and (not isinstance(a, dict) or set(a) != {'requested', 'effective'} or a.get('requested') not in ACTIONS or a.get('effective') not in ACTIONS):
        raise ValueError('Invalid recorded action')
    if s['provenance'] == 'recipient_receipt' and f['classification'] is None:
        raise ValueError('Recipient receipt requires its recorded classification')
    category = {'legitimate': 'legitimate', 'publicity': 'publicity',
                'spam': 'spam', 'phishing': 'spam', 'malware': 'spam'}.get(f['classification'])
    if category is not None and category != f['category']:
        raise ValueError('Contradictory recorded classification')
    return s


def engine_decision(row):
    s = validate_snapshot(row)
    value = s['engine'] if s is not None else row.get('legacy_decision')
    return value if isinstance(value, dict) and value.get('outcome') in OUTCOMES else None


def engine_outcome(row):
    return {'unwanted': 'spam', 'legitimate': 'legitimate'}.get((engine_decision(row) or {}).get('outcome'), 'review')


def raw_score(row):
    s = validate_snapshot(row)
    value = (s['engine'] or {}).get('raw_score') if s is not None else row.get('legacy_score')
    return value if type(value) in (int, float) and math.isfinite(value) and 0 <= value <= 100 else None


def policy_outcome(row):
    s = validate_snapshot(row)
    if s is not None:
        final = s['final']
        if final is None or final.get('classification') == 'unassessed':
            return 'review'
        return {'spam': 'spam', 'publicity': 'legitimate', 'legitimate': 'legitimate'}.get(final['category'], 'review')
    decision = engine_decision(row) or {}
    if decision.get('source') == 'antivirus':
        return engine_outcome(row)
    # A completed explicit verdict survives unrelated incomplete coverage. Never
    # reconstruct missing decisions by comparing an old score to today's cutoff.
    category = row.get('delivery_classification')
    if category in CATEGORIES:
        return {'spam': 'spam', 'publicity': 'legitimate', 'legitimate': 'legitimate'}.get(category, 'review')
    return engine_outcome(row)


def policy_report(rows):
    from quality_metrics import outcomes
    labelled = [r for r in rows if r.get('risk') in ('legitimate', 'spam')]
    result = {'classification': outcomes([int(r['risk'] == 'spam') for r in labelled], [policy_outcome(r) for r in labelled]),
              'records': len(labelled), 'snapshots': 0, 'legacy_without_snapshot': 0, 'invalid_snapshots': 0,
              'requested_actions': {}, 'effective_actions': {}, 'action_transitions': []}
    counts = {stage: {label: Counter() for label in ('legitimate', 'spam')} for stage in ('requested', 'effective')}
    transitions = Counter()
    for row in labelled:
        s = validate_snapshot(row)
        result['legacy_without_snapshot' if s is None else 'invalid_snapshots' if s['provenance'] == 'invalid' else 'snapshots'] += 1
        action = s['action'] if s else None
        for stage in counts:
            counts[stage][row['risk']][action[stage] if action else 'not_recorded'] += 1
        if action:
            transitions[(action['requested'], action['effective'])] += 1
    for stage in counts:
        result[stage + '_actions'] = {label: dict(values) for label, values in counts[stage].items()}
    result['action_transitions'] = [{'requested': a, 'effective': b, 'records': n} for (a, b), n in sorted(transitions.items())]
    result['scope'] = 'recorded_policy_intentions_not_confirmed_delivery'
    result['independent_validation'] = False
    return result
