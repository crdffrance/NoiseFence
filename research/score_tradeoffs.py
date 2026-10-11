"""Historical index diagnostics, never a policy replay or threshold activation."""
from collections import defaultdict
from recorded_decisions import raw_score
from quality_metrics import outcomes

THRESHOLDS = (50., 80., 90., 95., 97., 99., 99.5, 99.9, 100.)


def score_tradeoffs(rows, usable, protocol):
    """Keep artifact and recorded LLM feature states separate.

    Only independently prepared usable observations establish a cohort. These
    diagnostics ignore policy guards and cannot qualify an operating threshold.
    """
    observations = {r['id']: r for r in usable}
    states = [(i, f['name'].removeprefix('llm.state.'))
              for i, f in enumerate(protocol['features'])
              if f['name'].startswith('llm.state.')]
    groups = defaultdict(list)
    excluded = defaultdict(int)
    for row in rows:
        if row.get('risk') not in ('legitimate', 'spam'):
            excluded['unlabelled_or_uncertain'] += 1
            continue
        observed = observations.get(row['id'])
        if observed is None:
            excluded['incompatible_or_unusable_observation'] += 1
            continue
        score = raw_score(row)
        if score is None:
            excluded['missing_score'] += 1
            continue
        q = observed['quality']
        active = [name for i, name in states if q['values'][i] == 1]
        state = active[0] if len(active) == 1 else 'not_recorded'
        groups[(q['artifacts_sha256'], state)].append((row, score))
    profiles = []
    ordered = sorted(groups.items(), key=lambda item: (-len(item[1]), item[0]))
    for (cohort, state), group in ordered[:16]:
        labels = [int(row['risk'] == 'spam') for row, _ in group]
        curve = []
        for threshold in THRESHOLDS:
            m = outcomes(labels, ['spam' if score >= threshold else 'legitimate'
                                  for _, score in group])
            curve.append({'threshold': threshold, 'metrics': m})
        profiles.append({
            'cohort': cohort, 'llm_state': state, 'messages': len(group),
            'wanted': labels.count(0), 'unwanted': labels.count(1),
            'saturated': sum(score >= 99.9 for _, score in group),
            'points': curve,
            'empirical_target_possible': any(
                p['metrics']['fpr'] is not None and p['metrics']['recall'] is not None
                and p['metrics']['fpr'] <= .001 and p['metrics']['recall'] >= .95
                for p in curve) if 0 in labels and 1 in labels else None,
        })
    if len(ordered) > 16:
        excluded['profile_display_limit'] += sum(len(group) for _, group in ordered[16:])
    return {'schema': 'noisefence-score-tradeoffs-1', 'profiles': profiles,
            'excluded': dict(excluded), 'may_activate': False,
            'scope': 'historical_index_only_not_policy_replay',
            'limitations': [
                'Scores are historical indices, not calibrated spam probabilities.',
                'Threshold-only projections omit antivirus, evidence guards and recipient rules.',
                'Repeated campaigns are correlated; message intervals do not establish independence.',
                'Observed LLM states are different populations, not simulated LLM-off outcomes.',
                'The historical skipped feature can combine reasons; it does not identify expired pricing or budget exhaustion.',
                'An empirical target on this sample never qualifies a production threshold.',
            ]}
