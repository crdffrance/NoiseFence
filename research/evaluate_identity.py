#!/usr/bin/env python3
"""Evaluate identity candidates against separate labels, never full spam verdicts.

No network, training or production writes. Campaign overlap and conflicting labels
are excluded explicitly, not silently averaged into an optimistic result.
"""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
import math
from pathlib import Path


def require(value, message):
    if not value:
        raise ValueError(message)


def bounded(path):
    with Path(path).open('rb') as stream:
        raw = stream.read(64 * 1024 * 1024 + 1)
    require(len(raw) <= 64 * 1024 * 1024, 'Input exceeds 64 MiB')
    return json.loads(raw), hashlib.sha256(raw).hexdigest()


def interval(successes, total):
    if not total:
        return {'numerator': successes, 'denominator': 0, 'rate': None, 'wilson_95': None}
    z = 1.959963984540054
    rate = successes / total
    scale = 1 + z*z/total
    center = (rate + z*z/(2*total)) / scale
    half = z*math.sqrt(rate*(1-rate)/total + z*z/(4*total*total)) / scale
    return {'numerator': successes, 'denominator': total, 'rate': rate,
            'wilson_95': [max(0., center-half), min(1., center+half)]}


def evaluate(result, labels):
    require(result.get('protocol') == 'identity-replay-result-1'
            and result.get('scope') == 'identity_corroboration_not_message_verdict'
            and result.get('mode') == 'walk_forward'
            and result.get('evaluation_labels_used') is False
            and result.get('network_used') is False
            and result.get('production_changed') is False, 'Unknown or unsafe replay contract')
    require(result.get('provenance') in ('synthetic', 'gateway_recorded'), 'Missing input provenance')
    require(labels.get('protocol') == 'identity-evaluation-labels-1'
            and labels.get('provenance') in ('synthetic_fixture', 'human_confirmed'), 'Labels must be synthetic fixtures or human confirmed')
    require(not (result['provenance'] == 'synthetic' and labels['provenance'] != 'synthetic_fixture'),
            'Synthetic results cannot be presented as human-confirmed efficacy')
    boundary = result.get('evaluation_after')
    require(type(boundary) is int and boundary > 0, 'Missing evaluation boundary')
    if result['provenance'] == 'gateway_recorded':
        require(labels.get('input_sha256') == result.get('input_sha256')
                and isinstance(result.get('input_sha256'), str) and len(result['input_sha256']) == 64,
                'Human labels must be bound to the exact replay input digest')
    rows = result.get('rows')
    require(isinstance(rows, list) and 0 < len(rows) <= 4096, 'Invalid replay rows')
    by_id = {}
    previous = 0
    history = set()
    for row in rows:
        require(isinstance(row, dict) and isinstance(row.get('id'), str) and row['id'] not in by_id, 'Missing or duplicate replay ID')
        require(type(row.get('received_at')) is int and row['received_at'] >= previous and row['received_at'] > 0, 'Replay is not chronological')
        previous = row['received_at']
        require(row.get('phase') == ('history' if previous < boundary else 'evaluation'), 'Phase differs from evaluation boundary')
        require(row.get('phase') in ('history', 'evaluation') and type(row.get('campaign_group')) is int and row['campaign_group'] >= 0, 'Invalid replay phase/campaign')
        require(type(row.get('campaign_seen_in_history')) is bool, 'Missing overlap accounting')
        require(row['campaign_seen_in_history'] == (row['campaign_group'] in history), 'Campaign overlap accounting differs')
        if row['phase'] == 'history':
            history.add(row['campaign_group'])
        else:
            candidate = row.get('contribution', {})
            require(type(candidate.get('corroborated')) is bool and candidate.get('status') in ('complete', 'limited', 'unavailable'), 'Invalid candidate evidence')
            weight = candidate.get('applied_weight')
            require(type(weight) in (int, float) and math.isfinite(weight) and 0 <= weight <= 1, 'Invalid bounded contribution')
            require(row.get('observation', {}).get('applied_weight') == 0, 'Observation changed a score')
        by_id[row['id']] = row
    entries = labels.get('cases')
    require(isinstance(entries, list) and len(entries) <= 4096, 'Invalid label set')
    annotated = set()
    groups = defaultdict(list)
    excluded = Counter()
    for label in entries:
        require(isinstance(label, dict) and isinstance(label.get('id'), str) and label['id'] not in annotated, 'Duplicate or invalid label ID')
        annotated.add(label['id'])
        require(label['id'] in by_id, 'Label has no replay result')
        row = by_id[label['id']]
        require(row['phase'] == 'evaluation', 'Evaluation labels must not refer to history')
        require(label.get('label') in ('ham', 'pub', 'spam'), 'Unsupported evaluation label')
        require(isinstance(label.get('family'), str) and 0 < len(label['family']) <= 100, 'Missing evaluation family')
        if row['campaign_seen_in_history']:
            excluded['history_campaign_overlap'] += 1
        else:
            groups[row['campaign_group']].append((row, label))
    excluded['unlabelled_evaluation'] = sum(row['phase'] == 'evaluation' and row['id'] not in annotated for row in rows)
    selected = []
    for group in groups.values():
        if len({label['label'] for _, label in group}) != 1:
            excluded['conflicting_campaign_labels'] += len(group)
            continue
        # One earliest observed message per campaign, selected without looking at
        # candidate status. Report the discarded copies and disagreement count.
        selected.append(min(group, key=lambda pair: (pair[0]['received_at'], pair[0]['id'])))
        excluded['duplicate_campaign_copies'] += len(group) - 1
        if len({row['contribution']['corroborated'] for row, _ in group}) > 1:
            excluded['campaigns_with_differing_candidate_results'] += 1
    counts = Counter()
    families = defaultdict(Counter)
    false_candidates = []
    unwanted_without_candidate = []
    for row, label in selected:
        candidate = row['contribution']['corroborated']
        wanted = label['label'] in ('ham', 'pub')
        counts['wanted' if wanted else 'unwanted'] += 1
        counts['candidates'] += candidate
        counts['wanted_candidates' if wanted else 'unwanted_candidates'] += candidate
        counts['unavailable_correlation'] += row['contribution']['status'] != 'complete'
        families[label['family']]['evaluated_campaigns'] += 1
        families[label['family']]['identity_candidates'] += candidate
        if wanted and candidate:
            false_candidates.append(row['id'])
        if not wanted and not candidate:
            unwanted_without_candidate.append(row['id'])
    return {
        'protocol': 'identity-evaluation-report-1',
        'scope': 'identity_candidates_only_not_full_spam_verdicts',
        'provenance': result['provenance'], 'labels': labels['provenance'],
        'efficacy_qualified': False,
        'independence': 'chronological replay and campaign separation; prior tuning exposure is not attested',
        'evaluated_campaigns': len(selected), 'counts': dict(counts), 'excluded': dict(excluded),
        'candidate_rate_on_wanted': interval(counts['wanted_candidates'], counts['wanted']),
        'candidate_rate_on_unwanted': interval(counts['unwanted_candidates'], counts['unwanted']),
        'candidate_precision': interval(counts['unwanted_candidates'], counts['candidates']),
        'families': {name: dict(value) for name, value in sorted(families.items())},
        'wanted_candidate_ids': false_candidates,
        'unwanted_without_candidate_ids': unwanted_without_candidate,
        'limitations': ['A candidate is at most one additional log-odds unit, not a spam verdict.',
                        'Full-filter capture and false-positive rates are not measured here.',
                        'Synthetic fixtures cannot qualify real-world efficacy.',
                        'Holdout labels are never used to update memory or simulate human feedback.'],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('results')
    parser.add_argument('labels')
    args = parser.parse_args()
    result, result_hash = bounded(args.results)
    labels, labels_hash = bounded(args.labels)
    report = evaluate(result, labels)
    report.update(results_sha256=result_hash, labels_sha256=labels_hash)
    print(json.dumps(report, indent=2, allow_nan=False))


if __name__ == '__main__':
    main()
