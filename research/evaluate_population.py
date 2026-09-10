#!/usr/bin/env python3
"""Evaluate protocol-selected frozen candidates on every row of an SMTP population.

No fitting, content access, network requests, activation or mail delivery. Native
Rust predictions are bound to the population and model bytes. Unknown evidence
is not a negative prediction. Review declarations require a human provenance audit.
"""
import argparse
from collections import Counter, defaultdict
import hashlib
from pathlib import Path
import subprocess
import time

import train_fusion as f

SCHEMA = 'noisefence-population-evaluation-1'
PREDICTIONS = 'noisefence-population-predictions-1'
LABELS = ('legit', 'spam', 'phishing', 'unwanted_binary', 'uncertain')


def groups(rows):
    """Exact identity/body, declared campaigns and SimHash <=3, transitively.

    Missing values never become shared keys or fabricated hashes. A row with a
    missing SimHash can still connect other rows by exact or reviewed provenance.
    """
    f.require(len(rows) <= 200_000, 'Too many campaign history rows')
    parents = list(range(len(rows)))

    def find(i):
        while parents[i] != i:
            parents[i] = parents[parents[i]]
            i = parents[i]
        return i

    def union(i, j):
        i, j = find(i), find(j)
        parents[max(i, j)] = min(i, j)

    exact, hashes, bands = {}, {}, defaultdict(list)
    comparisons = 0
    for i, row in enumerate(rows):
        for field in ('id', 'raw_sha256', 'fingerprint', 'campaign'):
            value = row.get(field)
            f.require(value is None or f.is_hex(value), 'Invalid campaign provenance')
            if value is not None:
                key = (field, value)
                if key in exact:
                    union(i, exact[key])
                exact[key] = i
        value = row.get('simhash')
        f.require(value is None or f.is_hex(value, 16), 'Invalid campaign SimHash')
        if value is None:
            continue
        value = int(value, 16)
        if value in hashes:
            union(i, hashes[value])
            continue
        neighbors = set()
        for band in range(4):
            neighbors.update(bands[(band, (value >> (16 * band)) & 65535)])
        for previous in neighbors:
            comparisons += 1
            f.require(comparisons <= 5_000_000, 'Campaign comparison budget exceeded')
            if bin(value ^ previous).count('1') <= 3:
                union(i, hashes[previous])
        hashes[value] = i
        for band in range(4):
            bands[(band, (value >> (16 * band)) & 65535)].append(value)
    result = defaultdict(list)
    for i in range(len(rows)):
        result[find(i)].append(i)
    return list(result.values())


def independent_groups(rows, history):
    result = []
    for group in groups(rows + history):
        current = [i for i in group if i < len(rows)]
        if current:
            f.require(len(current) == len(group), 'Population overlaps fitting, calibration or a previous test campaign')
            result.append(current)
    return result


def annotate(rows, annotations, reviewed_at):
    f.require(len(rows) == len(annotations), 'Annotations must cover every population row')
    by_id = {}
    for a in annotations:
        f.require(isinstance(a, dict) and set(a) == {'id', 'label', 'campaign', 'language', 'kind',
                  'basis', 'review_reference', 'reviewed_at'} and f.is_hex(a['id']) and a['id'] not in by_id
                  and a['label'] in LABELS and (a['campaign'] is None or f.is_hex(a['campaign']))
                  and f.token(a['language']) and f.token(a['kind']), 'Invalid population annotation')
        by_id[a['id']] = a
    result = []
    for row in rows:
        a = by_id.get(row['id'])
        f.require(a is not None, 'Missing population annotation')
        known = a['label'] != 'uncertain'
        truth = row['label']
        if not known:
            f.require(a['basis'] == 'unresolved' and a['review_reference'] is None and a['reviewed_at'] is None,
                      'Uncertain annotations must remain unresolved')
        else:
            f.require(a['basis'] in ('feedback', 'reviewed', 'adjudicated')
                      and isinstance(a['review_reference'], str) and 0 < len(a['review_reference']) <= 2000
                      and type(a['reviewed_at']) is int and row['observed_at'] <= a['reviewed_at'] <= reviewed_at,
                      'Certain annotations need human review provenance')
            consensus = truth['status'] == 'consensus'
            agrees = consensus and truth['unwanted'] == (a['label'] != 'legit')
            if a['basis'] == 'feedback':
                f.require(agrees and a['reviewed_at'] >= truth['labelled_at'], 'Annotation conflicts with feedback')
            elif a['basis'] == 'reviewed':
                f.require(truth['status'] == 'unlabelled' or agrees, 'Conflicting labels require explicit adjudication')
        result.append({**row, **a, 'spam': a['label'] != 'legit' if known else None})
    return result


def outcome_metrics(rows, predictions, campaign_groups):
    f.require(len(rows) == len(predictions) and all(p is None or type(p) is bool for p in predictions),
              'Invalid population prediction coverage')
    labelled = [i for i, r in enumerate(rows) if r['spam'] is not None]
    assessed = [i for i in labelled if predictions[i] is not None]
    unknown = [i for i in labelled if predictions[i] is None]
    conditional = f.metrics([rows[i]['spam'] for i in assessed], [predictions[i] for i in assessed])
    # A missing result is FP for legitimate truth and FN for unwanted truth in
    # this conservative bound. It is never silently counted as a true negative.
    worst = [predictions[i] if predictions[i] is not None else not rows[i]['spam'] for i in labelled]
    conservative = f.metrics([rows[i]['spam'] for i in labelled], worst)
    campaign_labels, campaign_predictions = [], []
    unresolved = mixed = 0
    for group in campaign_groups:
        labels = {rows[i]['spam'] for i in group}
        if None in labels:
            unresolved += 1
            continue
        if len(labels) != 1:
            mixed += 1
            continue
        unwanted = next(iter(labels))
        values = [predictions[i] if predictions[i] is not None else not unwanted for i in group]
        # Any FP spoils a legitimate campaign; all copies must be captured in an
        # unwanted campaign. This is a conservative stability metric, not recall
        # of one randomly selected representative or a cluster bootstrap.
        campaign_labels.append(unwanted)
        campaign_predictions.append(all(values) if unwanted else any(values))
    return {'population': len(rows), 'labelled': len(labelled), 'unknown_truth': len(rows)-len(labelled),
            'assessed_with_truth': len(assessed), 'unassessable': sum(p is None for p in predictions),
            'unassessable_with_truth': len(unknown),
            'unassessable_legit': sum(not rows[i]['spam'] for i in unknown),
            'unassessable_unwanted': sum(rows[i]['spam'] for i in unknown),
            'conditional_on_assessed_and_labelled': conditional,
            'conservative_on_known_truth': conservative,
            'campaigns': {'total': len(campaign_groups), 'unresolved_truth': unresolved, 'mixed_truth': mixed,
                          'conservative_stability': f.metrics(campaign_labels, campaign_predictions)}}


def target_supported(result, rows, sampling, review):
    if (sampling['kind'] != 'representative' or not review['blinded'] or not review['independent_campaigns']
            or result['unknown_truth'] or result['unassessable']
            or result['campaigns']['unresolved_truth'] or result['campaigns']['mixed_truth']
            or any(r.get(k) is None for r in rows for k in ('campaign', 'fingerprint', 'simhash'))):
        return False
    for m in (result['conservative_on_known_truth'], result['campaigns']['conservative_stability']):
        if (m['tn']+m['fp'] < 10_000 or m['tp']+m['fn'] < 2_000
                or m['recall_ci95'][0] < .95 or m['fpr_ci95'][1] > f.TARGET_FPR):
            return False
    return True


def checked_predictions(path, population_hash, model_hash, manifest_hash, protocol=None):
    if protocol is None:
        protocol = f.protocol_for_hash(f.PROTOCOL_HASH)
    data = list(f.lines(path, max_line=16 * 1024 * 1024))
    f.require(len(data) >= 2, 'Missing native population prediction envelope')
    header, footer = data[0], data[-1]
    f.require(set(header) == {'type', 'schema', 'source', 'protocol_sha256', 'model_sha256',
              'manifest_sha256', 'hypothetical', 'production_eligible'}
              and header['type'] == 'header' and header['schema'] == PREDICTIONS
              and header['protocol_sha256'] == protocol.sha256 and header['model_sha256'] == model_hash
              and header['manifest_sha256'] == manifest_hash and header['hypothetical'] is True
              and header['production_eligible'] is False, 'Native prediction model binding mismatch')
    f.require(set(footer) == {'type', 'schema', 'population_sha256', 'source_counts', 'counts'}
              and footer['type'] == 'footer' and footer['schema'] == PREDICTIONS
              and footer['population_sha256'] == population_hash, 'Native prediction population binding mismatch')
    rows = data[1:-1]
    counts = footer['counts']
    f.require(set(counts) == {'rows', 'assessed', 'unassessable', 'artifact_mismatch', 'ineligible_to_tag',
              'unsupported_profiles', 'would_tag'} and all(type(v) is int and 0 <= v <= f.MAX_ROWS for v in counts.values())
              and counts['rows'] == len(rows) == counts['assessed']+counts['unassessable']
              and footer['source_counts']['exported'] == len(rows), 'Native prediction coverage mismatch')
    seen, actual = set(), Counter()
    for r in rows:
        f.require(set(r) == {'type', 'id', 'observed_at', 'raw_sha256', 'fingerprint', 'simhash', 'complete',
                  'features_complete', 'decision', 'tagged', 'label', 'evidence_status', 'availability_profile',
                  'assessment', 'prediction'} and r['type'] == 'row' and f.is_hex(r['id']) and r['id'] not in seen,
                  'Invalid native population row')
        seen.add(r['id'])
        p = r['prediction']
        if p is None:
            statuses = ('missing_or_invalid_evidence', 'artifact_mismatch')
            if protocol.version == 2:
                statuses += ('missing_local_evidence', 'invalid_local_evidence')
            f.require(r['assessment'] in statuses, 'Unknown assessment status')
            if r['assessment'] == 'missing_local_evidence':
                f.require(r['availability_profile'] is None, 'Missing local evidence cannot supply a profile')
            actual['unassessable'] += 1
            actual['artifact_mismatch'] += r['assessment'] == 'artifact_mismatch'
        else:
            f.require(r['assessment'] == 'assessed' and set(p) == {'version', 'logit', 'probability', 'above_threshold',
                      'profile_supported', 'tag_eligible', 'would_tag', 'contributions'}
                      and f.token(p['version']) and f.numeric(p['logit']) and f.numeric(p['probability'])
                      and 0 <= p['probability'] <= 1 and all(type(p[k]) is bool for k in
                          ('above_threshold', 'profile_supported', 'tag_eligible', 'would_tag'))
                      and p['would_tag'] == (p['above_threshold'] and p['profile_supported'] and p['tag_eligible']),
                      'Invalid native decision')
            actual['assessed'] += 1
            actual['ineligible_to_tag'] += not p['tag_eligible']
            actual['unsupported_profiles'] += not p['profile_supported']
            actual['would_tag'] += p['would_tag']
    actual['rows'] = len(rows)
    f.require(all(counts[k] == actual[k] for k in counts), 'Native prediction counters mismatch')
    return header, rows, footer


def evaluate(manifest_path, output):
    raw = f.bound_bytes(manifest_path, 64 * 1024)
    manifest = f.decode(raw)
    f.require(set(manifest) == {'schema', 'population', 'annotations', 'experiment', 'fit', 'models', 'binary',
              'sampling', 'review'} and manifest['schema'] == SCHEMA, 'Invalid population evaluation manifest')
    root = manifest_path.parent
    pins = {key: manifest[key] for key in ('population', 'annotations', 'experiment', 'fit', 'binary')}
    paths = {key: f.pinned_path(root, pin) for key, pin in pins.items()}
    original, experiment_hash, artifacts, selected_rows, audit, context = f.load_experiment_context(paths['experiment'])
    del selected_rows
    protocol = context.protocol
    f.require(isinstance(manifest['models'], dict) and set(manifest['models']) == set(protocol.variant_names),
              'Freeze exactly the variants selected by the experiment protocol')
    pins.update({name: manifest['models'][name] for name in protocol.variant_names})
    paths.update({name: f.pinned_path(root, pins[name]) for name in protocol.variant_names})

    def recheck():
        f.require(f.bound_bytes(manifest_path, 64 * 1024) == raw, 'Population manifest changed')
        for key, pin in pins.items():
            f.require(f.pinned_path(root, pin) == paths[key], 'Pinned path changed')
        for key in ('vectors', 'annotations', 'base_history'):
            f.pinned_path(paths['experiment'].parent, original[key])

    receipt = f.decode(f.bound_bytes(paths['fit'], 2 * 1024 * 1024))
    f.require(receipt['schema'] == 'noisefence-fusion-fit-1' and receipt['manifest_sha256'] == experiment_hash
              and receipt['protocol_sha256'] == protocol.sha256 and set(receipt['models_sha256']) == set(protocol.variant_names),
              'Frozen fit receipt mismatch')
    for variant in protocol.variant_names:
        model = f.decode(f.bound_bytes(paths[variant], 128 * 1024))
        f.validate_model(model, context)
        f.require(pins[variant]['sha256'] == receipt['models_sha256'][variant]
                  and model['manifest_sha256'] == experiment_hash and model['artifacts'] == artifacts,
                  'Frozen model changed')

    sampling, review = manifest['sampling'], manifest['review']
    f.require(isinstance(sampling, dict) and set(sampling) == {'kind', 'description', 'authorization', 'start_at', 'end_at'}
              and sampling['kind'] in ('synthetic', 'corrections', 'representative')
              and all(isinstance(sampling[k], str) and 0 < len(sampling[k]) <= 2000 for k in ('description', 'authorization'))
              and type(sampling['start_at']) is int and type(sampling['end_at']) is int
              and 0 < sampling['start_at'] < sampling['end_at'], 'Missing sampling provenance')
    f.require(isinstance(review, dict) and set(review) == {'reference', 'reviewed_at', 'blinded', 'independent_campaigns'}
              and isinstance(review['reference'], str) and 0 < len(review['reference']) <= 2000
              and type(review['reviewed_at']) is int and 0 < review['reviewed_at'] <= int(time.time())
              and type(review['blinded']) is bool and type(review['independent_campaigns']) is bool, 'Missing review provenance')

    # Include ALL source rows, not just selected representatives or train rows.
    original_root = paths['experiment'].parent
    annotations = {a['id']: a for a in f.lines(f.pinned_path(original_root, original['annotations']))}
    history = [{'id': r['id'], 'fingerprint': r['fingerprint'], 'simhash': r['simhash'],
                'campaign': annotations[r['id']]['campaign']} for r in
               f.lines(f.pinned_path(original_root, original['vectors'])) if r['type'] == 'row']
    history += f.decode(f.bound_bytes(f.pinned_path(original_root, original['base_history']), 32 * 1024 * 1024))['rows']
    new_annotations = list(f.lines(paths['annotations'], f.MAX_ROWS))
    recheck()
    f.require(not output.exists(), 'Output already exists; keep the evaluation immutable')
    # A receipt in the frozen fit directory also prevents accidental retesting in
    # a different output directory. Copying a fit directory cannot restore blindness.
    registry = paths['fit'].parent / 'population-tests'
    registry.mkdir(mode=0o700, exist_ok=True)
    consumed = registry / (pins['population']['sha256'] + '.json')
    f.private_json(consumed, {'schema': SCHEMA, 'test_consumed': True, 'started_at': int(time.time()),
                   'manifest_sha256': hashlib.sha256(raw).hexdigest(), 'pins': pins})
    output.mkdir(parents=True, mode=0o700)
    f.private_json(output/'started.json', f.decode(consumed.read_bytes()))
    results, first = {}, None
    for variant in protocol.variant_names:
        recheck()
        prediction_path = output / (variant + '.predictions.jsonl')
        # Never invoke a shell; the executable itself is a reviewed, pinned input.
        subprocess.run([str(paths['binary']), 'fusion-population-predict', str(paths['population']),
                        '--model', str(paths[variant]), '--output', str(prediction_path)],
                       check=True, stdout=subprocess.DEVNULL, timeout=300)
        header, native_rows, footer = checked_predictions(prediction_path, pins['population']['sha256'],
                                                         pins[variant]['sha256'], experiment_hash, protocol)
        source = header['source']
        f.require(source['since'] == sampling['start_at'] and source['until'] == sampling['end_at']
                  and source['captured_at'] <= review['reviewed_at'], 'Reviewed sampling interval differs from snapshot')
        rows = annotate(native_rows, new_annotations, review['reviewed_at'])
        campaign_groups = independent_groups(rows, history)
        common = [{k: v for k, v in r.items() if k not in ('assessment', 'prediction')} for r in rows]
        if first is None:
            first = (common, footer['source_counts'])
        else:
            f.require(first == (common, footer['source_counts']), 'Population changed between variants')
        predictions = [r['prediction']['would_tag'] if r['prediction'] is not None else None for r in rows]
        metrics = outcome_metrics(rows, predictions, campaign_groups)
        strata = {}
        for field in ('language', 'kind', 'label', 'evidence_status', 'assessment', 'availability_profile'):
            strata[field] = {}
            for value in sorted({r[field] for r in rows}, key=lambda v: (v is not None, v or '')):
                indices = [i for i, r in enumerate(rows) if r[field] == value]
                subset = [rows[i] for i in indices]
                strata[field]['<missing>' if value is None else value] = outcome_metrics(
                    subset, [predictions[i] for i in indices], groups(subset))
        results[variant] = {'metrics': metrics, 'native_counts': footer['counts'], 'by_stratum': strata,
                            'predictions_sha256': hashlib.sha256(f.bound_bytes(prediction_path, f.MAX_BYTES)).hexdigest(),
                            'target_supported_on_this_population': target_supported(metrics, rows, sampling, review)}
        recheck()
    report = {'schema': SCHEMA, 'manifest_sha256': hashlib.sha256(raw).hexdigest(), 'pins': pins,
              'sampling': sampling, 'review': review, 'source_counts': first[1], 'fit_audit': audit,
              'variants': results, 'test_consumed': True, 'production_eligible': False,
              'limitations': [
                  'Hypothetical fixed-observation predictions, assuming valid promotion, tag mode and Proton compatibility.',
                  'Unassessable evidence is unknown, not a legitimate prediction; conservative bounds apply to known truth only.',
                  'Message Wilson intervals assume independent messages; campaign copies can violate that assumption.',
                  'Campaign stability is conservative and its intervals still assume audited independent campaigns.',
                  'Reviews and complete history are human attestations; hashes cannot prove their truth or prevent copying/retesting.',
                  'Native v1 export DSN and invalid_scan counts can only be bounded, not reconstructed per row.',
                  'Accepted retained mail only, excluding SMTP refusals and already expired metadata.',
                  'Ablations freeze observations and LLM selection; no end-to-end latency or final Proton folder is measured.',
              ]}
    f.private_json(output/'report.json', report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('manifest', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    report = evaluate(args.manifest.resolve(), args.output.resolve())
    print(f"Population: {report['source_counts']['exported']}; production_eligible=false; {args.output/'report.json'}")


if __name__ == '__main__':
    main()
