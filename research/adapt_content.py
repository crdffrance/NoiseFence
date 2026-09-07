#!/usr/bin/env python3
"""Compare content augmentation on frozen train/development partitions only.

No test/calibration predictions, network calls or automatic activation. Inputs,
candidate grid and selection rule are frozen before fitting. Source names and
labels select partitions/weights only; neither is a detector feature.
"""
import argparse
from collections import Counter
import json
import math
import os
from pathlib import Path
import time
import warnings

import numpy as np
from scipy import sparse
from sklearn.exceptions import ConvergenceWarning
from sklearn.feature_extraction.text import TfidfTransformer
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import normalize

from train_linear import cutoff, digest, load, metrics, partition

DIMENSION = 262144
PROTOCOL = json.loads(Path(__file__).with_name('semantic-protocol.json').read_text())


def validate_rows(rows):
    if not rows:
        raise ValueError('Empty development experiment')
    groups, identities = set(), set()
    expected = partition(rows)
    for name in ('calibration', 'test', 'external'):
        if len(expected[name]):
            raise ValueError('Reserved holdout groups cannot enter this experiment')
    for name in ('train', 'development'):
        for index in expected[name]:
            if rows[index].get('partition') != name:
                raise ValueError('Declared partition differs from frozen group hash')
    for row in rows:
        group, key = row.get('group'), row.get('raw_sha256')
        if (not isinstance(group, str) or not isinstance(key, str) or len(key) != 64
                or any(c not in '0123456789abcdef' for c in key)
                or group in groups or key in identities):
            raise ValueError('Missing or duplicate campaign/raw identity')
        groups.add(group)
        identities.add(key)
        if row.get('feature_version') != 3 or not isinstance(row.get('stratum'), str) or not row['stratum']:
            raise ValueError('Feature schema and evaluation stratum required')
    for stratum in {row['stratum'] for row in rows}:
        for name in ('train', 'development'):
            labels = {row['spam'] for row in rows if row['stratum'] == stratum and row['partition'] == name}
            if labels != {False, True}:
                raise ValueError('Every stratum/partition needs both classes')


def load_vectors(directory, rows):
    protocol = json.loads((directory/'protocol.json').read_text())
    if (not protocol.get('complete') or any(protocol.get(k) != v for k, v in PROTOCOL.items())
            or digest(directory/'embeddings.npy') != protocol.get('embeddings_sha256')
            or digest(directory/'ids.json') != protocol.get('ids_sha256')):
        raise ValueError('Incomplete, altered or incompatible encoder inputs')
    ids = json.loads((directory/'ids.json').read_text())
    if len(set(ids)) != len(ids) or set(ids) != {row['raw_sha256'] for row in rows}:
        raise ValueError('Vector identities must match train/development exactly')
    vectors = np.load(directory/'embeddings.npy', mmap_mode='r', allow_pickle=False)
    if (vectors.dtype != np.float32 or vectors.shape != (len(ids), PROTOCOL['dimensions'])
            or not np.isfinite(vectors).all()
            or np.any(np.abs(np.linalg.norm(vectors, axis=1)-1) >= .001)):
        raise ValueError('Invalid encoder vectors')
    positions = {key: index for index, key in enumerate(ids)}
    return np.asarray(vectors[[positions[row['raw_sha256']] for row in rows]], dtype=np.float64)


def evaluate(labels, logits, strata, target):
    """One cutoff must respect the empirical FP budget in every stratum."""
    threshold = max(cutoff(labels[strata == name], logits[strata == name], target)
                    for name in sorted(set(strata)))
    by_stratum = {name: metrics(labels[strata == name], logits[strata == name], threshold)
                  for name in sorted(set(strata))}
    recalls = [result['recall'] for result in by_stratum.values()]
    aps = [result['average_precision'] for result in by_stratum.values()]
    return {'threshold_logit': threshold, 'by_stratum': by_stratum,
            'pooled': metrics(labels, logits, threshold),
            'ranking': [min(recalls), float(np.mean(recalls)), float(np.mean(aps))]}


def fit(matrix, labels, c, sample_weight):
    with warnings.catch_warnings():
        warnings.simplefilter('error', ConvergenceWarning)
        estimator = LogisticRegression(C=c, solver='liblinear', max_iter=2000,
                                       tol=1e-6, random_state=20260907)
        estimator.fit(matrix, labels, sample_weight=sample_weight)
    return estimator.coef_[0].copy(), float(estimator.intercept_[0])


def validate_grid(grid, strata):
    required = {'augmentation_strata', 'sample_weights', 'lexical_C', 'semantic_C',
                'semantic_weights', 'lexical_families', 'target_fpr'}
    if set(grid) != required:
        raise ValueError('Unexpected candidate grid schema')
    if (not grid['augmentation_strata'] or not set(grid['augmentation_strata']) < set(strata)
            or not set(grid['lexical_families']) <= {'tfidf_logistic', 'nb_logistic'}
            or not grid['lexical_families']):
        raise ValueError('Invalid augmentation strata or lexical families')
    if type(grid['target_fpr']) not in (int, float) or not 0 <= grid['target_fpr'] <= .001:
        raise ValueError('FPR target must be within 0..0.1%')
    for key in ('sample_weights', 'lexical_C', 'semantic_C', 'semantic_weights'):
        values = grid[key]
        if (not isinstance(values, list) or not 1 <= len(values) <= 10
                or any(type(v) not in (int, float) or not math.isfinite(v) or
                       not (0 <= v <= 1000 if key == 'semantic_weights' else 0 < v <= 1000) for v in values)):
            raise ValueError('Invalid or oversized grid')
    fits = len(grid['sample_weights'])*(len(grid['lexical_C'])*len(grid['lexical_families'])+len(grid['semantic_C']))
    if fits > 100:
        raise ValueError('Candidate grid exceeds fit budget')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('features', type=Path)
    parser.add_argument('embeddings', type=Path)
    parser.add_argument('grid', type=Path)
    parser.add_argument('baseline_model', type=Path)
    parser.add_argument('baseline_combination', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    grid = json.loads(args.grid.read_text())
    args.output.mkdir(parents=True, exist_ok=False)
    specification = {
        'schema': 'noisefence-content-adaptation-1', 'created': int(time.time()), 'grid': grid,
        'selection': 'Maximize worst-stratum development recall, then macro recall, then macro AP. One shared cutoff respects empirical FPR target within every stratum.',
        'partition': 'Frozen group-hash train/development only; no calibration/test/external predictions.',
        'idf': 'Fit on unique training rows only, independent of source sample weights.',
        'scope': 'Private content experiment. Development selection is not production validation; source licensing applies to all derived artifacts.',
        'inputs_sha256': {str(path): digest(path) for path in [args.features, args.grid,
            args.baseline_model, args.baseline_combination, args.embeddings/'protocol.json',
            args.embeddings/'ids.json', args.embeddings/'embeddings.npy']}}
    (args.output/'specification.json').write_text(json.dumps(specification, indent=2)+'\n')
    matrix, rows = load(args.features, DIMENSION)
    validate_rows(rows)
    validate_grid(grid, {row['stratum'] for row in rows})
    vectors = load_vectors(args.embeddings, rows)
    labels = np.asarray([row['spam'] for row in rows], dtype=bool)
    strata = np.asarray([row['stratum'] for row in rows])
    train = np.asarray([row['partition'] == 'train' for row in rows])
    dev = ~train
    augmentation = np.isin(strata[train], grid['augmentation_strata'])
    target = grid['target_fpr']

    baseline_model = json.loads(args.baseline_model.read_text())
    baseline_head = json.loads(args.baseline_combination.read_text())
    if (baseline_head['lexical_model_sha256'] != digest(args.baseline_model)
            or baseline_model['feature_version'] != 3 or baseline_model['algorithm'] != 'logistic'
            or any(baseline_head[k] != PROTOCOL[k] for k in ('encoder', 'revision', 'text_schema', 'max_tokens'))):
        raise ValueError('Baseline models/protocol do not match')
    lexical = np.asarray(normalize(matrix[dev].multiply(baseline_model['idf'])) @ baseline_model['weights']).ravel()+baseline_model['bias']
    hybrid = lexical + baseline_head['semantic_weight']*(vectors[dev] @ baseline_head['head_weights']+baseline_head['head_bias'])+baseline_head['score_bias_delta']
    baselines = {name: {'at_common_development_cutoff': evaluate(labels[dev], logits, strata[dev], target),
        'at_current_threshold': {stratum: metrics(labels[dev][strata[dev] == stratum], logits[strata[dev] == stratum], math.log(19))
                                  for stratum in sorted(set(strata))}}
        for name, logits in [('lexical', lexical), ('hybrid', hybrid)]}

    transformer = TfidfTransformer().fit(matrix[train])
    matrix = transformer.transform(matrix)
    presence = matrix[train].copy()
    presence.data[:] = 1
    xtrain, xdev = matrix[train], matrix[dev]
    dense_train, dense_dev = vectors[train], vectors[dev]
    lexical_candidates, semantic_candidates, fits = [], [], []
    for multiplier in grid['sample_weights']:
        sample_weight = np.where(augmentation, multiplier, 1.)
        weighted = presence.multiply(sample_weight[:, None]).tocsr()
        positive = np.asarray(weighted[labels[train]].sum(axis=0)).ravel()+1
        negative = np.asarray(weighted[~labels[train]].sum(axis=0)).ravel()+1
        ratio = np.log((positive/positive.sum())/(negative/negative.sum()))
        for family in grid['lexical_families']:
            scale = ratio if family == 'nb_logistic' else np.ones(DIMENSION)
            for c in grid['lexical_C']:
                started = time.monotonic()
                weights, bias = fit(xtrain.multiply(scale).tocsr(), labels[train], c, sample_weight)
                weights *= scale
                metadata = {'family': family, 'C': c, 'augmentation_weight': multiplier}
                lexical_candidates.append((metadata, weights, bias, np.asarray(xdev @ weights).ravel()+bias))
                fits.append({**metadata, 'seconds': time.monotonic()-started})
                print(json.dumps({'fitted': fits[-1]}), flush=True)
        for c in grid['semantic_C']:
            started = time.monotonic()
            weights, bias = fit(dense_train, labels[train], c, sample_weight)
            metadata = {'family': 'semantic', 'C': c, 'augmentation_weight': multiplier}
            semantic_candidates.append((metadata, weights, bias, dense_dev @ weights+bias))
            fits.append({**metadata, 'seconds': time.monotonic()-started})
            print(json.dumps({'fitted': fits[-1]}), flush=True)

    best, choices = None, []
    # Record semantic-only ablations without silently changing the native contract,
    # which currently includes lexical with coefficient 1.
    semantic_only = [{'model': meta, 'development': evaluate(labels[dev], logits, strata[dev], target)}
                     for meta, _, _, logits in semantic_candidates]
    for lexical_index, (lm, lw, lb, ll) in enumerate(lexical_candidates):
        variants = [(None, 0.)] + [(i, alpha) for i in range(len(semantic_candidates))
                                  for alpha in grid['semantic_weights'] if alpha > 0]
        for semantic_index, alpha in variants:
            sm, sw, sb, sl = semantic_candidates[semantic_index] if semantic_index is not None else ({}, np.zeros(384), 0., np.zeros(len(ll)))
            logits = ll+alpha*sl
            evaluation = evaluate(labels[dev], logits, strata[dev], target)
            choice = {'lexical': lm, 'semantic': sm, 'semantic_weight': alpha, 'development': evaluation}
            choices.append(choice)
            if best is None or tuple(evaluation['ranking']) > tuple(best[0]['development']['ranking']):
                best = (choice, lw, lb, sw, sb, logits, ll)
    selected, lw, lb, sw, sb, logits, lexical_logits = best
    model = {'version': 'research-content-adaptation-'+str(specification['created']),
             'algorithm': 'logistic', 'feature_version': 3, 'bias': lb,
             'weights': lw.tolist(), 'idf': transformer.idf_.tolist(),
             'trained_at': specification['created'], 'examples': int(train.sum())}
    payload = json.dumps(model, separators=(',', ':'), allow_nan=False)+'\n'
    (args.output/'raw-model.json').write_text(payload)
    head = {'schema': 'noisefence-content-candidate-1', 'head_weights': sw.tolist(), 'head_bias': sb,
            'semantic_weight': selected['semantic_weight'], 'protocol': PROTOCOL,
            'lexical_model_sha256': digest(args.output/'raw-model.json'),
            'threshold_calibrated': False, 'production_eligible': False}
    (args.output/'raw-head.json').write_text(json.dumps(head, indent=2, allow_nan=False)+'\n')
    report = {'specification_sha256': digest(args.output/'specification.json'), 'selected': selected,
              'baselines': baselines, 'semantic_only': semantic_only, 'candidates': choices,
              'fit_timings': fits, 'counts': dict(Counter(row['stratum']+'/'+row['partition'] for row in rows)),
              'calibration_evaluated': False, 'test_evaluated': False, 'production_eligible': False,
              'limitation': 'Source-stratified content development only; synthetic French and historical emails are not a recent representative population. No authentication/reputation/LLM fusion.'}
    (args.output/'development.json').write_text(json.dumps(report, indent=2, allow_nan=False)+'\n')
    with (args.output/'development-predictions.jsonl').open('x') as out:
        for row, ll, hl in zip((r for r in rows if r['partition'] == 'development'), lexical_logits, logits):
            out.write(json.dumps({k:row[k] for k in ('raw_sha256','group','stratum','spam')} |
                      {'lexical_logit':float(ll),'combined_logit':float(hl)})+'\n')
    for path, expected in specification['inputs_sha256'].items():
        if digest(Path(path)) != expected:
            raise ValueError('Experiment input changed while fitting')
    print(json.dumps({'selected': selected, 'test_evaluated': False, 'production_eligible': False}), flush=True)


if __name__ == '__main__':
    main()
