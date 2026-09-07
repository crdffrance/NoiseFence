#!/usr/bin/env python3
"""Train a private schema-3 candidate from retained human corrections.

Consumes vectors only: no bodies, network, model hub, Torch or executable pickle.
Correction-only metrics are selection-biased and never authorize activation.
"""
import argparse
from array import array
from collections import defaultdict
import hashlib
import json
import math
import os
from pathlib import Path
import tempfile
import time
import warnings

import numpy as np
from scipy import sparse
from sklearn.exceptions import ConvergenceWarning
from sklearn.feature_extraction.text import TfidfTransformer
from sklearn.linear_model import LogisticRegression

from train_linear import cutoff, metrics, partition

DIMENSION = 262144
PROTOCOL = json.loads(Path(__file__).with_name('semantic-protocol.json').read_text())
MAX_ROWS = 50000
MAX_VALUES = 10000000
MAX_BYTES = 512 * 1024 * 1024


def is_hex(value, length):
    return isinstance(value, str) and len(value) == length and all(c in '0123456789abcdef' for c in value)


def numeric(value):
    return type(value) in (int, float) and math.isfinite(value)


def read_rows(path, hybrid):
    rows, ids, values, consumed = [], set(), 0, 0
    digest = hashlib.sha256()
    with path.open('rb') as source:
        while line := source.readline(16 * 1024 * 1024 + 1):
            consumed += len(line)
            if len(line) > 16 * 1024 * 1024 or consumed > MAX_BYTES or len(rows) >= MAX_ROWS:
                raise ValueError('Feedback export exceeds bounded training input size')
            digest.update(line)
            row = json.loads(line)
            if ('semantic' not in row or row.get('schema') != 'noisefence-learning-1' or row.get('feature_version') != 3
                    or row.get('source') != 'local_human_feedback' or type(row.get('spam')) is not bool
                    or not is_hex(row.get('id'), 64) or not is_hex(row.get('fingerprint'), 64)
                    or not is_hex(row.get('simhash'), 16)
                    or any(type(row.get(k)) is not int or row[k] <= 0 for k in ('observed_at', 'labelled_at'))):
                raise ValueError('Invalid or mixed feedback schema/provenance')
            if row['id'] in ids:
                raise ValueError('Duplicate sample identity')
            ids.add(row['id'])
            pairs = row.get('features')
            if not isinstance(pairs, list) or not pairs or len(pairs) > DIMENSION:
                raise ValueError('Invalid lexical features')
            seen, norm = set(), 0.
            for pair in pairs:
                if not isinstance(pair, list) or len(pair) != 2:
                    raise ValueError('Invalid lexical feature pair')
                i, x = pair
                if type(i) is not int or not 0 <= i < DIMENSION or i in seen or not numeric(x) or not 0 < x <= 1:
                    raise ValueError('Invalid lexical feature index/value')
                seen.add(i)
                norm += x*x
            values += len(pairs)
            if abs(norm - 1) >= .001 or values > MAX_VALUES:
                raise ValueError('Unnormalized or oversized lexical feature matrix')
            semantic = row.get('semantic')
            if hybrid and semantic is None:
                raise ValueError('Hybrid training requires pinned embeddings for every sample')
            if semantic is not None:
                vector = semantic.get('features')
                if (semantic.get('protocol') != PROTOCOL or not isinstance(vector, list)
                        or len(vector) != PROTOCOL['dimensions']
                        or not all(numeric(x) and abs(x) <= 1 for x in vector)
                        or abs(sum(x*x for x in vector) - 1) >= .001):
                    raise ValueError('Invalid or incompatible semantic protocol/vector')
            # An allow-list prevents carrying arbitrary private fields into reports.
            rows.append({k: row[k] for k in ('id', 'observed_at', 'labelled_at', 'spam',
                                            'fingerprint', 'simhash', 'features', 'semantic')})
    return rows, digest.hexdigest()


def group_rows(rows):
    """One representative per transitive canonical/SimHash (distance <=3) group."""
    parents, exact, hashes, buckets = list(range(len(rows))), {}, {}, defaultdict(list)

    def find(i):
        while i != parents[i]:
            parents[i] = parents[parents[i]]
            i = parents[i]
        return i

    def union(a, b):
        a, b = find(a), find(b)
        parents[max(a, b)] = min(a, b)

    comparisons = 0
    for i, row in enumerate(rows):
        key = row['fingerprint']
        if key in exact:
            union(i, exact[key])
        exact[key] = i
        value = int(row['simhash'], 16)
        if value in hashes:
            union(i, hashes[value])
            continue
        neighbors = set()
        for band in range(4):
            neighbors.update(buckets[(band, (value >> (16*band)) & 0xffff)])
        for previous in neighbors:
            comparisons += 1
            if comparisons > 5000000:
                raise ValueError('Campaign grouping exceeded its comparison budget')
            if bin(value ^ previous).count('1') <= 3:
                union(i, hashes[previous])
        hashes[value] = i
        for band in range(4):
            buckets[(band, (value >> (16*band)) & 0xffff)].append(value)
    groups = defaultdict(list)
    for i in range(len(rows)):
        groups[find(i)].append(i)
    selected, conflicts, removed = [], 0, 0
    for indices in groups.values():
        if len({rows[i]['spam'] for i in indices}) != 1:
            conflicts += len(indices)
            continue
        representative = dict(rows[min(indices, key=lambda i: rows[i]['id'])])
        representative['group'] = min(rows[i]['fingerprint'] for i in indices)
        selected.append(representative)
        removed += len(indices)-1
    selected.sort(key=lambda row: row['id'])
    return selected, {'input': len(rows), 'groups': len(groups), 'conflicting_messages': conflicts,
                      'duplicates_removed': removed, 'retained': len(selected)}


def matrix_for(rows):
    columns, values, indptr = array('i'), array('d'), array('i', [0])
    for row in rows:
        for i, x in row['features']:
            columns.append(i)
            values.append(x)
        indptr.append(len(values))
    return sparse.csr_matrix((np.asarray(values), np.asarray(columns), np.asarray(indptr)),
                             shape=(len(rows), DIMENSION))


def fit(matrix, labels, c):
    # A failed solver must not quietly publish a partially converged candidate.
    with warnings.catch_warnings():
        warnings.simplefilter('error', ConvergenceWarning)
        estimator = LogisticRegression(C=c, solver='liblinear', max_iter=2000,
                                       tol=1e-6, random_state=20260907)
        estimator.fit(matrix, labels)
    return estimator.coef_[0], float(estimator.intercept_[0])


def ranking(labels, logits):
    result = metrics(labels, logits, cutoff(labels, logits))
    return (result['recall'], result['average_precision']), result


def train(rows, hybrid, version):
    labels = np.asarray([r['spam'] for r in rows], dtype=bool)
    splits = partition(rows)
    for name in ('train', 'development', 'calibration', 'test'):
        if set(labels[splits[name]]) != {False, True}:
            raise ValueError(f'{name} requires both classes after campaign grouping')
    tr, dev, cal, test = (splits[n] for n in ('train', 'development', 'calibration', 'test'))
    matrix = matrix_for(rows)
    transformer = TfidfTransformer().fit(matrix[tr])
    matrix = transformer.transform(matrix)
    presence = matrix[tr].copy()
    presence.data[:] = 1
    positive = np.asarray(presence[labels[tr]].sum(axis=0)).ravel() + 1
    negative = np.asarray(presence[~labels[tr]].sum(axis=0)).ravel() + 1
    ratio = np.log((positive/positive.sum())/(negative/negative.sum()))
    best, choices = None, []
    for family, scale in [('tfidf_logistic', np.ones(DIMENSION)), ('nb_logistic', ratio)]:
        for c in (.1, 1., 10., 100.):
            coef, bias = fit(matrix[tr].multiply(scale).tocsr(), labels[tr], c)
            weights = coef * scale
            rank, metric = ranking(labels[dev], np.asarray(matrix[dev] @ weights).ravel() + bias)
            choice = {'family': family, 'C': c, 'development': metric}
            choices.append(choice)
            if best is None or rank > best[0]:
                best = (rank, choice, weights, bias)
    _, chosen, weights, bias = best
    lexical = np.asarray(matrix @ weights).ravel() + bias
    selected = {'lexical': chosen, 'semantic_C': None, 'semantic_weight': 0.}
    head_weights, head_bias = np.zeros(PROTOCOL['dimensions']), 0.
    combined = lexical.copy()
    if hybrid:
        # Rust persists f32 vectors as shortest round-tripping JSON decimals.
        # Restore f32 first, then promote: training must see the same numbers
        # that native inference multiplies by the fitted f64 head weights.
        vectors = np.asarray([r['semantic']['features'] for r in rows], dtype=np.float32).astype(np.float64)
        best_rank, _ = ranking(labels[dev], lexical[dev])
        for c in (.1, 1., 10., 100.):
            hw, hb = fit(vectors[tr], labels[tr], c)
            semantic = vectors @ hw + hb
            for alpha in (.1, .25, .5, 1., 2.):
                logits = lexical + alpha * semantic
                rank, metric = ranking(labels[dev], logits[dev])
                choices.append({'semantic_C': c, 'semantic_weight': alpha, 'development': metric})
                if rank > best_rank:
                    best_rank, head_weights, head_bias, combined = rank, hw, hb, logits
                    selected.update(semantic_C=c, semantic_weight=alpha)
    # Selection ends here. Calibration uses legitimate messages only.
    lexical_point = cutoff(labels[cal], lexical[cal])
    combined_point = cutoff(labels[cal], combined[cal])
    threshold_logit = math.log(.95/.05)
    model = {'version': version+'-lexical', 'algorithm': 'logistic', 'feature_version': 3,
             'bias': bias + threshold_logit - lexical_point, 'weights': weights.tolist(),
             'idf': transformer.idf_.tolist(), 'trained_at': int(time.time()), 'examples': len(tr)}
    combination = None
    if hybrid:
        combination = {'schema': 'noisefence-hybrid-1', 'version': version,
                       'encoder': PROTOCOL['encoder'], 'revision': PROTOCOL['revision'],
                       'text_schema': 3, 'max_tokens': PROTOCOL['max_tokens'],
                       'head_weights': head_weights.tolist(), 'head_bias': head_bias,
                       'semantic_weight': selected['semantic_weight'],
                       'score_bias_delta': lexical_point-combined_point, 'threshold': 95.}
    report = {'schema': 'noisefence-feedback-training-1', 'eligible': False,
              'limitation': 'Human corrections are selection-biased, not a representative independent evaluation. No production activation; require a recent independent full-pipeline validation.',
              'split': 'canonical/SimHash distance <=3 components; one representative; group hash 60/10/10/20 train/dev/calibration/test. Heuristic campaign grouping, not a proof of independence.',
              'test_reused_across_periodic_runs': True, 'selected': selected, 'development_candidates': choices,
              'split_counts': {n: len(v) for n, v in splits.items()},
              'partitions': {n: metrics(labels[splits[n]], combined[splits[n]], combined_point)
                             for n in ('development', 'calibration', 'test')},
              'lexical_baseline': metrics(labels[test], lexical[test], lexical_point),
              'threshold': 95., 'score_is_probability': False,
              'semantic_protocol': PROTOCOL if hybrid else None}
    names = [''] * len(rows)
    for name, indices in splits.items():
        for i in indices:
            names[i] = name
    predictions = [{'id': row['id'], 'group': row['group'], 'spam': row['spam'],
                    'partition': names[i],
                    'lexical_logit': float(lexical[i]+threshold_logit-lexical_point),
                    'combined_logit': float(combined[i]+threshold_logit-combined_point)}
                   for i, row in enumerate(rows)]
    return model, combination, report, predictions


def publish(output, model, combination, report, predictions):
    """Publish a coherent new directory; never overwrite any active artifact."""
    if output.exists() or output.is_symlink():
        raise ValueError('Candidate directory already exists')
    with tempfile.TemporaryDirectory(prefix='.feedback-candidate-', dir=output.parent) as directory:
        root = Path(directory)

        def write(name, value):
            payload = json.dumps(value, separators=(',', ':'), allow_nan=False).encode() + b'\n'
            fd = os.open(root/name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            return hashlib.sha256(payload).hexdigest()

        report['model_sha256'] = write('model.json', model)
        if combination is not None:
            combination['lexical_model_sha256'] = report['model_sha256']
            report['combination_sha256'] = write('native-combination.json', combination)
        report['predictions_sha256'] = write('predictions.json', predictions)
        write('report.json', report)
        # Directory fsync precedes publishing the immutable candidate bundle.
        fd = os.open(root, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        os.rename(root, output)
        fd = os.open(output.parent, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--hybrid', action='store_true', help='Require pinned embeddings; never silently downgrade')
    args = parser.parse_args()
    os.umask(0o077)
    rows, corpus_hash = read_rows(args.input, args.hybrid)
    rows, groups = group_rows(rows)
    version = 'feedback-' + time.strftime('%Y%m%dT%H%M%SZ', time.gmtime()) + '-' + corpus_hash[:8]
    model, combination, report, predictions = train(rows, args.hybrid, version)
    report.update(corpus_sha256=corpus_hash, grouping=groups,
                  observed_range=[min(r['observed_at'] for r in rows), max(r['observed_at'] for r in rows)])
    publish(args.output, model, combination, report, predictions)
    print(json.dumps({'candidate': str(args.output), 'eligible': False,
                      'grouping': groups, 'test': report['partitions']['test']}))


if __name__ == '__main__':
    main()
