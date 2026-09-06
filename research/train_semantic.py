#!/usr/bin/env python3
"""Compare a frozen multilingual encoder on development only; never activate it."""
import argparse
import json
import os
from pathlib import Path
import time

import numpy as np
from sklearn.linear_model import LogisticRegression
from train_linear import cutoff, digest, metrics


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('embeddings', type=Path)
    p.add_argument('rows', type=Path)
    p.add_argument('lexical_predictions', type=Path)
    p.add_argument('output', type=Path)
    a = p.parse_args()
    os.umask(0o077)
    protocol = json.loads((a.embeddings / 'protocol.json').read_text())
    if not protocol.get('complete') or protocol['embeddings_sha256'] != digest(a.embeddings / 'embeddings.npy'):
        raise ValueError('Incomplete or altered embeddings')
    ids = json.loads((a.embeddings / 'ids.json').read_text())
    rows = {row['raw_sha256']: row for row in map(json.loads, a.rows.read_text().splitlines())}
    if len(set(ids)) != len(ids) or set(ids) != set(rows):
        raise ValueError('Embedding and partition identities differ')
    rows = [rows[key] for key in ids]
    if any(row['partition'] not in ('train', 'development') for row in rows):
        raise ValueError('This experiment must not include calibration or test messages')
    labels = np.asarray([row['spam'] for row in rows], dtype=bool)
    train = np.asarray([row['partition'] == 'train' for row in rows])
    dev = ~train
    if set(labels[train]) != {False, True} or set(labels[dev]) != {False, True}:
        raise ValueError('Both classes required in each partition')
    vectors = np.load(a.embeddings / 'embeddings.npy', allow_pickle=False, mmap_mode='r')
    if vectors.shape != (len(ids), protocol['dimensions']) or not np.isfinite(vectors).all():
        raise ValueError('Unexpected embedding shape or values')
    lexical = {row['raw_sha256']: row for row in map(json.loads, a.lexical_predictions.read_text().splitlines())
               if row['partition'] == 'development'}
    development = [row for row in rows if row['partition'] == 'development']
    if set(lexical) != {row['raw_sha256'] for row in development}:
        raise ValueError('Lexical and semantic development sets differ')
    if any(row['spam'] != lexical[row['raw_sha256']]['spam'] for row in development):
        raise ValueError('Labels differ between models')
    lexical_logits = np.asarray([lexical[row['raw_sha256']]['logit'] for row in development])
    a.output.mkdir(parents=True, exist_ok=False)
    specification = {'created': int(time.time()), 'protocol': protocol,
                     'regularization': [0.1, 1., 10., 100.],
                     'semantic_logit_weights': [0.1, 0.25, 0.5, 1., 2.],
                     'selection': 'development recall at empirical 0.1% FPR, then average precision',
                     'scope': 'development research; no calibration/test evaluated or production activation',
                     'rows_sha256': digest(a.rows), 'lexical_predictions_sha256': digest(a.lexical_predictions)}
    (a.output / 'specification.json').write_text(json.dumps(specification, indent=2) + '\n')
    baseline = {'family': 'lexical', 'development': metrics(labels[dev], lexical_logits,
                                                          cutoff(labels[dev], lexical_logits))}
    choices = [baseline]
    heads = {}
    for c in specification['regularization']:
        start = time.monotonic()
        estimator = LogisticRegression(C=c, solver='liblinear', max_iter=2000, tol=1e-6, random_state=20260907)
        estimator.fit(vectors[train], labels[train])
        semantic_logits = estimator.decision_function(vectors[dev])
        heads[str(c)] = {'weights': estimator.coef_[0].tolist(), 'bias': float(estimator.intercept_[0])}
        variants = [('semantic', 1., semantic_logits)] + [
            ('lexical_plus_semantic', weight, lexical_logits + weight * semantic_logits)
            for weight in specification['semantic_logit_weights']]
        for family, weight, logits in variants:
            result = {'family': family, 'C': c, 'semantic_logit_weight': weight,
                      'development': metrics(labels[dev], logits, cutoff(labels[dev], logits)),
                      'fit_seconds': time.monotonic() - start}
            choices.append(result)
            print(json.dumps(result), flush=True)
    selected = max(choices, key=lambda row: (row['development']['recall'], row['development']['average_precision']))
    report = {'selected': selected, 'baseline': baseline, 'candidates': choices,
              'trained_messages': int(train.sum()), 'development_messages': int(dev.sum()),
              'test_evaluated': False, 'eligible': False,
              'limitation': 'Development selection only. No native inference integration or new independent evaluation. Encoder pretraining data overlap cannot be ruled out.'}
    (a.output / 'heads.json').write_text(json.dumps(heads, separators=(',', ':'), allow_nan=False) + '\n')
    (a.output / 'report.json').write_text(json.dumps(report, indent=2, allow_nan=False) + '\n')
    print(json.dumps({'selected': selected, 'baseline': baseline, 'test_evaluated': False}, indent=2))


if __name__ == '__main__':
    main()
