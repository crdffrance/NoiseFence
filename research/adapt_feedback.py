#!/usr/bin/env python3
"""Fit a conservative correction of an existing lexical model, privately.

The IDF, intercept, semantic head and operating threshold stay fixed. A small
residual is learned in the span of human-corrected messages, with historical
replay to resist forgetting. Campaign-out and chronological scores are computed
before fitting the final candidate. Neither score authorizes production use.
"""
import argparse
from collections import Counter
import gzip
import hashlib
import json
import math
import os
from pathlib import Path
import time

import numpy as np
from scipy import sparse
from scipy.optimize import minimize
from scipy.special import expit
from sklearn.preprocessing import normalize

from train_feedback import (DIMENSION, PROTOCOL, group_rows, is_hex, matrix_for,
                            numeric, publish, read_rows)
from train_linear import digest, metrics, partition

THRESHOLD = math.log(19)
MAX_FEEDBACK = 256
MAX_REPLAY = 20000


def require(ok, message):
    if not ok:
        raise ValueError(message)


def load_baseline(path, head_path):
    require(path.stat().st_size <= 24 * 1024 * 1024, 'Oversized baseline')
    model = json.loads(path.read_bytes())
    require(model.get('algorithm') == 'logistic' and model.get('feature_version') == 3,
            'A schema-3 logistic baseline is required')
    for key in ('weights', 'idf'):
        require(isinstance(model.get(key), list) and len(model[key]) == DIMENSION
                and all(numeric(x) and (key != 'idf' or x > 0) for x in model[key]),
                'Invalid baseline coefficients')
    require(numeric(model.get('bias')), 'Invalid baseline intercept')
    head = None
    if head_path:
        require(head_path.stat().st_size <= 65536, 'Oversized semantic head')
        head = json.loads(head_path.read_bytes())
        require(head.get('schema') == 'noisefence-hybrid-1'
                and head.get('lexical_model_sha256') == digest(path)
                and head.get('threshold') == 95
                and all(head.get(k) == PROTOCOL[k]
                        for k in ('encoder', 'revision', 'text_schema', 'max_tokens')),
                'Semantic head is not bound to this baseline/protocol')
        require(isinstance(head.get('head_weights'), list)
                and len(head['head_weights']) == PROTOCOL['dimensions']
                and all(numeric(x) for x in head['head_weights'])
                and all(numeric(head.get(k)) for k in ('head_bias', 'semantic_weight', 'score_bias_delta'))
                and 0 <= head['semantic_weight'] <= 2, 'Invalid semantic coefficients')
    return model, head


def load_replay(path):
    """Bounded, data-only replay; reserved group hashes can never enter fitting."""
    rows, seen, values, size = [], set(), 0, 0
    opener = gzip.open if path.suffix == '.gz' else open
    with opener(path, 'rb') as stream:
        while raw := stream.readline(2 * 1024 * 1024 + 1):
            size += len(raw)
            require(len(raw) <= 2 * 1024 * 1024 and size <= 1024 * 1024 * 1024
                    and len(rows) < MAX_REPLAY, 'Replay exceeds resource limit')
            row = json.loads(raw)
            require(row.get('schema') == 'noisefence-content-replay-1'
                    and row.get('feature_version') == 3 and type(row.get('spam')) is bool
                    and all(is_hex(row.get(k), n) for k, n in
                            [('id', 64), ('fingerprint', 64), ('group', 64), ('simhash', 16)])
                    and row['id'] not in seen and row.get('partition') in ('train', 'control')
                    and row.get('stratum') in ('historical', 'french_synthetic', 'external'),
                    'Invalid replay schema/provenance')
            seen.add(row['id'])
            expected = partition([row])
            if row['partition'] == 'train':
                require(len(expected['train']) == 1 and not row.get('external_test')
                        and row['stratum'] != 'external', 'Reserved group cannot enter replay fitting')
            else:
                require(len(expected['test']) + len(expected['external']) == 1,
                        'Replay control must use a reserved test group')
            pairs = row.get('features')
            require(isinstance(pairs, list) and 0 < len(pairs) <= DIMENSION,
                    'Invalid replay features')
            indices, norm = set(), 0.
            for pair in pairs:
                require(isinstance(pair, list) and len(pair) == 2, 'Invalid replay pair')
                i, x = pair
                require(type(i) is int and 0 <= i < DIMENSION and i not in indices
                        and numeric(x) and 0 < x <= 1, 'Invalid replay feature')
                indices.add(i)
                norm += x*x
            values += len(pairs)
            require(abs(norm-1) < .001 and values <= 40000000, 'Unnormalized or oversized replay')
            rows.append(row)
    groups = [row['group'] for row in rows]
    require(len(set(groups)) == len(groups), 'Replay must have one representative per campaign')
    for name in ('train', 'control'):
        require({r['spam'] for r in rows if r['partition'] == name} == {False, True},
                'Replay train/control need both classes')
    return rows


def overlaps(row, others):
    """Also exclude replay near-duplicates of feedback, even when IDs differ."""
    value = int(row['simhash'], 16)
    return any(row['fingerprint'] == r['fingerprint']
               or (value ^ int(r['simhash'], 16)).bit_count() <= 3 for r in others)


def transformed(rows, model):
    return normalize(matrix_for(rows).multiply(model['idf'])).tocsr()


def baseline_logits(matrix, rows, model, head):
    logits = np.asarray(matrix @ model['weights']).ravel() + model['bias']
    if head:
        # Rust reconstitutes JSON decimals as f32 before multiplying by f64.
        vectors = np.asarray([r['semantic']['features'] for r in rows], dtype=np.float32).astype(np.float64)
        logits += head['semantic_weight'] * (vectors @ head['head_weights'] + head['head_bias']) + head['score_bias_delta']
    return logits


def fit_residual(x, labels, base, replay_x, replay_labels, replay_base,
                 regularization=1., replay_weight=1.):
    """Convex logistic loss in the feedback span. No intercept/IDF refit."""
    require(len(x.shape) == 2 and x.shape[0] <= MAX_FEEDBACK
            and set(labels) == {False, True}, 'Correction fitting needs both classes')
    require(numeric(regularization) and .001 <= regularization <= 1000
            and numeric(replay_weight) and .01 <= replay_weight <= 1000,
            'Invalid regularization/replay weight')
    gram = (x @ x.T).toarray()
    anchor = (replay_x @ x.T).toarray()
    penalty = gram + np.eye(len(labels))*1e-8
    # Each class contributes equally; bulk campaigns cannot outvote ham errors.
    def balanced(y):
        return np.array([.5/np.sum(y == v) for v in y])
    # Equivalent to a class-balanced sum over human examples; the replay budget
    # scales with that batch, not with an arbitrary number of replay duplicates.
    human_weight = balanced(labels)*len(labels)
    anchor_weight = balanced(replay_labels)*len(labels)
    def objective(beta):
        z, a = base + gram @ beta, replay_base + anchor @ beta
        loss = np.dot(human_weight, np.logaddexp(0, z)-labels*z)
        loss += replay_weight*np.dot(anchor_weight, np.logaddexp(0, a)-replay_labels*a)
        loss += .5*regularization*beta @ penalty @ beta
        grad = gram.T @ (human_weight*(expit(z)-labels))
        grad += replay_weight*anchor.T @ (anchor_weight*(expit(a)-replay_labels))
        grad += regularization*penalty @ beta
        return float(loss), grad
    fitted = minimize(objective, np.zeros(len(labels)), method='L-BFGS-B', jac=True,
                      options={'maxiter':1000, 'ftol':1e-12, 'gtol':1e-8})
    require(fitted.success and np.isfinite(fitted.x).all(), 'Correction solver did not converge')
    delta = np.asarray(x.T @ fitted.x).ravel()
    require(np.isfinite(delta).all(), 'Non-finite correction')
    return delta


def regression_gate(report):
    """A development rejection, never permission to activate a model."""
    reasons = []
    cohorts = {'campaign_out':report['campaign_out'], **report['lexical_replay_controls']}
    if report['temporal']['status'] == 'complete':
        cohorts['temporal'] = report['temporal']
    else:
        reasons.append('temporal_evaluation_unavailable')
    for name, cohort in cohorts.items():
        before, after = cohort['baseline'], cohort['candidate']
        if after['false_positive'] > before['false_positive']:
            reasons.append(name + ':more_false_positives')
        if after['true_positive'] < before['true_positive']:
            reasons.append(name + ':lower_capture')
    current = report['campaign_out']
    if (current['candidate']['false_positive'] >= current['baseline']['false_positive']
            and current['candidate']['true_positive'] <= current['baseline']['true_positive']):
        reasons.append('no_campaign_out_improvement')
    return {'status':'rejected' if reasons else 'needs_independent_validation',
            'reasons':reasons, 'may_activate':False}


def evaluate(rows, model, head, replay, regularization=1., replay_weight=1., members=None):
    require(4 <= len(rows) <= MAX_FEEDBACK, 'Need 4..256 independent feedback campaigns')
    labels = np.array([r['spam'] for r in rows], dtype=bool)
    require(min(np.sum(labels), np.sum(~labels)) >= 2, 'Need at least two campaigns per class')
    x = transformed(rows, model)
    base = baseline_logits(x, rows, model, head)
    # Check every original member, including removed/conflicting campaigns.
    replay_kept = [r for r in replay if not overlaps(r, members if members is not None else rows)]
    anchors = [r for r in replay_kept if r['partition'] == 'train']
    controls = [r for r in replay_kept if r['partition'] == 'control']
    for cohort in (anchors, controls):
        require({r['spam'] for r in cohort} == {False, True}, 'Overlap exclusions emptied replay class')
    rx = transformed(anchors, model)
    ry = np.array([r['spam'] for r in anchors], dtype=bool)
    # Replay anchors use the lexical score only. No new encoder or cached
    # semantic assumptions are required to retain the lexical decision boundary.
    rb = baseline_logits(rx, anchors, model, None)
    def fit(indices):
        return fit_residual(x[indices], labels[indices], base[indices], rx, ry, rb,
                            regularization, replay_weight)
    indices = np.arange(len(rows))
    predicted = np.empty(len(rows))
    for i in indices:
        delta = fit(indices[indices != i])
        predicted[i] = base[i] + float(np.asarray(x[i] @ delta).item())
    # A temporal control catches optimistic campaign-out validation. Exclude
    # delayed annotations and campaigns with observations spanning the time cut.
    times = sorted(r['observed_at'] for r in rows)
    cut = times[int(len(times)*.7)]
    train = np.array([i for i,r in enumerate(rows)
                      if r.get('last_observed_at',r['observed_at']) < cut and r['labelled_at'] < cut], dtype=int)
    test = np.array([i for i,r in enumerate(rows) if r['observed_at'] >= cut], dtype=int)
    temporal = {'status':'insufficient_past_labels', 'training':len(train), 'test':len(test),
                'excluded_from_temporal':len(rows)-len(train)-len(test)}
    if set(labels[train]) == {False,True} and len(test):
        delta = fit(train)
        temporal.update(status='complete', baseline=metrics(labels[test],base[test],THRESHOLD),
                        candidate=metrics(labels[test],base[test]+x[test] @ delta,THRESHOLD))
    delta = fit(indices)
    cx = transformed(controls, model)
    cb = baseline_logits(cx, controls, model, None)
    candidate_control = cb + cx @ delta
    control_reports = {}
    for stratum in sorted({r['stratum'] for r in controls}):
        selected = np.array([i for i,r in enumerate(controls) if r['stratum'] == stratum])
        y = np.array([controls[i]['spam'] for i in selected], dtype=bool)
        control_reports[stratum] = {'baseline':metrics(y,cb[selected],THRESHOLD),
                                    'candidate':metrics(y,candidate_control[selected],THRESHOLD)}
    report = {'schema':'noisefence-feedback-residual-1', 'eligible':False,
              'limitation':'Selection-biased human corrections. Campaign-out is development validation, not independent SMTP performance. Never auto-activate.',
              'threshold':95., 'score_is_probability':False,
              'parameters':{'regularization':regularization,'replay_weight':replay_weight},
              'frozen':['idf','intercept','semantic_head','threshold'],
              'feedback_campaigns':len(rows),'replay_training':len(anchors),
              'replay_control':len(controls),'replay_overlap_excluded':len(replay)-len(replay_kept),
              'campaign_out':{'baseline':metrics(labels,base,THRESHOLD),
                              'candidate':metrics(labels,predicted,THRESHOLD)},
              'temporal':temporal,'lexical_replay_controls':control_reports,
              'delta_l2':float(np.linalg.norm(delta))}
    report['gate'] = regression_gate(report)
    candidate = {**model, 'weights':(np.asarray(model['weights'])+delta).tolist(),
                 'version':'feedback-residual-'+str(int(time.time())), 'trained_at':int(time.time())}
    return candidate, report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('feedback', type=Path)
    parser.add_argument('replay', type=Path)
    parser.add_argument('baseline', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--semantic-head', type=Path)
    parser.add_argument('--regularization', type=float, default=1.)
    parser.add_argument('--replay-weight', type=float, default=1.)
    args = parser.parse_args()
    os.umask(0o077)
    require(not args.output.exists(), 'Candidate output already exists')
    model, head = load_baseline(args.baseline, args.semantic_head)
    raw, corpus_hash = read_rows(args.feedback, head is not None)
    now = int(time.time())
    require(all(r['observed_at'] <= r['labelled_at'] <= now for r in raw), 'Invalid annotation chronology')
    rows, grouping = group_rows(raw)
    replay = load_replay(args.replay)
    candidate, report = evaluate(rows,model,head,replay,args.regularization,args.replay_weight,raw)
    report.update(grouping=grouping, corpus_sha256=corpus_hash,
                  replay_sha256=digest(args.replay), baseline_sha256=digest(args.baseline),
                  semantic_head_sha256=digest(args.semantic_head) if args.semantic_head else None,
                  trainer_sha256=digest(Path(__file__)),
                  dependencies_sha256={name:digest(Path(__file__).with_name(name))
                                       for name in ('train_feedback.py','train_linear.py','semantic-protocol.json')})
    if head:
        head = {**head,'version':candidate['version']+'-hybrid'}
    publish(args.output,candidate,head,report,[],aggregate_only=True)
    print(json.dumps(report,allow_nan=False))


if __name__ == '__main__':
    main()
