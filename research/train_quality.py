#!/usr/bin/env python3
"""Train joint risk/type shadow candidates from frozen, human-labelled samples.

No mail body access, inferred labels, network, executable model or activation.
Time partitions are fixed before looking at labels; campaigns cannot cross them.
"""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
import math
import os
from pathlib import Path
import shutil
import tempfile
import time

import numpy as np
from scipy.optimize import minimize
from scipy.special import expit, softmax
from scipy.stats import beta
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import log_loss
from sklearn.preprocessing import StandardScaler

from train_fusion import components, decode, require, is_hex, numeric

PROTOCOL_BYTES = Path(__file__).with_name('quality-protocol.json').read_bytes()
PROTOCOL = json.loads(PROTOCOL_BYTES)
PROTOCOL_HASH = hashlib.sha256(PROTOCOL_BYTES).hexdigest()
KINDS = PROTOCOL['kinds']
SPLITS = ('train', 'development', 'calibration', 'threshold', 'test')
FRACTIONS = (.50, .65, .80, .90)


def read_jsonl(path):
    rows, digest, total = [], hashlib.sha256(), 0
    with Path(path).open('rb') as source:
        for _ in range(50003):
            raw = source.readline(2 * 1024 * 1024 + 1)
            if not raw:
                return rows, digest.hexdigest()
            total += len(raw)
            require(len(raw) <= 2 * 1024 * 1024 and total <= 256 * 1024 * 1024, 'Oversized quality dataset')
            digest.update(raw)
            rows.append(decode(raw))
    raise ValueError('Too many quality rows')


def load_dataset(path):
    data, digest = read_jsonl(path)
    require(len(data) >= 2 and data[0].get('type') == 'header' and data[-1].get('type') == 'footer', 'Incomplete quality export')
    header, rows = data[0], data[1:-1]
    require(header.get('schema') == 'noisefence-quality-dataset-1'
            and header.get('protocol_sha256') == PROTOCOL_HASH
            and header.get('sampling') == 'uniform_message'
            and data[-1].get('rows') == len(rows)
            and type(header.get('population')) is int and type(header.get('selected')) is int
            and 0 <= len(rows) <= header['selected'] <= header['population'] <= 50000
            and type(header.get('since')) is int and type(header.get('until')) is int
            and type(header.get('captured_at')) is int
            and 0 < header['since'] < header['until'] <= header['captured_at'] <= time.time() + 60
            and is_hex(header.get('seed_sha256')), 'Invalid sampling provenance')
    minimum = np.array([f['minimum'] for f in PROTOCOL['features']])
    maximum = np.array([f['maximum'] for f in PROTOCOL['features']])
    ids, artifacts, counts = set(), set(), Counter()
    usable = []
    for row in rows:
        require(row.get('type') == 'row' and is_hex(row.get('id')) and row['id'] not in ids
                and type(row.get('observed_at')) is int and header['since'] <= row['observed_at'] < header['until']
                and row.get('risk') in (None, 'legitimate', 'spam', 'uncertain')
                and row.get('kind') in (None, *KINDS), 'Invalid human quality row')
        ids.add(row['id'])
        if row['risk'] is not None:
            require(type(row.get('labelled_at')) is int and row['observed_at'] <= row['labelled_at'] <= header['captured_at'], 'Invalid annotation time')
        quality = row.get('quality')
        if quality is None:
            counts['missing_observations'] += 1
            continue
        require(isinstance(quality, dict) and quality.get('schema') == 'noisefence-quality-observation-1', 'Invalid observation')
        if not quality.get('complete_features') or quality.get('source') != 'smtp_session' or not quality.get('values'):
            counts['unusable_observations'] += 1
            continue
        require(quality.get('protocol_sha256') == PROTOCOL_HASH and is_hex(quality.get('artifacts_sha256'))
                and isinstance(quality.get('availability_profile'), str)
                and 0 < len(quality['availability_profile']) <= 1024
                and all(c in 'abcdefghijklmnopqrstuvwxyz/_' for c in quality['availability_profile']), 'Invalid joint provenance')
        values = quality['values']
        require(isinstance(values, list) and len(values) == len(minimum) and all(numeric(x) for x in values)
                and np.all(np.array(values) >= minimum) and np.all(np.array(values) <= maximum), 'Invalid feature range')
        artifacts.add(quality['artifacts_sha256'])
        require(is_hex(row.get('fingerprint')) and is_hex(row.get('simhash'), 16), 'Missing campaign identifiers')
        usable.append({**row, 'campaign': row['fingerprint'], 'split': '', 'values': values})
    require(len(artifacts) <= 1, 'Detector artifacts changed inside this sample; evaluate separately')
    counts['retained'] = len(rows)
    counts['deleted_or_no_longer_authorized'] = header['selected'] - len(rows)
    counts['usable'] = len(usable)
    return header, usable, counts, next(iter(artifacts), None), digest


def partition(rows):
    """Fixed chronological cuts; exclude campaigns spanning a cut or conflicting labels."""
    if len(rows) < 20:
        return {s: [] for s in SPLITS}, {'insufficient_rows': len(rows)}
    times = sorted(r['observed_at'] for r in rows)
    cuts = [times[min(len(times)-1, int(len(times)*f))] for f in FRACTIONS]
    require(len(set(cuts)) == 4, 'Insufficient distinct observation times for frozen temporal splits')
    result, counts = {s: [] for s in SPLITS}, Counter()
    for group in components(rows):
        candidates = [rows[i] for i in group]
        splits = {sum(r['observed_at'] >= cut for cut in cuts) for r in candidates}
        if len(splits) != 1:
            counts['cross_period_campaigns'] += 1
            continue
        labels = {(r['risk'], r['kind']) for r in candidates if r['risk'] not in (None, 'uncertain') and r['kind'] is not None}
        if len(labels) > 1:
            counts['conflicting_campaigns'] += 1
            continue
        labelled = [r for r in candidates if r['risk'] not in (None, 'uncertain') and r['kind'] is not None]
        if not labelled:
            counts['unlabelled_or_uncertain_campaigns'] += 1
            continue
        # One uniformly ordered representative per campaign, never chosen by score.
        selected = min(labelled, key=lambda r: r['id'])
        selected['split'] = SPLITS[next(iter(splits))]
        result[selected['split']].append(selected)
        counts['duplicates_removed'] += len(candidates) - 1
    return result, dict(counts)


def interval(success, total):
    if not total:
        return None
    return [0.0 if not success else float(beta.ppf(.025, success, total-success+1)),
            1.0 if success == total else float(beta.ppf(.975, success+1, total-success))]


def metrics(y, probability, lower, upper, available=None):
    available = np.ones(len(y), dtype=bool) if available is None else available
    spam = (probability >= upper) & available
    legit = (probability <= lower) & available
    tp, fp = int(np.sum(spam & (y == 1))), int(np.sum(spam & (y == 0)))
    positives, negatives = int(np.sum(y == 1)), int(np.sum(y == 0))
    return {'messages': len(y), 'tp': tp, 'fp': fp, 'spam_total': positives, 'legitimate_total': negatives,
            'spam_missed_or_review': positives-tp, 'review': int(np.sum(~spam & ~legit)),
            'spam_to_review': int(np.sum(~spam & ~legit & (y == 1))),
            'legitimate_to_review': int(np.sum(~spam & ~legit & (y == 0))),
            'recall': tp/positives if positives else None, 'recall_ci95': interval(tp, positives),
            'fpr': fp/negatives if negatives else None, 'fpr_ci95': interval(fp, negatives),
            'precision': tp/(tp+fp) if tp+fp else None, 'precision_ci95': interval(tp, tp+fp),
            'unsupported_profile': int(np.sum(~available)),
            'brier': float(np.mean((probability[available]-y[available])**2)) if np.any(available) else None}


def matrix(rows):
    return np.array([r['values'] for r in rows], dtype=float), np.array([r['risk'] == 'spam' for r in rows], dtype=int)


def fit_risk(parts, families=None):
    data = {name: matrix(rows) for name, rows in parts.items()}
    mask = np.array([families is None or s['family'] in families for s in PROTOCOL['features']])
    scaler = StandardScaler().fit(data['train'][0][:, mask])
    x = {s: scaler.transform(v[0][:, mask]) for s, v in data.items()}
    candidates = []
    for regularization in (.1, 1., 10.):
        model = LogisticRegression(C=regularization, max_iter=1500, random_state=0).fit(x['train'], data['train'][1])
        require(int(model.n_iter_.max()) < 1500, 'Risk fitting did not converge')
        loss = log_loss(data['development'][1], model.predict_proba(x['development']))
        candidates.append((loss, regularization, model))
    _, regularization, fitted = min(candidates, key=lambda x: (x[0], x[1]))
    logits = {s: fitted.decision_function(x[s]) for s in SPLITS}
    ycal = data['calibration'][1]
    def calibration_loss(v):
        a, b = np.exp(v[0]), v[1]
        z = a * logits['calibration'] + b
        return float(np.mean(np.logaddexp(0, z)-ycal*z) + 1e-4*np.sum(np.square(v)))
    calibrated = minimize(calibration_loss, [0., 0.], bounds=[(-4., 4.), (-30., 30.)], method='L-BFGS-B')
    require(calibrated.success, 'Risk calibration did not converge')
    a, b = float(np.exp(calibrated.x[0])), float(calibrated.x[1])
    probabilities = {s: expit(np.clip(a*logits[s]+b, -40, 40)) for s in SPLITS}
    threshold_p, threshold_y = probabilities['threshold'], data['threshold'][1]
    upper = min(1., max(.5, float(np.quantile(threshold_p[threshold_y == 0], .999)) + 1e-9))
    lower = max(0., min(upper-1e-6, .5, float(np.quantile(threshold_p[threshold_y == 1], .01))-1e-9))
    weights = np.zeros(len(mask))
    weights[mask] = fitted.coef_[0] / scaler.scale_
    bias = float(fitted.intercept_[0] - np.sum(fitted.coef_[0]*scaler.mean_/scaler.scale_))
    profiles = {r['quality']['availability_profile'] for r in parts['train']}
    available = np.array([r['quality']['availability_profile'] in profiles for r in parts['test']])
    return {'bias': bias, 'weights': weights.tolist()}, [a,b], [lower,upper], probabilities, {
        'regularization': regularization, 'test': metrics(data['test'][1], probabilities['test'], lower, upper, available)}


def fit_kinds(parts):
    data = {s: matrix(rows)[0] for s, rows in parts.items()}
    labels = {s: np.array([KINDS.index(r['kind']) for r in rows]) for s, rows in parts.items()}
    scaler = StandardScaler().fit(data['train'])
    x = {s: scaler.transform(v) for s,v in data.items()}
    candidates = []
    for c in (.1, 1., 10.):
        m = LogisticRegression(C=c, max_iter=1500, random_state=0).fit(x['train'],labels['train'])
        require(int(m.n_iter_.max()) < 1500, 'Kind fitting did not converge')
        candidates.append((log_loss(labels['development'],m.predict_proba(x['development']),labels=list(range(6))),c,m))
    _, c, fitted = min(candidates,key=lambda v:(v[0],v[1]))
    require(list(fitted.classes_) == list(range(6)), 'Training needs all six mail kinds')
    logits = {s:fitted.decision_function(x[s]) for s in SPLITS}
    def loss(v):
        return log_loss(labels['calibration'],softmax(logits['calibration']/np.exp(v[0]),axis=1),labels=list(range(6)))
    fit = minimize(loss,[0.],bounds=[(math.log(.05),math.log(20.))],method='L-BFGS-B')
    require(fit.success,'Kind calibration did not converge')
    temperature=float(np.exp(fit.x[0]))
    weights = fitted.coef_/scaler.scale_
    biases = fitted.intercept_-np.sum(fitted.coef_*scaler.mean_/scaler.scale_,axis=1)
    models=[{'bias':float(b),'weights':w.tolist()} for b,w in zip(biases,weights)]
    probabilities=softmax(logits['test']/temperature,axis=1)
    predicted=np.argmax(probabilities,axis=1)
    profiles={r['quality']['availability_profile'] for r in parts['train']}
    available=np.array([r['quality']['availability_profile'] in profiles for r in parts['test']])
    predicted[~available]=6
    confusion=[[int(np.sum((labels['test']==i)&(predicted==j))) for j in range(7)] for i in range(6)]
    return models,temperature,probabilities,{'regularization':c,'classes':KINDS,'prediction_classes':KINDS+['unavailable'],'confusion':confusion,
        'accuracy':float(np.mean(predicted==labels['test'])),
        'recall_ci95':{name:interval(confusion[i][i],sum(confusion[i])) for i,name in enumerate(KINDS)}}


def train(dataset, destination, version, base_history=None):
    require(not destination.exists(),'Candidate destination already exists')
    header, rows, coverage, artifacts, digest = load_dataset(dataset)
    parts, grouping = partition(rows)
    counts={s:{'campaigns':len(v),'risk':dict(Counter(r['risk'] for r in v)),
               'kind':dict(Counter(r['kind'] for r in v))} for s,v in parts.items()}
    report={'schema':'noisefence-quality-training-1','eligible':False,'observation_only':True,
            'sampling':header,'coverage':dict(coverage),'grouping':grouping,'splits':counts,
            'dataset_sha256':digest,'test_unit':'one_representative_per_campaign',
            'limitations':['No automatic activation; independent population review is still required.']}
    if any(len(v)<12 or len({r['risk'] for r in v})<2 or len({r['kind'] for r in v})<6 for v in parts.values()):
        report['status']='insufficient_labels'
        return report
    if base_history is not None:
        history, history_hash=read_jsonl(base_history)
        require(all(is_hex(r.get('fingerprint')) and is_hex(r.get('simhash'),16) and is_hex(r.get('campaign')) for r in history),'Invalid base history')
        combined=rows+history
        require(not any(any(i<len(rows) for i in g) and any(i>=len(rows) for i in g) for g in components(combined)),'Base-model data or previous evaluation overlaps the new sample')
        report['base_history_sha256']=history_hash
    else:
        report['limitations'].append('Base-model training and previous test provenance not supplied.')
    if header['until'] < time.time()-30*86400:
        report['limitations'].append('The evaluation population is not recent.')
    risk,calibration,thresholds,probabilities,risk_report=fit_risk(parts)
    kinds,temperature,kind_probabilities,kind_report=fit_kinds(parts)
    report.update(status='candidate_prepared',risk=risk_report,mail_kind=kind_report)
    families={f['family'] for f in PROTOCOL['features']}
    variants={'without_llm':families-{'llm'},'without_providers':families-{'external_reputation'},
              'without_sender_history':families-{'sender_history','campaign'},'content_only':{'lexical','semantic','llm','mail_type'}}
    report['ablations']={name:fit_risk(parts,selected)[4] for name,selected in variants.items()}
    report['baseline']=dict(Counter((r.get('legacy_decision') or {}).get('outcome','missing')+'|'+r['risk'] for r in parts['test']))
    report['slices']={}
    y=matrix(parts['test'])[1]
    supported={r['quality']['availability_profile'] for r in parts['train']}
    available=np.array([r['quality']['availability_profile'] in supported for r in parts['test']])
    for kind in KINDS:
        indices=np.array([r['kind']==kind for r in parts['test']])
        report['slices'][kind]=metrics(y[indices],probabilities['test'][indices],*thresholds,available[indices])
    model={'schema':'noisefence-quality-model-1','version':version,'protocol_sha256':PROTOCOL_HASH,
           'artifacts_sha256':artifacts,'trained_at':int(time.time()),'dataset_sha256':digest,
           'profiles':sorted({r['quality']['availability_profile'] for r in parts['train']}),
           'risk':risk,'calibration':calibration,'thresholds':thresholds,'kinds':KINDS,
           'kind_models':kinds,'kind_temperature':temperature}
    # References for native parity; no labels or text are included in these probes.
    probes=[{'observation':r['quality'],'risk_probability':float(p),'kind_probabilities':kp.tolist()}
            for r,p,kp in zip(parts['test'],probabilities['test'],kind_probabilities)
            if r['quality']['availability_profile'] in model['profiles']][:12]
    destination.parent.mkdir(parents=True,exist_ok=True)
    stage=Path(tempfile.mkdtemp(prefix='.quality-candidate-',dir=destination.parent))
    try:
        for name,value in [('model.json',model),('report.json',report),('parity.json',probes)]:
            path=stage/name
            with path.open('x') as out:
                os.chmod(path,0o600);json.dump(value,out,indent=2,allow_nan=False);out.write('\n');out.flush();os.fsync(out.fileno())
        stage.rename(destination)
    finally:
        if stage.exists():shutil.rmtree(stage)
    return report


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('dataset',type=Path)
    parser.add_argument('destination',type=Path)
    parser.add_argument('--version',required=True)
    parser.add_argument('--base-history',type=Path)
    args=parser.parse_args()
    os.umask(0o077)
    require(0<len(args.version)<=100 and all(32<=ord(c)<127 for c in args.version),'Invalid model version')
    report=train(args.dataset,args.destination,args.version,args.base_history)
    print(json.dumps(report,allow_nan=False))
    return 3 if report['status']=='insufficient_labels' else 0


if __name__=='__main__':
    raise SystemExit(main())
