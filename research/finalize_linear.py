#!/usr/bin/env python3
"""Freeze the development-selected feature/model family before test evaluation."""
import argparse
import hashlib
import json
import math
from pathlib import Path
import time

import numpy as np
from sklearn.preprocessing import normalize
from train_linear import digest, load, metrics, cutoff, partition


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("output", type=Path)
    p.add_argument("candidates", nargs='+', type=Path)
    a = p.parse_args()
    a.output.mkdir(parents=True, exist_ok=False)
    candidates = [(directory, json.loads((directory / 'development.json').read_text())) for directory in a.candidates]
    directory, selected = max(candidates, key=lambda item: (
        item[1]['selected']['development']['recall'],
        item[1]['selected']['development']['average_precision']))
    freeze = {'created': int(time.time()), 'selected_directory': str(directory),
              'selected': selected, 'compared': [record for _, record in candidates],
              'selection_rule': 'highest development recall at empirical 0.1% FPR; average precision tie-break',
              'test_metrics_observed_before_selection': False}
    (a.output / 'selection-frozen.json').write_text(json.dumps(freeze, indent=2) + '\n')
    source = Path(selected['input'])
    if digest(source) != selected['corpus_sha256']:
        raise ValueError('Frozen corpus checksum mismatch')
    model_path = directory / 'raw-model.json'
    if digest(model_path) != selected['model_sha256']:
        raise ValueError('Frozen model checksum mismatch')
    model = json.loads(model_path.read_text())
    matrix, examples = load(source, selected['dimension'])
    matrix = normalize(matrix.multiply(np.asarray(model['idf'])).tocsr(), norm='l2')
    labels = np.asarray([e['spam'] for e in examples], dtype=bool)
    partitions = partition(examples)
    logits = np.asarray(matrix @ np.asarray(model['weights'])).ravel() + model['bias']
    calibration = partitions['calibration']
    point = cutoff(labels[calibration], logits[calibration])
    model['bias'] += math.log(0.95 / 0.05) - point
    model['version'] += '-calibrated'
    payload = json.dumps(model, separators=(',', ':'), allow_nan=False).encode()
    (a.output / 'model.json').write_bytes(payload)
    results = {name: metrics(labels[indices], logits[indices], point)
               for name, indices in partitions.items() if len(indices)}
    by_source = {}
    with (a.output / 'predictions.jsonl').open('w') as stream:
        for name in ('development', 'calibration', 'test', 'external'):
            for i in partitions[name]:
                stream.write(json.dumps({'fingerprint': examples[i]['fingerprint'],
                                         'raw_sha256': examples[i]['raw_sha256'],
                                         'partition': name, 'source': examples[i]['source'],
                                         'spam': bool(labels[i]), 'logit': float(logits[i]),
                                         'predicted_spam': bool(logits[i] >= point)}) + '\n')
            for source_name in sorted({examples[i]['source'] for i in partitions[name]}):
                indices = np.asarray([i for i in partitions[name] if examples[i]['source'] == source_name])
                by_source[name + ':' + source_name] = metrics(labels[indices], logits[indices], point)
    test = results['test']
    report = {'model_sha256': hashlib.sha256(payload).hexdigest(), 'corpus_sha256': selected['corpus_sha256'],
              'created': int(time.time()), 'selected': selected['selected'],
              'feature_version': selected['feature_version'], 'dimension': selected['dimension'],
              'operating_point_raw_logit': point, 'threshold': 95.0, 'partitions': results,
              'by_source': by_source, 'internal_numeric_target_met': test['recall'] >= .95 and test['fpr_ci95'][1] <= .001,
              'eligible': False,
              'limitation': 'Historical ham and one-source recent phishing do not establish representative recent FPR or full-pipeline quality. Keep production activation gated.'}
    (a.output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({k: v for k, v in report.items() if k != 'by_source'}, indent=2))


if __name__ == '__main__':
    main()
