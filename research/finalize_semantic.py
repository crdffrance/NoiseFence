#!/usr/bin/env python3
"""Evaluate the frozen combination; reused historical tests are R&D references."""
import argparse
import json
import math
import os
from pathlib import Path

import numpy as np
from train_linear import cutoff, digest, metrics


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('selection', type=Path)
    p.add_argument('embeddings', type=Path)
    p.add_argument('rows', type=Path)
    p.add_argument('lexical_predictions', type=Path)
    p.add_argument('output', type=Path)
    a = p.parse_args()
    os.umask(0o077)
    frozen = json.loads((a.selection / 'selection-frozen.json').read_text())
    if frozen['report_sha256'] != digest(a.selection / 'report.json') or frozen['head_file_sha256'] != digest(a.selection / 'heads.json'):
        raise ValueError('Frozen selection changed')
    specification = json.loads((a.selection / 'specification.json').read_text())
    if specification['lexical_predictions_sha256'] != digest(a.lexical_predictions):
        raise ValueError('Lexical predictions differ from development comparison')
    protocol = json.loads((a.embeddings / 'protocol.json').read_text())
    if not protocol.get('complete') or protocol['embeddings_sha256'] != digest(a.embeddings / 'embeddings.npy'):
        raise ValueError('Incomplete or altered evaluation embeddings')
    for field in ('encoder', 'revision', 'dimensions', 'max_tokens', 'pooling', 'prefix', 'text_schema'):
        if protocol[field] != frozen['encoder_protocol'][field]:
            raise ValueError('Training/evaluation encoder protocols differ: ' + field)
    ids = json.loads((a.embeddings / 'ids.json').read_text())
    rows = {row['raw_sha256']: row for row in map(json.loads, a.rows.read_text().splitlines())}
    if len(set(ids)) != len(ids) or set(ids) != set(rows):
        raise ValueError('Embedding and evaluation identities differ')
    rows = [rows[key] for key in ids]
    if any(row['partition'] not in ('calibration', 'test', 'external') for row in rows):
        raise ValueError('Training/development rows are forbidden in this reference evaluation')
    labels = np.asarray([row['spam'] for row in rows], dtype=bool)
    partitions = {name: np.asarray([row['partition'] == name for row in rows])
                  for name in ('calibration', 'test', 'external')}
    vectors = np.load(a.embeddings / 'embeddings.npy', allow_pickle=False, mmap_mode='r')
    if vectors.shape != (len(ids), protocol['dimensions']) or not np.isfinite(vectors).all():
        raise ValueError('Unexpected evaluation embedding shape/values')
    lexical = {row['raw_sha256']: row for row in map(json.loads, a.lexical_predictions.read_text().splitlines())}
    if any(key not in lexical or row['spam'] != lexical[key]['spam'] or row['partition'] != lexical[key]['partition']
           for key, row in zip(ids, rows)):
        raise ValueError('Lexical and semantic evaluation labels or partitions differ')
    lexical_logits = np.asarray([lexical[key]['logit'] for key in ids])
    head = frozen['head']
    semantic = vectors @ np.asarray(head['weights']) + head['bias']
    combined = lexical_logits + frozen['selected']['semantic_logit_weight'] * semantic
    calibration = partitions['calibration']
    point = cutoff(labels[calibration], combined[calibration])
    baseline_point = cutoff(labels[calibration], lexical_logits[calibration])
    results = {name: metrics(labels[mask], combined[mask], point) for name, mask in partitions.items()}
    baseline = {name: metrics(labels[mask], lexical_logits[mask], baseline_point) for name, mask in partitions.items()}
    by_source = {}
    for name, mask in partitions.items():
        for source in sorted({rows[i]['source'] for i in np.flatnonzero(mask)}):
            indices = np.asarray([i for i in np.flatnonzero(mask) if rows[i]['source'] == source])
            by_source[name + ':' + source] = metrics(labels[indices], combined[indices], point)
    a.output.mkdir(parents=True, exist_ok=False)
    combination = {'schema': 'research-python-reference-only-1',
                   'lexical_model_sha256': frozen['lexical_model_sha256'],
                   'encoder': protocol, 'head': head,
                   'semantic_logit_weight': frozen['selected']['semantic_logit_weight'],
                   'score_bias': math.log(.95 / .05) - point, 'threshold': 95.0}
    (a.output / 'combination.json').write_text(json.dumps(combination, indent=2) + '\n')
    report = {'selected': frozen['selected'], 'partitions': results, 'lexical_baseline': baseline,
              'by_source': by_source, 'operating_point_raw_logit': point,
              'selection_sha256': digest(a.selection / 'selection-frozen.json'),
              'combination_sha256': digest(a.output / 'combination.json'),
              'eligible': False, 'test_reused_after_previous_experiments': True,
              'limitation': 'Frozen development selection, calibration ham only. Previously examined historical tests are R&D references, not fresh independent validation. No native encoder parity or complete-pipeline validation.'}
    (a.output / 'report.json').write_text(json.dumps(report, indent=2, allow_nan=False) + '\n')
    print(json.dumps({key: value for key, value in report.items() if key != 'by_source'}, indent=2))


if __name__ == '__main__':
    main()
