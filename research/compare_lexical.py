#!/usr/bin/env python3
"""Compare frozen lexical weights on identical held-out feature rows, offline.

Neither threshold is fitted here. Historical test reuse remains historical reuse.
The semantic head and the full gateway are not measured by this comparison.
"""
import argparse
import json
import math
import os
from pathlib import Path

import numpy as np
from sklearn.preprocessing import normalize
from train_linear import digest, load, metrics, partition


def main():
    os.umask(0o077)
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('experiment', type=Path)
    p.add_argument('baseline', type=Path)
    args = p.parse_args()
    report = json.loads((args.experiment / 'report.json').read_text())
    frozen = json.loads((args.experiment / 'selection-frozen.json').read_text())
    source = Path(frozen['selected']['input'])
    if digest(source) != report['corpus_sha256']:
        raise ValueError('Corpus changed after model selection')
    model_path = args.experiment / 'model.json'
    if digest(model_path) != report['model_sha256']:
        raise ValueError('Candidate changed after final evaluation')
    output = args.experiment / 'comparison.json'
    if output.exists():
        raise ValueError('Comparison already exists')
    matrix, examples = load(source, report['dimension'])
    splits = partition(examples)
    labels = np.array([r['spam'] for r in examples], dtype=bool)
    strata = {name: indices for name, indices in splits.items() if name in ('test', 'external') and len(indices)}
    for name, indices in list(strata.items()):
        for source_name in sorted({examples[i]['source'] for i in indices}):
            strata[name + ':' + source_name] = np.array([i for i in indices if examples[i]['source'] == source_name])
    result = {'schema': 'noisefence-lexical-comparison-1', 'threshold': 95.0,
              'corpus_sha256': report['corpus_sha256'], 'models': {}, 'eligible': False,
              'scope': 'Frozen lexical content models only; no semantic head, SMTP, DNS, reputation, OCR or LLM. Existing historical tests are reused references, not independent recent validation.'}
    for name, path in [('baseline', args.baseline), ('candidate', model_path)]:
        model = json.loads(path.read_text())
        if model['feature_version'] != report['feature_version'] or model['algorithm'] != 'logistic':
            raise ValueError('Incompatible lexical model')
        if len(model['idf']) != report['dimension'] or len(model['weights']) != report['dimension']:
            raise ValueError('Incompatible lexical dimensions')
        logits = np.asarray(normalize(matrix.multiply(np.array(model['idf'])).tocsr()) @ np.array(model['weights'])).ravel() + model['bias']
        scores = {key: metrics(labels[indices], logits[indices], math.log(.95 / .05))
                  for key, indices in strata.items()}
        if name == 'candidate':
            for metric in ('ham', 'spam', 'true_positive', 'false_positive'):
                if scores['test'][metric] != report['partitions']['test'][metric]:
                    raise ValueError('Exported model does not reproduce final evaluation')
        result['models'][name] = {'version': model['version'], 'sha256': digest(path), 'results': scores}
    with output.open('x') as stream:
        json.dump(result, stream, indent=2, allow_nan=False)
        stream.write('\n')
    print(json.dumps({name: model['results']['test'] for name, model in result['models'].items()}, indent=2))


if __name__ == '__main__':
    main()
