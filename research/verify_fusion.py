#!/usr/bin/env python3
"""Synthetic Rust export -> learned fusion -> Rust parity. Not a quality test."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

import numpy as np
import train_fusion as fusion
import verify_population


def pin(path):
    return {'path': str(path.resolve()), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    parser.add_argument('--binary', type=Path, default=Path('target/debug/noisefence'))
    parser.add_argument('--fixture', type=Path, default=Path('target/debug/examples/fusion_fixture'))
    args = parser.parse_args()
    os.umask(0o077)
    args.output.mkdir(parents=True, exist_ok=False)
    original, vectors = args.output/'observations.jsonl', args.output/'vectors.jsonl'
    subprocess.run([str(args.fixture.resolve()), str(original)], check=True, capture_output=True)
    subprocess.run([str(args.binary.resolve()), 'fusion-export', str(original), '--output', str(vectors)],
                   check=True, capture_output=True)
    annotations = args.output/'annotations.jsonl'
    artifacts = None
    with annotations.open('w') as writer:
        for i, row in enumerate(fusion.lines(original)):
            artifacts = row['evidence']['artifacts']
            writer.write(json.dumps({'id': row['id'], 'label': 'unwanted_binary' if row['spam'] else 'legit',
                                     'split': fusion.SPLITS[i//80], 'campaign': row['fingerprint'],
                                     'language': 'fr' if i % 3 else 'en', 'kind': 'software-fixture'})+'\n')
    history = args.output/'base-history.json'
    fusion.private_json(history, {'schema': 'noisefence-base-history-1', 'complete_for': fusion.BASE_USES,
                                  'lexical_model_sha256': artifacts['lexical_model_sha256'],
                                  'semantic_model_sha256': artifacts['semantic_model_sha256'],
                                  'rows': [{'fingerprint': hashlib.sha256(b'base fixture').hexdigest(),
                                            'campaign': hashlib.sha256(b'base fixture campaign').hexdigest(),
                                            'simhash': hashlib.sha256(b'base fixture simhash').hexdigest()[:16]}]})
    manifest = args.output/'manifest.json'
    fusion.private_json(manifest, {'schema': 'noisefence-fusion-experiment-1', 'version': 'synthetic-parity',
                                  'purpose': 'research', 'protocol_sha256': fusion.PROTOCOL_HASH,
                                  'vectors': pin(vectors), 'annotations': pin(annotations), 'base_history': pin(history),
                                  'sampling': {'kind': 'synthetic', 'description': 'Fabricated observations for software verification only',
                                               'authorization': 'No real message, delivery, detector query or model training corpus',
                                               'start_at': 1788739200, 'end_at': 1788739599}})
    candidate = args.output/'candidate'
    fusion.fit(manifest, candidate)
    _, _, _, rows, _ = fusion.load_experiment(manifest)
    maximum_logit_error = maximum_probability_error = 0.
    checked = 0
    for variant in fusion.VARIANTS:
        predictions = args.output/(variant+'-native.jsonl')
        model_path = candidate/(variant+'.json')
        subprocess.run([str(args.binary.resolve()), 'fusion-predict', str(original), '--model', str(model_path),
                        '--output', str(predictions)], check=True, capture_output=True)
        native = {r['id']: r['prediction'] for r in fusion.lines(predictions) if r['type'] == 'row'}
        model = fusion.decode(model_path.read_bytes())
        logits, probabilities, decisions = fusion.model_predictions(model, rows)
        for index, row in enumerate(rows):
            p = native[row['id']]
            maximum_logit_error = max(maximum_logit_error, abs(p['logit']-logits[index]))
            maximum_probability_error = max(maximum_probability_error, abs(p['probability']-probabilities[index]))
            fusion.require(p['would_tag'] == bool(decisions[index]), 'Native decision differs')
            fusion.require(row['tag_eligible'] or not p['would_tag'], 'Incomplete fixture marked')
            checked += 1
    fusion.require(maximum_logit_error < 1e-9 and maximum_probability_error < 1e-9, 'Native numerical parity failed')
    result = fusion.evaluate(manifest, candidate)
    fusion.require(not result['production_eligible'] and not result['target_supported_on_this_test'],
                   'Synthetic data incorrectly authorized production')
    report = {'synthetic': True, 'predictions_checked': checked, 'variants': len(fusion.VARIANTS),
              'application': artifacts['application'], 'protocol_sha256': fusion.PROTOCOL_HASH,
              'max_logit_error': maximum_logit_error, 'max_probability_error': maximum_probability_error,
              'decision_disagreements': 0, 'production_eligible': False, 'mail_sent': False}
    fusion.private_json(args.output/'parity.json', report)
    report['population'] = verify_population.verify(args.output, args.binary, args.output/'population')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
