#!/usr/bin/env python3
"""Bind a frozen combination to its calibrated lexical fallback for native trials."""
import argparse
import json
import os
from pathlib import Path
from train_linear import digest


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('reference', type=Path)
    p.add_argument('raw_lexical', type=Path)
    p.add_argument('calibrated_lexical', type=Path)
    p.add_argument('output', type=Path)
    a = p.parse_args()
    os.umask(0o077)
    reference = json.loads(a.reference.read_text())
    raw, calibrated = (json.loads(path.read_text()) for path in (a.raw_lexical, a.calibrated_lexical))
    if reference['lexical_model_sha256'] != digest(a.raw_lexical):
        raise ValueError('Reference lexical model checksum differs')
    for field in ('weights', 'idf', 'algorithm', 'feature_version'):
        if raw[field] != calibrated[field]:
            raise ValueError('Calibrated fallback must use exactly the same lexical features and weights')
    encoder = reference['encoder']
    result = {'schema': 'noisefence-hybrid-1', 'version': 'research-hybrid-e5-20260907',
              'lexical_model_sha256': digest(a.calibrated_lexical),
              'encoder': encoder['encoder'], 'revision': encoder['revision'],
              'text_schema': encoder['text_schema'], 'max_tokens': encoder['max_tokens'],
              'head_weights': reference['head']['weights'], 'head_bias': reference['head']['bias'],
              'semantic_weight': reference['semantic_logit_weight'],
              'score_bias_delta': reference['score_bias'] - (calibrated['bias'] - raw['bias']),
              'threshold': reference['threshold']}
    with a.output.open('x') as out:
        json.dump(result, out, indent=2, allow_nan=False)
        out.write('\n')
    print(json.dumps({'output': str(a.output), 'model_sha256': digest(a.output),
                      'production_eligible': False, 'purpose': 'native parity and bounded observation trials'}))


if __name__ == '__main__':
    main()
