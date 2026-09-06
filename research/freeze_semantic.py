#!/usr/bin/env python3
"""Freeze a development-selected combination before opening reference metrics."""
import argparse
import json
import os
from pathlib import Path
import time
from train_linear import digest


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('selection', type=Path)
    p.add_argument('lexical_model', type=Path)
    p.add_argument('training_embeddings', type=Path)
    a = p.parse_args()
    os.umask(0o077)
    report = json.loads((a.selection / 'report.json').read_text())
    selected = report['selected']
    if selected['family'] != 'lexical_plus_semantic':
        raise ValueError('This evaluator is only for a selected combined model')
    heads = json.loads((a.selection / 'heads.json').read_text())
    frozen = {'created': int(time.time()), 'selected': selected,
              'head': heads[str(selected['C'])],
              'head_file_sha256': digest(a.selection / 'heads.json'),
              'report_sha256': digest(a.selection / 'report.json'),
              'encoder_protocol': json.loads((a.training_embeddings / 'protocol.json').read_text()),
              'lexical_model_sha256': digest(a.lexical_model),
              'calibration_rule': 'empirical 0.1% FPR on calibration ham only; numerical margin 1e-6',
              'selection_metrics_scope': 'development only; already examined historical tests are reference measurements, not fresh independent validation'}
    with (a.selection / 'selection-frozen.json').open('x') as target:
        json.dump(frozen, target, indent=2)
        target.write('\n')


if __name__ == '__main__':
    main()
