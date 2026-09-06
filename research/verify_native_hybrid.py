#!/usr/bin/env python3
"""Compare complete Rust hybrid scores with the frozen Python reference."""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import subprocess
import time


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--config', type=Path, required=True)
    p.add_argument('--expected', type=Path, required=True)
    p.add_argument('--reference', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--binary', type=Path, default=Path('target/release/noisefence'))
    p.add_argument('--corpus', type=Path, default=Path('corpus'))
    p.add_argument('--regression', type=Path)
    a = p.parse_args()
    os.umask(0o077)
    expected = json.loads(a.expected.read_text())
    point = json.loads(a.reference.read_text())['operating_point_raw_logit']
    paths = {}
    with (a.corpus / 'research/prepared/manifest.jsonl').open() as source:
        for line in source:
            row = json.loads(line)
            key = Path(row['path']).stem
            if key in expected:
                paths[key] = a.corpus / row['path']
    if set(paths) != set(expected):
        raise ValueError('Missing native parity inputs')

    def scan(path):
        result = subprocess.run([str(a.binary.resolve()), '--config', str(a.config), 'scan', str(path)],
                                check=True, capture_output=True, text=True, timeout=30)
        return json.loads(result.stdout)

    checks = []
    for key, row in expected.items():
        actual = scan(paths[key])
        expected_score = 100 / (1 + math.exp(-max(-40, min(40, row['raw_combined_logit'] - point + math.log(19)))))
        error = abs(expected_score - actual['score'])
        if not actual['complete'] or actual['semantic']['status'] != 'complete' or error > 1e-4 or (actual['score'] >= 95) != row['python_spam']:
            raise ValueError(f'Native hybrid parity failed: {key}; score error={error}, status={actual["semantic"]["status"]}')
        checks.append({'raw_sha256': key, 'partition': row['partition'],
                       'score_absolute_error': error, 'score': actual['score'], 'classification_equal': True})
        if len(checks) % 8 == 0:
            print(json.dumps({'verified': len(checks), 'total': len(expected)}), flush=True)
    regression = None
    if a.regression:
        actual = scan(a.regression)
        actual.pop('features')
        actual['semantic'].pop('features')
        regression = {'known_development_case_not_independent_test': True,
                      'source_sha256': hashlib.sha256(a.regression.read_bytes()).hexdigest(), 'analysis': actual}
    report = {'created': int(time.time()), 'passed': True, 'fixtures': len(checks),
              'checks': checks, 'max_score_absolute_error': max(row['score_absolute_error'] for row in checks),
              'regression': regression, 'scope': 'Native MIME/lexical/semantic scores; no external checks or delivery'}
    with a.output.open('x') as out:
        json.dump(report, out, indent=2)
        out.write('\n')
    print(json.dumps({key: value for key, value in report.items() if key not in ('checks', 'regression')}, indent=2))


if __name__ == '__main__':
    main()
