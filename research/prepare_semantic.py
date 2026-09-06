#!/usr/bin/env python3
"""Prepare the existing train/development groups for a local encoder experiment."""
import argparse
import hashlib
import json
import os
from pathlib import Path
from collections import Counter


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('grouped_features', type=Path)
    p.add_argument('manifest', type=Path)
    p.add_argument('output', type=Path)
    p.add_argument('--evaluation-only', action='store_true',
                   help='Export calibration/test/external after freezing a model; never train on this output')
    a = p.parse_args()
    os.umask(0o077)
    a.output.mkdir(parents=True, exist_ok=False)
    rows = []
    with a.grouped_features.open() as source:
        for line in source:
            row = json.loads(line)
            bucket = int(hashlib.sha256(row.get('group', row['fingerprint']).encode()).hexdigest()[:8], 16) % 10
            partition = ('external' if row.get('external_test') else 'test' if bucket < 2 else
                         'calibration' if bucket == 2 else 'development' if bucket == 3 else 'train')
            if (partition in ('train', 'development')) == a.evaluation_only:
                continue
            rows.append({**{key: row[key] for key in ('fingerprint', 'raw_sha256', 'spam', 'source')},
                         'partition': partition})
    wanted = {row['raw_sha256'] for row in rows}
    if len(wanted) != len(rows):
        raise ValueError('Duplicate raw identities in grouped features')
    seen = set()
    with (a.output / 'manifest.jsonl').open('w') as target, a.manifest.open() as source:
        for line in source:
            row = json.loads(line)
            key = Path(row['path']).stem
            if key in wanted and key not in seen:
                target.write(line)
                seen.add(key)
    if wanted != seen:
        raise ValueError('Prepared manifest is missing feature inputs')
    (a.output / 'rows.jsonl').write_text(''.join(json.dumps(row) + '\n' for row in rows))
    print(json.dumps(dict(Counter(row['partition'] for row in rows))))


if __name__ == '__main__':
    main()
