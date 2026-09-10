#!/usr/bin/env python3
"""Add novel campaigns without reshuffling any historical corpus partition.

All reference records, including previously excluded and held-out messages, block
augmentation. References are metadata only during grouping; no evaluation occurs.
"""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile


def digest(path):
    hasher = hashlib.sha256()
    with path.open('rb') as source:
        while chunk := source.read(1024 * 1024):
            hasher.update(chunk)
    return hasher.hexdigest()


def select_novel(records, reference_count):
    parents = list(range(len(records)))

    def find(i):
        while i != parents[i]:
            parents[i] = parents[parents[i]]
            i = parents[i]
        return i

    def union(a, b):
        a, b = find(a), find(b)
        parents[max(a, b)] = min(a, b)

    exact, hashes, buckets = {}, {}, defaultdict(list)
    for i, item in enumerate(records):
        for name in ('raw_sha256', 'campaign', 'token_campaign'):
            if name not in item:
                continue
            key = name, item[name]
            if key in exact:
                union(i, exact[key])
            exact[key] = i
        for name in ('simhash', 'token_simhash'):
            if name not in item:
                continue
            value = int(item[name], 16)
            if (name, value) in hashes:
                union(i, hashes[(name, value)])
                continue
            neighbors = set()
            for band in range(4):
                neighbors.update(buckets[(name, band, (value >> (band * 16)) & 0xffff)])
            for neighbor in neighbors:
                if (value ^ neighbor).bit_count() <= 3:
                    union(i, hashes[(name, neighbor)])
            hashes[(name, value)] = i
            for band in range(4):
                buckets[(name, band, (value >> (band * 16)) & 0xffff)].append(value)
    groups = defaultdict(list)
    for i in range(len(records)):
        groups[find(i)].append(i)
    selected, counts = {}, Counter()
    for indices in groups.values():
        new = [i for i in indices if i >= reference_count]
        if not new:
            continue
        if len(new) != len(indices):
            counts['reference_overlap_rows_removed'] += len(new)
            counts['reference_overlap_groups_removed'] += 1
            if len({records[i]['spam'] for i in indices}) > 1:
                counts['reference_overlap_conflicting_rows'] += len(new)
            continue
        if len({records[i]['spam'] for i in new}) > 1:
            counts['novel_conflicting_rows_removed'] += len(new)
            counts['novel_conflicting_groups_removed'] += 1
            continue
        representative = min(new, key=lambda i: records[i]['raw_sha256'])
        selected[representative - reference_count] = min(records[i]['campaign'] for i in new)
        counts['novel_duplicate_rows_removed'] += len(new) - 1
        counts['novel_groups_selected'] += 1
        counts['selected_spam' if records[representative]['spam'] else 'selected_ham'] += 1
    return selected, counts


def metadata(paths, reject_external=False):
    records = []
    for path in paths:
        with path.open() as stream:
            for line in stream:
                row = json.loads(line)
                if row['feature_version'] != 3 or type(row['spam']) is not bool:
                    raise ValueError('Expected schema 3 with boolean source labels')
                if reject_external and row.get('external_test'):
                    raise ValueError('Reserved external tests cannot be used as augmentation')
                records.append({k: row[k] for k in ('raw_sha256', 'campaign', 'simhash', 'spam')})
    return records


def main():
    os.umask(0o077)
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('augmentation', type=Path)
    p.add_argument('baseline', type=Path, help='Frozen grouped corpus retained byte-for-byte')
    p.add_argument('output', type=Path, help='New private experiment directory')
    p.add_argument('--reference', type=Path, action='append', required=True,
                   help='All historical raw records, plus reserved diagnostics; repeat as needed')
    p.add_argument('--token-keys', type=Path, action='append', default=[],
                   help='Optional Rust corpus_keys exports covering every augmentation and baseline row')
    args = p.parse_args()
    if args.output.exists():
        raise ValueError('Output must not exist')
    references = metadata(args.reference)
    reference_ids = {r['raw_sha256'] for r in references}
    baseline = metadata([args.baseline])
    if any(r['raw_sha256'] not in reference_ids for r in baseline):
        raise ValueError('References do not cover every baseline record')
    additions = metadata([args.augmentation], reject_external=True)
    if args.token_keys:
        keys = {}
        for path in args.token_keys:
            with path.open() as stream:
                for line in stream:
                    row = json.loads(line)
                    key = row.pop('raw_sha256')
                    if (set(row) != {'token_campaign', 'token_simhash'}
                            or len(key) != 64 or len(row['token_campaign']) != 64
                            or len(row['token_simhash']) != 16
                            or any(c not in '0123456789abcdef' for c in key + row['token_campaign'] + row['token_simhash'])):
                        raise ValueError('Invalid normalization keys; labels and partitions must remain separate')
                    if key in keys and keys[key] != row:
                        raise ValueError('Conflicting normalization keys')
                    keys[key] = row
        if any(r['raw_sha256'] not in keys for r in additions + baseline):
            raise ValueError('Normalization keys must cover all additions and baseline rows')
        for row in references + additions:
            row.update(keys.get(row['raw_sha256'], {}))
    selected, counts = select_novel(references + additions, len(references))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix='.corpus-merge-', dir=args.output.parent))
    try:
        destination = stage / 'features.jsonl'
        shutil.copyfile(args.baseline, destination)
        with destination.open('a') as out, (stage / 'novel.features.jsonl').open('w') as novel:
            with args.augmentation.open() as source:
                for i, line in enumerate(source):
                    if i in selected:
                        row = json.loads(line)
                        row['group'] = selected[i]
                        row['fingerprint'] = row['campaign']
                        row['external_test'] = False
                        data = json.dumps(row, separators=(',', ':')) + '\n'
                        out.write(data)
                        novel.write(data)
        report = {'schema': 'noisefence-corpus-augmentation-1', 'counts': counts,
            'reference_rows': len(references), 'augmentation_rows': len(additions),
            'baseline_sha256': digest(args.baseline), 'augmentation_sha256': digest(args.augmentation),
            'reference_sha256': {str(p.resolve()): digest(p) for p in args.reference},
            'token_keys_sha256': {str(p.resolve()): digest(p) for p in args.token_keys},
            'merged_sha256': digest(destination), 'novel_sha256': digest(stage / 'novel.features.jsonl'),
            'baseline_partitions_unchanged': True,
            'method': 'Canonical/SHA identity and transitive SimHash distance <=3, plus optional punctuation-normalized token keys; exclude every new component touching any reference. One representative per remaining nonconflicting component.',
            'limitation': 'Heuristic similarity; historical evaluation remains reused, not a new independent production test.'}
        (stage / 'audit.json').write_text(json.dumps(report, indent=2) + '\n')
        stage.rename(args.output)
        print(json.dumps(report, indent=2))
    finally:
        if stage.exists():
            shutil.rmtree(stage)


if __name__ == '__main__':
    main()
