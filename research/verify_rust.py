#!/usr/bin/env python3
"""Check training/serving parity on held-out emails and optional private regressions."""
import argparse
import hashlib
import json
import math
from pathlib import Path
import subprocess
import tempfile
import time


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('experiment', type=Path)
    p.add_argument('--binary', type=Path, default=Path('target/release/noisefence'))
    p.add_argument('--corpus', type=Path, default=Path('corpus'))
    p.add_argument('--regression', type=Path)
    a = p.parse_args()
    binary = a.binary.resolve()
    report = json.loads((a.experiment / 'report.json').read_text())
    frozen = json.loads((a.experiment / 'selection-frozen.json').read_text())
    predictions = [json.loads(line) for line in (a.experiment / 'predictions.jsonl').read_text().splitlines()]
    test = [row for row in predictions if row['partition'] in ('test', 'external')]
    selected = sorted(test, key=lambda row: row['raw_sha256'])[:16]
    ham = [row for row in predictions if row['partition'] == 'calibration' and not row['spam']]
    selected += sorted(ham, key=lambda row: abs(row['logit'] - report['operating_point_raw_logit']))[:6]
    wanted = {row['raw_sha256']: row for row in selected}
    features = {}
    cache = a.experiment / 'parity-features.json'
    if cache.exists():
        cached = json.loads(cache.read_text())
        if cached['corpus_sha256'] == report['corpus_sha256'] and set(cached['features']) == set(wanted):
            features = cached['features']
    if not features:
        with Path(frozen['selected']['input']).open() as source:
            for line in source:
                row = json.loads(line)
                if row['raw_sha256'] in wanted:
                    features[row['raw_sha256']] = row['features']
                    if len(features) == len(wanted):
                        break
        cache.write_text(json.dumps({'corpus_sha256': report['corpus_sha256'], 'features': features}) + '\n')
    paths = {}
    with (a.corpus / 'research/prepared/manifest.jsonl').open() as source:
        for line in source:
            record = json.loads(line)
            raw_path = a.corpus / record['path']
            if raw_path.stem in wanted:
                paths[raw_path.stem] = raw_path.resolve()
    if set(paths) != set(wanted) or set(features) != set(wanted):
        raise ValueError('Missing parity fixtures')
    checks = []
    with tempfile.TemporaryDirectory(prefix='noisefence-parity-') as temporary:
        root = Path(temporary)
        config = Path('config/development.toml').read_text()
        config = config.replace('data_dir = "var/development"', 'data_dir = ' + json.dumps(str(root / 'state')))
        config = config.replace('[filter]', '[filter]\nmodel = ' + json.dumps(str((a.experiment / 'model.json').resolve())))
        config_file = root / 'config.toml'
        config_file.write_text(config)

        def scan(path):
            started = time.monotonic()
            result = subprocess.run([str(binary), '--config', str(config_file), 'scan', str(path)],
                                    check=True, capture_output=True, text=True, timeout=20)
            value = json.loads(result.stdout)
            return value, round((time.monotonic() - started) * 1000, 2)

        for key, row in wanted.items():
            value, elapsed = scan(paths[key])
            if value['features'] != features[key]:
                raise ValueError('Training/serving feature mismatch: ' + key)
            logit = row['logit'] + math.log(.95 / .05) - report['operating_point_raw_logit']
            expected = 100 / (1 + math.exp(-max(-40, min(40, logit))))
            if report['feature_version'] != 3:
                expected = round(expected, 1)
            error = abs(expected - value['score'])
            if error > 1e-8 or (value['score'] >= 95) != row['predicted_spam']:
                raise ValueError(f'Prediction parity failed: {key}, expected={expected}, got={value["score"]}')
            checks.append({'raw_sha256': key, 'partition': row['partition'],
                           'score_absolute_error': error, 'process_ms_including_model_load': elapsed})
        regression = None
        if a.regression:
            value, elapsed = scan(a.regression.resolve())
            value.pop('features')
            regression = {'known_development_case_not_independent_test': True,
                          'source_sha256': hashlib.sha256(a.regression.read_bytes()).hexdigest(),
                          'analysis': value, 'process_ms_including_model_load': elapsed}
        # Verify the new command doesn't create queue entries or require ARC.
        output = root / 'analysis.json'
        fixture = root / 'valid-smtp.eml'
        fixture.write_bytes(b'From: test@example.org\r\nTo: alice@example.test\r\nSubject: Meeting tomorrow\r\n\r\nOur meeting is confirmed for tomorrow.\r\n')
        result = subprocess.run([str(binary), '--config', str(config_file), 'analyze', str(fixture),
                                 '--source-ip', '192.0.2.10', '--helo', 'sender.example.org',
                                 '--mail-from', 'test@example.org', '--output', str(output)],
                                check=True, capture_output=True, text=True, timeout=20)
        receipt = json.loads(result.stdout)
        assert receipt['sent'] is False and output.is_file()
        assert output.stat().st_mode & 0o777 == 0o600
        existing = output.read_bytes()
        repeated = subprocess.run([str(binary), '--config', str(config_file), 'analyze', str(fixture),
                                   '--source-ip', '192.0.2.10', '--helo', 'sender.example.org',
                                   '--mail-from', 'test@example.org', '--output', str(output)],
                                  capture_output=True, text=True, timeout=20)
        assert repeated.returncode != 0 and output.read_bytes() == existing
        import sqlite3
        with sqlite3.connect(root / 'state/state.sqlite3') as db:
            assert db.execute('SELECT COUNT(*) FROM messages').fetchone()[0] == 0
    verification = {'passed': True, 'fixtures': len(checks), 'checks': checks,
                    'max_score_absolute_error': max(row['score_absolute_error'] for row in checks),
                    'analyze_without_delivery': True, 'regression': regression}
    (a.experiment / 'rust-verification.json').write_text(json.dumps(verification, indent=2) + '\n')
    print(json.dumps({k: v for k, v in verification.items() if k != 'checks'}, indent=2))


if __name__ == '__main__':
    main()
