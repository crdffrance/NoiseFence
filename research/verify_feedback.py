#!/usr/bin/env python3
"""Synthetic export -> fitting -> native prediction parity; not a quality metric."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import uuid

import numpy as np

PROTOCOL = json.loads(Path(__file__).with_name('semantic-protocol.json').read_text())


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('output', type=Path)
    p.add_argument('--binary', type=Path, default=Path('target/debug/noisefence'))
    p.add_argument('--probe', type=Path, default=Path('target/debug/examples/feedback_probe'))
    p.add_argument('--scheduler-python', type=Path, default=Path(sys.executable), help='Python 3.11+ for the service wrapper')
    a = p.parse_args()
    os.umask(0o077)
    a.output.mkdir(parents=True, exist_ok=False)
    config = a.output/'config.toml'
    state = (a.output/'state').resolve()
    settings = (Path(__file__).resolve().parents[1]/'config/development.toml').read_text()
    settings = settings.replace('data_dir = "var/development"', 'data_dir = '+json.dumps(str(state)))
    config.write_text(settings)
    subprocess.run([str(a.binary.resolve()), '--config', str(config), 'init'], check=True, capture_output=True)
    rng, now, count = np.random.default_rng(20260907), int(time.time()), 320
    with sqlite3.connect(state/'state.sqlite3') as db:
        db.execute("INSERT INTO users(username,password) VALUES('fixture','not-a-login-hash')")
        db.execute("INSERT INTO grants(username,address) VALUES('fixture','alice@example.test')")
        for i in range(count):
            spam = bool(i % 2)
            vector = rng.normal(0, .01, PROTOCOL['dimensions'])
            vector[0] = .7 if spam else -.7
            vector = vector.astype(np.float32)
            vector /= np.linalg.norm(vector)
            # The lexical component has deliberate errors, so hybrid selection
            # must exercise a nonzero dense contribution rather than a no-op head.
            word = 1 if spam ^ (i % 5 == 0) else 2
            features = [[word, .8], [3, .6]]
            fingerprint = hashlib.sha256(f'fixture-campaign-{i}'.encode()).hexdigest()
            scan = {'feature_version': 3, 'score': 50., 'tagged': False, 'complete': i % 7 != 0,
                    'features_complete': True,
                    'model': 'synthetic-parity', 'reasons': [], 'features': features,
                    'subject': 'synthetic', 'sender': 'fixture@example.test',
                    'fingerprint': fingerprint, 'campaign_simhash': fingerprint[:16], 'elapsed_ms': 0,
                    'semantic': {'status': 'complete', 'model': 'synthetic-parity',
                                 'encoder': PROTOCOL['encoder'], 'elapsed_ms': 0, 'logit': 0.,
                                 'contribution': 0., 'features': vector.tolist(), 'protocol': PROTOCOL}}
            key = str(uuid.UUID(int=i+1))
            db.execute('INSERT INTO messages(id,created,sender,scan,raw_present) VALUES(?,?,?,?,0)',
                       (key, now, 'fixture@example.test', json.dumps(scan)))
            db.execute("INSERT INTO deliveries(message_id,address,destination,hosts,status,next_attempt) VALUES(?,'alice@example.test','alice@example.test','[]','delivered',0)", (key,))
            db.execute("INSERT INTO feedback(username,message_id,spam,created) VALUES('fixture',?,?,?)", (key, spam, now))
    snapshot = a.output/'feedback.jsonl'
    export = subprocess.run([str(a.binary.resolve()), '--config', str(config), 'export-learning',
                             str(snapshot), '--require-semantic'], check=True, capture_output=True, text=True)
    exported = json.loads(export.stdout)
    if exported['exported'] != count or exported['semantic_exported'] != count:
        raise ValueError('Synthetic export incomplete')
    if exported['exported_with_incomplete_checks'] != len(range(0, count, 7)):
        raise ValueError('External failures selected the training corpus')
    candidate = a.output/'candidate'
    subprocess.run([sys.executable, str(Path(__file__).with_name('train_feedback.py')),
                    str(snapshot), str(candidate), '--hybrid'], check=True, capture_output=True)
    manifest = json.loads((candidate/'native-combination.json').read_text())
    if manifest['semantic_weight'] <= 0:
        raise ValueError('Fixture failed to exercise a nonzero semantic contribution')
    native = subprocess.run([str(a.probe.resolve()), str(candidate/'model.json'),
                             str(candidate/'native-combination.json'), str(snapshot)],
                            check=True, capture_output=True, text=True)
    reference = {r['id']: r for r in json.loads((candidate/'predictions.json').read_text())}
    actual = {r['id']: r for r in map(json.loads, native.stdout.splitlines())}
    if set(actual) != set(reference) or len(actual) != count:
        raise ValueError('Native/reference samples differ')
    errors = {field: max(abs(actual[k][field]-reference[k][field]) for k in actual)
              for field in ('lexical_logit', 'combined_logit')}
    if max(errors.values()) > 1e-8:
        raise ValueError('Native prediction mismatch: '+str(errors))
    boundary = np.log(.95/.05)
    if any((actual[k]['combined_logit'] >= boundary) != (reference[k]['combined_logit'] >= boundary) for k in actual):
        raise ValueError('Native/reference decisions differ')
    with sqlite3.connect(state/'state.sqlite3') as db:
        pending = db.execute("SELECT COUNT(*) FROM deliveries WHERE status!='delivered'").fetchone()[0]
    if pending or list((state/'spool').iterdir()):
        raise ValueError('Parity fixture unexpectedly queued mail')
    # Exercise the actual service wrapper with the real Rust export and trainer.
    # Linux uses tmpfs scratch to catch accidental cross-filesystem renames.
    bundle = a.output/'bundle'
    (bundle/'research').mkdir(parents=True)
    shutil.copy2(a.binary.resolve(), bundle/'noisefence')
    for name in ('train_feedback.py', 'train_linear.py', 'semantic-protocol.json'):
        shutil.copy2(Path(__file__).with_name(name), bundle/'research'/name)
    config.write_text(settings.replace('[filter]\n', '[filter]\nmodel = '+json.dumps(str((candidate/'model.json').resolve()))+'\n')
                      + '\n[filter.semantic]\nencoder_dir = "unused-by-vector-export"\ncombination = '
                      + json.dumps(str((candidate/'native-combination.json').resolve()))+'\n')
    scheduled = a.output/'scheduled'
    with tempfile.TemporaryDirectory(prefix='noisefence-feedback-parity-',
                                     dir='/dev/shm' if sys.platform == 'linux' else None) as directory:
        cross_device = os.stat(directory).st_dev != a.output.stat().st_dev
        subprocess.run([str(a.scheduler_python), str(Path(__file__).resolve().parents[1]/'deploy/train-feedback.py'),
                        '--binary', str(bundle/'noisefence'), '--config', str(config),
                        '--python', sys.executable, '--directory', str(scheduled),
                        '--scratch-directory', directory], check=True, capture_output=True)
        if list(Path(directory).iterdir()):
            raise ValueError('Scheduler retained per-message vectors')
    latest = json.loads((scheduled/'latest-candidate.json').read_text())
    prepared = Path(latest['candidate'])
    if latest['activated'] or latest['status'] != 'candidate_prepared' or (prepared/'predictions.json').exists():
        raise ValueError('Scheduler activation or retention invariant failed')
    scheduler_native = subprocess.run([str(a.probe.resolve()), str(prepared/'model.json'),
                                       str(prepared/'native-combination.json'), str(snapshot)],
                                      check=True, capture_output=True, text=True)
    if scheduler_native.stdout != native.stdout:
        raise ValueError('Scheduled aggregate candidate changed native predictions')
    report = {'scope': 'synthetic retained-vector pipeline parity; no quality claim',
              'samples': count, 'exported': exported, 'semantic_weight': manifest['semantic_weight'],
              'maximum_logit_errors': errors, 'all_decisions_match': True, 'sent': False,
              'eligible': json.loads((candidate/'report.json').read_text())['eligible']}
    report['scheduler'] = {'real_export_and_training': True, 'native_predictions_unchanged': True,
                           'per_message_files_retained': False, 'cross_device_scratch': cross_device}
    if report['eligible']:
        raise ValueError('Correction-only candidate unexpectedly eligible')
    (a.output/'verification.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
