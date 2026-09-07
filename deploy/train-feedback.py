#!/usr/bin/env python3
"""Export and train the configured feature family; publish candidates only."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import tomllib
import uuid


def commands(binary, config, training_python, candidate, snapshot):
    settings = tomllib.loads(config.read_text())
    model_path = settings['filter'].get('model')
    model = json.loads(Path(model_path).read_text()) if model_path else {}
    version = model.get('feature_version', 1)
    hybrid = bool(settings['filter'].get('semantic'))
    if version == 3:
        export = [str(binary), '--config', str(config), 'export-learning', str(snapshot)]
        train = [str(training_python), str(binary.resolve().parent/'research/train_feedback.py'),
                 str(snapshot), str(candidate)]
        if hybrid:
            export += ['--require-semantic']
            train += ['--hybrid']
        return export, train, 'schema-3-hybrid' if hybrid else 'schema-3-lexical'
    if version not in (1, 2) or hybrid:
        raise ValueError('Unsupported training schema; no fallback allowed')
    return ([str(binary), '--config', str(config), 'export-feedback', str(snapshot)],
            [str(binary), 'train', str(snapshot), '--output', str(candidate/'model.json'),
             '--algorithm', model.get('algorithm', 'logistic').replace('_', '-')], 'legacy')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', type=Path, default=Path('/opt/noisefence/noisefence'))
    p.add_argument('--config', type=Path, default=Path('/etc/noisefence/config.toml'))
    p.add_argument('--python', type=Path, default=Path(os.environ.get('NOISEFENCE_TRAIN_PYTHON', '/opt/noisefence-learning/bin/python')))
    p.add_argument('--directory', type=Path, default=Path('/var/lib/noisefence/models'))
    a = p.parse_args()
    os.umask(0o077)
    a.directory.mkdir(parents=True, exist_ok=True)
    # Never let a manual run race the timer or publish an older snapshot last.
    with (a.directory/'training.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        candidates = a.directory/'candidates'
        candidates.mkdir(exist_ok=True)
        name = time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())+'-'+uuid.uuid4().hex[:8]
        final = candidates/name
        with tempfile.TemporaryDirectory(prefix='.training-', dir=a.directory) as directory:
            snapshot = Path(directory)/'feedback.jsonl'
            candidate = Path(directory)/'candidate'
            export, train, family = commands(a.binary, a.config, a.python, candidate, snapshot)
            subprocess.run(export, check=True, timeout=120)
            if family == 'legacy':
                candidate.mkdir()
            env = dict(os.environ, OPENBLAS_NUM_THREADS='2', OMP_NUM_THREADS='2')
            subprocess.run(train, check=True, timeout=1800, env=env)
            os.rename(candidate, final)
            fd = os.open(candidates, os.O_RDONLY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
            result = {'candidate': str(final), 'family': family, 'activated': False}
            tmp = Path(directory)/'latest.json'
            with tmp.open('x') as stream:
                json.dump(result, stream)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(tmp, a.directory/'latest-candidate.json')
            fd = os.open(a.directory, os.O_RDONLY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        print(json.dumps(result))


if __name__ == '__main__':
    main()
