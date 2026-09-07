#!/usr/bin/env python3
"""Export and train the configured feature family; publish candidates only."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import stat
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
                 str(snapshot), str(candidate), '--aggregate-only']
        if hybrid:
            export += ['--require-semantic']
            train += ['--hybrid']
        return export, train, 'schema-3-hybrid' if hybrid else 'schema-3-lexical'
    if version not in (1, 2) or hybrid:
        raise ValueError('Unsupported training schema; no fallback allowed')
    return ([str(binary), '--config', str(config), 'export-feedback', str(snapshot)],
            [str(binary), 'train', str(snapshot), '--output', str(candidate/'model.json'),
             '--algorithm', model.get('algorithm', 'logistic').replace('_', '-')], 'legacy')


def private_directory(path):
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError('Training directory must be owned by this user, private and not a symlink')


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_json(path, value):
    # Always stage next to the destination: /run may be a different filesystem.
    with tempfile.NamedTemporaryFile(mode='w', prefix='.status-', dir=path.parent, delete=False) as stream:
        temporary = Path(stream.name)
        try:
            json.dump(value, stream, allow_nan=False)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
            os.replace(temporary, path)
            sync_directory(path.parent)
        finally:
            temporary.unlink(missing_ok=True)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', type=Path, default=Path('/opt/noisefence/noisefence'))
    p.add_argument('--config', type=Path, default=Path('/etc/noisefence/config.toml'))
    p.add_argument('--python', type=Path, default=Path(os.environ.get('NOISEFENCE_TRAIN_PYTHON', '/opt/noisefence-learning/bin/python')))
    p.add_argument('--directory', type=Path, default=Path('/var/lib/noisefence/models'))
    p.add_argument('--scratch-directory', type=Path,
                   default=Path(os.environ['RUNTIME_DIRECTORY']) if os.environ.get('RUNTIME_DIRECTORY') else None,
                   help='Private feature scratch space; systemd supplies /run/noisefence-learning')
    a = p.parse_args()
    os.umask(0o077)
    private_directory(a.directory)
    if a.scratch_directory is not None:
        private_directory(a.scratch_directory)
    # Keep the export and trainer from the same immutable release during upgrades.
    a.binary = a.binary.resolve()
    # Never let a manual run race the timer or publish an older snapshot last.
    lock_fd = os.open(a.directory/'training.lock', os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(lock_fd, 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        candidates = a.directory/'candidates'
        private_directory(candidates)
        name = time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())+'-'+uuid.uuid4().hex[:8]
        final = candidates/name
        result = {'status': 'failed', 'started_at': int(time.time()), 'activated': False}
        try:
            # Per-message data live only in runtime space; aggregate candidates stage
            # on the durable filesystem so their final rename never crosses devices.
            with tempfile.TemporaryDirectory(prefix='feedback-', dir=a.scratch_directory) as scratch, \
                    tempfile.TemporaryDirectory(prefix='.candidate-stage-', dir=a.directory) as stage:
                snapshot = Path(scratch)/'feedback.jsonl'
                candidate = Path(stage)/'candidate'
                export, train, family = commands(a.binary, a.config, a.python, candidate, snapshot)
                result['family'] = family
                exported = subprocess.run(export, check=True, capture_output=True, text=True, timeout=120)
                if family.startswith('schema-3'):
                    # Counts only; never put per-message data into the persistent status.
                    stats = json.loads(exported.stdout)
                    if not isinstance(stats, dict) or any(type(v) is not int or v < 0 for v in stats.values()):
                        raise ValueError('Invalid export counters')
                    result['export'] = stats
                if family == 'legacy':
                    candidate.mkdir()
                env = dict(os.environ, OPENBLAS_NUM_THREADS='2', OMP_NUM_THREADS='2')
                trained = subprocess.run(train, capture_output=True, text=True, timeout=1800, env=env)
                if trained.returncode == 3 and family.startswith('schema-3'):
                    outcome = json.loads(trained.stdout)
                    if outcome.get('status') != 'insufficient_feedback' or candidate.exists():
                        raise ValueError('Invalid insufficient-feedback outcome')
                    result['status'] = 'insufficient_feedback'
                else:
                    trained.check_returncode()
                    if (candidate/'predictions.json').exists():
                        raise ValueError('Scheduled training must not persist per-message predictions')
                    os.rename(candidate, final)
                    sync_directory(candidates)
                    result.update(status='candidate_prepared', candidate=str(final))
                    atomic_json(a.directory/'latest-candidate.json', result)
        except Exception:
            result['status'] = 'failed'
            raise
        finally:
            # Even failures/insufficient labels leave aggregate, monitorable status.
            result['finished_at'] = int(time.time())
            atomic_json(a.directory/'last-training.json', result)
        print(json.dumps(result))


if __name__ == '__main__':
    main()
