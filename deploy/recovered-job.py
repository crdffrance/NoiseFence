#!/usr/bin/env python3
"""Run local research against the explicitly authorized recovered console."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tomllib

CONFIG = Path('/var/lib/noisefence-standby/active/console.toml')
DATA = CONFIG.parent / 'data'
BINARY = Path('/opt/noisefence/current/noisefence')


def command(job):
    config = tomllib.loads(CONFIG.read_text())
    if config.get('cluster', {}).get('role') != 'coordinator' or Path(config['data_dir']) != DATA:
        raise ValueError('Recovered coordinator configuration required')
    if not config.get('management'):
        raise ValueError('Selected PostgreSQL management required')
    binary = BINARY.resolve(strict=True)
    checked = subprocess.run([str(binary), '--config', str(CONFIG), 'management-recovery-check-console'],
                             check=True, capture_output=True, text=True, timeout=30)
    proof = json.loads(checked.stdout)
    if (proof.get('status') != 'console_authorization_verified'
            or proof.get('smtp_enabled') is not False or proof.get('state_changed') is not False):
        raise ValueError('Recovered console authority was not confirmed')
    script = {'quality': 'quality-worker.py', 'train': 'train-feedback.py'}[job]
    args = ['/usr/bin/python3', str(binary.parent / 'deploy' / script),
            '--config', str(CONFIG), '--binary', str(binary)]
    if job == 'train':
        args += ['--directory', str(DATA / 'models')]
    return args


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('job', choices=('quality', 'train'))
    args = parser.parse_args()
    os.umask(0o077)
    command_line = command(args.job)
    os.execv(command_line[0], command_line)


if __name__ == '__main__':
    main()
