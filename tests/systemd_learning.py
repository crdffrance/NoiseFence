#!/usr/bin/env python3
"""Exercise training-unit lifetime rules on Linux; synthetic data, no SMTP.

Run as root on a systemd host. Unique, tiny test units use nobody and are removed.
"""
import configparser
import grp
import json
import os
from pathlib import Path
import pwd
import shutil
import subprocess
import time
import uuid


def main():
    if os.geteuid() != 0:
        raise SystemExit('This systemd integration test requires root')
    settings = configparser.ConfigParser(interpolation=None)
    settings.optionxform = str
    settings.read(Path(__file__).resolve().parents[1]/'deploy/noisefence-train.service')
    service = settings['Service']
    assert service['RuntimeDirectoryPreserve'] == 'no'
    assert service['RuntimeDirectoryMode'] == service['StateDirectoryMode'] == '0700'
    assert service['WorkingDirectory'] == '/var/lib/'+service['StateDirectory']
    user = pwd.getpwnam('nobody')
    results = []
    for abrupt in (False, True):
        name = 'noisefence-learning-test-'+uuid.uuid4().hex[:12]
        runtime = Path('/run')/name
        state = Path('/var/lib')/name
        assert not runtime.exists() and not state.exists()
        script = '''import os,signal,stat
from pathlib import Path
runtime=Path(os.environ['RUNTIME_DIRECTORY'])
state=Path(os.environ['STATE_DIRECTORY'])
assert Path.cwd()==state
assert stat.S_IMODE(runtime.stat().st_mode)==0o700
(runtime/'features.jsonl').write_text('synthetic per-message vectors')
(state/'model.json').write_text('aggregate test weights')
'''
        if abrupt:
            script += 'os.kill(os.getpid(),signal.SIGKILL)\n'
        command = ['systemd-run', '--wait', '--collect', '--pipe', '--quiet', '--unit='+name,
                   '--property=User=nobody', '--property=Group='+grp.getgrgid(user.pw_gid).gr_name,
                   '--property=StateDirectory='+name, '--property=RuntimeDirectory='+name,
                   '--property=WorkingDirectory='+str(state), '--property=RuntimeMaxSec=10']
        for key in ('RuntimeDirectoryPreserve', 'RuntimeDirectoryMode', 'StateDirectoryMode', 'UMask',
                    'MemoryMax', 'OOMScoreAdjust', 'CPUQuota', 'Nice', 'PrivateNetwork',
                    'NoNewPrivileges', 'ProtectSystem', 'ProtectHome', 'PrivateTmp'):
            command.append('--property='+key+'='+service[key])
        command += ['/usr/bin/python3', '-c', script]
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=20)
            if not abrupt and result.returncode:
                raise AssertionError(result.stderr)
            assert bool(result.returncode) == abrupt
            assert (state/'model.json').read_text() == 'aggregate test weights'
            deadline = time.monotonic()+3
            while runtime.exists() and time.monotonic() < deadline:
                time.sleep(.05)
            assert not runtime.exists(), 'Per-message runtime files survived unit termination'
            results.append({'termination': 'SIGKILL' if abrupt else 'normal',
                            'runtime_removed': True, 'aggregate_state_preserved': True})
        finally:
            subprocess.run(['systemctl', 'stop', name], capture_output=True, timeout=10)
            if state.exists():
                shutil.rmtree(state)
    print(json.dumps({'synthetic_only': True, 'sent': False, 'checks': results}, indent=2))


if __name__ == '__main__':
    main()
