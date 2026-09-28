#!/usr/bin/env python3
"""Explicitly stop and persistently fence this coordinator before a planned promotion.

Run only when intentionally moving the console. A network timeout is not fencing.
The resulting private receipt must accompany a NEW final standby checkpoint.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
import tomllib
import uuid
import standby
from standby import private_json, STATE, CONFIG, BINARY

SYSTEMD = Path('/etc/systemd/system')
SERVICES = (
    'noisefence.service', 'noisefence-console.service', 'noisefence-train.service',
    'noisefence-url-feed.service', 'noisefence-quality.service',
    'noisefence-standby-push.service', 'noisefence-recovered-standby-push.service',
    'noisefence-recovered-train.service', 'noisefence-recovered-quality.service',
)
TIMERS = (
    'noisefence-standby-push.timer', 'noisefence-recovered-standby-push.timer',
    'noisefence-train.timer', 'noisefence-url-feed.timer', 'noisefence-quality.timer',
    'noisefence-recovered-train.timer', 'noisefence-recovered-quality.timer',
)

def source(recovered):
    path=CONFIG/'config.toml'
    worker=path
    if recovered:
        standby.recovered_source()
        local=standby.selected_state(standby.DATA/'state.sqlite3')
        standby.verify_recovered_source(local)
        path=standby.config_path()
    raw=path.read_bytes()
    cfg=tomllib.loads(raw.decode())
    if cfg['cluster']['role']!='coordinator':
        raise ValueError('Only the active coordinator can issue this receipt; select the recovered console explicitly')
    binding={'source':'recovered' if recovered else 'coordinator',
             'config_sha256':hashlib.sha256(raw).hexdigest(),
             'worker_config_sha256':hashlib.sha256(worker.read_bytes()).hexdigest()}
    return cfg,worker,binding


def fence(recovered=False):
    cfg,worker,binding=source(recovered)
    path=STATE/'fenced.json'
    if path.exists():
        saved=json.loads(path.read_bytes())
        if (saved.get('owner')!=cfg['cluster']['node_id'] or saved.get('source_binding')!=binding
                or not isinstance(saved.get('operation'),str)):
            raise ValueError('Existing fence belongs to another source or requires manual review')
        operation=str(uuid.UUID(saved['operation']))
        if operation!=saved['operation']:raise ValueError('Invalid existing fence operation')
    else:
        operation=str(uuid.uuid4())
        saved={'owner':cfg['cluster']['node_id'],'operation':operation,'fenced':False,'source_binding':binding}
        private_json(path,saved)
    units=[]
    for unit in (*TIMERS, *SERVICES):
        if subprocess.check_output(['systemctl','show',unit,'-p','LoadState','--value'],text=True).strip()!='not-found':
            units.append(unit)
    for unit in units:
        folder=SYSTEMD/(unit+'.d');folder.mkdir(parents=True,exist_ok=True)
        dropin=folder/'99-ha-fenced.conf'
        expected='[Unit]\nConditionPathExists=!/var/lib/noisefence-standby/fenced.json\n'
        if dropin.exists():
            if dropin.is_symlink() or dropin.read_text()!=expected:
                raise ValueError('Fencing drop-in changed')
        else:
            with dropin.open('x') as f:
                f.write(expected);f.flush();os.fsync(f.fileno())
            dropin.chmod(0o644)
            fd=os.open(folder,os.O_RDONLY);os.fsync(fd);os.close(fd)
    subprocess.run(['systemctl','daemon-reload'],check=True)
    for unit in units:
        subprocess.run(['systemctl','stop',unit],check=False,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=70)
    for unit in units:
        state=subprocess.check_output(['systemctl','show',unit,'-p','ActiveState','--value'],text=True).strip()
        if state not in ['inactive','failed']:raise ValueError('Service did not stop: '+unit)
    pid=subprocess.check_output(['systemctl','show','noisefence','-p','MainPID','--value'],text=True).strip()
    if pid!='0':raise ValueError('The SMTP process is still running')
    if saved.get('fenced') is True:
        # Preserve the original time/operation so final checkpoints remain bound.
        return saved
    # Flush newly generated notices and terminal updates before certifying the fence.
    # Run as the queue owner so SQLite/lock-file ownership stays unchanged.
    subprocess.run(['runuser','-u','noisefence','--',str(BINARY),'--config',str(worker),'ha-flush'],check=True,timeout=195,stdout=subprocess.DEVNULL)
    created_ns=time.time_ns()
    receipt={'owner':cfg['cluster']['node_id'],'hostname':cfg['hostname'],'operation':operation,'fenced':True,'created':created_ns//1_000_000_000,'created_ns':created_ns,'method':'systemd-persistent-condition','automatic_restart_blocked':True,'source_binding':binding}
    private_json(STATE/'fenced.json',receipt)
    return receipt

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--recovered-console',action='store_true',help='Fence the restored coordinator and its colocated worker')
    args=parser.parse_args()
    os.umask(0o077)
    if os.geteuid()!=0:raise SystemExit('Root required')
    STATE.mkdir(mode=0o700,parents=True,exist_ok=True)
    with open('/run/noisefence-upgrade.lock','a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        print(json.dumps(fence(args.recovered_console)))
