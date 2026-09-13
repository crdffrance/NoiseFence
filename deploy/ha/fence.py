#!/usr/bin/env python3
"""Explicitly stop and persistently fence this coordinator before a planned promotion.

Run only when intentionally moving the console. A network timeout is not fencing.
The resulting private receipt must accompany a NEW final standby checkpoint.
"""
import fcntl
import json
import os
from pathlib import Path
import subprocess
import time
import tomllib
import uuid
from standby import private_json, STATE, CONFIG

def fence():
    cfg=tomllib.loads((CONFIG/'config.toml').read_text())
    if cfg['cluster']['role']!='coordinator':raise ValueError('Only the active coordinator can issue this receipt')
    if (STATE/'fenced.json').exists():raise ValueError('Already fenced: inspect the existing receipt; do not issue another')
    operation=str(uuid.uuid4())
    private_json(STATE/'fenced.json',{'owner':cfg['cluster']['node_id'],'operation':operation,'fenced':False})
    units=['noisefence.service','noisefence-console.service','noisefence-train.service','noisefence-url-feed.service']
    for unit in units:
        if subprocess.check_output(['systemctl','show',unit,'-p','LoadState','--value'],text=True).strip()=='not-found':continue
        folder=Path('/etc/systemd/system')/(unit+'.d');folder.mkdir(parents=True,exist_ok=True)
        dropin=folder/'99-ha-fenced.conf'
        if dropin.exists():raise ValueError('Fencing drop-in already exists')
        with dropin.open('x') as f:
            f.write('[Unit]\nConditionPathExists=!/var/lib/noisefence-standby/fenced.json\n');f.flush();os.fsync(f.fileno())
        dropin.chmod(0o644)
    subprocess.run(['systemctl','daemon-reload'],check=True)
    for unit in ['noisefence-standby-push.timer','noisefence-train.timer','noisefence-url-feed.timer',*units]:
        subprocess.run(['systemctl','stop',unit],check=False,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=70)
    for unit in units:
        state=subprocess.check_output(['systemctl','show',unit,'-p','ActiveState','--value'],text=True).strip()
        if state not in ['inactive','failed']:raise ValueError('Service did not stop: '+unit)
    pid=subprocess.check_output(['systemctl','show','noisefence','-p','MainPID','--value'],text=True).strip()
    if pid!='0':raise ValueError('The SMTP process is still running')
    receipt={'owner':cfg['cluster']['node_id'],'hostname':cfg['hostname'],'operation':operation,'fenced':True,'created':int(time.time()),'method':'systemd-persistent-condition','automatic_restart_blocked':True}
    private_json(STATE/'fenced.json',receipt)
    return receipt

if __name__=='__main__':
    os.umask(0o077)
    if os.geteuid()!=0:raise SystemExit('Root required')
    STATE.mkdir(mode=0o700,parents=True,exist_ok=True)
    with open('/run/noisefence-upgrade.lock','a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        print(json.dumps(fence()))
