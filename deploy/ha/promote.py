#!/usr/bin/env python3
"""Promote a prepared console after a verified, explicit planned fence.

Never overwrites the live worker queue, never starts a relay, and never assumes
that an unreachable source is stopped. An unreachable source needs a separate
operator recovery with provider-level fencing and review of stale credentials.
"""
import argparse
import fcntl
import json
import os
from pathlib import Path
import pwd
import shutil
import sqlite3
import subprocess
import time
import urllib.request
from standby import STATE, DATA, CONFIG, BINARY, private_json, atomic_text

def validate_fence(fence,settings,manifest,disaster,now):
    if fence['owner']!=settings['owner'] or not fence.get('fenced'):
        raise ValueError('Explicit source fencing evidence required')
    if not 0<=now-fence['created']<=3600:raise ValueError('Fencing receipt expired')
    if disaster:
        if fence.get('method')!='provider-poweroff' or not isinstance(fence.get('reference'),str) or not 1<=len(fence['reference'])<=500:
            raise ValueError('Record the verified provider power-off operation; an unreachable host is not fenced')
        if not 0<=now-manifest['created']<=86400:raise ValueError('Disaster checkpoint older than 24h: separate recovery review required')
    elif fence.get('method')!='systemd-persistent-condition' or manifest.get('fence_operation')!=fence['operation'] or manifest.get('started',0)<fence['created']:
        raise ValueError('Take a final checkpoint AFTER fencing; the periodic checkpoint is not enough for a planned switch')

def promote(fence_path,disaster=False):
    if (STATE/'promoted.json').exists() or (STATE/'active').exists():raise ValueError('A recovery already exists; do not overwrite it')
    fence=json.loads(fence_path.read_text());settings=json.loads((STATE/'settings.json').read_text())
    checkpoint=(STATE/'current').resolve();manifest=json.loads((checkpoint/'manifest.json').read_text())
    validate_fence(fence,settings,manifest,disaster,int(time.time()))
    if manifest['build']!=subprocess.check_output([str(BINARY),'--version'],text=True).strip():raise ValueError('Release mismatch')
    # This stage is independent of the worker's live /var/lib/noisefence queue.
    active=STATE/'active';shutil.copytree(checkpoint,active)
    data=active/'data';config=active/'config';fence_copy=active/'fence.json';private_json(fence_copy,fence)
    subprocess.run([str(BINARY),'ha-restore','--source',str(DATA),'--target',str(data),'--owner',settings['owner'],'--fence-receipt',str(fence_copy)],check=True,timeout=180)
    if disaster:
        subprocess.run([str(BINARY),'ha-disaster-access','--data',str(data),'--credentials',str(STATE/'recovery-admin.json')],check=True,timeout=30)
    with sqlite3.connect(data/'state.sqlite3') as db:
        db.execute('PRAGMA foreign_keys=ON')
        # New host: require fresh logins, retaining current password hashes and MFA.
        db.execute('DELETE FROM sessions')
    private_json(data/'ha-console-activated.json',{'owner':settings['owner'],'console_only':True,'operation':fence['operation'],'created':int(time.time())})
    subprocess.run([str(BINARY),'ha-console-config','--source',str(config/'config.toml'),'--data-directory',str(data),'--config-directory',str(config),'--hostname',settings['hostname'],'--public-origin',settings['console_url'],'--listen','127.0.0.1:18081','--output',str(active/'console.toml')],check=True,timeout=30)
    account=pwd.getpwnam('noisefence')
    os.chown(STATE,0,account.pw_gid);STATE.chmod(0o710)
    for p in [active,*active.rglob('*')]:
        if p.is_symlink():raise ValueError('Symlinks are forbidden in the recovery stage')
        in_data=p==data or data in p.parents
        os.chown(p,account.pw_uid if in_data else 0,account.pw_gid)
        p.chmod((0o700 if in_data else 0o750) if p.is_dir() else (0o600 if in_data else 0o640))
    result={'owner':settings['owner'],'operation':fence['operation'],'snapshot':manifest['snapshot'],'console_only':True,'created':int(time.time()),'console_url':settings['console_url'],'worker_queue_replaced':False}
    private_json(STATE/'promoted.json',result)
    subprocess.run(['systemctl','start','noisefence-console'],check=True,timeout=60)
    deadline=time.monotonic()+60
    while True:
        try:
            with urllib.request.urlopen('http://127.0.0.1:18081/healthz',timeout=2) as response:
                if json.load(response)['status']=='ok':break
        except OSError:pass
        if time.monotonic()>deadline:raise ValueError('Recovery console did not become ready; original coordinator remains fenced')
        time.sleep(1)
    # Installer prepares this switch file; it changes only the standby Web routes.
    switch=Path('/etc/nginx/noisefence-console-upstream.conf')
    if switch.read_text()!='set $noisefence_console 127.0.0.1:18080;\n':raise ValueError('Unexpected proxy state')
    before_switch=switch.read_text()
    atomic_text(switch,'set $noisefence_console 127.0.0.1:18081;\n')
    try:
        subprocess.run(['nginx','-t'],check=True)
        subprocess.run(['systemctl','reload','nginx'],check=True)
    except Exception:
        atomic_text(switch,before_switch)
        subprocess.run(['systemctl','reload','nginx'],check=False)
        raise
    # Keep the worker's node identity and queue, changing only its authority URL.
    worker=CONFIG/'config.toml';original=worker.read_text()
    import re
    changed,count=re.subn(r'(?m)^coordinator_url\s*=\s*"[^"]+"\s*$', 'coordinator_url = '+json.dumps(settings['console_url']), original)
    if count!=1:raise ValueError('Worker coordinator URL not uniquely identified')
    private_json(STATE/'worker-before-promotion.json',{'config':original})
    import tomllib
    old=tomllib.loads(original);new=tomllib.loads(changed);old['cluster']['coordinator_url']=settings['console_url']
    if old!=new:raise ValueError('Unexpected worker configuration difference')
    atomic_text(worker,changed)
    try:
        subprocess.run([str(BINARY),'--config',str(worker),'check-config'],check=True,timeout=30)
        subprocess.run(['systemctl','restart','noisefence'],check=True,timeout=70)
    except Exception:
        atomic_text(worker,original)
        subprocess.run(['systemctl','restart','noisefence'],check=False,timeout=70)
        raise
    return result

if __name__=='__main__':
    os.umask(0o077)
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--fence-receipt',type=Path,required=True);parser.add_argument('--disaster',action='store_true',help='Provider power-off verified by operator; revoke stale accounts and hold new provider credits');args=parser.parse_args()
    if os.geteuid()!=0:parser.error('Root required')
    with open('/run/noisefence-upgrade.lock','a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        print(json.dumps(promote(args.fence_receipt,args.disaster)))
