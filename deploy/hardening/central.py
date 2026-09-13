#!/usr/bin/env python3
"""Pull encrypted backups and bounded normalized reports onto the coordinator.

The source has no credentials for the repository and cannot delete its snapshots.
Configuration and keys are root-owned; a report never supplies commands or paths.
"""
import argparse
import datetime
import fcntl
import json
import os
from pathlib import Path
import re
import subprocess
import time
import tempfile

ROOT=Path('/var/lib/noisefence-hardening')
CONFIG=Path('/etc/noisefence-hardening/central.json')
BASE='/usr/local/libexec/noisefence-hardening/'

def ssh(config,node,operation):
    if operation not in ['report','snapshot-full','snapshot-metadata']:raise ValueError('Bad operation')
    return ['/usr/bin/ssh','-T','-o','BatchMode=yes','-o','ConnectTimeout=10','-o','ServerAliveInterval=15','-o','ServerAliveCountMax=3','-o','IdentitiesOnly=yes','-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+config['known_hosts'],'-i',config['ssh_key'],node['ssh'],operation]

def execute(args,timeout=60):
    return subprocess.run(args,capture_output=True,text=True,timeout=timeout,check=True).stdout

def restic(config,*args,timeout=1800):
    return execute(['/usr/bin/restic','--repo',config['repository'],'--password-file',config['password_file'],*args],timeout)

def collect(config):
    day=datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d');folder=ROOT/'reports';folder.mkdir(mode=0o700,parents=True,exist_ok=True)
    results=[]
    for name,node in config['nodes'].items():
        if not re.fullmatch('[a-zA-Z0-9_-]{1,32}',name):raise ValueError('Invalid node name')
        try:
            raw=execute(ssh(config,node,'report'),30) if node.get('ssh') else (ROOT/'monitor.json').read_text()
            if len(raw)>128*1024:raise ValueError('Oversized report')
            data=json.loads(raw)
            if not isinstance(data,dict) or data.get('version')!=1:raise ValueError('Bad report')
            if abs(time.time()-data.get('time',0))>900:raise ValueError('Stale report')
            # Whitelisted schema; no arbitrary raw source strings are logged.
            summary={'node':name,'received':int(time.time()),'time':int(data['time']),
                     'issues':[v for v in data.get('issues',[]) if isinstance(v,str) and re.fullmatch('[a-zA-Z0-9_.:-]{1,100}',v)][:40],
                     'services':{k:v for k,v in data.get('services',{}).items() if re.fullmatch('[a-zA-Z0-9_.-]{1,60}',k) and v in ['active','inactive','failed','activating','deactivating','socket_waiting']},
                     'audit_counts':{k:int(v) for k,v in data.get('audit_counts',{}).items() if re.fullmatch('[a-z_]{1,60}',k) and isinstance(v,int)},
                     'journal_counts':{k:int(v) for k,v in data.get('journal_counts',{}).items() if re.fullmatch('[a-z_]{1,60}',k) and isinstance(v,int)}}
        except Exception:
            summary={'node':name,'received':int(time.time()),'issues':['collection_failed']}
        with (folder/(day+'.jsonl')).open('a') as f:f.write(json.dumps(summary)+'\n')
        results.append(summary)
    for p in folder.glob('????-??-??.jsonl'):
        if datetime.date.fromisoformat(p.stem)<datetime.date.today()-datetime.timedelta(days=30):p.unlink()
    (ROOT/'cluster-security.json').write_text(json.dumps({'time':int(time.time()),'nodes':results})+'\n')
    print(json.dumps({'collected':len(results),'issues':{r['node']:r['issues'] for r in results}}))

def backup(config):
    mode=config.get('backup_mode','metadata')
    if mode not in ['metadata','full']:raise ValueError('Invalid backup mode')
    days=config.get('retention_days',30)
    if not isinstance(days,int) or not 1<=days<=30:raise ValueError('Retention must be explicit, 1..30 days')
    if mode=='full' and config.get('body_retention_authorized') is not True:raise ValueError('Body retention authorization required')
    result=[]
    for name,node in config['nodes'].items():
        if not re.fullmatch('[a-zA-Z0-9_-]{1,32}',name):raise ValueError('Invalid node name')
        source=ssh(config,node,'snapshot-'+mode) if node.get('ssh') else [BASE+'snapshot.py','--mode',mode]
        raw=restic(config,'backup','--json','--host',name,'--tag',mode,'--stdin-from-command','--stdin-filename',name+'.tar','--',*source)
        summaries=[json.loads(line) for line in raw.splitlines() if line.strip().startswith('{')]
        summary=next((r for r in summaries if r.get('message_type')=='summary'),None)
        if not summary or not summary.get('snapshot_id'):raise RuntimeError('Backup snapshot not confirmed')
        result.append({'node':name,'snapshot_id':summary['snapshot_id'],'mode':mode})
    # Expire only this deployment's nodes/tag. No unrelated snapshots are pruned.
    for name in config['nodes']:
        restic(config,'forget','--host',name,'--tag',mode,'--keep-within',str(days)+'d','--prune')
    restic(config,'check',timeout=1800)
    (ROOT/'backup-status.json').write_text(json.dumps({'time':int(time.time()),'status':'complete','snapshots':result})+'\n')
    print(json.dumps({'status':'complete','snapshots':result}))

def verify(config):
    status=json.loads((ROOT/'backup-status.json').read_text());results=[]
    for item in status['snapshots']:
        name=item['node'];ident=item['snapshot_id']
        if name not in config['nodes'] or not re.fullmatch('[a-f0-9]{64}',ident):raise ValueError('Unrecognized snapshot')
        with tempfile.TemporaryDirectory(prefix='restore-test-',dir=ROOT) as tmp:
            archive=Path(tmp)/'snapshot.tar'
            with archive.open('wb') as out:
                subprocess.run(['/usr/bin/restic','--no-cache','--repo',config['repository'],'--password-file',config['password_file'],'dump',ident,name+'.tar'],stdout=out,check=True,timeout=300)
            result=json.loads(execute(['/usr/bin/unshare','--net','--',BASE+'restore-check.py',str(archive)],300))
            result.update({'node':name,'snapshot_id':ident});results.append(result)
    (ROOT/'restore-status.json').write_text(json.dumps({'time':int(time.time()),'results':results})+'\n')
    print(json.dumps({'restoration':'verified','results':results}))

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('action',choices=['collect','backup','verify']);args=parser.parse_args()
    if os.geteuid()!=0:parser.error('root required')
    os.umask(0o077);ROOT.mkdir(mode=0o700,parents=True,exist_ok=True)
    with (ROOT/(args.action+'.lock')).open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        config=json.loads(CONFIG.read_text());{'collect':collect,'backup':backup,'verify':verify}[args.action](config)

if __name__=='__main__':main()
