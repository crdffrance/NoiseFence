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
    try:
        return subprocess.run(args,capture_output=True,text=True,timeout=timeout,check=True).stdout
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        # Keep bounded tool diagnostics locally, never in the normalized report.
        # In particular, do not log an argv or credentials to the journal.
        detail=error.stderr or ''
        if isinstance(detail,bytes):detail=detail.decode(errors='replace')
        path=ROOT/'last-tool-error.log'
        with path.open('w') as log:
            os.fchmod(log.fileno(),0o600)
            log.write(detail[-32768:])
        raise RuntimeError('Backup tool failed; inspect the private last-tool-error.log') from None

def restic(config,*args,timeout=1800):
    return execute(['/usr/bin/restic','--repo',config['repository'],'--password-file',config['password_file'],*args],timeout)

def write_status(name, value):
    fd, temporary = tempfile.mkstemp(prefix='.backup-status-', dir=ROOT)
    try:
        with os.fdopen(fd, 'w') as output:
            json.dump(value, output, allow_nan=False)
            output.write('\n'); output.flush(); os.fsync(output.fileno())
        os.replace(temporary, ROOT/name)
        directory = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def backup_nodes(config):
    nodes = config.get('nodes')
    if not isinstance(nodes, dict) or not nodes or len(nodes) > 32:
        raise ValueError('Configure the complete backup node set')
    if any(not isinstance(name, str) or not re.fullmatch('[a-zA-Z0-9_-]{1,32}', name) for name in nodes):
        raise ValueError('Invalid node name')
    if any(not isinstance(node, dict) for node in nodes.values()):
        raise ValueError('Invalid backup source')
    return nodes


def verified_snapshot_set(status, config):
    nodes = backup_nodes(config)
    if not isinstance(status, dict) or status.get('status') != 'complete':
        raise ValueError('Backup completion not confirmed')
    recorded = status.get('time')
    if type(recorded) is not int or recorded <= 0 or recorded > time.time() + 30:
        raise ValueError('Invalid backup timestamp')
    mode = config.get('backup_mode', 'metadata')
    if mode not in ('metadata', 'full'):
        raise ValueError('Invalid backup mode')
    items = status.get('snapshots')
    if not isinstance(items, list) or len(items) != len(nodes):
        raise ValueError('Incomplete backup snapshot set')
    seen = set()
    for item in items:
        if not isinstance(item, dict):
            raise ValueError('Invalid backup snapshot')
        name, ident = item.get('node'), item.get('snapshot_id')
        if not isinstance(name, str) or name not in nodes or name in seen:
            raise ValueError('Unrecognized or duplicate backup node')
        if not isinstance(ident, str) or not re.fullmatch('[a-f0-9]{64}', ident):
            raise ValueError('Invalid snapshot identity')
        if item.get('mode') != mode:
            raise ValueError('Snapshot mode differs from current backup policy')
        seen.add(name)
    return items


def checked_restore_result(result, item):
    if not isinstance(result, dict):
        raise ValueError('Missing archive verification result')
    postgres = result.get('postgresql_restore_required')
    expected = 'requires_postgresql_restore' if postgres is True else 'verified'
    if (type(postgres) is not bool or result.get('status') != expected
            or result.get('mode') != item['mode']
            or result.get('network_used') is not False
            or result.get('services_started') is not False
            or type(result.get('files')) is not int or result['files'] < 1):
        raise ValueError('Incomplete archive verification result')
    databases = result.get('databases')
    if not isinstance(databases, list) or 'data/state.sqlite3' not in databases:
        raise ValueError('Queue metadata verification missing')
    return {**result, 'node': item['node'], 'snapshot_id': item['snapshot_id']}


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
    backup_nodes(config)
    mode=config.get('backup_mode','metadata')
    if mode not in ['metadata','full']:raise ValueError('Invalid backup mode')
    days=config.get('retention_days',30)
    if type(days) is not int or not 1<=days<=30:raise ValueError('Retention must be explicit, 1..30 days')
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
    completed={'time':int(time.time()),'status':'complete','snapshots':result}
    verified_snapshot_set(completed,config)
    # Expire only this deployment's nodes/tag. No unrelated snapshots are pruned.
    for name in config['nodes']:
        restic(config,'forget','--host',name,'--tag',mode,'--keep-within',str(days)+'d','--prune')
    restic(config,'check',timeout=1800)
    write_status('backup-status.json',completed)
    print(json.dumps({'status':'complete','snapshots':result}))

def verify(config):
    status=json.loads((ROOT/'backup-status.json').read_text());results=[]
    for item in verified_snapshot_set(status,config):
        name=item['node'];ident=item['snapshot_id']
        if name not in config['nodes'] or not re.fullmatch('[a-f0-9]{64}',ident):raise ValueError('Unrecognized snapshot')
        with tempfile.TemporaryDirectory(prefix='restore-test-',dir=ROOT) as tmp:
            archive=Path(tmp)/'snapshot.tar'
            with archive.open('wb') as out:
                subprocess.run(['/usr/bin/restic','--no-cache','--repo',config['repository'],'--password-file',config['password_file'],'dump',ident,name+'.tar'],stdout=out,check=True,timeout=300)
            result=json.loads(execute(['/usr/bin/unshare','--net','--',BASE+'restore-check.py',str(archive)],300))
            results.append(checked_restore_result(result,item))
    state='requires_postgresql_restore' if any(r.get('postgresql_restore_required') for r in results) else 'verified'
    write_status('restore-status.json',{'time':int(time.time()),'backup_time':status['time'],
        'restoration':state,'recovery_scope':'metadata_only_not_a_queue_restore'
            if config.get('backup_mode','metadata')=='metadata' else 'archive_contents_only',
        'results':results})
    print(json.dumps({'restoration':state,'results':results}))

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('action',choices=['collect','backup','verify']);args=parser.parse_args()
    if os.geteuid()!=0:parser.error('root required')
    os.umask(0o077);ROOT.mkdir(mode=0o700,parents=True,exist_ok=True)
    with (ROOT/(args.action+'.lock')).open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        config=json.loads(CONFIG.read_text());{'collect':collect,'backup':backup,'verify':verify}[args.action](config)

if __name__=='__main__':main()
