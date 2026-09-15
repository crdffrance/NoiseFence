#!/usr/bin/env python3
"""Private console checkpoints over a restricted SSH channel; never copies a live WAL.

export: root on the coordinator, stream a verified checkpoint to stdout.
receive: root on the standby, install a new immutable checkpoint from stdin.
push: root on coordinator, export to the configured, pinned SSH receiver.
No command starts SMTP, restores a live queue, or promotes a console.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import time
import tomllib
import uuid

DATA = Path('/var/lib/noisefence')
CONFIG = Path('/etc/noisefence')
STATE = Path('/var/lib/noisefence-standby')
BINARY = Path('/opt/noisefence/current/noisefence')
MAX_BYTES = 2 * 1024**3

def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1024*1024), b''): h.update(block)
    return h.hexdigest()

def private_json(path, data):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = path.with_name('.' + path.name + '-' + uuid.uuid4().hex)
    with temporary.open('x') as f:
        json.dump(data, f, sort_keys=True); f.write('\n'); f.flush(); os.fsync(f.fileno())
    os.replace(temporary, path)
    fd = os.open(path.parent, os.O_RDONLY); os.fsync(fd); os.close(fd)

def atomic_text(path, text):
    """Replace an existing configuration without changing its owner or mode."""
    original=path.stat();temporary=path.with_name('.'+path.name+'-'+uuid.uuid4().hex)
    try:
        with temporary.open('x') as f:
            f.write(text);f.flush();os.fchmod(f.fileno(),original.st_mode & 0o777)
            os.fchown(f.fileno(),original.st_uid,original.st_gid);os.fsync(f.fileno())
        os.replace(temporary,path)
        fd=os.open(path.parent,os.O_RDONLY);os.fsync(fd);os.close(fd)
    finally:
        temporary.unlink(missing_ok=True)

def data_paths(value):
    if isinstance(value, dict):
        for v in value.values(): yield from data_paths(v)
    elif isinstance(value, list):
        for v in value: yield from data_paths(v)
    elif isinstance(value, str) and value.startswith(str(DATA)+'/'):
        p=Path(value)
        if p.exists() and p.resolve().is_relative_to(DATA): yield p

def export():
    started_ns=time.time_ns();started=started_ns//1_000_000_000
    cfg_bytes=(CONFIG/'config.toml').read_bytes();cfg=tomllib.loads(cfg_bytes.decode())
    if cfg['cluster']['role']!='coordinator': raise ValueError('Only a coordinator exports console state')
    with sqlite3.connect('file:'+str(DATA/'state.sqlite3')+'?mode=ro',uri=True) as db:
        before=db.execute('SELECT id,settings FROM console_revisions ORDER BY id DESC LIMIT 1').fetchone()
    selected=set(data_paths(cfg)) | set(data_paths(json.loads(before[1])))
    for name in ['state.sqlite3','llm-budget.sqlite3','mfa.key','credentials','protection']:
        if (DATA/name).exists(): selected.add(DATA/name)
    # References can name directories. Never collect mail, research or caches of raw input.
    selected={p for p in selected if p.relative_to(DATA).parts[0] not in ['spool','incoming','replicas','research-archive']}
    files={}
    for p in selected:
        for f in p.rglob('*') if p.is_dir() else [p]:
            if f.is_file() and not f.name.endswith(('-wal','-shm')):
                if not f.resolve().is_relative_to(DATA): raise ValueError('Operational data symlink escapes data directory')
                files['data/'+str(f.relative_to(DATA))]=f
    for f in CONFIG.rglob('*'):
        if f.is_file(): files['config/'+str(f.relative_to(CONFIG))]=f
    size=sum(f.stat().st_size for f in files.values())
    if size>MAX_BYTES or shutil.disk_usage(STATE).free<size*2+2*1024**3:
        raise ValueError('Checkpoint exceeds storage reserve')
    with tempfile.TemporaryDirectory(prefix='.export-',dir=STATE) as tmp:
        root=Path(tmp)
        for name,source in sorted(files.items()):
            target=root/name;target.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
            if source.name.endswith('.sqlite3'):
                subprocess.run([str(BINARY),'ha-snapshot',str(source),str(target)],check=True,stdout=subprocess.DEVNULL,timeout=40)
            else:
                original=digest(source);shutil.copyfile(source,target)
                if original!=digest(target) or original!=digest(source): raise ValueError('Configuration or model changed; retry checkpoint')
                with target.open('rb') as f: os.fsync(f.fileno())
            target.chmod(0o600)
        if (CONFIG/'config.toml').read_bytes()!=cfg_bytes: raise ValueError('Base configuration changed')
        with sqlite3.connect(root/'data/state.sqlite3') as db:
            snapshot=db.execute('SELECT id,settings FROM console_revisions ORDER BY id DESC LIMIT 1').fetchone()
        with sqlite3.connect('file:'+str(DATA/'state.sqlite3')+'?mode=ro',uri=True) as db:
            after=db.execute('SELECT id,settings FROM console_revisions ORDER BY id DESC LIMIT 1').fetchone()
        if before!=snapshot or before!=after: raise ValueError('Console revision changed during checkpoint')
        manifest={'protocol':'noisefence-console-1','owner':cfg['cluster']['node_id'],'created':int(time.time()),'started':started,'started_ns':started_ns,'revision':before[0],
                  'build':subprocess.check_output([str(BINARY),'--version'],text=True).strip(),'snapshot':str(uuid.uuid4()),
                  'files':{name:{'bytes':(root/name).stat().st_size,'sha256':digest(root/name)} for name in files}}
        if (STATE/'fenced.json').exists():
            fence=json.loads((STATE/'fenced.json').read_text())
            if fence.get('fenced') and started_ns>fence.get('created_ns',2**63-1):manifest['fence_operation']=fence['operation']
        private_json(root/'manifest.json',manifest)
        with tarfile.open(fileobj=sys.stdout.buffer,mode='w|') as archive:
            for name in sorted([*files,'manifest.json']):archive.add(root/name,arcname=name,recursive=False)

def safe_name(name):
    p=PurePosixPath(name)
    if p.is_absolute() or '..' in p.parts or '\\' in name or not p.parts or p.parts[0] not in ['config','data','manifest.json']:
        raise ValueError('Invalid checkpoint path')
    if len(name)>1024 or p.parts[0]=='data' and len(p.parts)>1 and p.parts[1] in ['spool','incoming','replicas','research-archive']:
        raise ValueError('Mail bodies do not belong in console checkpoints')
    return str(p)

def receive(stream=None):
    settings=json.loads((STATE/'settings.json').read_text())
    if (STATE/'promoted.json').exists(): raise ValueError('An active recovery console cannot receive an older checkpoint')
    with tempfile.TemporaryDirectory(prefix='.receive-',dir=STATE) as tmp:
        root=Path(tmp);seen=set();total=0
        with tarfile.open(fileobj=stream or sys.stdin.buffer,mode='r|*') as archive:
            for member in archive:
                name=safe_name(member.name)
                if name in seen or not member.isfile() or len(seen)>100000:raise ValueError('Invalid archive member')
                total+=member.size
                if total>MAX_BYTES or member.size<0 or name=='manifest.json' and member.size>16*1024**2:
                    raise ValueError('Checkpoint too large')
                if shutil.disk_usage(STATE).free<member.size+2*1024**3:raise ValueError('Insufficient standby disk reserve')
                seen.add(name);p=root/name;p.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
                with p.open('xb') as f:
                    shutil.copyfileobj(archive.extractfile(member),f,1024*1024);f.flush();os.fsync(f.fileno())
                p.chmod(0o600)
        manifest=json.loads((root/'manifest.json').read_text())
        if manifest['protocol']!='noisefence-console-1' or manifest['owner']!=settings['owner']:
            raise ValueError('Wrong console authority')
        if not 0<=int(time.time())-manifest['created']<=600:raise ValueError('Checkpoint expired or future dated')
        if manifest['build']!=subprocess.check_output([str(BINARY),'--version'],text=True).strip():raise ValueError('Install the same release on both nodes first')
        snapshot=str(uuid.UUID(manifest['snapshot']))
        if snapshot!=manifest['snapshot'] or set(manifest['files'])!=seen-{'manifest.json'}:raise ValueError('Invalid checkpoint manifest')
        if not {'config/config.toml','data/state.sqlite3','data/mfa.key'}<=seen:raise ValueError('Incomplete console recovery material')
        for name,expected in manifest['files'].items():
            p=root/safe_name(name)
            if p.stat().st_size!=expected['bytes'] or digest(p)!=expected['sha256']:raise ValueError('Checkpoint checksum mismatch')
            if p.name.endswith('.sqlite3'):
                with sqlite3.connect('file:'+str(p)+'?mode=ro',uri=True) as db:
                    if db.execute('PRAGMA quick_check').fetchone()[0]!='ok' or db.execute('PRAGMA foreign_key_check').fetchone():raise ValueError('Invalid database')
        with sqlite3.connect(root/'data/state.sqlite3') as db:
            state=dict(db.execute('SELECT key,value FROM cluster_state'))
            if state.get('node_id')!=settings['owner'] or state.get('role')!='coordinator':raise ValueError('Checkpoint is not the coordinator database')
        if (root/'data/mfa.key').stat().st_size!=32:raise ValueError('MFA recovery key is invalid')
        parent=STATE/'checkpoints';parent.mkdir(mode=0o700,exist_ok=True)
        current=STATE/'current'
        if current.exists():
            previous=json.loads((current/'manifest.json').read_text())
            if manifest['created']<previous['created'] or manifest['revision']<previous['revision']:raise ValueError('Stale checkpoint refused')
        destination=parent/snapshot
        if destination.exists():raise ValueError('Checkpoint already installed')
        for directory in sorted([root,*[p for p in root.rglob('*') if p.is_dir()]],key=lambda p:len(p.parts),reverse=True):
            fd=os.open(directory,os.O_RDONLY);os.fsync(fd);os.close(fd)
        os.rename(root,destination)
        fd=os.open(parent,os.O_RDONLY);os.fsync(fd);os.close(fd)
        link=STATE/('.current-'+uuid.uuid4().hex);link.symlink_to(Path('checkpoints')/snapshot);os.replace(link,current)
        fd=os.open(STATE,os.O_RDONLY);os.fsync(fd);os.close(fd)
        report={k:manifest[k] for k in ['owner','created','revision','snapshot','build']}
        report.update(received=int(time.time()),bytes=total,console_url=settings['console_url'],last_error=None)
        private_json(STATE/'status.json',report)
        # Keep two independently verified checkpoints. An activated console is copied elsewhere.
        others=sorted((p for p in parent.iterdir() if p.is_dir() and p!=destination),key=lambda p:p.stat().st_mtime,reverse=True)
        for old in others[1:]:shutil.rmtree(old)
        return report

def push():
    settings=json.loads((STATE/'settings.json').read_text())
    ssh=['ssh','-T','-o','BatchMode=yes','-o','IdentityAgent=none','-o','IdentitiesOnly=yes','-o','ConnectTimeout=5',
         '-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+str(STATE/'known_hosts'),'-i',str(STATE/'transport.key'),settings['receiver'],'standby-receive']
    with tempfile.TemporaryDirectory(prefix='.transport-',dir=STATE) as tmp:
        archive=Path(tmp)/'checkpoint.tar'
        with archive.open('wb') as out:
            subprocess.run([sys.executable,__file__,'export'],stdout=out,check=True,timeout=180)
        with archive.open('rb') as stream:
            result=subprocess.run(ssh,stdin=stream,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True,timeout=180)
        report=json.loads(result.stdout)
        if report['owner']!=settings['owner']:raise ValueError('Wrong checkpoint receipt')
        private_json(DATA/'ha-standby-status.json',report)
        import pwd
        account=pwd.getpwnam('noisefence');os.chown(DATA/'ha-standby-status.json',account.pw_uid,account.pw_gid)
        return report

def main():
    os.umask(0o077)
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('command',choices=['export','receive','push']);args=parser.parse_args()
    if os.geteuid()!=0:parser.error('Root required')
    STATE.mkdir(mode=0o700,parents=True,exist_ok=True)
    with (STATE/(args.command+'.lock')).open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        if args.command=='export':export()
        else:print(json.dumps(receive() if args.command=='receive' else push()))

if __name__=='__main__':main()
