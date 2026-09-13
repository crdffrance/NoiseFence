#!/usr/bin/env python3
"""Export a coherent, bounded offline snapshot; never roll a live queue back.

The archive is sensitive. Invoke only through the restricted backup SSH account,
and pipe stdout straight into restic. Diagnostics go to stderr. No upload API.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import time
import tomllib
import uuid

DATA=Path('/var/lib/noisefence')
ROOT=Path('/var/lib/noisefence-hardening')

def run(*args,check=True,timeout=70):
    return subprocess.run(args,check=check,timeout=timeout,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)

def tree_bytes(root):
    return sum(p.lstat().st_size for p in root.rglob('*') if p.is_file() and not p.is_symlink())

def manifest(root,mode):
    files={};links={}
    for p in sorted(root.rglob('*')):
        name=str(p.relative_to(root))
        if p.is_symlink():links[name]=os.readlink(p)
        elif p.is_file():
            h=hashlib.sha256()
            with p.open('rb') as f:
                for block in iter(lambda:f.read(1024*1024),b''):h.update(block)
            files[name]={'sha256':h.hexdigest(),'bytes':p.stat().st_size}
    return {'format':1,'created':int(time.time()),'mode':mode,'files':files,'symlinks':links}

def export(mode):
    os.umask(0o077);ROOT.mkdir(mode=0o700,parents=True,exist_ok=True)
    with (ROOT/'snapshot.lock').open('a') as own:
        fcntl.flock(own,fcntl.LOCK_EX|fcntl.LOCK_NB)
        # Only operational data and configured model artifacts, never old research corpora.
        allowed=[p for p in DATA.iterdir() if p.name in ['protection','spool','incoming','cluster','credentials','mfa.key'] or p.name.startswith(('state.sqlite3','llm-budget.sqlite3','cluster-'))]
        cfg=tomllib.loads(Path('/etc/noisefence/config.toml').read_text())
        def paths(value):
            if isinstance(value,dict):
                for item in value.values():yield from paths(item)
            elif isinstance(value,list):
                for item in value:yield from paths(item)
            elif isinstance(value,str) and value.startswith(str(DATA)+'/'):yield Path(value)
        for p in paths(cfg):
            if p.exists() and p not in allowed and p.resolve().is_relative_to(DATA) and p!=DATA:allowed.append(p)
        allowed=[p for p in allowed if not any(parent in allowed for parent in p.parents)]
        if mode=='metadata':allowed=[p for p in allowed if p.name not in ['spool','incoming']]
        size=sum(tree_bytes(p) if p.is_dir() and not p.is_symlink() else p.lstat().st_size for p in allowed)+tree_bytes(Path('/etc/noisefence'))
        if shutil.disk_usage(ROOT).free<size*2+2*1024**3:raise RuntimeError('Insufficient snapshot reserve')
        with tempfile.TemporaryDirectory(prefix='snapshot-',dir=ROOT) as tmp:
            dest=Path(tmp);timers=[];stopped=False;started=time.monotonic();guard='noisefence-snapshot-resume-'+uuid.uuid4().hex
            try:
                for timer in ['noisefence-train.timer','noisefence-url-feed.timer']:
                    if run('systemctl','is-active','--quiet',timer,check=False).returncode==0:
                        timers.append(timer);run('systemctl','stop',timer)
                for service in ['noisefence-train.service','noisefence-url-feed.service']:
                    if run('systemctl','is-active','--quiet',service,check=False).returncode==0:raise RuntimeError('Background writer busy; retry later')
                if run('systemctl','is-active','--quiet','noisefence',check=False).returncode!=0:raise RuntimeError('Refuse snapshot of unhealthy daemon')
                run('systemd-run','--unit='+guard,'--on-active=180s','--timer-property=AccuracySec=1s','/usr/bin/systemctl','start','noisefence')
                stopped=True;run('systemctl','stop','noisefence');copy_started=time.monotonic()
                with (DATA/'daemon.lock').open('a') as lock:
                    fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
                    # Copy-on-write if the filesystem supports it, bounded full copy otherwise.
                    (dest/'data').mkdir(mode=0o700)
                    for source in allowed:
                        remaining=120-int(time.monotonic()-copy_started)
                        if remaining<=0:raise RuntimeError('Snapshot copy deadline exceeded')
                        if not source.exists():continue  # SQLite may remove WAL/SHM on clean shutdown.
                        target=dest/'data'/source.relative_to(DATA)
                        target.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
                        run('cp','-a','--reflink=auto',str(source),str(target),timeout=min(90,remaining))
                    run('cp','-a','--reflink=auto','/etc/noisefence',str(dest/'config'),timeout=30)
                    with sqlite3.connect('file:'+str(dest/'data/state.sqlite3')+'?mode=ro',uri=True) as db:
                        if db.execute('PRAGMA quick_check').fetchone()[0]!='ok':raise RuntimeError('SQLite snapshot failed integrity check')
            finally:
                if stopped:
                    run('systemctl','start','noisefence',timeout=120)
                    run('systemctl','stop',guard+'.timer',check=False)
                for timer in timers:run('systemctl','start',timer)
            metadata=manifest(dest,mode);metadata['pause_and_copy_seconds']=round(time.monotonic()-started,2)
            (dest/'manifest.json').write_text(json.dumps(metadata,sort_keys=True)+'\n')
            # Streaming tar: the receiver checks the SSH exit code as well as restic's.
            with tarfile.open(fileobj=sys.stdout.buffer,mode='w|') as archive:
                for p in sorted(dest.iterdir()):archive.add(p,arcname=p.name,recursive=True)


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--mode',choices=['metadata','full'],required=True);args=parser.parse_args()
    if os.geteuid()!=0:parser.error('root required')
    export(args.mode)

if __name__=='__main__':main()
