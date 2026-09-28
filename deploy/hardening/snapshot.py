#!/usr/bin/env python3
"""Export a coherent, bounded offline snapshot; never roll a live queue back.

The archive is sensitive. Invoke only through the restricted backup SSH account,
and pipe stdout straight into restic. Diagnostics go to stderr. No upload API.
"""
import argparse
import contextlib
import fcntl
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import sqlite3
import stat
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

def postgres_target(config):
    """Supported backup profile: local PostgreSQL 17 with Unix peer auth."""
    management=config.get('management')
    if management is None:return None
    backend=management.get('backend')
    role=config.get('cluster',{}).get('role')
    if backend=='coordinator' and role=='worker':return None
    if backend!='postgresql' or role!='coordinator':raise ValueError('Unsupported management backup configuration')
    connection=management.get('connection',{})
    host=connection.get('host','');database=connection.get('database','');username=connection.get('username','');port=connection.get('port',5432)
    if not isinstance(host,str) or not re.fullmatch(r'/[A-Za-z0-9_./-]+',host) or '..' in Path(host).parts:raise ValueError('PostgreSQL backups require a local Unix socket')
    if any(not isinstance(v,str) or not re.fullmatch(r'[A-Za-z0-9_]{1,63}',v) for v in [database,username]):raise ValueError('Invalid PostgreSQL backup identity')
    if type(port) is not int or not 1<=port<=65535:raise ValueError('Invalid PostgreSQL backup port')
    if connection.get('password_file') or connection.get('ca_file'):raise ValueError('This backup profile requires Unix peer authentication')
    return {'host':host,'database':database,'username':username,'port':port}

def postgres_command(target,tool):
    if tool not in ['psql','pg_dump']:raise ValueError('Unsupported PostgreSQL backup tool')
    # Do not inherit PGDATABASE, PGSERVICE, PGPASSFILE or other ambient connection
    # settings. No connection URI, password, or shell interpolation is used.
    return ['/usr/sbin/runuser','-u',target['username'],'--','/usr/bin/env','-i','PATH=/usr/bin:/bin','LC_ALL=C','PGCONNECT_TIMEOUT=5',
            '/usr/lib/postgresql/17/bin/'+tool,'--no-password','--host='+target['host'],'--port='+str(target['port']),
            '--username='+target['username'],'--dbname='+target['database']]

def postgres_bytes(target):
    result=run(*postgres_command(target,'psql'),'-X','-A','-t','-v','ON_ERROR_STOP=1','-c','SELECT pg_database_size(current_database())',timeout=15)
    value=result.stdout.strip()
    if not re.fullmatch(r'[0-9]{1,15}',value):raise ValueError('Invalid PostgreSQL size response')
    return int(value)

def dump_postgres(target,path,timeout):
    if timeout<=0:raise RuntimeError('PostgreSQL snapshot deadline exceeded')
    created=False
    try:
        with path.open('xb') as output:
            created=True
            os.chmod(path,0o600)
            bound=min(60,int(timeout))
            if bound<1:raise RuntimeError('PostgreSQL snapshot deadline exceeded')
            # GNU timeout terminates the entire runuser/pg_dump process group;
            # killing only the launcher could leave an orphan dump transaction.
            subprocess.run(['/usr/bin/timeout','--signal=TERM','--kill-after=5s',str(bound)+'s',
                            *postgres_command(target,'pg_dump'),'--format=custom','--compress=6','--lock-wait-timeout=5s'],
                           stdout=output,stderr=subprocess.PIPE,check=True,timeout=bound+10)
            output.flush();os.fsync(output.fileno())
        with path.open('rb') as source:
            if source.read(5)!=b'PGDMP':raise ValueError('Invalid PostgreSQL dump format')
    except Exception:
        if created:path.unlink(missing_ok=True)
        raise

def verify_management_selection(state,config):
    with sqlite3.connect('file:'+str(state)+'?mode=ro',uri=True) as db:
        version=db.execute('PRAGMA user_version').fetchone()[0]
        if version<7:
            if config.get('management') is not None:raise ValueError('Management configuration precedes storage selection')
            return
        if version!=7:raise ValueError('Unsupported selected management backup format')
        row=db.execute("SELECT value FROM cluster_state WHERE key='management_selection'").fetchone()
        if not row:raise ValueError('Missing management selection receipt')
        selected=json.loads(row[0])
        expected='postgresql' if selected.get('role')=='coordinator' else 'coordinator' if selected.get('role')=='worker' else None
        if expected is None or config.get('management',{}).get('backend')!=expected:raise ValueError('Backup configuration does not match selected management authority')

BACKGROUND_TIMERS=('noisefence-train.timer','noisefence-url-feed.timer','noisefence-quality.timer')
BACKGROUND_SERVICES=('noisefence-train.service','noisefence-url-feed.service','noisefence-quality.service')

def pause_background_writers(timers):
    for timer in BACKGROUND_TIMERS:
        if run('systemctl','is-active','--quiet',timer,check=False).returncode==0:
            timers.append(timer)
            run('systemctl','stop',timer)
    for service in BACKGROUND_SERVICES:
        state=run('systemctl','is-active',service,check=False).stdout.strip()
        if state not in ('inactive','failed','unknown'):
            raise RuntimeError('Background writer busy or state unknown; retry later')

@contextlib.contextmanager
def writer_locks(data):
    owner=data.lstat()
    if not stat.S_ISDIR(owner.st_mode) or owner.st_mode&0o022:
        raise ValueError('Unsafe snapshot source directory')
    calibration=data/'calibration'
    try:
        calibration.mkdir(mode=0o700)
        if os.geteuid()==0:os.chown(calibration,owner.st_uid,owner.st_gid)
    except FileExistsError:pass
    directory=calibration.lstat()
    if not stat.S_ISDIR(directory.st_mode) or directory.st_uid!=owner.st_uid or directory.st_mode&0o022:
        raise ValueError('Unsafe calibration directory')
    with contextlib.ExitStack() as stack:
        for path in (data/'daemon.lock',calibration/'worker.lock'):
            flags=os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK
            try:
                fd=os.open(path,flags|os.O_CREAT|os.O_EXCL,0o600)
                try:
                    if os.geteuid()==0:os.fchown(fd,owner.st_uid,owner.st_gid)
                except BaseException:
                    os.close(fd)
                    raise
            except FileExistsError:
                fd=os.open(path,flags)
            lock=stack.enter_context(os.fdopen(fd,'r+'))
            info=os.fstat(lock.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_uid!=owner.st_uid or info.st_mode&0o022:
                raise ValueError('Unsafe snapshot writer lock')
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        yield

def export(mode):
    os.umask(0o077);ROOT.mkdir(mode=0o700,parents=True,exist_ok=True)
    with (ROOT/'snapshot.lock').open('a') as own:
        fcntl.flock(own,fcntl.LOCK_EX|fcntl.LOCK_NB)
        # Only operational data and configured model artifacts, never old research corpora.
        allowed=[p for p in DATA.iterdir() if p.name in ['protection','spool','incoming','cluster','credentials','mfa.key'] or p.name.startswith(('state.sqlite3','llm-budget.sqlite3','cluster-'))]
        cfg=tomllib.loads(Path('/etc/noisefence/config.toml').read_text())
        pg=postgres_target(cfg)
        pg_size=postgres_bytes(pg) if pg else 0
        verify_management_selection(DATA/'state.sqlite3',cfg)
        def paths(value):
            if isinstance(value,dict):
                for item in value.values():yield from paths(item)
            elif isinstance(value,list):
                for item in value:yield from paths(item)
            elif isinstance(value,str) and value.startswith(str(DATA)+'/'):yield Path(value)
        for p in paths(cfg):
            if p.exists() and p not in allowed and p.resolve().is_relative_to(DATA) and p!=DATA:allowed.append(p)
        allowed=[p for p in allowed if p.relative_to(DATA).parts[0]!='research-archive' and not any(parent in allowed for parent in p.parents)]
        if mode=='metadata':allowed=[p for p in allowed if p.name not in ['spool','incoming']]
        size=sum(tree_bytes(p) if p.is_dir() and not p.is_symlink() else p.lstat().st_size for p in allowed)+tree_bytes(Path('/etc/noisefence'))+pg_size
        if shutil.disk_usage(ROOT).free<size*2+2*1024**3:raise RuntimeError('Insufficient snapshot reserve')
        with tempfile.TemporaryDirectory(prefix='snapshot-',dir=ROOT) as tmp:
            dest=Path(tmp);timers=[];stopped=False;started=time.monotonic();guard='noisefence-snapshot-resume-'+uuid.uuid4().hex
            try:
                pause_background_writers(timers)
                if run('systemctl','is-active','--quiet','noisefence',check=False).returncode!=0:raise RuntimeError('Refuse snapshot of unhealthy daemon')
                run('systemd-run','--unit='+guard,'--on-active=180s','--timer-property=AccuracySec=1s','/usr/bin/systemctl','start','noisefence')
                stopped=True;run('systemctl','stop','noisefence');copy_started=time.monotonic()
                with writer_locks(DATA):
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
                    if pg:
                        dump_postgres(pg,dest/'data/management.postgresql.dump',120-int(time.monotonic()-copy_started))
                    verify_management_selection(dest/'data/state.sqlite3',cfg)
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
