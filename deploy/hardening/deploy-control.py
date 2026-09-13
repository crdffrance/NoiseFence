#!/usr/bin/env python3
"""Limited deployment operations on releases already approved and staged by root.

Never runs release-provided scripts as root. No arbitrary paths, shell, service
names, uploads, key management or configuration writes are accepted here.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path,PurePosixPath
import re
import sqlite3
import subprocess
import sys
import time
import urllib.request

BASE=Path('/opt/noisefence')
STATE=Path('/var/lib/noisefence-hardening/deploy')

def run(*args,timeout=90):
    return subprocess.run(args,check=True,capture_output=True,text=True,timeout=timeout).stdout

def protected(path):
    s=path.lstat()
    if path.is_symlink() or s.st_uid!=0 or s.st_mode&0o022:raise ValueError('Release must be root-owned and not writable by other accounts')

def release(version):
    if not re.fullmatch(r'\d+\.\d+\.\d+(?:-[a-zA-Z0-9.-]+)?',version):raise ValueError('Invalid release version')
    root=BASE/'releases'/version
    for p in [BASE,BASE/'releases',root]:protected(p)
    expected={}
    for line in (root/'SHA256SUMS').read_text().splitlines():
        digest,name=line.split('  ',1);path=PurePosixPath(name)
        if not re.fullmatch('[a-f0-9]{64}',digest) or path.is_absolute() or '..' in path.parts or '\\' in name:raise ValueError('Invalid release manifest')
        if name in expected:raise ValueError('Duplicate release member')
        expected[name]=digest
    actual=set()
    for p in root.rglob('*'):
        protected(p)
        if p.is_dir():continue
        if not p.is_file():raise ValueError('Release contains special file')
        name=str(p.relative_to(root))
        if name=='SHA256SUMS':continue
        actual.add(name);digest=hashlib.sha256(p.read_bytes()).hexdigest()
        if expected.get(name)!=digest:raise ValueError('Release checksum mismatch')
    if actual!=set(expected):raise ValueError('Incomplete release')
    manifest=json.loads((root/'build.json').read_text())
    if manifest['project']!='NoiseFence' or manifest['version']!=version:raise ValueError('Release identity mismatch')
    return root,manifest

def ready():
    with urllib.request.urlopen('http://127.0.0.1:18080/healthz',timeout=5) as response:
        return json.load(response).get('smtp_ready') is True

def activate(version):
    root,manifest=release(version)
    with sqlite3.connect('file:/var/lib/noisefence/state.sqlite3?mode=ro',uri=True) as db:
        schema=db.execute('PRAGMA user_version').fetchone()[0]
    if manifest.get('storage_schema',1)<schema:raise ValueError('Incompatible storage schema; downgrade refused')
    run('/usr/sbin/runuser','-u','noisefence','--',str(root/'noisefence'),'--config','/etc/noisefence/config.toml','check-config')
    old=os.readlink(BASE/'current');next_path=BASE/'current.deploy-next'
    if next_path.exists() or next_path.is_symlink():raise ValueError('Unresolved deployment pointer')
    next_path.symlink_to('releases/'+version);os.replace(next_path,BASE/'current')
    # An error preserves the new pointer. It never restores a database or ignores schema checks.
    try:
        run('systemctl','restart','noisefence-vision');run('systemctl','restart','noisefence')
        if not ready():raise RuntimeError('Gateway not ready')
    finally:
        (STATE/'last.json').write_text(json.dumps({'at':int(time.time()),'previous':old,'candidate':version})+'\n')
    print(json.dumps({'activated':version,'smtp_ready':True}))

def main():
    args=sys.argv[1:]
    if os.geteuid()!=0:raise PermissionError('root required')
    if not args or (args[0] in ['status','check','restart'] and len(args)!=1) or (args[0]=='activate' and len(args)!=2) or args[0] not in ['status','check','restart','activate']:raise ValueError('Unsupported deployment operation')
    os.umask(0o077);STATE.mkdir(mode=0o700,parents=True,exist_ok=True)
    with (STATE/'lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        if args[0]=='status':
            print(json.dumps({'release':Path(os.readlink(BASE/'current')).name,'smtp_ready':ready(),'service':run('systemctl','is-active','noisefence').strip()}))
        elif args[0]=='check':
            root,_=release((BASE/'current').resolve().name)
            run('/usr/sbin/runuser','-u','noisefence','--',str(root/'noisefence'),'--config','/etc/noisefence/config.toml','check-config');print('Configuration and approved release valid')
        elif args[0]=='restart':run('systemctl','restart','noisefence');print(json.dumps({'smtp_ready':ready()}))
        else:activate(args[1])

if __name__=='__main__':main()
