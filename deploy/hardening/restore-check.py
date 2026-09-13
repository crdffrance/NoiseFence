#!/usr/bin/env python3
"""Verify a restored snapshot offline. Never starts NoiseFence or installs files.

Run in a network namespace: unshare --net -- this-script snapshot.tar
Symlinks are validated against the manifest but never materialized.
"""
import argparse
import hashlib
import json
from pathlib import Path,PurePosixPath
import re
import sqlite3
import tarfile
import tempfile

def safe_name(name):
    path=PurePosixPath(name)
    if path.is_absolute() or '..' in path.parts or '\\' in name or len(name)>1024:raise ValueError('Unsafe archive path')
    if not path.parts or path.parts[0] not in ['config','data','manifest.json']:raise ValueError('Unknown archive root')
    return path

def verify(archive_path):
    with tempfile.TemporaryDirectory(prefix='noisefence-restore-check-') as tmp:
        root=Path(tmp);seen=set();links={};total=0
        with tarfile.open(archive_path,'r|*') as archive:
            for entry in archive:
                path=safe_name(entry.name)
                if str(path) in seen:raise ValueError('Duplicate archive member')
                seen.add(str(path));dest=root/str(path)
                if len(seen)>200000:raise ValueError('Too many archive members')
                if str(path)=='manifest.json' and entry.size>16*1024*1024:raise ValueError('Manifest too large')
                if entry.isdir():dest.mkdir(mode=0o700,parents=True,exist_ok=True)
                elif entry.issym():links[str(path)]=entry.linkname
                elif entry.isfile():
                    total+=entry.size
                    if total>20*1024**3 or len(seen)>200000:raise ValueError('Archive too large')
                    dest.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
                    with dest.open('xb') as f:
                        source=archive.extractfile(entry)
                        while block:=source.read(1024*1024):f.write(block)
                else:raise ValueError('Unsupported archive member')
        manifest=json.loads((root/'manifest.json').read_text())
        if manifest['format']!=1 or manifest['mode'] not in ['metadata','full']:raise ValueError('Unknown snapshot format')
        if links!=manifest['symlinks']:raise ValueError('Symlink manifest mismatch')
        actual={str(p.relative_to(root)) for p in root.rglob('*') if p.is_file() and p.name!='manifest.json'}
        if actual!=set(manifest['files']):raise ValueError('File manifest mismatch')
        for name,expected in manifest['files'].items():
            p=root/str(safe_name(name));h=hashlib.sha256()
            with p.open('rb') as f:
                for block in iter(lambda:f.read(1024*1024),b''):h.update(block)
            if h.hexdigest()!=expected['sha256'] or p.stat().st_size!=expected['bytes']:raise ValueError('Checksum mismatch')
        databases=[]
        for p in (root/'data').rglob('*.sqlite3'):
            with sqlite3.connect('file:'+str(p)+'?mode=ro',uri=True) as db:
                if db.execute('PRAGMA quick_check').fetchone()[0]!='ok':raise ValueError('Invalid SQLite')
            databases.append(str(p.relative_to(root)))
        if manifest['mode']=='metadata' and any(name.startswith(('data/spool/','data/incoming/')) for name in actual|set(links)):
            raise ValueError('Metadata snapshot contains message bodies')
        state=root/'data/state.sqlite3'
        if state.exists():
            with sqlite3.connect('file:'+str(state)+'?mode=ro',uri=True) as db:
                tables={r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                if 'mfa_credentials' in tables and db.execute('SELECT COUNT(*) FROM mfa_credentials').fetchone()[0]:
                    if not (root/'data/mfa.key').is_file() or (root/'data/mfa.key').stat().st_size!=32:
                        raise ValueError('MFA recovery key missing')
                if manifest['mode']=='full' and 'messages' in tables:
                    for (message_id,) in db.execute('SELECT id FROM messages WHERE raw_present=1'):
                        if not re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',message_id):
                            raise ValueError('Invalid queued message identifier')
                        if not (root/'data/spool'/(message_id+'.eml')).is_file():
                            raise ValueError('Queued message body missing')
        return {'status':'verified','mode':manifest['mode'],'files':len(actual),'databases':databases,'network_used':False,'services_started':False}

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('archive');args=parser.parse_args();print(json.dumps(verify(args.archive)))
