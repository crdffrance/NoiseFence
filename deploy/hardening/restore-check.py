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
import tomllib

def safe_name(name):
    path=PurePosixPath(name)
    if path.is_absolute() or '..' in path.parts or '\\' in name or len(name)>1024:raise ValueError('Unsafe archive path')
    if not path.parts or path.parts[0] not in ['config','data','manifest.json']:raise ValueError('Unknown archive root')
    return path

def valid_queued_id(db,message_id):
    if not isinstance(message_id,str):return False
    if re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',message_id):return True
    # Match the Rust queue's legacy DSN identity contract. Never use an
    # unchecked database identifier to construct a restored body path.
    legacy=re.fullmatch(r'dsn-([1-9][0-9]{0,18})',message_id)
    if not legacy or int(legacy[1])>2**63-1:return False
    columns={row[1] for row in db.execute('PRAGMA table_info(messages)')}
    if not {'is_dsn','sender'}.issubset(columns):return False
    rows=db.execute('SELECT is_dsn,sender FROM messages WHERE id=?',(message_id,)).fetchall()
    return rows==[(1,'')]

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
                        if not valid_queued_id(db,message_id):
                            raise ValueError('Invalid queued message identifier')
                        if not (root/'data/spool'/(message_id+'.eml')).is_file():
                            raise ValueError('Queued message body missing')
        pg_dump=root/'data/management.postgresql.dump'
        has_postgres=pg_dump.is_file()
        if has_postgres:
            with pg_dump.open('rb') as source:
                if source.read(5)!=b'PGDMP':raise ValueError('Invalid PostgreSQL dump format')
        config_path=root/'config/config.toml'
        config=tomllib.loads(config_path.read_text()) if config_path.is_file() else {}
        backend=config.get('management',{}).get('backend')
        if backend is not None and not state.is_file():raise ValueError('Selected management spool snapshot missing')
        if backend=='postgresql' and not has_postgres:raise ValueError('PostgreSQL management backup missing')
        if state.exists():
            with sqlite3.connect('file:'+str(state)+'?mode=ro',uri=True) as db:
                version=db.execute('PRAGMA user_version').fetchone()[0]
                if version>7:raise ValueError('Unsupported selected management backup format')
                if version==7:
                    row=db.execute("SELECT value FROM cluster_state WHERE key='management_selection'").fetchone()
                    if not row:raise ValueError('Missing management selection receipt')
                    selection=json.loads(row[0])
                    role=selection.get('role')
                    if role=='coordinator':
                        if backend!='postgresql' or not has_postgres:raise ValueError('Selected PostgreSQL management backup missing')
                        key=root/'data/mfa.key'
                        if not key.is_file() or key.stat().st_size!=32 or hashlib.sha256(key.read_bytes()).hexdigest()!=selection.get('mfa_key_sha256'):raise ValueError('Selected MFA recovery key mismatch')
                    elif role=='worker':
                        if backend!='coordinator':raise ValueError('Worker management configuration mismatch')
                    else:raise ValueError('Invalid selected management role')
                elif backend is not None:raise ValueError('Management configuration precedes storage selection')
        # A checksummed PGDMP header does not prove that SQL can be restored.
        # Never execute archive-supplied SQL against the production cluster here.
        return {'status':'requires_postgresql_restore' if has_postgres else 'verified','mode':manifest['mode'],'files':len(actual),'databases':databases,'postgresql_restore_required':has_postgres,'network_used':False,'services_started':False}

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('archive');args=parser.parse_args();print(json.dumps(verify(args.archive)))
