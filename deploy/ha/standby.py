#!/usr/bin/env python3
"""Private console checkpoints over a restricted SSH channel; never copies a live WAL.

export: root on the coordinator, stream a verified checkpoint to stdout.
receive: root on the standby, install a new immutable checkpoint from stdin.
push: root on coordinator, export to the configured, pinned SSH receiver.
No command starts SMTP, restores a live queue, or promotes a console.
"""
import argparse
import contextlib
import fcntl
import hashlib
import importlib.util
import json
import os
import pwd
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
CONFIG_FILE = None
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
        selection=value.get('quality_candidate')
        if isinstance(selection,dict) and selection.get('job') is not None:
            identifier=selection['job']
            if str(uuid.UUID(identifier))!=identifier:raise ValueError('Invalid managed candidate identifier')
            candidate=DATA/'calibration'/identifier/'candidate'
            model=candidate/'model.json'
            if not model.is_file() or digest(model)!=selection.get('sha256'):raise ValueError('Managed shadow candidate changed or missing')
            yield candidate
        for v in value.values(): yield from data_paths(v)
    elif isinstance(value, list):
        for v in value: yield from data_paths(v)
    elif isinstance(value, str) and value.startswith(str(DATA)+'/'):
        p=Path(value)
        if p.exists() and p.resolve().is_relative_to(DATA): yield p

def backup_tools():
    path=Path(__file__).resolve().parent.parent/'hardening/snapshot.py'
    if not path.is_file():path=Path('/usr/local/libexec/noisefence-hardening/snapshot.py')
    spec=importlib.util.spec_from_file_location('noisefence_checkpoint_backup',path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module

def snapshot_uri(path):
    # Only completed backup copies use immutable mode. A live queue must read its WAL.
    path=Path(path)
    if any(Path(str(path)+suffix).exists() or Path(str(path)+suffix).is_symlink() for suffix in ('-wal','-shm','-journal')):
        raise ValueError('Immutable checkpoint contains SQLite sidecars')
    return path.as_uri()+'?mode=ro&immutable=1'


def selected_state(path, *, immutable=False):
    uri=snapshot_uri(path) if immutable else path.as_uri()+'?mode=ro'
    with contextlib.closing(sqlite3.connect(uri,uri=True,timeout=2)) as db:
        if db.execute('PRAGMA user_version').fetchone()[0]!=7:raise ValueError('Selected checkpoint requires storage format seven')
        state=dict(db.execute("SELECT key,CASE WHEN length(value)<=4194304 THEN value END FROM cluster_state WHERE key IN ('management_selection','activation_participant','management_recovery_required','management_console_activation')"))
    if any(v is None for v in state.values()):raise ValueError('Oversized checkpoint authority record')
    selection=json.loads(state['management_selection']);local=json.loads(state['activation_participant'])
    if selection.get('protocol')!='noisefence-management-selection-1' or selection.get('role')!='coordinator':raise ValueError('Invalid selected checkpoint authority')
    if local.get('node')!=selection['node']['node'] or local.get('version')!=1:raise ValueError('Participant differs from selected node')
    epoch=local['installed_epoch'];bundle=local['installed'];journal=local['authority']
    if (journal.get('owner')!=local['node'] or journal.get('current_sequence')!=epoch['sequence']
        or journal.get('current')!=bundle or bundle['revision']!=epoch['revision'] or bundle['digest']!=epoch['digest']
        or not isinstance(journal.get('rollout'),dict) or journal['rollout'].get('phase') not in ('released','aborted')):raise ValueError('Checkpoint requires a stable installed policy')
    if type(journal.get('sequence')) is not int or journal['sequence']<epoch['sequence']:raise ValueError('Invalid checkpoint policy sequence')
    result={'selection':selection,'epoch':epoch,'bundle':bundle,'policy_sequence':journal['sequence'],'phase':journal['rollout']['phase']}
    if 'management_recovery_required' in state or 'management_console_activation' in state:
        if not {'management_recovery_required','management_console_activation'} <= state.keys():raise ValueError('Cannot checkpoint an unfinished recovery')
        pending=json.loads(state['management_recovery_required']);receipt=json.loads(state['management_console_activation'])
        operation=pending.get('operation')
        if (not isinstance(operation,str) or str(uuid.UUID(operation))!=operation
            or pending.get('protocol')!='noisefence-management-recovery-1'
            or receipt.get('protocol')!='noisefence-management-console-1'
            or receipt.get('operation')!=operation or receipt.get('database')!=selection['database']
            or receipt.get('node')!=selection['node'] or receipt.get('console_only') is not True):raise ValueError('Checkpoint console recovery authority differs')
        result['recovery']=receipt
    return result


def config_path():
    return CONFIG_FILE or CONFIG/'config.toml'


def recovered_source():
    """Select the standard restored console explicitly; never infer it from worker state."""
    global DATA,CONFIG,CONFIG_FILE
    active=STATE/'active'
    path=active/'console.toml'
    for item in (active,path,STATE/'promoted.json'):
        info=item.lstat()
        if item.is_symlink() or item.resolve()!=item or info.st_uid!=0 or info.st_mode&0o022:
            raise ValueError('Recovery export requires a root-protected installed console')
    cfg=tomllib.loads(path.read_text())
    if (cfg.get('data_dir')!=str(active/'data') or cfg.get('management',{}).get('backend')!='postgresql'
        or cfg.get('cluster',{}).get('role')!='coordinator'):
        raise ValueError('Recovery checkpoint source must be the installed PostgreSQL console')
    DATA=active/'data';CONFIG=active/'config';CONFIG_FILE=path


def verify_recovered_source(local):
    if 'recovery' not in local:
        if CONFIG_FILE is not None:raise ValueError('Recovered checkpoint source has no console authorization')
        return
    # Native typed configuration hashing, immutable credentials, MFA and both local
    # and PostgreSQL receipts are checked without opening listeners or granting access.
    command=['/usr/sbin/runuser','-u','noisefence','--','/usr/bin/env','-i','PATH=/usr/bin:/bin',
             str(BINARY),'--config',str(config_path()),'management-recovery-check-console']
    checked=subprocess.run(command,check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=25)
    if len(checked.stdout)>65536:raise ValueError('Oversized console authorization result')
    report=json.loads(checked.stdout)
    if (report.get('status')!='console_authorization_verified' or report.get('receipt')!=local['recovery']
        or report.get('smtp_enabled') is not False or report.get('state_changed') is not False):
        raise ValueError('Recovered console authorization differs from checkpoint')

def selected_artifacts(root,state):
    files=state['bundle']['files']
    if not isinstance(files,dict) or len(files)>250:raise ValueError('Invalid installed artifact manifest')
    encoded=json.dumps(files,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
    generation=hashlib.sha256(encoded).hexdigest();paths={}
    import re
    for name,info in files.items():
        if (not isinstance(name,str) or not re.fullmatch(r'[A-Za-z0-9_./-]{1,240}',name)
            or any(not p or p.startswith('.') for p in name.split('/'))
            or set(info)!={'sha256','size'} or type(info['size']) is not int or not 0<=info['size']<=512*1024**2
            or not re.fullmatch('[a-f0-9]{64}',info['sha256'])):raise ValueError('Invalid installed artifact')
        relative='cluster/models/'+generation+'/'+name;path=root/relative
        if not path.is_file() or path.is_symlink() or not path.resolve().is_relative_to(root.resolve()) or path.stat().st_size!=info['size'] or digest(path)!=info['sha256']:raise ValueError('Installed artifact changed or missing')
        paths['data/'+relative]=path
    credential=state['bundle'].get('credential_generation')
    if not isinstance(credential,str) or not re.fullmatch('[a-f0-9]{64}',credential):raise ValueError('Missing installed credential generation')
    relative='cluster/credentials/'+credential+'.json';path=root/relative
    if not path.is_file() or path.is_symlink() or not path.resolve().is_relative_to(root.resolve()) or path.stat().st_size>4096 or digest(path)!=credential:raise ValueError('Installed credentials changed or missing')
    paths['data/'+relative]=path
    return paths

def postgres_state(tools,target):
    query="""SELECT json_build_object('database',json_build_object('instance',m.report->>'instance','source_digest',m.source_digest),
        'node',json_build_object('node',a.node,'epoch',a.epoch),'epoch',h.activation_epoch,
        'revision',h.revision,'phase',a.journal#>>'{rollout,phase}','policy_sequence',a.journal->'sequence')
        FROM noisefence.migration_state m CROSS JOIN noisefence.policy_head h CROSS JOIN noisefence.policy_authority a
        WHERE m.id=1 AND h.id=1 AND a.id=1 AND m.activated_at IS NOT NULL"""
    result=tools.run(*tools.postgres_command(target,'psql'),'-X','-A','-t','-v','ON_ERROR_STOP=1','-c',query,timeout=15)
    if len(result.stdout)>8192:raise ValueError('Oversized PostgreSQL checkpoint identity')
    return json.loads(result.stdout)

def match_central(local,central):
    if (central.get('database')!=local['selection']['database'] or central.get('node')!=local['selection']['node']
        or central.get('epoch')!=local['epoch'] or central.get('revision')!=local['epoch']['revision']
        or central.get('phase')!=local['phase'] or central.get('policy_sequence')!=local['policy_sequence']):raise ValueError('Local and PostgreSQL checkpoint authorities differ')

def export_selected(cfg,cfg_bytes,started_ns):
    tools=backup_tools();target=tools.postgres_target(cfg)
    if target is None:raise ValueError('Coordinator PostgreSQL backup target required')
    before=selected_state(DATA/'state.sqlite3');verify_recovered_source(before)
    central=postgres_state(tools,target);match_central(before,central)
    if cfg['cluster']['node_id']!=before['selection']['node']['node']:raise ValueError('Configuration differs from selected authority')
    files=selected_artifacts(DATA,before)
    files.update({'data/state.sqlite3':DATA/'state.sqlite3','data/mfa.key':DATA/'mfa.key'})
    for name in ['llm-budget.sqlite3']:
        if (DATA/name).is_file():files['data/'+name]=DATA/name
    for path in CONFIG.rglob('*'):
        if path.is_file():
            if path.is_symlink() or not path.resolve().is_relative_to(CONFIG.resolve()):raise ValueError('Configuration symlink refused')
            files['config/'+str(path.relative_to(CONFIG))]=path
    files['config/config.toml']=config_path()
    size=sum(p.stat().st_size for p in files.values())+tools.postgres_bytes(target)
    if size>MAX_BYTES or shutil.disk_usage(STATE).free<size*2+2*1024**3:raise ValueError('Selected checkpoint exceeds reserve')
    with tempfile.TemporaryDirectory(prefix='.export-',dir=STATE) as tmp:
        root=Path(tmp)
        for name,source in sorted(files.items()):
            dest=root/name;dest.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
            if source.name.endswith('.sqlite3'):
                subprocess.run([str(BINARY),'ha-snapshot',str(source),str(dest)],check=True,stdout=subprocess.DEVNULL,timeout=40)
            else:
                original=digest(source);shutil.copyfile(source,dest)
                if digest(dest)!=original or digest(source)!=original:raise ValueError('Checkpoint source changed')
                with dest.open('rb') as f:os.fsync(f.fileno())
            dest.chmod(0o600)
        dump=root/'data/management.postgresql.dump';tools.dump_postgres(target,dump,60)
        files['data/management.postgresql.dump']=dump
        if config_path().read_bytes()!=cfg_bytes or selected_state(root/'data/state.sqlite3',immutable=True)!=before or selected_state(DATA/'state.sqlite3')!=before or postgres_state(tools,target)!=central:raise ValueError('Policy changed during checkpoint; retry')
        verify_recovered_source(before)
        selected_artifacts(root/'data',before)
        if digest(root/'data/mfa.key')!=before['selection']['mfa_key_sha256']:raise ValueError('MFA key differs from selected authority')
        metadata={'protocol':'noisefence-console-2','owner':cfg['cluster']['node_id'],'created':int(time.time()),
            'started':started_ns//1_000_000_000,'started_ns':started_ns,'revision':before['epoch']['revision'],
            'build':subprocess.check_output([str(BINARY),'--version'],text=True).strip(),'snapshot':str(uuid.uuid4()),
            'management':central,'postgresql_restore_required':True,
            'files':{name:{'bytes':(root/name).stat().st_size,'sha256':digest(root/name)} for name in files}}
        if sum(x['bytes'] for x in metadata['files'].values())>MAX_BYTES:raise ValueError('Selected checkpoint grew beyond limit')
        if (STATE/'fenced.json').exists():
            fence=json.loads((STATE/'fenced.json').read_text())
            if fence.get('fenced') and started_ns>fence.get('created_ns',2**63-1):metadata['fence_operation']=fence['operation']
        private_json(root/'manifest.json',metadata)
        with tarfile.open(fileobj=sys.stdout.buffer,mode='w|') as archive:
            for name in sorted([*files,'manifest.json']):archive.add(root/name,arcname=name,recursive=False)

def export():
    started_ns=time.time_ns();started=started_ns//1_000_000_000
    cfg_bytes=config_path().read_bytes();cfg=tomllib.loads(cfg_bytes.decode())
    if cfg['cluster']['role']!='coordinator': raise ValueError('Only a coordinator exports console state')
    if cfg.get('management') is not None:return export_selected(cfg,cfg_bytes,started_ns)
    with sqlite3.connect('file:'+str(DATA/'state.sqlite3')+'?mode=ro',uri=True) as db:
        if db.execute('PRAGMA user_version').fetchone()[0]>=7:raise ValueError('Selected checkpoint requires its management configuration')
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
        with contextlib.closing(sqlite3.connect(snapshot_uri(root/'data/state.sqlite3'),uri=True)) as db:
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
        if manifest['protocol'] not in ['noisefence-console-1','noisefence-console-2'] or manifest['owner']!=settings['owner']:
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
                with contextlib.closing(sqlite3.connect(snapshot_uri(p),uri=True)) as db:
                    if db.execute('PRAGMA quick_check').fetchone()[0]!='ok' or db.execute('PRAGMA foreign_key_check').fetchone():raise ValueError('Invalid database')
        with contextlib.closing(sqlite3.connect(snapshot_uri(root/'data/state.sqlite3'),uri=True)) as db:
            state=dict(db.execute('SELECT key,value FROM cluster_state'))
            if state.get('node_id')!=settings['owner'] or state.get('role')!='coordinator':raise ValueError('Checkpoint is not the coordinator database')
            version=db.execute('PRAGMA user_version').fetchone()[0]
        if manifest['protocol']=='noisefence-console-2':
            local=selected_state(root/'data/state.sqlite3',immutable=True);match_central(local,manifest['management'])
            cfg=tomllib.loads((root/'config/config.toml').read_text())
            if (cfg.get('management',{}).get('backend')!='postgresql' or cfg.get('cluster',{}).get('node_id')!=settings['owner']
                or manifest.get('postgresql_restore_required') is not True or manifest['revision']!=local['epoch']['revision']):raise ValueError('Selected checkpoint configuration mismatch')
            selected_artifacts(root/'data',local)
            if digest(root/'data/mfa.key')!=local['selection']['mfa_key_sha256']:raise ValueError('Selected MFA key mismatch')
            with (root/'data/management.postgresql.dump').open('rb') as dump:
                if dump.read(5)!=b'PGDMP':raise ValueError('Missing or invalid PostgreSQL checkpoint')
        elif version>=7 or 'management_selection' in state or 'data/management.postgresql.dump' in seen:
            raise ValueError('Selected management cannot use a legacy console checkpoint')
        if (root/'data/mfa.key').stat().st_size!=32:raise ValueError('MFA recovery key is invalid')
        parent=STATE/'checkpoints';parent.mkdir(mode=0o700,exist_ok=True)
        current=STATE/'current'
        if current.exists():
            previous=json.loads((current/'manifest.json').read_text())
            if manifest['created']<previous['created'] or manifest['revision']<previous['revision']:raise ValueError('Stale checkpoint refused')
            if previous['protocol']=='noisefence-console-2':
                if (manifest['protocol']!='noisefence-console-2' or manifest['management']['database']!=previous['management']['database']
                    or manifest['management']['epoch']['sequence']<previous['management']['epoch']['sequence']
                    or manifest['management']['policy_sequence']<previous['management']['policy_sequence']):raise ValueError('Checkpoint authority downgrade refused')
                if manifest['management']['epoch']['sequence']==previous['management']['epoch']['sequence'] and manifest['management']['epoch']!=previous['management']['epoch']:raise ValueError('Conflicting checkpoint policy epoch')
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
        if manifest['protocol']=='noisefence-console-2':report['postgresql_restore_required']=True
        private_json(STATE/'status.json',report)
        # Keep two independently verified checkpoints. An activated console is copied elsewhere.
        others=sorted((p for p in parent.iterdir() if p.is_dir() and p!=destination),key=lambda p:p.stat().st_mtime,reverse=True)
        for old in others[1:]:shutil.rmtree(old)
        return report

def transfer_identity(archive):
    with tarfile.open(archive) as source:
        members=source.getmembers()
        entry=source.getmember('manifest.json')
        if entry.size>16*1024**2:raise ValueError('Oversized checkpoint manifest')
        manifest=json.load(source.extractfile(entry))
    return manifest,sum(member.size for member in members)


def verify_receipt(report,manifest,total):
    if not isinstance(report,dict):raise ValueError('Invalid checkpoint receipt')
    if any(report.get(key)!=manifest[key] for key in ('owner','created','revision','snapshot','build')):
        raise ValueError('Receiver acknowledged a different checkpoint')
    if type(report.get('bytes')) is not int or report['bytes']!=total:
        raise ValueError('Receiver checkpoint inventory size differs')
    if (report.get('postgresql_restore_required') is True)!=(manifest['protocol']=='noisefence-console-2'):
        raise ValueError('Receiver checkpoint backend differs')
    if type(report.get('received')) is not int or report.get('last_error') is not None:
        raise ValueError('Receiver did not confirm a successful checkpoint')


def transfer_record(settings, manifest, report, total):
    """Root-owned handoff evidence, separate from the application's UI status."""
    verify_receipt(report,manifest,total)
    if manifest['owner']!=settings['owner']:raise ValueError('Wrong checkpoint source authority')
    return {'protocol':'noisefence-checkpoint-transfer-1','receiver':settings['receiver'],
            'report':report,'checkpoint_protocol':manifest['protocol'],
            'started_ns':manifest['started_ns'],'fence_operation':manifest.get('fence_operation'),
            'config_sha256':manifest['files']['config/config.toml']['sha256'],
            'management':manifest.get('management')}


def push():
    settings=json.loads((STATE/'settings.json').read_text())
    ssh=['ssh','-T','-o','BatchMode=yes','-o','IdentityAgent=none','-o','IdentitiesOnly=yes','-o','ConnectTimeout=5',
         '-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+str(STATE/'known_hosts'),'-i',str(STATE/'transport.key'),settings['receiver'],'standby-receive']
    with tempfile.TemporaryDirectory(prefix='.transport-',dir=STATE) as tmp:
        archive=Path(tmp)/'checkpoint.tar'
        with archive.open('wb') as out:
            subprocess.run([sys.executable,__file__,'export']+(['--recovered-console'] if CONFIG_FILE else []),stdout=out,check=True,timeout=180)
        manifest,total=transfer_identity(archive)
        with archive.open('rb') as stream:
            result=subprocess.run(ssh,stdin=stream,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True,timeout=180)
        report=json.loads(result.stdout)
        if manifest['owner']!=settings['owner']:raise ValueError('Wrong checkpoint source authority')
        verify_receipt(report,manifest,total)
        private_json(STATE/'last-transfer.json',transfer_record(settings,manifest,report,total))
        private_json(DATA/'ha-standby-status.json',report)
        account=pwd.getpwnam('noisefence');os.chown(DATA/'ha-standby-status.json',account.pw_uid,account.pw_gid)
        return report

def main():
    os.umask(0o077)
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('command',choices=['export','receive','push'])
    parser.add_argument('--recovered-console',action='store_true',help='Export the authorized installed recovery console instead of the normal coordinator')
    args=parser.parse_args()
    if args.recovered_console and args.command=='receive':parser.error('Recovered console selection applies only to export/push')
    if os.geteuid()!=0:parser.error('Root required')
    STATE.mkdir(mode=0o700,parents=True,exist_ok=True)
    if args.recovered_console:recovered_source()
    with (STATE/(args.command+'.lock')).open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        if args.command=='export':export()
        else:print(json.dumps(receive() if args.command=='receive' else push()))

if __name__=='__main__':main()
