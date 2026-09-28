#!/usr/bin/python3
"""Join checkpoint restoration and native two-node recovery, keeping services stopped.

This is the offline half of selected promotion. It never switches HTTP routing,
removes persistent service fences, starts services or replaces the surviving queue.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import pwd
import re
import shutil
import tempfile
import time
import tomllib

from migration_agent import read_selection, unit_state
from migration_protocol import atomic, canonical, identity, private_read, require, sha
import recovery_database
import recovery_install
from recovery_install import protected

STATE = Path('/var/lib/noisefence-selected-recovery')
STANDBY = Path('/var/lib/noisefence-standby')
PHASES = ('new', 'copied', 'database_restored', 'queue_restored', 'console_configured',
          'workers_attached', 'management_prepared', 'keys_installed', 'console_authorized', 'workers_authorized')


def connection_config(raw, connection, data=None):
    """Typed equality guards a narrowly scoped TOML installation edit."""
    original = tomllib.loads(raw.decode())
    require(original.get('management',{}).get('backend') == 'postgresql', 'Checkpoint is not a PostgreSQL coordinator')
    lines = raw.decode().splitlines(keepends=True)
    start = [i for i,line in enumerate(lines) if line.strip() == '[management.connection]']
    require(len(start) == 1, 'Explicit PostgreSQL connection table required')
    first = start[0]
    end = next((i for i in range(first+1,len(lines)) if lines[i].lstrip().startswith('[')), len(lines))
    updated = ''.join(lines[:first]+['[management.connection]\n']+
        [key+' = '+json.dumps(value)+'\n' for key,value in connection.items()]+lines[end:])
    expected = json.loads(json.dumps(original))
    expected['management']['connection'] = connection
    if data is not None:
        segments = updated.splitlines(keepends=True)
        limit = next((i for i,line in enumerate(segments) if line.lstrip().startswith('[')),len(segments))
        positions = [i for i in range(limit) if re.match(r'^\s*data_dir\s*=',segments[i])]
        require(len(positions) == 1, 'Explicit top-level data directory required')
        segments[positions[0]] = 'data_dir = '+json.dumps(str(data))+'\n'
        updated = ''.join(segments)
        expected['data_dir'] = str(data)
    require(tomllib.loads(updated) == expected, 'Recovery configuration changed unrelated values')
    return updated.encode()


def console_source_config(raw, destination):
    """Set the authorized HTTPS origin and secure cookies before native validation."""
    recovery_install.origin(destination)
    original=tomllib.loads(raw.decode())
    lines=raw.decode().splitlines(keepends=True)
    starts=[i for i,line in enumerate(lines) if line.strip()=='[web]']
    require(len(starts)==1, 'Explicit Web table required for recovered HTTPS console')
    start=starts[0]
    end=next((i for i in range(start+1,len(lines)) if lines[i].lstrip().startswith('[')),len(lines))
    kept=[line for line in lines[start+1:end] if not re.match(r'^\s*(public_origin|secure_cookies)\s*=',line)]
    updated=''.join(lines[:start+1]+['public_origin = '+json.dumps(destination)+'\n','secure_cookies = true\n']+kept+lines[end:])
    expected=json.loads(json.dumps(original))
    expected['web'].update(public_origin=destination,secure_cookies=True)
    require(tomllib.loads(updated)==expected, 'Recovery HTTPS preparation changed unrelated values')
    return updated.encode()


def queue_source_config(raw, worker, destination):
    """A console-only checkpoint needs an explicit pair for offline queue restore.

    Derive that temporary pair from the reviewed installed worker; never enable
    replication in the console configuration or start either network listener.
    """
    original=tomllib.loads(raw.decode())
    coordinator=original.get('cluster',{})
    peer=worker.get('cluster',{})
    replica=worker.get('replication',{})
    require(coordinator.get('role')=='coordinator' and peer.get('role')=='worker'
            and isinstance(peer.get('node_id'),str) and peer['node_id']!=coordinator.get('node_id')
            and replica.get('peer_id')==coordinator.get('node_id'),
            'Queue restoration requires the installed reciprocal replication pair')
    if original.get('replication') is not None:
        require(original['replication'].get('peer_id')==peer['node_id'],
                'Checkpoint replication names another worker')
        return raw
    recovery_install.origin(destination)
    pair={**replica,'peer_id':peer['node_id'],'peer_url':destination,'allow_loopback_http':False}
    require(isinstance(pair.get('credential_file'),str) and Path(pair['credential_file']).is_absolute(),
            'Installed replication credential path required')
    updated=raw.decode()+'\n[replication]\n'+''.join(key+' = '+json.dumps(value)+'\n' for key,value in pair.items())
    expected={**original,'replication':pair}
    require(tomllib.loads(updated)==expected,'Temporary queue configuration changed unrelated settings')
    return updated.encode()


def checkpoint(path, expected_hash):
    protected(path, True)
    with private_read(path/'manifest.json', 4*1024**2) as source:
        raw = source.read()
    require(hashlib.sha256(raw).hexdigest() == expected_hash, 'Checkpoint manifest changed')
    manifest = json.loads(raw)
    require(manifest['protocol'] == 'noisefence-console-2' and manifest.get('postgresql_restore_required') is True
            and identity(manifest['snapshot']), 'Selected checkpoint required')
    files = manifest['files']
    require(isinstance(files,dict) and 1 <= len(files) <= 100000, 'Invalid checkpoint inventory')
    total = 0
    for name, info in files.items():
        relative = PurePosixPath(name)
        require(not relative.is_absolute() and str(relative) == name and '..' not in relative.parts
                and relative.parts[0] in ('data','config') and type(info['bytes']) is int
                and 0 <= info['bytes'] <= 2*1024**3 and sha(info['sha256']), 'Unsafe checkpoint entry')
        with private_read(path/name, 2*1024**3) as source:
            require(os.fstat(source.fileno()).st_size == info['bytes']
                    and hashlib.file_digest(source,'sha256').hexdigest() == info['sha256'], 'Checkpoint file changed')
        total += info['bytes']
    require(total <= 2*1024**3, 'Checkpoint exceeds bound')
    for item in path.rglob('*'):
        require(not item.is_symlink() and (item.is_dir() or str(item.relative_to(path)) in {*files,'manifest.json'}),
                'Unlisted checkpoint content')
    required = {'config/config.toml','data/state.sqlite3','data/mfa.key','data/management.postgresql.dump'}
    require(required <= files.keys(), 'Incomplete selected checkpoint')
    return manifest


def fencing(receipt, manifest, operation, disaster):
    require(receipt.get('operation') == operation and receipt.get('owner') == manifest['owner']
            and receipt.get('fenced') is True and type(receipt.get('created')) is int
            and 0 <= time.time()-receipt['created'] <= 3600, 'Fresh matching original-source fence required')
    if disaster:
        require(receipt.get('method') == 'provider-poweroff' and isinstance(receipt.get('reference'),str)
                and 1 <= len(receipt['reference']) <= 500 and 0 <= time.time()-manifest['created'] <= 86400,
                'Disaster recovery requires verified provider fencing and a recent checkpoint')
    else:
        require(receipt.get('method') == 'systemd-persistent-condition' and manifest.get('fence_operation') == operation
                and type(receipt.get('created_ns')) is int and manifest.get('started_ns',0) > receipt['created_ns'],
                'Planned recovery requires a final checkpoint after the source fence')


class Preparation:
    def __init__(self, authorization):
        require(not protected(authorization).st_mode & 0o077, 'Private root authorization required')
        with private_read(authorization,65536) as source:
            self.plan = p = json.load(source)
        require(set(p) == {'protocol','operation','checkpoint','manifest_sha256','fence','disaster','binary',
                          'binary_sha256','worker_config','user','hostname','console_url','postgres','expires_at'},
                'Invalid selected recovery authorization')
        require(p['protocol'] == 'noisefence-selected-recovery-1' and identity(p['operation'])
                and sha(p['manifest_sha256']) and sha(p['binary_sha256']) and type(p['disaster']) is bool
                and type(p['expires_at']) is int and time.time() < p['expires_at'] <= time.time()+3600,
                'Invalid or expired recovery authorization')
        self.account = pwd.getpwnam(p['user'])
        require(self.account.pw_uid != 0, 'Unprivileged recovery owner required')
        recovery_install.origin(p['console_url'])
        protected(p['binary'])
        with private_read(p['binary'],512*1024**2) as source:
            require(hashlib.file_digest(source,'sha256').hexdigest() == p['binary_sha256'], 'Recovery binary changed')
        self.manifest = checkpoint(Path(p['checkpoint']),p['manifest_sha256'])
        fencing(p['fence'],self.manifest,p['operation'],p['disaster'])
        coordinator_selection = read_selection(Path(p['checkpoint'])/'data',immutable=True)
        require(coordinator_selection and coordinator_selection['role'] == 'coordinator'
                and coordinator_selection['node'] == self.manifest['management']['node']
                and coordinator_selection['database'] == self.manifest['management']['database']
                and coordinator_selection['node']['node'] == self.manifest['owner'], 'Checkpoint selection differs from manifest')
        c = p['postgres']
        require(set(c) == {'host','port','username','max_connections'} and c['username'] == p['user']
                and type(c['max_connections']) is int and 1 <= c['max_connections'] <= 6
                and isinstance(c['host'],str) and re.fullmatch('/[A-Za-z0-9_./-]+',c['host'])
                and '..' not in Path(c['host']).parts and type(c['port']) is int and 1 <= c['port'] <= 65535, 'Invalid recovery database profile')
        self.connection = {**c,'database':'nf_recovery_'+p['operation'].replace('-','')}
        self.worker = Path(p['worker_config'])
        protected(self.worker)
        with private_read(self.worker,1024**2) as source:
            self.worker_raw = source.read()
        self.worker_config = tomllib.loads(self.worker_raw.decode())
        self.worker_selection = read_selection(self.worker_config['data_dir'])
        require(self.worker_selection and self.worker_selection['role'] == 'worker'
                and self.worker_selection['database'] == self.manifest['management']['database']
                and self.worker_config['cluster']['node_id'] == self.worker_selection['node']['node']
                and self.worker_config['cluster']['role'] == 'worker'
                and self.worker_config.get('management',{}).get('backend') == 'coordinator'
                and self.worker_selection['node']['node'] != self.manifest['owner'],
                'Actual worker queue differs from checkpoint authority')
        source_info = Path(self.worker_config['data_dir']).lstat()
        require(source_info.st_uid == self.account.pw_uid and not source_info.st_mode & 0o022, 'Unsafe actual worker data ownership')
        recovery_install.installed_service(self.worker,p['user'])
        require(unit_state('noisefence-console.service') in ('inactive','failed','unknown'), 'Stop the recovery console before offline preparation')
        STATE.mkdir(mode=0o700,exist_ok=True)
        protected(STATE,True)
        self.root = STATE/p['operation']
        self.root.mkdir(mode=0o700,exist_ok=True)
        protected(self.root,True)
        require(self.native('--version', plain=True).strip() == self.manifest['build'], 'Checkpoint/native build mismatch')
        pinned = {k:v for k,v in p.items() if k != 'expires_at'}
        pinned['fence'] = {k:v for k,v in p['fence'].items() if k != 'created'}
        self.fingerprint = hashlib.sha256(canonical(pinned)).hexdigest()
        self.state_path = self.root/'state.json'
        if self.state_path.exists():
            protected(self.state_path)
            with private_read(self.state_path,2*1024**2) as source:
                self.state = json.load(source)
            require(self.state['authorization'] == self.fingerprint and self.state['phase'] in PHASES, 'Recovery plan changed during retry')
        else:
            self.state = {'authorization':self.fingerprint,'phase':'new','worker_original':self.worker_raw.decode()}
            self.save('new')
        require(self.worker_raw in (self.state['worker_original'].encode(),recovery_install.rewrite(self.state['worker_original'].encode(),p['console_url'])),
                'Original worker configuration changed')
        self.active = STANDBY/'active'
        self.data = self.active/'data'
        self.private = self.data/'recovery-private'
        self.native_plan = self.private/'plan.json'
        self.credentials = self.private/'admin.json'

    def save(self, phase):
        self.state['phase'] = phase
        atomic(self.state_path,canonical(self.state))

    def native(self, *args, plain=False):
        with tempfile.TemporaryFile() as output:
            recovery_database.run(['/usr/sbin/runuser','-u',self.plan['user'],'--','/usr/bin/env','-i',
                'PATH=/usr/bin:/bin','LC_ALL=C',self.plan['binary'],*map(str,args)], self.root,
                stdout=output,timeout=1800,byte_limit=1024**2)
            output.seek(0)
            raw = output.read(1024**2+1)
            require(len(raw) <= 1024**2, 'Native recovery output exceeds bound')
            return raw.decode() if plain else json.loads(raw)

    def managed(self, command, status, *options):
        result = self.native(command,*options,'--plan',self.native_plan)
        require(result.get('operation') == self.plan['operation'] and result.get('status') == status,
                'Native recovery phase was not confirmed')
        return result

    def private_file(self, path, value):
        atomic(path,canonical(value),uid=self.account.pw_uid,gid=self.account.pw_gid)

    def copy(self):
        STANDBY.mkdir(mode=0o710,exist_ok=True)
        protected(STANDBY,True)
        os.chown(STANDBY,0,self.account.pw_gid)
        STANDBY.chmod(0o710)
        require(not (STANDBY/'promoted.json').exists(), 'An existing promoted console must not be replaced')
        marker = {'operation':self.plan['operation'],'snapshot':self.manifest['snapshot'],'manifest_sha256':self.plan['manifest_sha256']}
        if not self.active.exists():
            require(shutil.disk_usage(STANDBY).free >= sum(v['bytes'] for v in self.manifest['files'].values())*2+2*1024**3, 'Insufficient checkpoint staging reserve')
            with tempfile.TemporaryDirectory(prefix='.selected-',dir=STANDBY) as temporary:
                candidate = Path(temporary)/'active'
                shutil.copytree(self.plan['checkpoint'],candidate)
                checkpoint(candidate,self.plan['manifest_sha256'])
                atomic(candidate/'recovery-stage.json',canonical(marker))
                for item in [candidate,*candidate.rglob('*')]:
                    in_data = item == candidate/'data' or candidate/'data' in item.parents
                    os.chown(item,self.account.pw_uid if in_data else 0,self.account.pw_gid)
                    item.chmod((0o700 if in_data else 0o750) if item.is_dir() else (0o600 if in_data else 0o640))
                    fd = os.open(item,os.O_RDONLY)
                    try: os.fsync(fd)
                    finally: os.close(fd)
                os.rename(candidate,self.active)
                fd = os.open(STANDBY,os.O_RDONLY)
                try: os.fsync(fd)
                finally: os.close(fd)
        protected(self.active,True)
        require(json.loads((self.active/'recovery-stage.json').read_bytes()) == marker, 'Another recovery owns the active stage')
        self.private.mkdir(mode=0o700,exist_ok=True)
        os.chown(self.private,self.account.pw_uid,self.account.pw_gid)

    def database(self):
        p = self.plan
        value = {'protocol':'noisefence-recovery-database-1','operation':p['operation'],
            'binding':self.manifest['management']['database'],'dump':str(Path(p['checkpoint'])/'data/management.postgresql.dump'),
            'dump_sha256':self.manifest['files']['data/management.postgresql.dump']['sha256'],
            **{k:self.connection[k] for k in ('host','port','username','database')},'expires_at':p['expires_at']}
        path = self.root/'database.json'
        atomic(path,canonical(value))
        result = recovery_database.restore(path)
        require(result['status'] == 'restored_not_activated', 'Database restore incomplete')

    def queue(self):
        raw = (self.active/'config/config.toml').read_bytes()
        queue = self.private/'queue.toml'
        source=queue_source_config(raw,self.worker_config,self.plan['console_url'])
        atomic(queue,connection_config(source,self.connection,self.data),uid=self.account.pw_uid,gid=self.account.pw_gid)
        self.private_file(self.private/'fence.json',self.plan['fence'])
        result = self.native('ha-restore','--management-config',queue,'--source',self.worker_config['data_dir'],
            '--target',self.data,'--owner',self.manifest['owner'],'--fence-receipt',self.private/'fence.json')
        require(result.get('operation') == self.plan['operation'] and result.get('smtp_started') is False, 'Queue restore not confirmed')

    def console(self):
        source = self.private/'console-source.toml'
        atomic(source,console_source_config(connection_config((self.active/'config/config.toml').read_bytes(),self.connection),self.plan['console_url']),uid=self.account.pw_uid,gid=self.account.pw_gid)
        candidate = self.private/'console.toml'
        result = self.native('ha-console-config','--source',source,'--data-directory',self.data,
            '--config-directory',self.active/'config','--hostname',self.plan['hostname'],
            '--public-origin',self.plan['console_url'],'--listen','127.0.0.1:18081','--output',candidate)
        require(result.get('console_config') == 'prepared', 'Console configuration not verified')
        atomic(self.active/'console.toml',candidate.read_bytes(),gid=self.account.pw_gid,uid=0,mode=0o640)

    def plan_native(self):
        fence = self.plan['fence']
        self.private_file(self.native_plan,{'protocol':'noisefence-management-recovery-plan-1',
            'operation':self.plan['operation'],'database':self.manifest['management']['database'],
            'source_configs':[str(self.active/'console.toml'),str(self.worker)],'credentials_file':str(self.credentials),
            'fences':[{'source':self.manifest['management']['node'],'method':fence['method'],
                'reference':fence.get('reference','Verified original systemd fence'),'created':fence['created'],'fenced':True},
                {'source':self.worker_selection['node'],'method':'systemd-persistent-condition',
                 'reference':str(recovery_install.STATE/'hold.json'),'created':int(time.time()),'fenced':True}]})

    def install(self):
        bundle = self.credentials.with_name(self.credentials.name+'.workers.json')
        value = {'protocol':'noisefence-recovery-install-1','operation':self.plan['operation'],
            'selection':self.worker_selection,'config':str(self.worker),
            'config_sha256':hashlib.sha256(self.state['worker_original'].encode()).hexdigest(),
            'bundle_sha256':hashlib.sha256(bundle.read_bytes()).hexdigest(),
            'coordinator_url':self.plan['console_url'],'user':self.plan['user'],'expires_at':self.plan['expires_at']}
        path = self.root/'install.json'
        atomic(path,canonical(value))
        recovery_install.install(path,bundle)

    def run(self):
        # A persistent local fence is checked/reinstalled on every invocation.
        recovery_install.STATE.mkdir(mode=0o700,exist_ok=True)
        protected(recovery_install.STATE,True)
        recovery_install.fence(self.plan['operation'])
        if PHASES.index(self.state['phase']) >= PHASES.index('copied'):
            protected(self.active,True)
            require(json.loads((self.active/'recovery-stage.json').read_bytes()) == {
                'operation':self.plan['operation'],'snapshot':self.manifest['snapshot'],
                'manifest_sha256':self.plan['manifest_sha256']}, 'Active recovery stage changed')
        if PHASES.index(self.state['phase']) >= PHASES.index('database_restored'):
            self.database()
        already_authorized = self.state['phase'] == 'workers_authorized'
        steps = [('copied',self.copy),('database_restored',self.database),('queue_restored',self.queue),
            ('console_configured',self.console),('workers_attached',lambda:self.managed('management-recovery-attach-workers','workers_fenced_in_place')),
            ('management_prepared',lambda:self.managed('management-recovery-prepare','prepared_not_activated')),
            ('keys_installed',self.install),('console_authorized',lambda:self.managed('management-recovery-prepare','console_authorized_not_started','--activate-console')),
            ('workers_authorized',lambda:self.managed('management-recovery-release-workers','workers_authorized_not_started'))]
        for phase, action in steps:
            if PHASES.index(self.state['phase']) >= PHASES.index(phase):
                continue
            if PHASES.index(phase) >= PHASES.index('workers_attached'):
                self.plan_native()
            action()
            self.save(phase)
        if already_authorized:
            self.plan_native()
            self.managed('management-recovery-release-workers','workers_authorized_not_started')
        return {'operation':self.plan['operation'],'status':'authorized_services_stopped',
            'console_config':str(self.active/'console.toml'),'credentials_file':str(self.credentials),
            'services_started':False,'worker_queue_replaced':False,'http_routing_changed':False}


if __name__ == '__main__':
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--authorization',type=Path,required=True)
    args = parser.parse_args()
    require(os.geteuid() == 0, 'Root required')
    with open('/run/noisefence-upgrade.lock','a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        print(json.dumps(Preparation(args.authorization).run()))
