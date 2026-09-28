#!/usr/bin/python3
"""Root-owned, fixed-operation migration agent. Intended for a restricted SSH key.

Metadata travels only to the migration coordinator. All failure paths retain a
persistent service fence; nothing restarts automatically after a broken session.
"""
import contextlib
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import signal
import socket
import sqlite3
import stat
import subprocess
import sys
import time
import tomllib
import urllib.parse
import urllib.request
from migration_protocol import AGENT, Channel, SourceSession, atomic, canonical, checked_selection, identity, private_read, require, sha
from migration_snapshot import management_config, source_files

CONFIG = Path('/etc/noisefence-migration/agent.json')
SERVICES = ('noisefence.service', 'noisefence-train.service', 'noisefence-url-feed.service', 'noisefence-quality.service')
TIMERS = ('noisefence-train.timer', 'noisefence-url-feed.timer', 'noisefence-quality.timer')
DROPIN = '98-management-migration.conf'
UNIT_DIRECTORY = Path('/etc/systemd/system')


def execute(args, timeout=90):
    process = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, start_new_session=True)
    try:
        stdout, _ = process.communicate(timeout=timeout)
    except BaseException:
        # Terminate runuser and its native child together, not only the wrapper.
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGTERM)
        try:
            process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            process.communicate(timeout=5)
        raise
    require(process.returncode == 0, 'Migration subprocess failed; inspect the protected local state')
    return stdout


def unit_state(unit):
    # is-active reports "inactive" even for a nonexistent unit. Query LoadState
    # as well so optional absent jobs are not passed to stop/start operations.
    result = subprocess.run(['/usr/bin/systemctl', 'show', '--property=LoadState,ActiveState', unit],
                            capture_output=True, timeout=10)
    require(result.returncode == 0, 'Cannot inspect service state')
    fields = {}
    for line in result.stdout.decode().splitlines():
        key, separator, value = line.partition('=')
        require(separator and key not in fields, 'Invalid service state response')
        fields[key] = value
    require(set(fields) == {'LoadState', 'ActiveState'}, 'Incomplete service state response')
    if fields['LoadState'] == 'not-found':
        return 'unknown'
    require(fields['LoadState'] == 'loaded', 'Service unit is masked or invalid')
    state = fields['ActiveState']
    require(state in ('active', 'inactive', 'failed', 'activating', 'deactivating'), 'Unknown service state')
    return state


def protected(path, directory=False):
    path = Path(path)
    info = path.lstat()
    require(path.resolve() == path and info.st_uid == 0 and not info.st_mode & 0o022
            and (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)),
            'Migration installation must be protected by root')
    return info


def load_config(path):
    protected(path)
    with private_read(path, 65536) as source:
        config = json.load(source)
    required = {'run_id', 'node_id', 'role', 'user', 'data', 'config', 'root', 'runtime',
                'release_directory', 'binary_sha256', 'current_link', 'management',
                'expires_at', 'lease_seconds', 'health_url'}
    require(isinstance(config, dict) and set(config) == required, 'Invalid migration agent configuration')
    require(identity(config['run_id']) and re.fullmatch('[a-z0-9_-]{1,40}', config['node_id'])
            and config['role'] in ('coordinator', 'worker') and re.fullmatch('[a-z_][a-z0-9_-]{0,31}', config['user'])
            and sha(config['binary_sha256']), 'Invalid migration identity')
    require(type(config['expires_at']) is int and time.time() < config['expires_at'] <= time.time() + 86400
            and type(config['lease_seconds']) is int and 30 <= config['lease_seconds'] <= 1800,
            'Migration authorization expired or lease invalid')
    for key in ('data', 'config', 'root', 'runtime', 'release_directory', 'current_link'):
        value = config[key]
        require(isinstance(value, str) and re.fullmatch('/[A-Za-z0-9_./-]+', value)
                and '..' not in Path(value).parts, 'Invalid migration installation path')
    url = urllib.parse.urlsplit(config['health_url'])
    require(url.scheme == 'http' and url.username is None and url.password is None
            and ipaddress.ip_address(url.hostname).is_loopback and url.path == '/healthz'
            and not url.query and not url.fragment, 'Health check must be local')
    require(config['management'].get('backend') == ('postgresql' if config['role'] == 'coordinator' else 'coordinator'),
            'Management role mismatch')
    management_config(b'hostname="fixture"\n', config['management'])
    release = Path(config['release_directory'])
    protected(release, True)
    with private_read(release / 'noisefence', 512 * 1024**2) as binary:
        require(hashlib.file_digest(binary, 'sha256').hexdigest() == config['binary_sha256'], 'Migration binary checksum mismatch')
    protected(release / 'noisefence')
    protected(Path(config['current_link']).parent, True)
    require(Path(config['current_link']).is_symlink() and Path(config['current_link']).lstat().st_uid == 0,
            'Unrecognized service release pointer')
    protected(config['config'])
    with private_read(config['config'], 1024 * 1024) as source:
        installed = tomllib.loads(source.read().decode())
    require(installed.get('data_dir') == config['data'] and installed.get('cluster', {}).get('node_id') == config['node_id']
            and installed.get('cluster', {}).get('role') == config['role'], 'Installed source identity differs from agent configuration')
    owner = pwd.getpwnam(config['user'])
    info = Path(config['data']).lstat()
    require(Path(config['data']).resolve() == Path(config['data']) and stat.S_ISDIR(info.st_mode)
            and info.st_uid == owner.pw_uid and not info.st_mode & 0o077, 'Unsafe original data directory')
    return config


def read_selection(data, *, immutable=False):
    path = Path(data) / 'state.sqlite3'
    require(path.is_file() and path.resolve() == path, 'Invalid original spool database')
    if immutable:
        require(not any(Path(str(path)+suffix).exists() or Path(str(path)+suffix).is_symlink() for suffix in ('-wal','-shm','-journal')), 'Immutable source contains SQLite sidecars')
    uri = path.as_uri() + '?mode=ro' + ('&immutable=1' if immutable else '')
    with contextlib.closing(sqlite3.connect(uri, uri=True, timeout=2)) as db:
        version = db.execute('PRAGMA user_version').fetchone()[0]
        row = db.execute("SELECT CASE WHEN length(value)<=8192 THEN value END FROM cluster_state WHERE key='management_selection'").fetchone()
        if version == 6:
            require(row is None, 'Unexpected selection in legacy source')
            return None
        require(version == 7 and row is not None and row[0] is not None, 'Invalid selected source format')
        selected = json.loads(row[0])
        require(isinstance(selected, dict), 'Invalid durable selection')
        return checked_selection(selected)


class Agent:
    def __init__(self, config):
        self.config = config
        self.root = Path(config['root']) / config['run_id']
        self.root.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        protected(self.root.parent, True)
        self.root.mkdir(mode=0o700, exist_ok=True)
        protected(self.root, True)
        self.account = pwd.getpwnam(config['user'])
        self.runtime = Path(config['runtime'])
        if not self.runtime.exists():
            self.runtime.mkdir(mode=0o700)
            os.chown(self.runtime, self.account.pw_uid, self.account.pw_gid)
        info = self.runtime.lstat()
        require(self.runtime.resolve() == self.runtime and stat.S_ISDIR(info.st_mode)
                and info.st_uid == self.account.pw_uid and not info.st_mode & 0o077, 'Unsafe migration runtime directory')
        self.hold = Path(config['root']) / 'hold.json'
        self.state_path = self.root / 'state.json'
        pinned = {k: v for k, v in config.items() if k != 'expires_at'}
        fingerprint = hashlib.sha256(canonical(pinned)).hexdigest()
        self.state = json.loads(self.state_path.read_bytes()) if self.state_path.exists() else {'phase': 'new', 'configuration': fingerprint}
        require(self.state['configuration'] == fingerprint, 'Migration configuration changed during recovery')
        self.child = None
        self.source = None
        self.log = None

    def save(self, **changes):
        self.state.update(changes)
        atomic(self.state_path, canonical(self.state))

    def inspect(self):
        current = Path(self.config['current_link'])
        with private_read(self.config['config'], 1024 * 1024) as source:
            digest = hashlib.file_digest(source, 'sha256').hexdigest()
        return {'phase': self.state['phase'], 'selection': read_selection(self.config['data']),
                'fenced': self.hold.exists(), 'release': os.readlink(current),
                'config_sha256': digest, 'service': unit_state('noisefence.service')}

    def fence(self):
        if self.state['phase'] == 'new':
            require(unit_state('noisefence.service') == 'active', 'Initial migration requires a healthy running service')
            require(read_selection(self.config['data']) is None, 'Selected source needs its existing migration state')
            with private_read(self.config['config'], 1024 * 1024) as source:
                original = source.read()
            info = Path(self.config['config']).stat()
            atomic(self.root / 'original.toml', original)
            self.save(phase='prepared', original_sha256=hashlib.sha256(original).hexdigest(),
                      original_release=os.readlink(self.config['current_link']),
                      config_uid=info.st_uid, config_gid=info.st_gid, config_mode=stat.S_IMODE(info.st_mode),
                      timers=[unit for unit in TIMERS if unit_state(unit) == 'active'])
        require(self.state['phase'] not in ('complete', 'cancelled'), 'Migration already finished')
        if self.hold.exists():
            require(json.loads(self.hold.read_bytes()).get('run_id') == self.config['run_id'], 'Another migration owns the service fence')
        atomic(self.hold, canonical({'run_id': self.config['run_id']}))
        for unit in SERVICES:
            directory = UNIT_DIRECTORY / (unit + '.d')
            directory.mkdir(mode=0o755, exist_ok=True)
            protected(directory, True)
            path = directory / DROPIN
            raw = ('[Unit]\nConditionPathExists=!' + str(self.hold) + '\n').encode()
            if path.exists():
                require(path.read_bytes() == raw, 'Unexpected existing migration service condition')
            else:
                atomic(path, raw, mode=0o644)
        execute(['/usr/bin/systemctl', 'daemon-reload'])
        for timer in TIMERS:
            if unit_state(timer) != 'unknown':
                execute(['/usr/bin/systemctl', 'stop', timer])
        for unit in SERVICES:
            if unit_state(unit) != 'unknown':
                execute(['/usr/bin/systemctl', 'stop', unit])
            require(unit_state(unit) in ('inactive', 'failed', 'unknown'), 'Source service still writes')
        self.save(phase='stopped')

    def program(self, *args):
        return ['/usr/sbin/runuser', '-u', self.config['user'], '--', '/usr/bin/env', '-i',
                'PATH=/usr/bin:/bin', 'LC_ALL=C', str(Path(self.config['release_directory']) / 'noisefence'),
                '--config', self.config['config'], *args]

    def freeze(self, deadline, preserve_generations):
        require(self.source is None, 'Source session already exists')
        previous_receipt = self.state.get('receipt')
        require(type(preserve_generations) is bool and (not preserve_generations or previous_receipt is not None),
                'Journal-preserving recovery requires the prior source receipt')
        self.fence()
        selected = read_selection(self.config['data'])
        extra = []
        attempt = self.runtime / ('attempt-' + os.urandom(12).hex())
        attempt.mkdir(mode=0o700)
        os.chown(attempt, self.account.pw_uid, self.account.pw_gid)
        self.save(attempt=str(attempt))
        if selected is not None:
            require(selected == self.state.get('proposal'), 'Selected source differs from persisted proposal')
            atomic(attempt / 'resume.json', canonical(selected), uid=self.account.pw_uid, gid=self.account.pw_gid)
            extra = ['--resume-selection', str(attempt / 'resume.json')]
        if preserve_generations and selected is None:
            extra = ['--preserve-source-generations']
        path = attempt / 'source.sock'
        self.log = (self.root / 'source-session.log').open('ab')
        self.child = subprocess.Popen(self.program('management-freeze-source', '--export-parent', str(attempt),
                    '--socket', str(path), '--lease-seconds', str(self.config['lease_seconds']), *extra),
                    stdin=subprocess.DEVNULL, stdout=self.log, stderr=self.log, start_new_session=True)
        until = min(deadline, time.monotonic() + 15)
        while not path.exists():
            require(self.child.poll() is None, 'Native source session failed; inspect protected source-session.log')
            if time.monotonic() >= until:
                raise TimeoutError('Source session did not bind')
            time.sleep(0.02)
        self.source = SourceSession(path, self.config['node_id'], deadline)
        if preserve_generations:
            require(self.source.ready['receipt']['journal'] == previous_receipt['receipt']['journal'],
                    'Original journal changed after import')
        self.save(phase='frozen', receipt=self.source.ready)
        return self.source.ready

    def native(self, command):
        require(self.source is not None, 'Source is not frozen')
        require(command.get('action') in ('check', 'select', 'release', 'abort'), 'Unsupported native source operation')
        if command['action'] == 'select':
            proposal = checked_selection(command.get('selection', {}))
            require(proposal.get('node') == self.source.ready['receipt']['journal']['identity']
                    and proposal.get('role') == self.config['role'], 'Proposed source identity differs')
            previous = self.state.get('proposal')
            require(previous is None or previous == proposal, 'Cannot replace a persisted migration authority')
            # Persist BEFORE forwarding: a lost acknowledgement can still be recovered.
            self.save(proposal=proposal)
        response = self.source.command(command)
        if command['action'] == 'select':
            self.save(phase='selected', selection=response['selection'])
        if command['action'] in ('release', 'abort'):
            require(self.child.wait(timeout=10) == 0, 'Native source session did not finish cleanly')
            self.source.close()
            self.source = None
            self.save(phase='released' if command['action'] == 'release' else 'stopped')
        return response

    def publish(self, receipt):
        selected = read_selection(self.config['data'])
        require(selected is not None and selected == self.state.get('proposal'), 'No matching durable source selection')
        require(receipt.get('phase') == 'active' and receipt.get('activated_at') is not None
                and receipt.get('database') == selected['database']
                and receipt.get('selections', []).count(selected) == 1, 'PostgreSQL activation has not been confirmed')
        require(self.hold.exists(), 'Configuration publication requires the persistent fence')
        original = (self.root / 'original.toml').read_bytes()
        require(hashlib.sha256(original).hexdigest() == self.state['original_sha256'], 'Original configuration backup changed')
        updated = management_config(original, self.config['management'])
        digest = hashlib.sha256(updated).hexdigest()
        with private_read(self.config['config'], 1024 * 1024) as source:
            current = hashlib.file_digest(source, 'sha256').hexdigest()
        require(current in (self.state['original_sha256'], digest), 'Installation configuration changed outside migration')
        candidate = self.runtime / ('configuration-' + self.config['run_id'] + '.toml')
        atomic(candidate, updated, uid=self.account.pw_uid, gid=self.account.pw_gid)
        # Native check uses the selected cache and immutable artifacts; no providers are queried.
        args = self.program('check-config')
        args[args.index('--config') + 1] = str(candidate)
        execute(args, timeout=120)
        self.save(phase='publishing', published_sha256=digest, activation=receipt)
        atomic(Path(self.config['config']), updated, uid=self.state['config_uid'], gid=self.state['config_gid'],
               mode=self.state['config_mode'])
        current = Path(self.config['current_link'])
        require(os.readlink(current) in (self.state['original_release'], self.config['release_directory']),
                'Service release changed outside migration')
        temporary = current.with_name('.management-' + self.config['run_id'])
        if temporary.exists() or temporary.is_symlink():
            require(temporary.is_symlink() and temporary.lstat().st_uid == 0
                    and os.readlink(temporary) == self.config['release_directory'], 'Unresolved release publication')
        else:
            temporary.symlink_to(self.config['release_directory'])
        os.replace(temporary, current)
        directory = os.open(current.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        self.save(phase='configured')
        return {'configured': True, 'sha256': digest}

    def start(self):
        require(self.state['phase'] in ('configured', 'released', 'started') and self.source is None,
                'Release all source sessions before starting services')
        require(read_selection(self.config['data']) == self.state.get('proposal') and self.state.get('activation', {}).get('phase') == 'active',
                'Migration activation receipt missing')
        with private_read(self.config['config'], 1024 * 1024) as source:
            require(hashlib.file_digest(source, 'sha256').hexdigest() == self.state['published_sha256'], 'Published configuration changed')
        require(os.readlink(self.config['current_link']) == self.config['release_directory'], 'Published release changed')
        if self.hold.exists():
            require(json.loads(self.hold.read_bytes()).get('run_id') == self.config['run_id'], 'Foreign service fence')
            self.hold.unlink()
            fd = os.open(self.hold.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        self.save(phase='started')
        # Stopped successful units can be garbage-collected by systemd. In that
        # state reset-failed reports 'unit not loaded' and must not prevent start.
        if unit_state('noisefence.service') == 'failed':
            execute(['/usr/bin/systemctl', 'reset-failed', 'noisefence.service'])
        execute(['/usr/bin/systemctl', 'start', 'noisefence.service'], timeout=120)
        return {'service': unit_state('noisefence.service')}

    def health(self):
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            with opener.open(self.config['health_url'], timeout=3) as response:
                value = json.loads(response.read(65537))
                return {'smtp_ready': value.get('smtp_ready') is True, 'service': unit_state('noisefence.service')}
        except (OSError, ValueError):
            return {'smtp_ready': False, 'service': unit_state('noisefence.service')}

    def complete(self):
        require(self.state['phase'] == 'started' and self.health()['smtp_ready'], 'Gateway has not become ready')
        for timer in self.state['timers']:
            execute(['/usr/bin/systemctl', 'start', timer])
        self.save(phase='complete')
        return {'complete': True}

    def cancel(self):
        require(read_selection(self.config['data']) is None and self.source is None,
                'Cannot restore legacy service after a selection')
        require(self.state['phase'] in ('prepared', 'stopped', 'frozen'), 'Migration cannot be cancelled in this phase')
        with private_read(self.config['config'], 1024 * 1024) as source:
            require(hashlib.file_digest(source, 'sha256').hexdigest() == self.state['original_sha256'], 'Legacy configuration changed')
        require(os.readlink(self.config['current_link']) == self.state['original_release'], 'Legacy release changed')
        require(self.hold.exists() and json.loads(self.hold.read_bytes()).get('run_id') == self.config['run_id'], 'Migration fence missing')
        self.hold.unlink()
        execute(['/usr/bin/systemctl', 'start', 'noisefence.service'], timeout=120)
        for timer in self.state['timers']:
            execute(['/usr/bin/systemctl', 'start', timer])
        self.save(phase='cancelled')
        return {'cancelled': True}

    def close(self):
        if self.source:
            self.source.close()
        if self.child and self.child.poll() is None:
            os.killpg(self.child.pid, signal.SIGTERM)
            try:
                self.child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(self.child.pid, signal.SIGKILL)
                self.child.wait(timeout=5)
        if self.log:
            self.log.close()


def serve(config, channel):
    with contextlib.ExitStack() as stack:
        for path in ['/run/noisefence-upgrade.lock', *['/var/lib/noisefence-hardening/' + n + '.lock' for n in ('snapshot', 'backup', 'verify', 'collect')]]:
            fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
            lock = stack.enter_context(os.fdopen(fd, 'a'))
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1, 'Unsafe operation lock')
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        agent = Agent(config)
        try:
            channel.send({'protocol': AGENT, 'run_id': config['run_id'], 'node_id': config['node_id'], 'state': agent.inspect()})
            for sequence in range(1, 80):
                request = channel.receive()
                require(set(request) == {'protocol', 'run_id', 'sequence', 'operation', 'arguments'}
                        and request['protocol'] == AGENT and request['run_id'] == config['run_id']
                        and type(request['sequence']) is int and request['sequence'] == sequence and isinstance(request['arguments'], dict), 'Invalid agent request')
                operation, args = request['operation'], request['arguments']
                require(set(args) == ({'preserve_generations'} if operation == 'freeze' else {'command'} if operation == 'native' else {'receipt'} if operation == 'publish' else set()),
                        'Unexpected agent operation arguments')
                if operation == 'freeze':
                    result = agent.freeze(channel.deadline, args['preserve_generations'])
                elif operation == 'native':
                    result = agent.native(args['command'])
                elif operation == 'export':
                    require(agent.source is not None, 'Source must remain frozen during export')
                    paths, manifest = source_files(config['data'], Path(config['config']), agent.source.ready)
                    channel.send({'protocol': AGENT, 'run_id': config['run_id'], 'sequence': sequence, 'result': {'manifest': manifest}})
                    for name in sorted(paths):
                        channel.send_file(paths[name], manifest[name])
                    channel.send({'status': 'exported', 'manifest_sha256': hashlib.sha256(canonical(manifest)).hexdigest()})
                    continue
                elif operation == 'inspect':
                    result = agent.inspect()
                elif operation == 'publish':
                    result = agent.publish(args['receipt'])
                elif operation == 'start':
                    result = agent.start()
                elif operation == 'health':
                    result = agent.health()
                elif operation == 'complete':
                    result = agent.complete()
                elif operation == 'cancel':
                    result = agent.cancel()
                elif operation == 'close':
                    result = {'closed': True}
                else:
                    raise ValueError('Unknown migration agent operation')
                channel.send({'protocol': AGENT, 'run_id': config['run_id'], 'sequence': sequence, 'result': result})
                if operation == 'close':
                    return
            raise ValueError('Agent command limit exceeded')
        finally:
            agent.close()


def main():
    require(os.geteuid() == 0 and len(sys.argv) == 1, 'Root and no command arguments required')
    os.umask(0o077)
    config = load_config(CONFIG)
    channel = Channel(sys.stdin.fileno(), sys.stdout.fileno(), time.monotonic() + min(config['lease_seconds'], config['expires_at'] - time.time()))
    serve(config, channel)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print('Migration agent stopped: ' + type(error).__name__ + ': ' + str(error)[:300], file=sys.stderr)
        sys.exit(1)
