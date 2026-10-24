#!/usr/bin/env python3
"""Durably stop one native MX for a reviewed, coordinated maintenance window.

This is a reservation primitive, not an updater. It never switches releases,
changes policy, migrates a database or authorizes a new binary to start. Cancellation
can restart only the unchanged installation recorded before the hold.
"""
import argparse
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import pwd
import re
import stat
import sys
import time

from migration_agent import SERVICES, TIMERS, execute, read_selection, unit_state
from migration_protocol import atomic, canonical, identity, pairs, private_read, require
from recovery_install import RECOVERED_JOBS, installed_service, protected

STATE = Path('/var/lib/noisefence-upgrade')
ACTIVE = STATE / 'active.json'
HOLD = STATE / 'hold.json'
LOCK = Path('/run/noisefence-upgrade.lock')
UNITS = Path('/etc/systemd/system')
DROPIN = '97-noisefence-upgrade.conf'
CONFIG = Path('/etc/noisefence/config.toml')
CURRENT = Path('/opt/noisefence/current')
DATA = Path('/var/lib/noisefence')
PROTOCOL = 'noisefence-upgrade-reservation-1'
JOBS = tuple(name + suffix for name in RECOVERED_JOBS for suffix in ('.service', '.timer'))
FENCED = (*SERVICES, *TIMERS, *JOBS, 'noisefence-console.service')
RESUMABLE = ('noisefence.service', *TIMERS, *(name+'.timer' for name in RECOVERED_JOBS))


def exists(path):
    try:
        path.lstat()
        return True
    except FileNotFoundError:
        return False


def require_no_activation(operation, *, abort=False, cancellation=False):
    if exists(STATE/'activation.json') or exists(STATE/(operation+'-activation.json')):
        if abort:
            from upgrade_activation import allow_abort
            allow_abort(operation, cancellation=cancellation)
        else:
            raise ValueError('A durable activation owns this operation; use its decision and recovery path')


def read_json(path):
    protected(path)
    with private_read(path, 65536) as source:
        return json.load(source, object_pairs_hook=pairs)


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def remove(path):
    path.unlink()
    sync_directory(path.parent)


@contextlib.contextmanager
def operation_lock():
    protected(LOCK.parent, True)
    fd = os.open(LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    with os.fdopen(fd, 'r+b') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                and not info.st_mode & 0o022, 'Unsafe operation lock')
        fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
        current = LOCK.lstat()
        require((current.st_dev, current.st_ino) == (info.st_dev, info.st_ino), 'Operation lock replaced')


def file_digest(path, maximum):
    protected(path)
    with private_read(path, maximum) as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def release_inventory(release):
    """Root-protected native release inventory, shared by candidate validation."""
    require(release.is_absolute() and release.resolve(strict=True) == release
            and release.parent == CURRENT.parent / 'releases', 'Release outside the native directory')
    protected(release, True)
    manifest_path = release / 'SHA256SUMS'
    protected(manifest_path)
    with private_read(manifest_path, 4 * 1024 * 1024) as source:
        manifest = source.read()
    files = {}; total = 0
    for line in manifest.decode().splitlines():
        digest, separator, name = line.partition('  ')
        relative = PurePosixPath(name)
        require(separator and re.fullmatch('[a-f0-9]{64}', digest) and name == str(relative)
                and not relative.is_absolute() and '..' not in relative.parts and '\\' not in name
                and name not in files and name != 'SHA256SUMS' and len(files) < 30000,
                'Invalid installed release manifest')
        path = release / name
        info = protected(path)
        total += info.st_size
        require(total <= 2 * 1024**3 and file_digest(path, 2 * 1024**3) == digest,
                'Installed release differs from its manifest')
        files[name] = digest
    require({'noisefence', 'build.json'} <= set(files), 'Incomplete release manifest')
    # Extra executable/assets are also unqualified; do not merely trust a manifest subset.
    actual = set()
    for path in release.rglob('*'):
        protected(path, path.is_dir())
        if path.is_file() and path != manifest_path:
            actual.add(str(path.relative_to(release)))
        require(len(actual) <= 30000, 'Installed release exceeds bounds')
    require(actual == set(files), 'Unlisted installed release files')
    return files, manifest


def installation():
    """Verify installed files without executing any release-provided program."""
    import tomllib
    protected(CONFIG)
    with private_read(CONFIG, 1024 * 1024) as source:
        raw = source.read()
    config = tomllib.loads(raw.decode())
    require(config.get('data_dir') == str(DATA), 'Only the native absolute data directory is supported')
    cluster = config.get('cluster', {})
    node, role = cluster.get('node_id'), cluster.get('role')
    require(isinstance(node, str) and re.fullmatch('[a-z0-9_-]{1,40}', node)
            and role in ('coordinator', 'worker') and 'replication' in config,
            'An identified replicated native MX is required')
    protected(CURRENT.parent, True)
    info = CURRENT.lstat()
    require(stat.S_ISLNK(info.st_mode) and info.st_uid == 0, 'Current release must be a root-owned symlink')
    release = CURRENT.resolve(strict=True)
    require(release.parent == CURRENT.parent / 'releases', 'Current release is outside the native release directory')
    protected(release, True)
    require(installed_service(CONFIG, 'noisefence') == release / 'noisefence', 'Installed startup command changed')
    files, manifest = release_inventory(release)
    account = pwd.getpwnam('noisefence')
    require(account.pw_uid != 0, 'The service must use an unprivileged account')
    info = DATA.lstat()
    require(DATA.resolve() == DATA and stat.S_ISDIR(info.st_mode)
            and info.st_uid == account.pw_uid and not info.st_mode & 0o077, 'Unsafe native data directory')
    selected = read_selection(DATA)
    if selected is not None:
        require(selected['node']['node'] == node and selected['role'] == role, 'Selected node differs from configuration')
    return {'node': node, 'role': role, 'config_sha256': hashlib.sha256(raw).hexdigest(),
            'current_link': os.readlink(CURRENT), 'release_directory': str(release),
            'manifest_sha256': hashlib.sha256(manifest).hexdigest(), 'binary_sha256': files['noisefence'],
            'build_sha256': files['build.json'], 'selection_sha256': hashlib.sha256(canonical(selected)).hexdigest()}


class Reservation:
    def __init__(self, operation):
        require(identity(operation), 'A canonical operation UUID is required')
        self.operation = operation
        self.path = STATE / (operation + '.json')

    def state(self):
        value = read_json(self.path)
        require(isinstance(value, dict) and set(value) == {'protocol', 'operation', 'created', 'phase', 'installation', 'units'}
                and value['protocol'] == PROTOCOL and value['operation'] == self.operation
                and value['phase'] in ('prepared', 'held', 'releasing', 'cancelled', 'upgraded')
                and type(value['created']) is int and value['created'] > 0
                and isinstance(value['installation'], dict) and isinstance(value['units'], dict)
                and set(value['units']) == set(FENCED)
                and all(s in ('active', 'inactive', 'failed', 'unknown') for s in value['units'].values()),
                'Invalid reservation receipt')
        return value

    def save(self, state, phase):
        state = {**state, 'phase': phase}
        atomic(self.path, canonical(state))
        return state

    def owner(self):
        expected = {'protocol': PROTOCOL, 'operation': self.operation}
        require(read_json(ACTIVE) == expected, 'Another operation owns the maintenance reservation')
        if exists(HOLD):
            require(read_json(HOLD) == expected, 'Unexpected service hold')
        return expected

    def install_conditions(self):
        # Conditions precede the hold. Reboot after publication must keep *every*
        # known writer stopped, even if the controller disconnects before stop.
        raw = ('[Unit]\nConditionPathExists=!' + str(HOLD) + '\n').encode()
        for unit in FENCED:
            directory = UNITS / (unit + '.d')
            directory.mkdir(mode=0o755, exist_ok=True)
            protected(directory, True)
            path = directory / DROPIN
            if exists(path):
                protected(path)
                require(path.read_bytes() == raw, 'Unexpected maintenance condition')
            else:
                atomic(path, raw, mode=0o644)
        sync_directory(UNITS)
        execute(['/usr/bin/systemctl', 'daemon-reload'])

    def stopped(self):
        return all(unit_state(unit) in ('inactive', 'failed', 'unknown') for unit in FENCED)

    def begin(self, *, activation_abort=False):
        require_no_activation(self.operation, abort=activation_abort, cancellation=True)
        STATE.mkdir(mode=0o700, exist_ok=True)
        protected(STATE, True)
        if exists(ACTIVE):
            self.owner()
        else:
            require(not exists(HOLD), 'Orphaned service hold requires recovery')
        if exists(self.path):
            state = self.state()
            require(state['phase'] in ('prepared', 'held'), 'Reservation already releasing or finished')
            require(installation() == state['installation'], 'Recorded installation changed; preserve the hold')
        else:
            require(not exists(ACTIVE), 'Reservation receipt missing; preserve the hold')
            for path in ['/var/lib/noisefence-migration/hold.json',
                         '/var/lib/noisefence-recovery-install/hold.json',
                         '/var/lib/noisefence-standby/fenced.json']:
                require(not exists(Path(path)), 'Another migration or recovery fence is present')
            baseline = installation()
            units = {unit: unit_state(unit) for unit in FENCED}
            require(units['noisefence.service'] == 'active' and units['noisefence-console.service'] in ('inactive', 'failed', 'unknown')
                    and all(s in ('active', 'inactive', 'failed', 'unknown') for s in units.values()),
                    'Native service must be running without a recovered console or transitioning jobs')
            state = {'protocol': PROTOCOL, 'operation': self.operation, 'created': int(time.time()),
                     'phase': 'prepared', 'installation': baseline, 'units': units}
            atomic(self.path, canonical(state))
        atomic(ACTIVE, canonical({'protocol': PROTOCOL, 'operation': self.operation}))
        self.install_conditions()
        atomic(HOLD, canonical(self.owner()))
        # Stop timers before services, including recovered jobs. No automatic
        # rollback on timeout: the persistent hold is the recovery boundary.
        for unit in sorted(FENCED, key=lambda name: not name.endswith('.timer')):
            if unit_state(unit) != 'unknown':
                execute(['/usr/bin/systemctl', 'stop', unit])
        require(self.stopped(), 'Maintenance writers still running')
        require(installation() == state['installation'], 'Installation changed while stopping; preserve the hold')
        state = self.save(state, 'held')
        return {'operation': self.operation, 'phase': state['phase'], 'node': state['installation']['node'], 'writers_stopped': True, 'reserved': True, 'service_hold': True}

    def cancel(self, *, activation_abort=False):
        require_no_activation(self.operation, abort=activation_abort, cancellation=True)
        require(not exists(STATE / 'promotion.json'), 'Restore and release the prepared pair before cancellation')
        promotion = STATE / (self.operation+'-promotion.json')
        if exists(promotion):
            # Import lazily: promotion uses this reservation primitive too.
            # A phase string alone is not a valid, fully bound release receipt.
            from upgrade_promotion import Promotion
            receipt = Promotion(self.operation).state()
            require(receipt['phase'] == 'released', 'Unreleased pair preparation prevents cancellation')
        require(not exists(STATE / 'validation.json'), 'Stop candidate validation before cancellation')
        require(unit_state('noisefence-validation.service') in ('inactive', 'failed', 'unknown'),
                'Candidate validation still running; preserve the hold')
        state = self.state()
        require(state['phase'] in ('prepared', 'held', 'releasing', 'cancelled'), 'Invalid cancellation state')
        if state['phase'] == 'cancelled':
            require(not exists(HOLD), 'Orphaned hold after cancellation')
            if exists(ACTIVE):
                self.owner()
                require(installation() == state['installation'], 'Completed cancellation installation changed')
                require(all(unit_state(unit) == 'active' for unit in RESUMABLE if state['units'][unit] == 'active'),
                        'Completed cancellation units changed; inspect before recovery')
                if not activation_abort:remove(ACTIVE)
            return {'operation': self.operation, 'phase': 'cancelled'}
        self.owner()
        require(installation() == state['installation'], 'Cannot cancel after installation changed; preserve the hold')
        if state['phase'] in ('prepared', 'held'):
            # Finish an interrupted stop before authorizing resumption.
            self.begin(activation_abort=activation_abort)
            state = self.save(self.state(), 'releasing')
        # The durable cancellation intent precedes removal. ACTIVE remains until
        # every originally active service/timer is actually restored. A failed
        # restart or lost response resumes this exact intent on retry.
        if exists(HOLD):
            remove(HOLD)
        # Do not rerun interrupted oneshot jobs; their timers schedule later work.
        for unit in RESUMABLE:
            if state['units'][unit] == 'active':
                if unit_state(unit) == 'failed':
                    execute(['/usr/bin/systemctl', 'reset-failed', unit])
                execute(['/usr/bin/systemctl', 'start', unit])
                require(unit_state(unit) == 'active', 'Recorded unit could not resume; reservation remains')
        self.save(state, 'cancelled')
        if not activation_abort:remove(ACTIVE)
        return {'operation': self.operation, 'phase': 'cancelled'}

    def status(self):
        state = self.state()
        owned = False
        if exists(ACTIVE):
            self.owner()
            owned = True
        return {'operation': self.operation, 'phase': state['phase'], 'node': state['installation']['node'],
                'reserved': owned, 'service_hold': exists(HOLD), 'writers_stopped': self.stopped()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['begin', 'status', 'cancel'])
    parser.add_argument('--operation', required=True)
    args = parser.parse_args()
    require(os.geteuid() == 0, 'Root is required')
    os.umask(0o077)
    with operation_lock():
        result = getattr(Reservation(args.operation), args.action)()
    print(json.dumps(result))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print('Maintenance reservation stopped: ' + type(error).__name__ + ': ' + str(error)[:300], file=sys.stderr)
        sys.exit(1)
