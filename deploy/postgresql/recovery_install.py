#!/usr/bin/python3
"""Install one recovered worker's key and authority while keeping services fenced.

The root-owned authorization pins the selected identity, original configuration
and exact key bundle. No writable recovery plan controls privileged destinations.
This helper does not authorize native startup, remove its fence or start services.
"""
import argparse
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shlex
import stat
import time
import tomllib
import urllib.parse

from migration_agent import SERVICES, TIMERS, execute, read_selection, unit_state
from migration_protocol import atomic, canonical, checked_selection, identity, private_read, require, sha

STATE = Path('/var/lib/noisefence-recovery-install')
UNITS = Path('/etc/systemd/system')
DROPIN = '99-management-recovery-install.conf'
RECOVERED_JOBS = ('noisefence-recovered-train', 'noisefence-recovered-quality')


def protected(path, directory=False):
    """Reject replaceable ancestors as well as unsafe final files."""
    path = Path(path)
    require(path.is_absolute() and path.resolve() == path, 'Installation path must be physical and absolute')
    for parent in [path, *path.parents]:
        info = parent.lstat()
        is_directory = directory if parent == path else True
        require(info.st_uid == 0 and not info.st_mode & 0o022
                and (stat.S_ISDIR(info.st_mode) if is_directory else stat.S_ISREG(info.st_mode)),
                'Installation and ancestors must be protected by root')
    return path.stat()


def origin(value):
    require(isinstance(value, str), 'Invalid coordinator origin')
    url = urllib.parse.urlsplit(value)
    require(url.scheme == 'https' and url.hostname and url.username is None and url.password is None
            and url.path in ('', '/') and not url.query and not url.fragment
            and not any(c.isspace() or ord(c) < 32 for c in value), 'Recovery coordinator requires an HTTPS origin')
    url.port  # Reject malformed ports.
    return value


def rewrite(raw, destination):
    original = tomllib.loads(raw.decode())
    changed, count = re.subn(r'(?m)^coordinator_url\s*=\s*"[^"\r\n]+"[ \t]*$',
                             lambda _: 'coordinator_url = ' + json.dumps(destination), raw.decode())
    require(count == 1, 'Worker authority is not uniquely editable')
    expected = json.loads(json.dumps(original))
    expected['cluster']['coordinator_url'] = destination
    require(tomllib.loads(changed) == expected, 'Unexpected worker configuration change')
    return changed.encode()


@contextlib.contextmanager
def source_locks(data, uid):
    data = Path(data)
    require(data.resolve() == data, 'Worker source must be a physical directory')
    with contextlib.ExitStack() as stack:
        files = []
        for path in [data / 'daemon.lock', data / 'calibration/worker.lock']:
            parent = path.parent.lstat()
            require(path.parent.resolve() == path.parent and stat.S_ISDIR(parent.st_mode)
                    and parent.st_uid == uid and not parent.st_mode & 0o022, 'Unsafe worker lock directory')
            fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
            file = stack.enter_context(os.fdopen(fd, 'r+b'))
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == uid and not info.st_mode & 0o077,
                    'Unsafe worker lock file')
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            files.append((path, file))
        def verify():
            for path, file in files:
                now, held = path.lstat(), os.fstat(file.fileno())
                require(stat.S_ISREG(now.st_mode) and (now.st_dev, now.st_ino) == (held.st_dev, held.st_ino),
                        'Worker source lock was replaced')
        verify()
        yield verify
        verify()


def installed_service(worker, user):
    raw = execute(['/usr/bin/systemctl', 'show', '--property=User,ExecStart', 'noisefence.service'])
    fields = {}
    for line in raw.decode().splitlines():
        key, separator, value = line.partition('=')
        require(separator and key not in fields, 'Invalid installed service description')
        fields[key] = value
    require(set(fields) == {'User', 'ExecStart'} and fields['User'] == user,
            'Installed service account differs from authorization')
    starts = re.findall(r'argv\[\]=([^;]+);', fields['ExecStart'])
    require(len(starts) == 1, 'Worker must have one explicit native startup command')
    arguments = shlex.split(starts[0])
    require(len(arguments) == 4 and Path(arguments[0]).name == 'noisefence'
            and arguments[1:] == ['--config', str(worker), 'serve'],
            'Installed service uses another configuration or command')
    return Path(arguments[0]).resolve()


def fence(operation):
    hold = STATE / 'hold.json'
    if hold.exists():
        protected(hold)
        require(json.loads(hold.read_bytes()) == {'operation': operation}, 'Another operation owns this service fence')
    else:
        atomic(hold, canonical({'operation': operation}))
    for unit in SERVICES:
        directory = UNITS / (unit + '.d')
        directory.mkdir(mode=0o755, exist_ok=True)
        protected(directory, True)
        path = directory / DROPIN
        raw = ('[Unit]\nConditionPathExists=!' + str(hold) + '\n').encode()
        if path.exists():
            protected(path)
            require(path.read_bytes() == raw, 'Unexpected recovery service fence')
        else:
            atomic(path, raw, mode=0o644)
    execute(['/usr/bin/systemctl', 'daemon-reload'])
    require(unit_state('noisefence.service') != 'unknown', 'Installed worker service missing')
    for unit in [*TIMERS, *SERVICES, *(name+suffix for name in RECOVERED_JOBS for suffix in ('.timer', '.service'))]:
        if unit_state(unit) != 'unknown':
            execute(['/usr/bin/systemctl', 'stop', unit])
        require(unit_state(unit) in ('inactive', 'failed', 'unknown'), 'Worker still running')


def install(authorization, bundle_path):
    require(not protected(authorization).st_mode & 0o077, 'Installation authorization must be private')
    with private_read(authorization, 65536) as source:
        plan = json.load(source)
    require(set(plan) == {'protocol', 'operation', 'selection', 'config', 'config_sha256',
                         'bundle_sha256', 'coordinator_url', 'user', 'expires_at'}, 'Invalid installation authorization')
    require(plan['protocol'] == 'noisefence-recovery-install-1' and identity(plan['operation'])
            and sha(plan['config_sha256']) and sha(plan['bundle_sha256'])
            and type(plan['expires_at']) is int and time.time() < plan['expires_at'] <= time.time() + 3600,
            'Invalid or expired installation authorization')
    selected = checked_selection(plan['selection'])
    require(selected['role'] == 'worker', 'Only worker installations may be changed')
    destination = origin(plan['coordinator_url'])
    account = pwd.getpwnam(plan['user'])
    require(account.pw_uid != 0, 'Worker must use an unprivileged service account')
    worker = Path(plan['config'])
    info = protected(worker)
    with private_read(worker, 1024 * 1024) as source:
        current = source.read()
    config = tomllib.loads(current.decode())
    cluster = config.get('cluster', {})
    require(config.get('management', {}).get('backend') == 'coordinator'
            and cluster.get('role') == 'worker' and cluster.get('node_id') == selected['node']['node'],
            'Installed worker identity differs from authorization')
    key = Path(cluster['credential_file'])
    protected(key.parent, True)
    require(key.is_absolute() and key.resolve() == key and key != worker, 'Unsafe installed credential destination')
    old_key_info = key.lstat()
    require(stat.S_ISREG(old_key_info.st_mode) and old_key_info.st_uid == account.pw_uid
            and not old_key_info.st_mode & 0o077, 'Installed key must be service-owned and private')
    with private_read(bundle_path, 32768) as source:
        bundle_info = os.fstat(source.fileno())
        require(bundle_info.st_uid in (0, account.pw_uid) and not bundle_info.st_mode & 0o077,
                'Prepared key bundle must be owner-private')
        raw = source.read()
    require(hashlib.sha256(raw).hexdigest() == plan['bundle_sha256'], 'Prepared key bundle checksum changed')
    bundle = json.loads(raw)
    require(set(bundle) == {'protocol', 'operation', 'database', 'workers'}
            and bundle['protocol'] == 'noisefence-recovery-worker-credentials-1'
            and bundle['operation'] == plan['operation'] and bundle['database'] == selected['database'],
            'Prepared keys belong to another recovery authority')
    entry = bundle['workers'].get(selected['node']['node'], {})
    require(set(entry) == {'epoch', 'token'} and entry['epoch'] == selected['node']['epoch']
            and isinstance(entry['token'], str) and re.fullmatch('[0-9a-fA-F]{64}', entry['token']),
            'Prepared worker key differs from selected source')
    STATE.mkdir(mode=0o700, exist_ok=True)
    protected(STATE, True)
    receipt_path = STATE / (plan['operation'] + '.json')
    fingerprint = hashlib.sha256(canonical({k:v for k,v in plan.items() if k != 'expires_at'})).hexdigest()
    receipt = None
    if receipt_path.exists():
        protected(receipt_path)
        with private_read(receipt_path, 2 * 1024 * 1024) as source:
            receipt = json.load(source)
        require(receipt['authorization'] == fingerprint, 'Installation authorization changed during retry')
        original = receipt['original'].encode()
    else:
        original = current
    require(hashlib.sha256(original).hexdigest() == plan['config_sha256'], 'Original worker configuration checksum differs')
    updated = rewrite(original, destination)
    require(current in (original, updated), 'Installed worker configuration changed unexpectedly')
    if receipt is None:
        atomic(receipt_path, canonical({'authorization': fingerprint, 'original': original.decode(), 'completed': False}))
    installed_service(worker, plan['user'])
    fence(plan['operation'])
    installed_service(worker, plan['user'])
    with source_locks(config['data_dir'], account.pw_uid) as verify:
        require(read_selection(config['data_dir']) == selected, 'Actual worker queue differs from authorized selection')
        with private_read(worker, 1024 * 1024) as source:
            require(source.read() == current, 'Worker configuration changed while fencing')
        # Destinations come exclusively from the protected installed configuration.
        atomic(key, entry['token'].encode(), uid=account.pw_uid, gid=account.pw_gid)
        verify()
        atomic(worker, updated, uid=info.st_uid, gid=info.st_gid, mode=stat.S_IMODE(info.st_mode))
        verify()
        atomic(receipt_path, canonical({'authorization': fingerprint, 'original': original.decode(), 'completed': True}))
    return {'operation': plan['operation'], 'node': selected['node']['node'], 'status': 'installed_services_fenced',
            'services_started': False, 'queue_replaced': False, 'native_verification_required': True}


if __name__ == '__main__':
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--authorization', required=True, type=Path)
    parser.add_argument('--keys', required=True, type=Path)
    args = parser.parse_args()
    require(os.geteuid() == 0, 'Root required')
    with open('/run/noisefence-upgrade.lock', 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        print(json.dumps(install(args.authorization, args.keys)))
