#!/usr/bin/python3
"""Start an authorized recovered console before releasing its surviving worker.

Only the standard installed systemd/AppArmor/Nginx layout is supported. Offline
preparation must already be complete. This command does not recover a remote peer,
remove the original coordinator fence or resume checkpoint transport/timers.
"""
import argparse
import fcntl
import hashlib
from http.cookies import SimpleCookie
import json
import os
from pathlib import Path
import pwd
import re
import shlex
import tempfile
import time
import tomllib
import urllib.request

from migration_agent import SERVICES, execute, unit_state
from migration_protocol import atomic, canonical, identity, private_read, require, sha
import recovery_database
import recovery_install
import recovery_prepare
import recovery_proxy
from recovery_install import protected

STATE = Path('/var/lib/noisefence-selected-recovery')
ACTIVE = Path('/var/lib/noisefence-standby/active')
MARKER = ACTIVE.parent/'promoted.json'
PROFILE = Path('/etc/apparmor.d/noisefence-console')
UNIT = 'noisefence-console.service'
PHASES = ('prepared', 'console_started', 'login_verified', 'proxy_verified', 'worker_releasing', 'running')


def root_json(path, limit=65536, private=True):
    info = protected(path)
    require(not private or not info.st_mode & 0o077, 'Private root recovery record required')
    with private_read(path, limit) as source:
        return json.load(source)


def fingerprint(path, expected, limit=512*1024**2):
    protected(path)
    with private_read(path, limit) as source:
        require(hashlib.file_digest(source, 'sha256').hexdigest() == expected,
                'Installed recovery artifact changed')


def fence_identity(receipt):
    require(isinstance(receipt, dict), 'Runtime requires explicit original-source fencing evidence')
    return {key:value for key,value in receipt.items() if key != 'created'}


def authorization_identity(plan):
    pinned = {key:value for key,value in plan.items() if key != 'expires_at'}
    pinned['fence'] = fence_identity(plan['fence'])
    return hashlib.sha256(canonical(pinned)).hexdigest()


def unit_properties():
    names = ('User', 'Group', 'ExecStart', 'ExecStartPre', 'ExecStartPost', 'ExecCondition',
             'ExecStop', 'ExecStopPost', 'NoNewPrivileges', 'ProtectSystem', 'ProtectHome',
             'PrivateTmp', 'PrivateDevices', 'AppArmorProfile', 'CapabilityBoundingSet',
             'RestrictSUIDSGID', 'FragmentPath', 'DropInPaths', 'MainPID')
    raw = execute(['/usr/bin/systemctl', 'show', '--all', '--property='+','.join(names), UNIT]).decode()
    result = {}
    for line in raw.splitlines():
        key, separator, value = line.partition('=')
        require(separator and key in names and key not in result, 'Invalid console unit inspection')
        result[key] = value
    # systemctl omits empty Exec* arrays even with --all. Nonempty hooks are
    # emitted and refused below; the unit bytes and absence of drop-ins are pinned.
    for key in ('ExecStartPre', 'ExecStartPost', 'ExecCondition', 'ExecStop', 'ExecStopPost'):
        result.setdefault(key, '')
    require(set(result) == set(names), 'Console unit properties unavailable: '+','.join(sorted(set(names)-set(result))))
    return result


def validate_unit(fields, user, binary, unit_hash):
    require(fields['User'] == fields['Group'] == user and user != 'root', 'Unexpected console account')
    for key in ('ExecStartPre', 'ExecStartPost', 'ExecCondition', 'ExecStop', 'ExecStopPost', 'DropInPaths'):
        require(not fields[key], 'Console unit contains unreviewed commands or overrides')
    for key in ('NoNewPrivileges', 'PrivateTmp', 'PrivateDevices', 'RestrictSUIDSGID'):
        require(fields[key] == 'yes', 'Console unit confinement is not enabled')
    require(fields['ProtectSystem'] == 'strict' and fields['ProtectHome'] == 'yes'
            and fields['AppArmorProfile'] == 'noisefence-console' and not fields['CapabilityBoundingSet'],
            'Console unit confinement differs from the supported profile')
    starts = re.findall(r'argv\[\]=([^;]+);', fields['ExecStart'])
    require(len(starts) == 1, 'One explicit console command required')
    arguments = shlex.split(starts[0])
    require(len(arguments) == 4 and arguments[1:] == ['--config', str(ACTIVE/'console.toml'), 'serve-console']
            and Path(arguments[0]).resolve() == Path(binary), 'Console service uses another binary or configuration')
    fingerprint(Path(fields['FragmentPath']).resolve(), unit_hash, 65536)


def loaded_profile():
    path = Path('/sys/kernel/security/apparmor/profiles')
    require(path.is_file(), 'Loaded AppArmor profiles are unavailable; runtime promotion refused')
    with path.open() as source:
        raw = source.read(4*1024**2+1)
    require(len(raw) <= 4*1024**2 and 'noisefence-console (enforce)' in raw.splitlines(),
            'Recovery console AppArmor profile is not enforced')


def process_profile(fields, uid, binary):
    pid = fields['MainPID']
    require(re.fullmatch('[1-9][0-9]*', pid), 'Console service has no main process')
    process = Path('/proc')/pid
    require(process.stat().st_uid == uid, 'Console process runs under another account')
    actual, expected = (process/'exe').stat(), Path(binary).stat()
    require((actual.st_dev, actual.st_ino) == (expected.st_dev, expected.st_ino),
            'Running console executable differs from the authorized release')
    command = (process/'cmdline').read_bytes().split(b'\0')
    require(len(command) == 5 and command[-1] == b'' and command[1:4] ==
            [b'--config', str(ACTIVE/'console.toml').encode(), b'serve-console'],
            'Running console command differs from its authorized configuration')
    require((process/'attr/current').read_text().strip() == 'noisefence-console (enforce)',
            'Running console is not confined by the required AppArmor profile')


def login(credentials, origin):
    # Only loopback HTTP receives these credentials. Nginx/TLS routing is probed
    # separately without credentials. Never log the request, response or cookie.
    with private_read(credentials, 16384) as source:
        require(not os.fstat(source.fileno()).st_mode & 0o077, 'Recovery credentials must be private')
        admin = json.load(source)
    require(isinstance(admin.get('username'), str) and isinstance(admin.get('password'), str),
            'Prepared administrator credentials are missing')
    client = urllib.request.build_opener(urllib.request.ProxyHandler({}), recovery_proxy.NoRedirect())
    base = 'http://127.0.0.1:18081'
    request = urllib.request.Request(base+'/api/v1/login', method='POST',
        data=canonical({key:admin[key] for key in ('username', 'password')}),
        headers={'Content-Type':'application/json', 'Origin':origin})
    with client.open(request, timeout=15) as response:
        raw = response.read(65537)
        require(response.status == 200 and len(raw) <= 65536, 'Recovery administrator login failed')
        user = json.loads(raw)
        cookie = SimpleCookie()
        cookie.load(response.headers.get('Set-Cookie', ''))
    require('noisefence_session' in cookie, 'Login did not create a session')
    token = cookie['noisefence_session']
    require(token['secure'] and token['httponly'] and token['samesite'].lower() in ('strict','lax'),
            'Recovery session cookie is not protected')
    require(user.get('username') == admin['username'] and user.get('admin') is True
            and isinstance(user.get('csrf'), str) and user['csrf'], 'Recovery administrator identity differs')
    headers = {'Cookie':'noisefence_session='+token.value, 'Origin':origin}
    try:
        with client.open(urllib.request.Request(base+'/api/v1/me', headers=headers), timeout=10) as response:
            raw = response.read(65537)
            require(response.status == 200 and len(raw) <= 65536, 'Recovery session lookup failed')
            found = json.loads(raw)
            require(found.get('username') == user['username'] and found.get('admin') is True,
                    'Database-backed recovery session was not verified')
    finally:
        with client.open(urllib.request.Request(base+'/api/v1/logout', method='POST',
                data=b'', headers={**headers, 'X-CSRF-Token':user['csrf']}), timeout=10) as response:
            require(response.status == 200, 'Could not retire recovery verification session')


class Runtime:
    def __init__(self, authorization):
        self.plan = p = root_json(authorization)
        require(set(p) == {'protocol','operation','preparation','preparation_sha256','console_unit_sha256',
                          'apparmor_sha256','fence','expires_at'}, 'Invalid runtime recovery authorization')
        require(p['protocol'] == 'noisefence-recovery-runtime-1' and identity(p['operation'])
                and all(sha(p[key]) for key in ('preparation_sha256','console_unit_sha256','apparmor_sha256'))
                and type(p['expires_at']) is int and time.time() < p['expires_at'] <= time.time()+3600,
                'Expired or invalid runtime authorization')
        fingerprint(p['preparation'], p['preparation_sha256'], 65536)
        self.preparation = source = root_json(p['preparation'])
        require(source['protocol'] == 'noisefence-selected-recovery-1' and source['operation'] == p['operation'],
                'Another offline recovery is referenced')
        self.root = STATE/p['operation']
        protected(self.root, True)
        offline = root_json(self.root/'state.json', 2*1024**2)
        pinned = {k:v for k,v in source.items() if k != 'expires_at'}
        pinned['fence'] = {k:v for k,v in source['fence'].items() if k != 'created'}
        require(offline['phase'] == 'workers_authorized'
                and offline['authorization'] == hashlib.sha256(canonical(pinned)).hexdigest(),
                'Offline preparation is incomplete or belongs to another plan')
        self.manifest = recovery_prepare.checkpoint(Path(source['checkpoint']), source['manifest_sha256'])
        require(fence_identity(p['fence']) == fence_identity(source['fence']),
                'Runtime fencing refers to another original coordinator operation')
        recovery_prepare.fencing(p['fence'], self.manifest, p['operation'], source['disaster'])
        protected(ACTIVE, True)
        protected(ACTIVE/'recovery-stage.json')
        require(root_json(ACTIVE/'recovery-stage.json', private=False) == {'operation':p['operation'],
            'snapshot':self.manifest['snapshot'],'manifest_sha256':source['manifest_sha256']},
            'Another active recovery stage is installed')
        self.account = pwd.getpwnam(source['user'])
        require(self.account.pw_uid != 0, 'Unprivileged console owner required')
        protected(ACTIVE/'console.toml')
        self.config_hash = hashlib.sha256((ACTIVE/'console.toml').read_bytes()).hexdigest()
        self.worker = Path(source['worker_config'])
        protected(self.worker)
        self.worker_raw = self.worker.read_bytes()
        require(self.worker_raw == recovery_install.rewrite(offline['worker_original'].encode(), source['console_url']),
                'Worker installation changed after offline recovery')
        self.worker_data = Path(tomllib.loads(self.worker_raw.decode())['data_dir'])
        self.credentials = ACTIVE/'data/recovery-private/admin.json'
        self.state_path = self.root/'runtime.json'
        self.binding = authorization_identity(p)
        if self.state_path.exists():
            self.state = root_json(self.state_path)
            require(self.state.get('authorization') == self.binding and self.state.get('phase') in PHASES
                    and self.state.get('console_config_sha256') == self.config_hash,
                    'Runtime recovery changed during retry')
        else:
            require(unit_state(UNIT) in ('inactive','failed'), 'Unowned recovery console is already running')
            self.state = {'authorization':self.binding,'phase':'prepared','console_config_sha256':self.config_hash}
            self.save('prepared')

    def save(self, phase):
        self.state['phase'] = phase
        atomic(self.state_path, canonical(self.state))

    def verify(self):
        self.verify_native()
        p = self.preparation
        validate_unit(unit_properties(), p['user'], p['binary'], self.plan['console_unit_sha256'])

    def verify_native(self):
        """Validate prepared authority without accepting or changing service overrides."""
        p = self.preparation
        fingerprint(p['binary'], p['binary_sha256'])
        fingerprint(ACTIVE/'console.toml', self.config_hash, 1024**2)
        require(self.worker.read_bytes() == self.worker_raw, 'Worker configuration changed during handoff')
        require(recovery_install.installed_service(self.worker, p['user']) == Path(p['binary']),
                'Worker and console must use the same authorized release')
        with tempfile.TemporaryFile() as output:
            recovery_database.run(['/usr/sbin/runuser','-u',p['user'],'--','/usr/bin/env','-i',
                'PATH=/usr/bin:/bin','LC_ALL=C',p['binary'],'--config',str(ACTIVE/'console.toml'),
                'management-recovery-check-console'], self.root, stdout=output, timeout=30, byte_limit=65536)
            output.seek(0)
            result = json.load(output)
        require(result.get('status') == 'console_authorization_verified' and result.get('smtp_enabled') is False
                and result.get('state_changed') is False and result['receipt']['operation'] == self.plan['operation']
                and result['receipt']['database'] == self.manifest['management']['database'],
                'Native recovery authorization differs from prepared console')

    def fence(self):
        recovery_install.fence(self.plan['operation'])

    def console(self):
        fingerprint(PROFILE, self.plan['apparmor_sha256'], 1024**2)
        require(Path('/sys/kernel/security/apparmor/profiles').is_file(),
                'AppArmor enforcement is unavailable; worker remains fenced')
        execute(['/usr/sbin/apparmor_parser','--replace',str(PROFILE)], timeout=30)
        loaded_profile()
        marker = {'owner':self.manifest['owner'],'operation':self.plan['operation'],
            'snapshot':self.manifest['snapshot'],'console_only':True,'console_url':self.preparation['console_url'],
            'worker_queue_replaced':False}
        if MARKER.exists():
            require(root_json(MARKER) == marker, 'Another promotion owns the console startup marker')
        else:
            atomic(MARKER, canonical(marker))
        execute(['/usr/bin/systemctl','start',UNIT], timeout=60)
        deadline = time.monotonic()+60
        while True:
            try:
                recovery_proxy.console_health()
                break
            except (OSError, ValueError):
                require(unit_state(UNIT) not in ('inactive','failed') and time.monotonic() < deadline,
                        'Recovery console did not become healthy; worker remains fenced')
                time.sleep(1)
        process_profile(unit_properties(), self.account.pw_uid, self.preparation['binary'])
        self.verify()

    def worker_health(self):
        client = urllib.request.build_opener(urllib.request.ProxyHandler({}), recovery_proxy.NoRedirect())
        deadline = time.monotonic()+30
        while True:
            try:
                with client.open('http://127.0.0.1:18080/healthz', timeout=3) as response:
                    raw = response.read(8193)
                    require(response.status == 200 and len(raw) <= 8192, 'Worker health is unavailable')
                    health = json.loads(raw)
                    require(health.get('status') == 'ok' and type(health.get('smtp_ready')) is bool,
                            'Worker health response is invalid')
                return
            except OSError:
                require(unit_state('noisefence.service') == 'active' and time.monotonic() < deadline,
                        'Worker health did not become available')
                time.sleep(1)

    def release(self):
        # The native cold-start guard additionally verifies the actual worker's
        # selection, route, credential and committed worker-release receipt.
        hold = recovery_install.STATE/'hold.json'
        require(root_json(hold) == {'operation':self.plan['operation']}, 'Another operation owns the worker fence')
        paths = [recovery_install.UNITS/(unit+'.d')/recovery_install.DROPIN for unit in SERVICES]
        expected = ('[Unit]\nConditionPathExists=!'+str(hold)+'\n').encode()
        for path in paths:
            protected(path)
            require(path.read_bytes() == expected, 'Recovery service fence changed externally')
        with recovery_install.source_locks(self.worker_data, self.account.pw_uid):
            self.verify()
            loaded_profile()
            process_profile(unit_properties(), self.account.pw_uid, self.preparation['binary'])
            recovery_proxy.console_health()
            recovery_proxy.probe(self.preparation['hostname'])
            # Persist the intent first. A crash at any subsequent point is
            # recoverable by reinstalling this exact operation's fence.
            self.save('worker_releasing')
            # Keep the exact ConditionPathExists drop-ins installed. Removing
            # them one by one would create a boot-time gap if power failed
            # before the final hold removal or daemon-reload.
            hold.unlink()
            fd = os.open(hold.parent, os.O_RDONLY)
            try: os.fsync(fd)
            finally: os.close(fd)
            execute(['/usr/bin/systemctl','daemon-reload'])
        execute(['/usr/bin/systemctl','start','noisefence.service'], timeout=90)
        require(unit_state('noisefence.service') == 'active', 'Recovered worker did not start')
        self.worker_health()

    def boot_persistence(self, install=False):
        directory = recovery_install.UNITS/'multi-user.target.wants'
        if install:
            execute(['/usr/bin/systemctl','add-wants','multi-user.target',UNIT,'noisefence.service'])
            execute(['/usr/bin/systemctl','daemon-reload'])
        protected(directory, True)
        for unit in (UNIT, 'noisefence.service'):
            link = directory/unit
            require(link.is_symlink() and link.lstat().st_uid == 0,
                    'Recovery service has no persistent root-owned boot dependency')
            protected(link.resolve())
            wanted = execute(['/usr/bin/systemctl','show','--property=WantedBy','--value',unit]).decode().split()
            require('multi-user.target' in wanted, 'Recovery service is not selected for normal boot')
        return {'target':'multi-user.target','services':[UNIT,'noisefence.service']}

    def persist_boot(self):
        # This is called only after successful runtime/route verification. The
        # permanent console marker and native startup authority remain required.
        expected = {'target':'multi-user.target','services':[UNIT,'noisefence.service']}
        if self.state.get('boot') is None:
            self.state['boot'] = self.boot_persistence(install=True)
            self.save(self.state['phase'])
        else:
            require(self.state['boot'] == expected, 'Recovery boot receipt changed')
            require(self.boot_persistence() == expected, 'Recovery boot dependencies changed')

    def run(self):
        # A completed invocation is an inspection, not another key rotation,
        # login or service restart. An earlier runtime without a boot receipt
        # receives that missing installation step only after all live checks.
        # Incomplete retries retain/reinstall fences.
        if self.state['phase'] == 'running':
            self.verify()
            loaded_profile()
            process_profile(unit_properties(), self.account.pw_uid, self.preparation['binary'])
            recovery_proxy.console_health()
            recovery_proxy.probe(self.preparation['hostname'])
            require(unit_state('noisefence.service') == 'active', 'Recovered worker is not running')
            require(not (recovery_install.STATE/'hold.json').exists(), 'Running recovery still has a worker fence')
            self.worker_health()
            self.persist_boot()
            return self.result()
        self.fence()
        try:
            self.verify()
            self.console()
            self.save('console_started')
            login(self.credentials, self.preparation['console_url'])
            self.save('login_verified')
            recovery_proxy.switch(self.root, self.plan['operation'], self.preparation['hostname'],
                                  reentry_binding=self.binding)
            self.save('proxy_verified')
            self.release()
            self.persist_boot()
            self.save('running')
        except BaseException:
            self.fence()
            raise
        return self.result()

    def result(self):
        return {'operation':self.plan['operation'],'status':'console_and_worker_running',
            'console_smtp_fenced':True,'original_coordinator_fence_retained':True,
            'worker_queue_replaced':False,'boot_dependencies_verified':True,'checkpoint_transport_resumed':False,
            'two_copy_smtp_availability_verified':False}


if __name__ == '__main__':
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--authorization', type=Path, required=True)
    args = parser.parse_args()
    require(os.geteuid() == 0, 'Root required')
    with open('/run/noisefence-upgrade.lock', 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX|fcntl.LOCK_NB)
        print(json.dumps(Runtime(args.authorization).run()))
