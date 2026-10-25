"""AppArmor assertions for disposable native lifecycle containers only."""
import hashlib
import os
from pathlib import Path
import re
import subprocess

PROFILE = re.compile(r'noisefence-test-[a-f0-9]{12}')
ENVIRONMENT = 'NOISEFENCE_TEST_APPARMOR_PROFILE'
DROPIN_DIRECTORY = Path('/etc/systemd/system/noisefence.service.d')
CANARY = Path('/etc/noisefence-blocked-fixture.toml')
PROC = Path('/proc')
DISCONNECTED_ROOT = Path('/att/noisefence')


def expected_profile():
    value = os.environ.get(ENVIRONMENT, '')
    if value and not PROFILE.fullmatch(value):
        raise RuntimeError('Invalid disposable AppArmor profile name')
    return value


def call(*arguments):
    return subprocess.run(arguments, capture_output=True, timeout=20)


def require(result, message):
    if not result:
        raise RuntimeError(message)


def install(binary, config):
    profile = expected_profile()
    if not profile:
        return None
    require(os.environ.get('NOISEFENCE_DISPOSABLE_PAIRED_TEST') == '1'
            and Path('/.dockerenv').is_file(), 'Disposable container required')
    require(not DISCONNECTED_ROOT.exists() and not DISCONNECTED_ROOT.is_symlink(),
            'Reserved AppArmor attachment prefix must not exist')
    directory = DROPIN_DIRECTORY
    directory.mkdir(exist_ok=True)
    dropin = directory/'95-fixture-confinement.conf'
    require(not dropin.exists(), 'Confinement drop-in already exists')
    dropin.write_text('[Service]\nAppArmorProfile='+profile+'\n')
    dropin.chmod(0o644)
    # The canary is readable by the daemon user under DAC, outside the allowed
    # AppArmor paths. Success must change solely with the confinement boundary.
    canary = CANARY
    require(not canary.exists(), 'Canary path already exists')
    try:
        canary.write_bytes(config.read_bytes()); canary.chmod(0o644)
        command = ['runuser', '-u', 'noisefence', '--']
        baseline = call(*command, str(binary), '--config', str(canary), 'check-config')
        allowed = call(*command, '/usr/bin/aa-exec', '-p', profile, '--',
                       str(binary), '--config', str(config), 'check-config')
        denied = call(*command, '/usr/bin/aa-exec', '-p', profile, '--',
                      str(binary), '--config', str(canary), 'check-config')
        require(baseline.returncode == 0, 'Canary is not readable without AppArmor')
        require(allowed.returncode == 0, 'Expected configuration fails under AppArmor')
        require(denied.returncode != 0 and b'Permission denied' in denied.stderr,
                'AppArmor did not deny the readable out-of-scope configuration')
    finally:
        canary.unlink(missing_ok=True)
    return {'profile': profile, 'allowed_configuration': True,
            'unconfined_canary_read': True, 'confined_canary_denied': True,
            'dropin_sha256': hashlib.sha256(dropin.read_bytes()).hexdigest()}


def inspect(service):
    profile = expected_profile()
    if not profile:
        return None
    require(service in ('noisefence.service', 'noisefence-validation.service'),
            'Unknown test service')
    result = call('systemctl', 'show', service, '--property=MainPID',
                  '--property=AppArmorProfile', '--property=ActiveState')
    require(result.returncode == 0, 'Cannot inspect confined service')
    fields = dict(line.split('=', 1) for line in result.stdout.decode().splitlines() if '=' in line)
    require(fields.get('ActiveState') == 'active' and fields.get('AppArmorProfile') == profile
            and fields.get('MainPID', '').isdecimal() and int(fields['MainPID']) > 0,
            'The expected confined service is not active')
    pid = fields['MainPID']
    actual = (PROC/pid/'attr/current').read_text().strip()
    require(actual == profile+' (enforce)', 'Daemon is not confined in enforce mode')
    binary = (PROC/pid/'exe')
    with binary.open('rb') as source:
        digest = hashlib.file_digest(source, 'sha256').hexdigest()
    confirmed = call('systemctl', 'show', service, '--property=MainPID', '--value')
    require(confirmed.returncode == 0 and confirmed.stdout.decode().strip() == pid,
            'Service changed while reading confinement evidence')
    return {'profile': profile, 'process_profile': actual, 'mode': 'enforce',
            'binary_sha256': digest}
