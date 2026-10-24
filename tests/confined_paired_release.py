#!/usr/bin/env python3
"""Run the paired lifecycle under a unique policy on an ephemeral GitHub Linux VM.

This controller is deliberately unavailable on self-hosted or production hosts.
The policy generator runs without network, privileges or a writable source mount.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import uuid

SOURCE = Path(__file__).resolve().parents[1]
PROFILES = '/sys/kernel/security/apparmor/profiles'
PARSER = '/usr/sbin/apparmor_parser'
PATH = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def command(*arguments, timeout=30):
    return subprocess.check_output(arguments, timeout=timeout, stderr=subprocess.STDOUT,
                                   env={'PATH': PATH, 'LANG': 'C'})


def profiles():
    return command('sudo', '-n', 'cat', PROFILES).decode().splitlines()


def policy(image, name):
    with tempfile.TemporaryDirectory(prefix='nf-policy-source-') as temporary:
        root = Path(temporary)
        # isolation.py imports its network helper even when only rendering.
        for relative in ('tests/render_apparmor_fixture.py', 'deploy/hardening/isolation.py',
                         'deploy/hardening/network.py'):
            target = root/relative; target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(SOURCE/relative, target); target.chmod(0o444)
        for directory in (root, root/'tests', root/'deploy', root/'deploy/hardening'):
            directory.chmod(0o755)
        result = command('docker', 'run', '--rm', '--network', 'none', '--read-only',
            '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--cpus', '1',
            '--memory', '256m', '--pids-limit', '32', '--ulimit', 'fsize=1048576:1048576',
            '--tmpfs', '/tmp:rw,size=16m,mode=1777', '--user', '65534:65534',
            '--mount', 'type=bind,src='+str(root)+',dst=/source,readonly', image,
            'env', '-i', 'PATH='+PATH, 'HOME=/tmp', 'TMPDIR=/tmp', 'PYTHONDONTWRITEBYTECODE=1',
            'python3', '-B', '/source/tests/render_apparmor_fixture.py', '--name', name,
            timeout=60)
    require(0 < len(result) <= 128*1024, 'Unexpected generated policy size')
    return result


def containers_removed(output):
    path = output/'operation.json'
    if not path.exists():
        return True
    value = json.loads(path.read_text())
    operation = str(uuid.UUID(value['operation']))
    require(value['operation'] == operation, 'Invalid fixture operation identity')
    expected = {node:'nf-paired-'+operation[:8]+'-'+node for node in ('mx1', 'mx2')}
    require(value.get('containers') == expected, 'Unexpected fixture container identities')
    existing = set(command('docker', 'ps', '--all', '--format', '{{.Names}}').decode().splitlines())
    return not (set(expected.values()) & existing)


def run(args):
    require(sys.platform == 'linux' and os.environ.get('GITHUB_ACTIONS') == 'true'
            and os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted'
            and os.environ.get('RUNNER_OS') == 'Linux',
            'Use only an ephemeral GitHub-hosted Linux runner')
    require(Path('/sys/module/apparmor/parameters/enabled').read_text().strip() == 'Y',
            'The runner kernel does not enable AppArmor')
    output = args.output.resolve(); evidence = args.evidence.resolve()
    require(not output.exists(), 'Use a fresh paired output directory')
    evidence.mkdir(mode=0o700, parents=True, exist_ok=False)
    name = 'noisefence-test-'+uuid.uuid4().hex[:12]
    policy_file = evidence/'profile'
    raw = policy(args.image, name)
    policy_file.write_bytes(raw); policy_file.chmod(0o600)
    initial = profiles()
    require(not any(line.split(' ',1)[0] == name for line in initial), 'Profile already exists')
    # --add fails on collisions. Never replace an existing policy, including on
    # retries; only a successfully added profile belongs to this operation.
    proof = {'schema':'noisefence-confinement-rehearsal-1', 'status':'running',
        'profile':name, 'profile_sha256':hashlib.sha256(raw).hexdigest(),
        'generator_sha256':hashlib.sha256((SOURCE/'deploy/hardening/isolation.py').read_bytes()).hexdigest(),
        'renderer_sha256':hashlib.sha256((SOURCE/'tests/render_apparmor_fixture.py').read_bytes()).hexdigest(),
        'kernel':platform.release(), 'platform':args.platform,
        'production_affected':False, 'profile_removed':False}
    (evidence/'confinement.json').write_text(json.dumps({**proof, 'status':'load_not_confirmed'},indent=2)+'\n')
    command('sudo', '-n', PARSER, '--add', '--skip-cache', str(policy_file))
    try:
        require(name+' (enforce)' in profiles(), 'Loaded profile is not enforcing')
        arguments = [sys.executable, '-B', str(SOURCE/'tests/paired_release_lifecycle.py'),
            '--old-archive', str(args.old_archive.resolve()), '--new-archive', str(args.new_archive.resolve()),
            '--archive-candidate', '--image', args.image, '--platform', args.platform,
            '--fixture', str(args.fixture.resolve()), '--output', str(output), '--apparmor-profile', name]
        subprocess.run(arguments, timeout=1800, check=True,
            env={'PATH':PATH, 'HOME':str(evidence), 'LANG':'C', 'PYTHONDONTWRITEBYTECODE':'1'})
        proof['status'] = 'passed'
    finally:
        # Removing a policy from a surviving test process would silently remove
        # confinement. Preserve that failure until this ephemeral VM is destroyed.
        if not containers_removed(output):
            proof['status'] = 'cleanup_failed'
            (evidence/'confinement.json').write_text(json.dumps(proof,indent=2)+'\n')
            raise RuntimeError('Fixture containers remain; do not unload their profile')
        require(policy_file.read_bytes() == raw, 'Generated profile changed before removal')
        command('sudo', '-n', PARSER, '--remove', '--skip-cache', str(policy_file))
        proof['profile_removed'] = not any(line.split(' ',1)[0] == name for line in profiles())
        if proof['status'] == 'running':proof['status'] = 'failed'
        (evidence/'confinement.json').write_text(json.dumps(proof,indent=2)+'\n')
        require(proof['profile_removed'], 'Disposable AppArmor profile was not removed')
    return proof


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image',required=True)
    parser.add_argument('--platform',required=True,choices=['linux/amd64','linux/arm64'])
    for name in ('old-archive','new-archive','fixture','output','evidence'):
        parser.add_argument('--'+name,required=True,type=Path)
    args = parser.parse_args();os.umask(0o077)
    print(json.dumps(run(args)))


if __name__ == '__main__':main()
