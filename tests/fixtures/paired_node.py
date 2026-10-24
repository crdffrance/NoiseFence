"""Fixed-path helper used only inside disposable paired-lifecycle containers."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import smtplib
import sqlite3
import subprocess
import time
import urllib.request
import uuid

BASE = Path('/opt/noisefence')
DATA = Path('/var/lib/noisefence')
CONFIG = Path('/etc/noisefence/config.toml')
PRIVATE = Path('/root/paired-test')
PG = '/usr/lib/postgresql/17/bin/'


def require(value, message):
    if not value:
        raise RuntimeError(message)


def run(*args, timeout=90):
    try:
        return subprocess.check_output(args, stderr=subprocess.STDOUT, timeout=timeout)
    except subprocess.CalledProcessError as error:
        if PRIVATE.is_dir():
            (PRIVATE/'command-error.log').write_bytes(error.output[-131072:])
        raise


def sql(statement, database='postgres', user='postgres'):
    return run('runuser', '-u', user, '--', PG+'psql', '-X', '-A', '-t',
               '-v', 'ON_ERROR_STOP=1', '--host=/run/postgresql', '--dbname='+database,
               '-c', statement).decode().strip()


def digest(path):
    with Path(path).open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def atomic(path, value):
    path = Path(path)
    temporary = path.with_name('.'+path.name+'-'+uuid.uuid4().hex)
    with temporary.open('xb') as output:
        os.fchmod(output.fileno(), 0o600)
        output.write(value); output.flush(); os.fsync(output.fileno())
    os.replace(temporary, path)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def bootstrap(node, old, new):
    require(not BASE.exists() and not DATA.exists() and not CONFIG.exists(), 'Installation is not empty')
    run('useradd', '--system', '--home-dir', str(DATA), '--shell', '/usr/sbin/nologin', 'noisefence')
    account = pwd.getpwnam('noisefence')
    BASE.mkdir(); BASE.chmod(0o755)
    (BASE/'releases').mkdir(); (BASE/'releases').chmod(0o755)
    for version in [old, new]:
        source = Path('/root/releases') / ('noisefence-'+version+'-linux-'+os.environ['FIXTURE_ARCH'])
        subprocess.run(['sha256sum', '-c', 'SHA256SUMS'], cwd=source,
                       stdout=subprocess.DEVNULL, check=True)
        release = BASE/'releases'/version
        shutil.move(str(source), release)
        for path in [release, *release.rglob('*')]:
            os.chown(path, 0, 0)
            path.chmod(path.stat().st_mode & 0o755)
    (BASE/'current').symlink_to('releases/'+old)
    (BASE/'noisefence').symlink_to('current/noisefence')
    (BASE/'web').symlink_to('current/web')
    CONFIG.parent.mkdir(mode=0o750)
    shutil.copytree(Path('/root/fixture')/node/'data', DATA)
    for path in [DATA, *DATA.rglob('*')]:
        require(not path.is_symlink(), 'Synthetic data must not contain symlinks')
        os.chown(path, account.pw_uid, account.pw_gid)
    for name in ['config.toml', 'worker.key', 'replica.key']:
        target = CONFIG.parent/name
        shutil.copyfile(Path('/root/fixture')/node/name, target)
        target.chmod(0o640 if name == 'config.toml' else 0o600)
        os.chown(target, 0 if name == 'config.toml' else account.pw_uid, account.pw_gid)
    os.chown(CONFIG.parent, 0, account.pw_gid); CONFIG.parent.chmod(0o750)
    shutil.copyfile('/root/source/deploy/noisefence.service', '/etc/systemd/system/noisefence.service')
    destination = Path('/usr/local/libexec/noisefence-management')
    shutil.copytree('/root/source/deploy/postgresql', destination)
    for path in destination.glob('*.py'):
        path.chmod(0o755)
    Path('/var/lib/noisefence-hardening').mkdir(mode=0o700)
    PRIVATE.mkdir(mode=0o700)
    atomic(PRIVATE/'identity.json', json.dumps({'node': node, 'old': old, 'new': new}).encode())
    run('systemctl', 'daemon-reload')
    run('runuser', '-u', 'noisefence', '--', str(BASE/'noisefence'), '--config', str(CONFIG), 'check-config')
    return {'node': node, 'bootstrapped': True, 'machine': digest('/etc/machine-id'),
            'binary_sha256': {v: digest(BASE/'releases'/v/'noisefence') for v in (old, new)}}


def readiness(node, expected=None, seconds=90):
    port = 18080 if node == 'mx1' else 18081
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    until = time.monotonic()+seconds
    while time.monotonic() < until:
        try:
            with opener.open(f'http://127.0.0.1:{port}/healthz', timeout=2) as response:
                healthy = json.loads(response.read(4097))['smtp_ready'] is True
            pid = int(run('systemctl', 'show', 'noisefence.service', '--property=MainPID', '--value').strip())
            executable = Path(f'/proc/{pid}/exe').resolve()
            if healthy and (expected is None or executable == BASE/'releases'/expected/'noisefence'):
                return {'node': node, 'smtp_ready': True, 'binary_sha256': digest(executable),
                        'running_release': executable.parent.name}
        except Exception:
            pass
        time.sleep(.25)
    raise RuntimeError('Synthetic gateway readiness deadline exceeded')


def migration_setup(node, old, operation):
    binary = BASE/'releases'/old/'noisefence'
    cfg = {'run_id': operation, 'node_id': node, 'role': 'coordinator' if node == 'mx1' else 'worker',
           'user': 'noisefence', 'data': str(DATA), 'config': str(CONFIG),
           'root': '/var/lib/noisefence-migration', 'runtime': '/var/lib/noisefence-migration-runtime',
           'release_directory': str(binary.parent), 'binary_sha256': digest(binary),
           'current_link': str(BASE/'current'), 'expires_at': int(time.time())+1800,
           'lease_seconds': 900, 'health_url': f'http://127.0.0.1:{18080 if node == "mx1" else 18081}/healthz'}
    connection = {'host': '/run/postgresql', 'port': 5432, 'database': 'noisefence_test',
                  'username': 'noisefence', 'max_connections': 4}
    cfg['management'] = {'backend': 'postgresql', 'connection': connection} if node == 'mx1' else {'backend': 'coordinator'}
    folder = Path('/etc/noisefence-migration'); folder.mkdir(mode=0o700)
    atomic(folder/'agent.json', json.dumps(cfg).encode())
    if node == 'mx1':
        pguser = pwd.getpwnam('postgres')
        pgdata = Path('/var/lib/postgresql/paired-test'); pgdata.mkdir(mode=0o700)
        os.chown(pgdata, pguser.pw_uid, pguser.pw_gid)
        socket = Path('/run/postgresql'); socket.mkdir(mode=0o775, exist_ok=True)
        os.chown(socket, pguser.pw_uid, pguser.pw_gid); socket.chmod(0o775)
        run('runuser', '-u', 'postgres', '--', PG+'initdb', '-D', str(pgdata),
            '--auth-local=peer', '--auth-host=reject', '--no-instructions')
        run('runuser', '-u', 'postgres', '--', PG+'pg_ctl', '-D', str(pgdata),
            '-l', str(pgdata/'server.log'), '-o', "-k /run/postgresql -c listen_addresses=''", '-w', 'start')
        sql('CREATE ROLE noisefence LOGIN'); sql('CREATE DATABASE noisefence_test OWNER noisefence')
        run('ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(folder/'identity'))
        controller = {'run_id': operation, 'coordinator': 'mx1', 'user': 'noisefence',
                      'root': '/var/lib/noisefence-migration-controller',
                      'runtime': '/var/lib/noisefence-migration-coordinator', 'binary': str(binary),
                      'binary_sha256': digest(binary), 'database': connection,
                      'ssh_key': str(folder/'identity'), 'known_hosts': str(folder/'known_hosts'),
                      'nodes': {'mx1': {'ssh': None}, 'mx2': {'ssh': 'root@127.0.0.1'}},
                      'lease_seconds': 900}
        atomic(folder/'controller.json', json.dumps(controller).encode())
    else:
        ssh = Path('/root/.ssh'); ssh.mkdir(mode=0o700, exist_ok=True)
        key = (PRIVATE/'controller.pub').read_text().strip()
        atomic(ssh/'authorized_keys', ('restrict,command="/usr/local/libexec/noisefence-management/migration_agent.py" '+key+'\n').encode())
        # Only the synthetic key is accepted, on the namespace with no outside route.
        configuration = ('ListenAddress 127.0.0.1\nPort 22\nPasswordAuthentication no\n'
                         'KbdInteractiveAuthentication no\nPermitRootLogin forced-commands-only\n'
                         'UsePAM yes\nAllowUsers root\nDisableForwarding yes\n'
                         'HostKey /etc/ssh/ssh_host_ed25519_key\n')
        atomic(PRIVATE/'sshd_config', configuration.encode())
        unit = ('[Unit]\nDescription=Disposable paired migration SSH\n[Service]\n'
                'ExecStartPre=/usr/bin/mkdir -p /run/sshd\n'
                'ExecStart=/usr/sbin/sshd -D -e -f /root/paired-test/sshd_config\n')
        Path('/etc/systemd/system/paired-ssh.service').write_text(unit)
        run('systemctl', 'daemon-reload'); run('systemctl', 'start', 'paired-ssh.service')
    return {'node': node, 'migration_prepared': True}


def submit(node, label):
    require(re.fullmatch('[a-z0-9_-]{1,40}', label), 'Invalid synthetic label')
    message = (f'From: sender@example.test\r\nTo: alice@example.test\r\nSubject: Synthetic paired lifecycle {label}\r\n'
               f'Message-ID: <{uuid.uuid4()}@example.test>\r\n\r\nIsolated synthetic fixture. No external delivery.\r\n').encode()
    with smtplib.SMTP('127.0.0.1', 2525 if node == 'mx1' else 2527, timeout=20) as client:
        require(client.ehlo('fixture.example.test')[0] == 250, 'EHLO failed')
        require(client.mail('sender@example.test')[0] == 250, 'MAIL failed')
        require(client.rcpt('alice@example.test')[0] == 250, 'RCPT failed')
        code, reply = client.data(message)
    require(code == 250, 'Synthetic message not accepted')
    match = re.search(rb'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}', reply)
    require(match, 'Queue identity missing')
    ident = match[0].decode()
    return {'node': node, 'id': ident, 'label': label, 'body_sha256': digest(DATA/'spool'/(ident+'.eml'))}


def deferred(node):
    # A fresh DATA transaction must never be accepted without the mandatory peer.
    client = smtplib.SMTP(timeout=15)
    try:
        steps = [('connect', lambda: client.connect('127.0.0.1', 2525 if node == 'mx1' else 2527)),
                 ('ehlo', lambda: client.ehlo('fixture.example.test')),
                 ('mail', lambda: client.mail('sender@example.test')),
                 ('rcpt', lambda: client.rcpt('alice@example.test')),
                 ('data', lambda: client.data(b'From: sender@example.test\r\nTo: alice@example.test\r\nSubject: Mandatory peer unavailable\r\n\r\nSynthetic.\r\n'))]
        for phase, call in steps:
            try:
                code, _ = call()
            except smtplib.SMTPResponseException as error:
                code = error.smtp_code
            if 400 <= code < 500:
                return {'node': node, 'phase': phase, 'smtp_code': code, 'accepted': False}
            require(200 <= code < 300, 'Unexpected response during peer-outage test')
        raise RuntimeError('Message accepted without a mandatory replica')
    finally:
        client.close()


def inspect(node):
    with sqlite3.connect((DATA/'state.sqlite3').as_uri()+'?mode=ro', uri=True) as db:
        state = dict(db.execute("SELECT key,value FROM cluster_state WHERE key IN ('management_selection','ha_required','activation_participant')"))
        pending = db.execute('SELECT COUNT(*) FROM ha_local WHERE acked<generation').fetchone()[0]
        messages = db.execute('SELECT id FROM messages WHERE is_dsn=0').fetchall()
        receipts = {ident: {'generation': generation, 'acked': acked} for ident, generation, acked in db.execute('SELECT message_id,generation,acked FROM ha_local')}
        remote = {ident: {'owner': owner, 'generation': generation, 'body_sha256': sha, 'body_present': present == 1} for owner, ident, generation, sha, present in db.execute('SELECT owner,id,generation,body_hash,body_present FROM ha_remote')}
        deliveries = [dict(zip(['message_id','address','destination','status','attempts'], row)) for row in db.execute('SELECT message_id,address,destination,status,attempts FROM deliveries ORDER BY id')]
    return {'node': node, 'config_sha256': digest(CONFIG),
            'selection': json.loads(state['management_selection']) if 'management_selection' in state else None,
            'policy_epoch': json.loads(state['activation_participant'])['installed_epoch'],
            'policy_digest': json.loads(state['activation_participant'])['installed']['digest'],
            'replication_required': state.get('ha_required') == '1', 'pending_replica_updates': pending,
            'message_ids': [ident for (ident,) in messages],
            'replication_receipts': receipts, 'remote_receipts': remote, 'deliveries': deliveries,
            'bodies': {path.stem: digest(path) for path in (DATA/'spool').glob('*.eml')},
            'replicas': {path.stem: digest(path) for path in (DATA/'replicas').glob('*/*.eml')}}


def policy_status():
    raw = sql("SELECT coalesce(jsonb_agg(jsonb_build_object('node',node,'seen',seen,'build',build,'revision',revision,'digest',digest)),'[]'::jsonb) FROM noisefence.policy_peers", 'noisefence_test', 'noisefence')
    return json.loads(raw)


def switch(version):
    # Deliberately a laboratory operation, not a production updater or rollback guard.
    identity = json.loads((PRIVATE/'identity.json').read_text())
    require(version in (identity['old'], identity['new']), 'Unapproved test version')
    require((BASE/'releases'/version/'noisefence').is_file(), 'Missing staged test archive')
    run('systemctl', 'stop', 'noisefence.service')
    temporary = BASE/'.paired-next'; temporary.symlink_to('releases/'+version)
    os.replace(temporary, BASE/'current')
    state = run('systemctl', 'show', 'noisefence.service', '--property=ActiveState', '--value').strip()
    if state == b'failed':
        run('systemctl', 'reset-failed', 'noisefence.service')
    return {'staged_pointer': version}


def main():
    require(os.geteuid() == 0 and Path('/.dockerenv').exists()
            and os.environ.get('NOISEFENCE_DISPOSABLE_PAIRED_TEST') == '1'
            and Path('/run/systemd/container').read_text().strip() == 'docker', 'Disposable container required')
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['bootstrap', 'migration', 'ready', 'submit', 'inspect', 'switch', 'policy', 'deferred'])
    parser.add_argument('--node', choices=['mx1', 'mx2'], required=True)
    parser.add_argument('--old', required=True); parser.add_argument('--new', required=True)
    parser.add_argument('--value')
    args = parser.parse_args()
    require(all(re.fullmatch(r'\d+\.\d+\.\d+', v) for v in [args.old, args.new]), 'Invalid archive versions')
    if args.action == 'bootstrap': result = bootstrap(args.node, args.old, args.new)
    elif args.action == 'migration': result = migration_setup(args.node, args.old, args.value)
    elif args.action == 'ready': result = readiness(args.node, args.value)
    elif args.action == 'submit': result = submit(args.node, args.value)
    elif args.action == 'inspect': result = inspect(args.node)
    elif args.action == 'deferred': result = deferred(args.node)
    elif args.action == 'policy':
        require(args.node == 'mx1', 'Policy snapshot requires the synthetic coordinator')
        result = policy_status()
    else: result = switch(args.value)
    print(json.dumps(result))


if __name__ == '__main__':
    main()
