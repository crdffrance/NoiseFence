#!/usr/bin/env python3
"""Transactional Debian MX network hardening, with a mandatory rollback deadline."""
import argparse
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import sys
import time
import uuid

STATE = Path('/var/lib/noisefence-hardening')
SELF = Path('/usr/local/libexec/noisefence-network')
TABLE = 'noisefence_host'
UNIT = 'noisefence-firewall.service'


def run(*args, check=True, **kwargs):
    return subprocess.run(args, check=check, capture_output=True, text=True, timeout=30, **kwargs)


def firewall(uid):
    if type(uid) is not int or uid <= 0:
        raise ValueError('A non-root NoiseFence UID is required')
    # This owns only one named table. Never flush another firewall/EDR's rules.
    return f'''# Managed by NoiseFence; changes are applied atomically.
add table inet {TABLE}
flush table inet {TABLE}
table inet {TABLE} {{
  chain input {{
    type filter hook input priority 10; policy drop;
    iifname "lo" accept
    ct state established,related accept
    ct state invalid drop
    meta l4proto {{ icmp, ipv6-icmp }} accept
    udp sport 67 udp dport 68 accept
    ip6 saddr fe80::/10 udp sport 547 udp dport 546 accept
    tcp dport {{ 22, 25, 80, 443 }} accept
    limit rate 4/minute burst 8 packets log prefix "noisefence-input-drop "
    counter drop
  }}
  chain output {{
    type filter hook output priority 10; policy accept;
    oifname "lo" accept
    ct state established,related accept
    meta skuid {uid} ip daddr {{ 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 198.18.0.0/15, 224.0.0.0/4, 240.0.0.0/4 }} counter reject
    meta skuid {uid} ip6 daddr {{ fc00::/7, fe80::/10, ff00::/8 }} counter reject
  }}
}}
'''


def desired_files(admins, uid):
    if not admins or len(set(admins)) != len(admins) or any(not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', n) for n in admins):
        raise ValueError('Explicit, unique Unix account names required')
    return {
        '/etc/ssh/sshd_config.d/00-noisefence-hardening.conf': '''# Managed by NoiseFence
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
PermitRootLogin no
PermitEmptyPasswords no
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
AllowStreamLocalForwarding no
PermitTunnel no
GatewayPorts no
MaxAuthTries 3
MaxStartups 10:30:60
LoginGraceTime 30
LogLevel VERBOSE
AllowUsers ''' + ' '.join(admins) + '\n',
        '/etc/noisefence-hardening/firewall.nft': firewall(uid),
        '/etc/systemd/system/' + UNIT: '''[Unit]
Description=NoiseFence host firewall (IPv4 and IPv6)
Before=network-pre.target
Wants=network-pre.target
After=local-fs.target
[Service]
Type=oneshot
ExecStart=/usr/sbin/nft -f /etc/noisefence-hardening/firewall.nft
ExecReload=/usr/sbin/nft -f /etc/noisefence-hardening/firewall.nft
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
''',
        '/etc/systemd/resolved.conf.d/90-noisefence.conf': '[Resolve]\nLLMNR=no\nMulticastDNS=no\n',
        '/etc/sysctl.d/90-noisefence.conf': '''# Do not alter BPF, IPv6 RA, forwarding or strict reverse-path checks.
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 1
kernel.dmesg_restrict = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
''',
        '/etc/systemd/journald.conf.d/90-noisefence.conf': '''[Journal]
Storage=persistent
SystemMaxUse=256M
SystemKeepFree=1G
RuntimeMaxUse=32M
MaxRetentionSec=30day
Compress=yes
''',
        '/etc/systemd/coredump.conf.d/90-noisefence.conf': '[Coredump]\nStorage=none\nProcessSizeMax=0\n',
    }


def atomic(path, data, mode=0o644, uid=0, gid=0):
    path = Path(path)
    if path.is_symlink():
        raise ValueError('Refusing a symlink: ' + str(path))
    missing = []
    parent = path.parent
    while not parent.exists():
        missing.append(parent)
        parent = parent.parent
    path.parent.mkdir(parents=True, exist_ok=True)
    # Service configuration directories must be traversable by unprivileged
    # daemons even though the installer's private state uses umask 0077.
    for parent in missing:
        parent.chmod(0o755)
    pending = path.with_name(path.name + '.nf-' + uuid.uuid4().hex)
    with pending.open('xb') as f:
        os.fchmod(f.fileno(), mode)
        os.fchown(f.fileno(), uid, gid)
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    pending.replace(path)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def save(state):
    atomic(STATE / (state['id'] + '.json'), (json.dumps(state, indent=2) + '\n').encode(), 0o600)


def transaction_states():
    return [json.loads(path.read_text()) for path in STATE.glob('*.json')
            if re.fullmatch(r'[a-f0-9]{32}', path.stem)]


def read_state(transaction):
    if not re.fullmatch(r'[0-9a-f]{32}', transaction):
        raise ValueError('Invalid transaction')
    return json.loads((STATE / (transaction + '.json')).read_text())


def refresh_network(state, restore=False):
    run('/usr/sbin/sshd', '-t')
    run('systemctl', 'daemon-reload')
    run('systemctl', 'reload', 'ssh')
    run('systemctl', 'restart', 'systemd-resolved')
    for link in state['links']:
        run('resolvectl', 'llmnr', link, state['links'][link] if restore else 'no', check=False)
    run('systemctl', 'restart', 'systemd-journald')


def rollback(transaction):
    state = read_state(transaction)
    if state['status'] != 'pending':
        return {'id': transaction, 'status': state['status']}
    # Firewall first restores new-connection access even if another service fails.
    run('/usr/sbin/nft', 'delete', 'table', 'inet', TABLE, check=False)
    if state['firewall_before']:
        run('/usr/sbin/nft', '-f', '-', input=state['firewall_before'])
    for name, before in state['files'].items():
        if before is None:
            Path(name).unlink(missing_ok=True)
        else:
            atomic(name, base64.b64decode(before['data']), before['mode'], before['uid'], before['gid'])
    for key, value in state['sysctls'].items():
        run('sysctl', '-q', '-w', key + '=' + value)
    if not state['firewall_was_enabled']:
        run('systemctl', 'disable', UNIT, check=False)
    if not state['firewall_was_active']:
        run('systemctl', 'stop', UNIT, check=False)
    refresh_network(state, restore=True)
    state['status'] = 'rolled_back'
    state['resolved_at'] = int(time.time())
    save(state)
    return {'id': transaction, 'status': state['status']}


def apply(admins, seconds):
    if not 180 <= seconds <= 1800:
        raise ValueError('Rollback deadline must be 180..1800 seconds')
    for old in transaction_states():
        if old.get('status') == 'pending':
            raise ValueError('Resolve existing transaction first')
    for name in admins:
        pwd.getpwnam(name)
    files = desired_files(admins, pwd.getpwnam('noisefence').pw_uid)
    state = {'id': uuid.uuid4().hex, 'status': 'pending', 'created': int(time.time()),
             'deadline': int(time.time()) + seconds, 'files': {}, 'sysctls': {}, 'links': {}, 'admins': admins}
    for name in files:
        path = Path(name)
        if path.is_symlink():
            raise ValueError('Refusing a managed-path symlink')
        if path.exists():
            s = path.stat()
            if not stat.S_ISREG(s.st_mode):
                raise ValueError('Expected regular file')
            state['files'][name] = {'data': base64.b64encode(path.read_bytes()).decode(), 'mode': s.st_mode & 0o777, 'uid': s.st_uid, 'gid': s.st_gid}
        else:
            state['files'][name] = None
    for line in files['/etc/sysctl.d/90-noisefence.conf'].splitlines():
        if '=' in line:
            key = line.split('=', 1)[0].strip()
            state['sysctls'][key] = run('sysctl', '-n', key).stdout.strip()
    for entry in json.loads(run('ip', '-j', 'link').stdout):
        link = entry['ifname']
        if link != 'lo':
            output = run('resolvectl', 'llmnr', link, check=False).stdout
            state['links'][link] = 'no' if output.rstrip().endswith('no') else 'yes'
            # Some IPv4 options combine the all/ and per-interface values.
            if re.fullmatch(r'[a-zA-Z0-9_-]{1,32}', link):
                for protocol, option in [('ipv4', 'accept_redirects'), ('ipv4', 'send_redirects'), ('ipv6', 'accept_redirects')]:
                    key = 'net.' + protocol + '.conf.' + link + '.' + option
                    previous = run('sysctl', '-n', key, check=False)
                    if previous.returncode == 0:
                        state['sysctls'][key] = previous.stdout.strip()
                        files['/etc/sysctl.d/90-noisefence.conf'] += key + ' = 0\n'
    old = run('/usr/sbin/nft', 'list', 'table', 'inet', TABLE, check=False)
    state['firewall_before'] = old.stdout if old.returncode == 0 else None
    state['firewall_was_enabled'] = run('systemctl', 'is-enabled', UNIT, check=False).returncode == 0
    state['firewall_was_active'] = run('systemctl', 'is-active', UNIT, check=False).returncode == 0
    save(state)
    unit = 'noisefence-network-rollback-' + state['id']
    run('systemd-run', '--unit=' + unit, '--on-active=' + str(seconds) + 's',
        '--timer-property=AccuracySec=1s', '--property=TimeoutStartSec=120',
        str(SELF), 'rollback', '--id', state['id'])
    try:
        for name, content in files.items():
            atomic(name, content.encode())
        run('/usr/sbin/sshd', '-t')
        for admin in admins:
            settings = run('/usr/sbin/sshd', '-T', '-C', 'user=' + admin + ',host=probe.invalid,addr=192.0.2.1').stdout
            for required in ['passwordauthentication no', 'permitrootlogin no', 'pubkeyauthentication yes']:
                if required not in settings.splitlines():
                    raise ValueError('An earlier SSH setting overrides the policy: ' + required)
        run('/usr/sbin/nft', '-c', '-f', '/etc/noisefence-hardening/firewall.nft')
        run('/usr/sbin/nft', '-f', '/etc/noisefence-hardening/firewall.nft')
        run('sysctl', '-q', '-p', '/etc/sysctl.d/90-noisefence.conf')
        refresh_network(state)
        run('systemctl', 'enable', '--now', UNIT)
    except BaseException:
        rollback(state['id'])
        raise
    state['applied_hashes'] = {name: hashlib.sha256(Path(name).read_bytes()).hexdigest() for name in files}
    save(state)
    return {'id': state['id'], 'status': 'pending', 'deadline': state['deadline'], 'rollback_timer': unit + '.timer'}


def commit(transaction):
    state = read_state(transaction)
    if state['status'] != 'pending' or int(time.time()) >= state['deadline'] - 10:
        raise ValueError('Transaction not pending or too close to rollback deadline')
    for name, digest in state['applied_hashes'].items():
        if hashlib.sha256(Path(name).read_bytes()).hexdigest() != digest:
            raise ValueError('Managed file changed before commit: ' + name)
    # Invoke only after independent fresh SSH/SMTP/HTTPS/DNS probes succeed.
    state['status'] = 'committed'
    state['resolved_at'] = int(time.time())
    save(state)
    run('systemctl', 'stop', 'noisefence-network-rollback-' + transaction + '.timer')
    return {'id': transaction, 'status': 'committed'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['apply', 'commit', 'rollback', 'status'])
    parser.add_argument('--admin', action='append', default=[])
    parser.add_argument('--timeout', type=int, default=600)
    parser.add_argument('--id')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('root required')
    os.umask(0o077)
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    with (STATE / 'lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if args.action == 'apply':
            result = apply(args.admin, args.timeout)
        elif args.action == 'commit':
            result = commit(args.id)
        elif args.action == 'rollback':
            result = rollback(args.id)
        else:
            result = [{k: s[k] for k in ['id', 'status', 'created', 'deadline']} for s in transaction_states()]
        print(json.dumps(result))


if __name__ == '__main__':
    main()
