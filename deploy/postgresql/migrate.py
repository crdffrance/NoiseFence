#!/usr/bin/python3
"""Coordinate frozen original MXs, local PostgreSQL activation and service recovery.

Run on the PostgreSQL coordinator only, with root-owned installation JSON. This
program never accepts message bodies, arbitrary remote commands or remote paths.
"""
import argparse
import concurrent.futures
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import signal
import socket
import stat
import subprocess
import sys
import threading
import time
from migration_protocol import AGENT, COMMIT, Channel, atomic, canonical, checked_selection, identity, private_read, require, sha
from migration_snapshot import management_config, receive_export, remap_config

AGENT_PATH = '/usr/local/libexec/noisefence-management/migration_agent.py'


def read_config(path):
    info = path.lstat()
    require(info.st_uid == 0 and not info.st_mode & 0o022, 'Coordinator configuration must be root protected')
    with private_read(path, 65536) as source:
        cfg = json.load(source)
    required = {'run_id', 'coordinator', 'user', 'root', 'runtime', 'binary', 'binary_sha256', 'database',
                'ssh_key', 'known_hosts', 'nodes', 'lease_seconds'}
    require(isinstance(cfg, dict) and set(cfg) == required and identity(cfg['run_id']), 'Invalid migration coordinator configuration')
    require(isinstance(cfg['nodes'], dict) and 2 <= len(cfg['nodes']) <= 64 and cfg['coordinator'] in cfg['nodes'],
            'Migration requires the complete MX source set')
    require(type(cfg['lease_seconds']) is int and 30 <= cfg['lease_seconds'] <= 1800, 'Invalid coordinator deadline')
    require(re.fullmatch('[a-z_][a-z0-9_-]{0,31}', cfg['user']), 'Invalid installation account')
    for name, node in cfg['nodes'].items():
        require(re.fullmatch('[a-z0-9_-]{1,40}', name) and isinstance(node, dict) and set(node) == {'ssh'}, 'Invalid source identity')
        if name == cfg['coordinator']:
            require(node['ssh'] is None, 'Coordinator agent must execute locally')
        else:
            require(isinstance(node['ssh'], str) and re.fullmatch('[a-z_][a-z0-9_-]{0,31}@[A-Za-z0-9.-]+', node['ssh']),
                    'Invalid remote source address')
    for key in ('root', 'runtime', 'binary', 'ssh_key', 'known_hosts'):
        require(isinstance(cfg[key], str) and re.fullmatch('/[A-Za-z0-9_./-]+', cfg[key])
                and '..' not in Path(cfg[key]).parts, 'Invalid migration coordinator path')
    # Same bounded local peer profile as the installed coordinator configuration.
    management_config(b'hostname="fixture"\n', {'backend': 'postgresql', 'connection': cfg['database']})
    require(cfg['database']['username'] == cfg['user'], 'Peer authentication must use the installation account')
    with private_read(cfg['binary'], 512 * 1024**2) as source:
        require(hashlib.file_digest(source, 'sha256').hexdigest() == cfg['binary_sha256'], 'Coordinator binary checksum mismatch')
    require(Path(cfg['binary']).stat().st_uid == 0, 'Migration executable must belong to root')
    with private_read(cfg['ssh_key'], 16384) as key:
        info = os.fstat(key.fileno())
        require(info.st_uid == 0 and not info.st_mode & 0o077, 'Dedicated migration key must be private to root')
    with private_read(cfg['known_hosts'], 65536) as hosts:
        require(os.fstat(hosts.fileno()).st_uid == 0, 'Known hosts must be root protected')
    return cfg


class Peer:
    def __init__(self, cfg, name, folder, deadline):
        self.name, self.run_id, self.sequence = name, cfg['run_id'], 0
        remote = cfg['nodes'][name]['ssh']
        args = [AGENT_PATH] if remote is None else [
            '/usr/bin/ssh', '-T', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10',
            '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=3', '-o', 'IdentitiesOnly=yes',
            '-o', 'IdentityAgent=none', '-o', 'StrictHostKeyChecking=yes',
            '-o', 'UserKnownHostsFile=' + cfg['known_hosts'], '-i', cfg['ssh_key'], remote, 'noisefence-migrate']
        self.log = (folder / (name + '-agent.log')).open('ab')
        self.process = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.log, start_new_session=True)
        self.channel = Channel(self.process.stdout.fileno(), self.process.stdin.fileno(), deadline)
        try:
            hello = self.channel.receive()
            require(hello.get('protocol') == AGENT and hello.get('node_id') == name
                    and hello.get('run_id') == self.run_id, 'Unexpected migration agent identity')
            self.initial = hello['state']
        except BaseException:
            self.close()
            raise

    def command(self, operation, **arguments):
        self.sequence += 1
        self.channel.send({'protocol': AGENT, 'run_id': self.run_id, 'sequence': self.sequence,
                           'operation': operation, 'arguments': arguments})
        response = self.channel.receive()
        require(response.get('protocol') == AGENT and response.get('run_id') == self.run_id
                and response.get('sequence') == self.sequence and isinstance(response.get('result'), dict),
                'Invalid agent response')
        return response['result']

    def close(self):
        if self.process.poll() is None:
            self.process.stdin.close()
            try:
                self.process.wait(timeout=12)
            except subprocess.TimeoutExpired:
                os.killpg(self.process.pid, signal.SIGTERM)
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(self.process.pid, signal.SIGKILL)
                    self.process.wait(timeout=5)
        self.process.stdout.close()
        if not self.process.stdin.closed:
            self.process.stdin.close()
        self.log.close()


class Coordinator:
    def __init__(self, cfg):
        self.cfg = cfg
        self.account = pwd.getpwnam(cfg['user'])
        self.root = Path(cfg['root']) / cfg['run_id']
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = self.root.lstat()
        require(self.root.resolve() == self.root and info.st_uid == 0 and not info.st_mode & 0o077, 'Unsafe coordinator state directory')
        self.runtime = Path(cfg['runtime'])
        if not self.runtime.exists():
            self.runtime.mkdir(mode=0o700)
            os.chown(self.runtime, self.account.pw_uid, self.account.pw_gid)
        info = self.runtime.lstat()
        require(self.runtime.resolve() == self.runtime and info.st_uid == self.account.pw_uid and not info.st_mode & 0o077,
                'Unsafe coordinator runtime directory')
        self.file = self.root / 'state.json'
        self.state = json.loads(self.file.read_bytes()) if self.file.exists() else {'phase': 'new', 'configuration': hashlib.sha256(canonical(cfg)).hexdigest()}
        require(self.state['configuration'] == hashlib.sha256(canonical(cfg)).hexdigest(), 'Coordinator plan changed during recovery')
        self.deadline = time.monotonic() + cfg['lease_seconds']
        self.peers = {}

    def save(self, **changes):
        self.state.update(changes)
        atomic(self.file, canonical(self.state))
        print(json.dumps({'phase': self.state['phase']}), flush=True)

    def open_peers(self):
        for name in self.cfg['nodes']:
            self.peers[name] = Peer(self.cfg, name, self.root, self.deadline)

    def program(self, args, output, timeout=900):
        timeout = min(timeout, self.deadline - time.monotonic())
        require(timeout > 0, 'Migration deadline expired')
        command = ['/usr/sbin/runuser', '-u', self.cfg['user'], '--', '/usr/bin/env', '-i', 'PATH=/usr/bin:/bin',
                   'LC_ALL=C', self.cfg['binary'], *args]
        # A separate process group bounds runuser AND the native child.
        with output.open('wb') as stdout, (self.root / 'native-errors.log').open('ab') as stderr:
            process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, start_new_session=True)
            try:
                code = process.wait(timeout=timeout)
            except BaseException:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=5)
                raise
        require(code == 0, 'Native migration command failed; inspect the protected native-errors.log')
        with private_read(output, 1024 * 1024) as source:
            result = json.load(source)
        require(isinstance(result, dict), 'Native migration result is not an object')
        return result

    def bound_args(self, command):
        binding = self.state['binding']
        return [command, '--plan', self.state['plan'], '--instance', binding['instance'], '--source-digest', binding['source_digest']]

    def status(self):
        return self.program(self.bound_args('management-status'), self.root / 'status.json', 20)

    def recover_staging(self):
        # A completed native receipt may survive a lost controller save. Never
        # infer success from an empty destination or restart an ambiguous import.
        require(self.state['phase'] == 'importing' and 'binding' not in self.state,
                'Unexpected staging recovery state')
        with private_read(self.root / 'staged.json', 1024 * 1024) as source:
            staged = json.load(source)
        binding = staged.get('database', {})
        require(isinstance(binding, dict) and set(binding) == {'instance', 'source_digest'}
                and identity(binding['instance']) and sha(binding['source_digest']), 'Missing complete staging receipt')
        arguments = ['--plan', self.state['plan'], '--instance', binding['instance'], '--source-digest', binding['source_digest']]
        receipt = self.program(['management-status', *arguments], self.root / 'status.json', 20)
        require(receipt.get('database') == binding and receipt.get('phase') == 'copied_not_activated',
                'Interrupted staging has no matching completed inactive database')
        self.program(['management-verify-sources', *arguments], self.root / 'verified.json')
        self.save(phase='imported', binding=binding)

    def collect(self):
        attempt = self.runtime / ('import-' + os.urandom(12).hex())
        attempt.mkdir(mode=0o700)
        os.chown(attempt, self.account.pw_uid, self.account.pw_gid)
        self.save(phase='freezing', attempt=str(attempt))
        self.ready = {}
        for name, peer in self.peers.items():
            ready = peer.command('freeze', preserve_generations='binding' in self.state)
            require(ready.get('receipt', {}).get('journal', {}).get('identity', {}).get('node') == name, 'Frozen source identity differs')
            self.ready[name] = ready
        self.save(phase='exporting', sources=self.ready)
        directories = {}
        for name, peer in self.peers.items():
            response = peer.command('export')
            directory = attempt / name
            require(shutil.disk_usage(attempt).free > sum(i['bytes'] for i in response['manifest'].values()) + 2 * 1024**3,
                    'Insufficient coordinator export reserve')
            receive_export(peer.channel, directory, response['manifest'], self.ready[name])
            remap_config(directory)
            for path in [directory, *directory.rglob('*')]:
                require(not path.is_symlink(), 'Unexpected link in verified export')
                os.chown(path, self.account.pw_uid, self.account.pw_gid)
            directories[name] = directory
        text = '[database]\n' + ''.join(key + ' = ' + json.dumps(value) + '\n' for key, value in self.cfg['database'].items())
        for name, directory in directories.items():
            text += '\n[[sources]]\nnode_id=' + json.dumps(name) + '\nrole=' + json.dumps('coordinator' if name == self.cfg['coordinator'] else 'worker')
            text += '\ndata_dir=' + json.dumps(str(directory)) + '\nconfig=' + json.dumps(str(directory / 'config.toml')) + '\n'
        plan = attempt / 'import.toml'
        atomic(plan, text.encode(), uid=self.account.pw_uid, gid=self.account.pw_gid)
        self.save(phase='copied', plan=str(plan))

    def activate(self):
        if 'binding' not in self.state:
            self.save(phase='importing')
            staged = self.program(['management-stage', '--preserve-source-generations', '--plan', self.state['plan']], self.root / 'staged.json')
            self.save(phase='imported', binding=staged['database'])
        self.program(self.bound_args('management-verify-sources'), self.root / 'verified.json')
        proposals = self.program(self.bound_args('management-prepare-selections'), self.root / 'prepared.json')['selections']
        require({s['node']['node'] for s in proposals} == set(self.peers), 'Import does not include every source')
        for selected in proposals:
            checked_selection(selected)
            require(selected['database'] == self.state['binding'] and selected['node'] == self.ready[selected['node']['node']]['receipt']['journal']['identity'],
                    'Import proposal differs from frozen originals')
        # Persist all intended selections before any original may be changed.
        self.save(phase='selecting', proposals=proposals)
        path = Path(self.state['attempt']) / 'commit.sock'
        listener = socket.socket(socket.AF_UNIX)
        listener.bind(str(path))
        os.chmod(path, 0o600)
        os.chown(path, self.account.pw_uid, self.account.pw_gid)
        listener.listen(1)
        listener.settimeout(min(120, self.deadline - time.monotonic()))
        errors = []
        def barrier():
            try:
                stream, _ = listener.accept()
                with stream:
                    channel = Channel(stream.fileno(), stream.fileno(), min(self.deadline, time.monotonic() + 90))
                    request = channel.receive()
                    require(set(request) == {'protocol', 'request', 'database', 'authority', 'selections'}
                            and request['protocol'] == COMMIT and identity(request['request']) and request['database'] == self.state['binding']
                            and request['selections'] == proposals, 'Activation barrier differs from prepared import')
                    for peer in self.peers.values():
                        peer.channel.deadline = min(peer.channel.deadline, channel.deadline)
                    for peer in self.peers.values():
                        peer.command('native', command={'action': 'check'})
                    receipts = []
                    for selected in proposals:
                        node = selected['node']['node']
                        receipt = self.ready[node]['receipt']
                        response = self.peers[node].command('native', command={'action': 'select', 'authority': request['authority'],
                            'selection': selected, 'export_sha256': receipt['sha256'], 'source_sequence': receipt['journal']['sequence']})
                        require(response.get('state') == 'selected' and response.get('selection') == selected, 'Original source did not acknowledge selection')
                        receipts.append(response['selection'])
                        atomic(self.root / (node + '-selected.json'), canonical(response['selection']))
                    channel.send({'protocol': COMMIT, 'request': request['request'], 'database': self.state['binding'], 'selections': receipts})
            except BaseException as error:
                errors.append(error)
        thread = threading.Thread(target=barrier, daemon=True)
        thread.start()
        try:
            self.program([*self.bound_args('management-activate'), '--commit-socket', str(path)], self.root / 'activation.json', 180)
        finally:
            listener.close()
            thread.join(timeout=130)
            require(not thread.is_alive(), 'Activation supervisor has not terminated')
            path.unlink(missing_ok=True)
        if errors:
            raise RuntimeError('Source selection barrier failed') from errors[0]
        for peer in self.peers.values():
            peer.channel.deadline = self.deadline
        receipt = self.status()
        require(receipt.get('phase') == 'active', 'PostgreSQL activation is not committed')
        self.save(phase='activated', activation=receipt)

    def finish(self):
        receipt = self.status()
        require(receipt.get('phase') == 'active' and receipt.get('database') == self.state['binding'], 'Cannot finish an inactive migration')
        require({s['node']['node'] for s in receipt['selections']} == set(self.peers), 'Active receipt source set differs')
        for name, peer in self.peers.items():
            inspected = peer.command('inspect')
            expected = next(s for s in receipt['selections'] if s['node']['node'] == name)
            require(inspected.get('selection') == expected, 'Original source selection differs from active receipt')
            if inspected['phase'] == 'complete':
                continue
            if inspected['phase'] not in ('configured', 'released', 'started'):
                peer.command('publish', receipt=receipt)
        # During uninterrupted cutover the original sessions are still held.
        for name, peer in self.peers.items():
            if hasattr(self, 'ready') and name in self.ready:
                peer.command('native', command={'action': 'release'})
        self.save(phase='starting', activation=receipt)
        def start(item):
            _, peer = item
            if peer.command('inspect')['phase'] != 'complete':
                peer.command('start')
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(16, len(self.peers))) as pool:
            list(pool.map(start, self.peers.items()))
        until = min(self.deadline, time.monotonic() + 180)
        while True:
            health = {name: peer.command('health') for name, peer in self.peers.items()}
            if all(v.get('smtp_ready') is True and v.get('service') == 'active' for v in health.values()):
                break
            require(time.monotonic() < until, 'MX readiness deadline exceeded; no legacy rollback is permitted')
            time.sleep(3)
        for peer in self.peers.values():
            if peer.command('inspect')['phase'] != 'complete':
                peer.command('complete')
        self.save(phase='complete', health=health)

    def run(self, cancel=False):
        self.open_peers()
        if cancel:
            inspections = {name: p.command('inspect') for name, p in self.peers.items()}
            require(all(i['selection'] is None for i in inspections.values()), 'At least one source is selected; only forward recovery is allowed')
            if 'binding' in self.state:
                require(self.status()['phase'] != 'active', 'PostgreSQL is active; cannot cancel')
            for peer in self.peers.values():
                peer.command('cancel')
            self.save(phase='cancelled')
            return
        if self.state['phase'] == 'importing' and 'binding' not in self.state:
            self.recover_staging()
        if 'binding' in self.state and self.status()['phase'] == 'active':
            self.finish()
            return
        require(self.state['phase'] not in ('importing', 'cancelled', 'complete'),
                'An interrupted import or completed run needs explicit operator review, not automatic reimport')
        self.collect()
        self.activate()
        self.finish()

    def close(self):
        for peer in self.peers.values():
            peer.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--cancel-before-selection', action='store_true')
    args = parser.parse_args()
    require(os.geteuid() == 0, 'Run the migration coordinator as root')
    os.umask(0o077)
    cfg = read_config(args.config)
    with open('/run/noisefence-management-controller.lock', 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        coordinator = Coordinator(cfg)
        try:
            coordinator.run(args.cancel_before_selection)
        finally:
            coordinator.close()


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print('Migration coordinator stopped: ' + type(error).__name__ + ': ' + str(error)[:300], file=sys.stderr)
        sys.exit(1)
