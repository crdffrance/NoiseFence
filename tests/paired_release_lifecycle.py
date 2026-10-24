#!/usr/bin/env python3
"""Exercise published archive pairs on two disposable Linux installations.

No production host, volume or credential is accepted. Both containers use a shared
loopback-only network namespace with no outside route. This tests installed runtime
compatibility, not a production deployment controller or detection accuracy.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile
import time
import uuid

SOURCE = Path(__file__).resolve().parents[1]


def digest(path):
    with Path(path).open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def archive(path, architecture):
    match = re.fullmatch(r'noisefence-(\d+\.\d+\.\d+)-linux-(amd64|arm64)\.tar\.gz', path.name)
    if not match or match[2] != architecture:
        raise ValueError('Release archive name/platform mismatch')
    expected = Path(str(path)+'.sha256').read_text().split()[0]
    actual = digest(path)
    if not re.fullmatch('[0-9a-f]{64}', expected) or actual != expected:
        raise ValueError('Archive checksum mismatch')
    top = path.name.removesuffix('.tar.gz')
    with tarfile.open(path) as source:
        total = 0; seen = set()
        for member in source:
            name = PurePosixPath(member.name)
            if (name.is_absolute() or '..' in name.parts or not name.parts or name.parts[0] != top
                    or str(name) in seen or not (member.isdir() or member.isfile())):
                raise ValueError('Unsafe or duplicated archive member')
            seen.add(str(name)); total += member.size
            if len(seen) > 30000 or total > 2*1024**3:
                raise ValueError('Archive exceeds fixture bounds')
        build_source = source.extractfile(top+'/build.json')
        raw = build_source.read(1048577)
        if len(raw) > 1048576:
            raise ValueError('Release metadata exceeds bounds')
        build = json.loads(raw)
    if (build.get('project') != 'NoiseFence' or build.get('version') != match[1]
            or build.get('platform') != 'linux-'+architecture
            or not re.fullmatch('[a-f0-9]{40}', build.get('commit', ''))
            or type(build.get('storage_schema')) is not int or build['storage_schema'] != 7):
        raise ValueError('Release build metadata mismatch')
    return {'path': path.resolve(), 'version': match[1], 'top': top,
            'sha256': actual, 'commit': build['commit']}


def policy_is_fresh(peers, expected_build, since, digest, now):
    return any(p.get('node') == 'mx2' and p.get('build') == expected_build
               and type(p.get('seen')) is int and since < p['seen'] <= now
               and p.get('digest') == digest for p in peers)


class Lab:
    def __init__(self, args, old, new):
        self.args, self.old, self.new = args, old, new
        self.root = args.output.resolve()
        self.root.mkdir(mode=0o700, parents=True, exist_ok=False)
        self.operation = str(uuid.uuid4())
        self.names = {node: 'nf-paired-'+self.operation[:8]+'-'+node for node in ('mx1', 'mx2')}
        self.created = []; self.checks = []; self.accepted = []
        self.binary_hashes = {}
        self.started = time.monotonic()
        (self.root/'operation.json').write_text(json.dumps({'operation': self.operation, 'containers': self.names, 'synthetic_only': True})+'\n')

    def run(self, *args, timeout=90):
        try:
            return subprocess.check_output(['docker', *args], stderr=subprocess.STDOUT, timeout=timeout)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
            with (self.root/'failure-command.log').open('ab') as output:
                output.write((error.output or b'')[-131072:])
            raise

    def command(self, node, *args, timeout=90):
        return self.run('exec', self.names[node], *args, timeout=timeout)

    def node(self, node, action, value=None, timeout=120):
        args = ['python3', '/root/source/tests/fixtures/paired_node.py', action,
                '--node', node, '--old', self.old['version'], '--new', self.new['version']]
        if value is not None:
            args += ['--value', value]
        return json.loads(self.command(node, *args, timeout=timeout))

    def ready(self, node, version):
        result = self.node(node, 'ready', version)
        if (result['running_release'] != version
                or result['binary_sha256'] != self.binary_hashes[node][version]):
            raise RuntimeError('Running executable differs from verified staged archive')
        return result

    def record(self, check, **details):
        row = {'check': check, 'elapsed_seconds': round(time.monotonic()-self.started, 3), **details}
        self.checks.append(row)
        with (self.root/'events.jsonl').open('a') as output:
            output.write(json.dumps(row)+'\n'); output.flush(); os.fsync(output.fileno())
        print(json.dumps(row), flush=True)

    def start(self):
        machines = []
        for node in self.names:
            network = 'none' if node == 'mx1' else 'container:'+self.names['mx1']
            self.created.append(node)
            self.run('run', '-d', '--name', self.names[node], '--platform', self.args.platform,
                     '--network', network, '--cgroupns', 'private', '--privileged',
                     '--cpus', '2', '--memory', '1536m', '--pids-limit', '256',
                     '--tmpfs', '/run', '--tmpfs', '/tmp',
                     '--env', 'NOISEFENCE_DISPOSABLE_PAIRED_TEST=1',
                     '--env', 'FIXTURE_ARCH='+self.args.platform.split('/')[1], self.args.image)
            self.command(node, 'mkdir', '-p', '/root/releases', '/root/source/deploy', '/root/source/tests/fixtures')
            self.run('cp', str(self.args.fixture.resolve()), self.names[node]+':/root/fixture')
            for source, target in [(SOURCE/'deploy/postgresql', '/root/source/deploy/postgresql'),
                                   (SOURCE/'deploy/noisefence.service', '/root/source/deploy/noisefence.service'),
                                   (SOURCE/'deploy/install.sh', '/root/source/deploy/install.sh'),
                                   (SOURCE/'tests/fixtures/paired_node.py', '/root/source/tests/fixtures/paired_node.py')]:
                self.run('cp', str(source), self.names[node]+':'+target)
            for item in (self.old, self.new):
                self.run('cp', str(item['path']), self.names[node]+':/root/'+item['path'].name)
                self.command(node, 'tar', '-xzf', '/root/'+item['path'].name, '-C', '/root/releases')
            state = self.node(node, 'bootstrap')
            machines.append(state['machine'])
            self.binary_hashes[node] = state['binary_sha256']
        if len(set(machines)) != 2:
            raise RuntimeError('Fixture nodes need distinct machine identities')
        for node in self.names:
            self.command(node, 'systemctl', 'start', 'noisefence.service')
        for node in self.names:
            self.ready(node, self.old['version'])
        self.record('both_old_runtimes_ready', version=self.old['version'])

    def submit(self, label):
        for node in self.names:
            self.accepted.append(self.node(node, 'submit', label))
        self.verify_bodies(confirmed=False)
        self.wait_replicas()
        self.record('accepted_two_messages', phase=label, total=len(self.accepted))

    def inspect(self):
        result = {node: self.node(node, 'inspect') for node in self.names}
        if not all(v['replication_required'] for v in result.values()):
            raise RuntimeError('Mandatory replication disappeared')
        return result

    def verify_bodies(self, confirmed=True):
        rows = self.inspect()
        # Read replicas after all source acknowledgement snapshots. A replica
        # queried before its source can legitimately show an older generation.
        later = self.inspect()
        for node in rows:
            rows[node]['remote_receipts'] = later[node].get('remote_receipts', {})
            rows[node]['replicas'] = later[node].get('replicas', {})
        for message in self.accepted:
            node = message['node']; peer = 'mx2' if node == 'mx1' else 'mx1'
            ident, expected = message['id'], message['body_sha256']
            if (ident not in rows[node]['message_ids'] or rows[node]['bodies'].get(ident) != expected
                    or rows[peer]['replicas'].get(ident) != expected):
                raise RuntimeError('Accepted message metadata or durable body copy missing/changed')
            local = rows[node]['replication_receipts'].get(ident, {})
            remote = rows[peer]['remote_receipts'].get(ident, {})
            if (local.get('acked', -1) < (1 if confirmed else 0) or remote.get('generation', -1) < local['acked']
                    or remote.get('owner') != node or remote.get('body_sha256') != expected
                    or remote.get('body_present') is not True):
                raise RuntimeError('Accepted message has no matching durable replica receipt')
            recipients = [r for r in rows[node]['deliveries'] if r['message_id'] == ident]
            if (len(recipients) != 1 or recipients[0]['address'] != 'alice@example.test'
                    or recipients[0]['destination'] != 'alice@example.test'
                    or recipients[0]['status'] not in ('pending', 'sending')):
                raise RuntimeError('Accepted recipient missing, altered or unexpectedly resolved')
        return rows

    def wait_replicas(self):
        deadline = time.monotonic()+30
        while time.monotonic() < deadline:
            rows = self.verify_bodies(confirmed=False)
            if all(r['pending_replica_updates'] == 0 for r in rows.values()):
                return self.verify_bodies()
            time.sleep(.25)
        raise RuntimeError('Replica metadata acknowledgements did not converge')

    def migrate(self):
        self.node('mx1', 'migration', self.operation)
        public = self.command('mx1', 'cat', '/etc/noisefence-migration/identity.pub')
        (self.root/'controller.pub').write_bytes(public)
        self.run('cp', str(self.root/'controller.pub'), self.names['mx2']+':/root/paired-test/controller.pub')
        self.node('mx2', 'migration', self.operation)
        host_key = self.command('mx2', 'cat', '/etc/ssh/ssh_host_ed25519_key.pub').decode().split()
        (self.root/'known_hosts').write_text('127.0.0.1 '+host_key[0]+' '+host_key[1]+'\n')
        self.run('cp', str(self.root/'known_hosts'), self.names['mx1']+':/etc/noisefence-migration/known_hosts')
        self.command('mx1', 'chown', 'root:root', '/etc/noisefence-migration/known_hosts')
        self.command('mx1', 'chmod', '0600', '/etc/noisefence-migration/known_hosts')
        output = self.command('mx1', '/usr/local/libexec/noisefence-management/migrate.py',
                              '--config', '/etc/noisefence-migration/controller.json', timeout=920)
        (self.root/'migration.log').write_bytes(output)
        for node in self.names:
            self.ready(node, self.old['version'])
        rows = self.verify_bodies()
        if not all(row['selection'] is not None for row in rows.values()):
            raise RuntimeError('Missing selected management authority')
        self.baseline = rows
        self.fresh_policy(self.old['version'], int(time.time()))
        self.record('selected_postgresql_authority', accepted_before=len(self.accepted))

    def invariant(self):
        rows = self.verify_bodies()
        for node, row in rows.items():
            for key in ['config_sha256', 'selection', 'policy_epoch', 'policy_digest']:
                if row[key] != self.baseline[node][key]:
                    raise RuntimeError('Upgrade changed authority/configuration/policy: '+key)

    def fresh_policy(self, expected_build, since):
        deadline = time.monotonic()+30
        while time.monotonic() < deadline:
            peers = self.node('mx1', 'policy')
            if policy_is_fresh(peers, expected_build, since,
                               self.baseline['mx2']['policy_digest'], int(time.time())):
                self.record('fresh_authenticated_policy_sync', worker_build=expected_build)
                return
            time.sleep(.25)
        raise RuntimeError('No fresh matching authenticated policy synchronization')

    def maintenance_reservation(self):
        helper = '/usr/local/libexec/noisefence-management/upgrade_reservation.py'
        results = {}
        for node in ['mx2', 'mx1']:
            first = json.loads(self.command(node, 'python3', helper, 'begin', '--operation', self.operation))
            # The first process has exited: the reservation must survive a lost
            # controller connection without an open advisory-lock descriptor.
            resumed = json.loads(self.command(node, 'python3', helper, 'begin', '--operation', self.operation))
            if first != resumed or first.get('phase') != 'held' or any(first.get(key) is not True for key in ['writers_stopped', 'reserved', 'service_hold']):
                raise RuntimeError('Maintenance reservation was not durable/idempotent')
            self.command(node, 'systemctl', 'start', 'noisefence.service')
            state = self.command(node, 'systemctl', 'show', '--property=ActiveState,ConditionResult', 'noisefence.service').decode()
            if 'ActiveState=inactive' not in state or 'ConditionResult=no' not in state:
                raise RuntimeError('Maintenance condition did not prevent an independent restart')
            # The current root installer must reject before even looking for its
            # release argument. Use a fixed nonexistent fixture path.
            refused = self.command(node, 'python3', '-c',
                "import subprocess; p=subprocess.run(['sh','/root/source/deploy/install.sh','/missing-fixture-release'],capture_output=True); "
                "assert p.returncode!=0 and b'durable upgrade reservation' in p.stderr, (p.returncode,p.stderr); print('refused')")
            if refused.strip() != b'refused':
                raise RuntimeError('Installer did not enforce the durable reservation')
            results[node] = first
        self.invariant()
        self.record('durable_maintenance_reservations_and_restart_guards', nodes=results)
        since = int(time.time())
        for node in ['mx1', 'mx2']:
            cancelled = json.loads(self.command(node, 'python3', helper, 'cancel', '--operation', self.operation))
            if cancelled.get('phase') != 'cancelled':
                raise RuntimeError('Unchanged installation did not resume')
        self.fresh_policy(self.old['version'], since)
        for node in self.names:
            self.ready(node, self.old['version'])
        self.invariant()
        self.submit('after_unchanged_maintenance_cancellation')

    def failure_recovery(self):
        self.command('mx2', 'systemctl', 'stop', 'noisefence.service')
        refused = self.node('mx1', 'deferred')
        self.verify_bodies()
        self.record('mandatory_peer_outage_deferred', **refused)
        since = int(time.time())
        self.command('mx2', 'systemctl', 'start', 'noisefence.service')
        self.fresh_policy(self.old['version'], since)
        for node in self.names:
            self.ready(node, self.old['version'])
        self.submit('after_peer_recovery')

        # Inject a deterministic startup failure into the disposable coordinator.
        # Leave the second node stopped on its old pointer throughout the failure.
        for node in ['mx2', 'mx1']:
            self.command(node, 'systemctl', 'stop', 'noisefence.service')
        self.node('mx1', 'switch', self.new['version'])
        override = '/etc/systemd/system/noisefence.service.d/paired-start-failure.conf'
        self.command('mx1', 'python3', '-c',
                     "from pathlib import Path; p=Path("+repr(override)+"); p.parent.mkdir(exist_ok=True); p.write_text('[Service]\\nType=oneshot\\nRestart=no\\nExecStart=\\nExecStart=/bin/false\\n')")
        self.command('mx1', 'systemctl', 'daemon-reload')
        failed = False
        try:
            self.command('mx1', 'systemctl', 'start', 'noisefence.service', timeout=30)
        except subprocess.CalledProcessError:
            failed = True
        if not failed:
            raise RuntimeError('Injected failed candidate unexpectedly started')
        state = self.command('mx2', 'systemctl', 'show', 'noisefence.service', '--property=ActiveState', '--value').strip()
        pointer = self.command('mx2', 'readlink', '-f', '/opt/noisefence/current').decode().strip()
        if state != b'inactive' or pointer != '/opt/noisefence/releases/'+self.old['version']:
            raise RuntimeError('Second node changed during failed candidate rehearsal')
        self.invariant()
        self.record('failed_candidate_preserved_pair')
        self.command('mx1', 'rm', '--', override)
        self.command('mx1', 'systemctl', 'daemon-reload')
        self.node('mx1', 'switch', self.old['version'])
        since = int(time.time())
        for node in self.names:
            self.command(node, 'systemctl', 'start', 'noisefence.service')
        self.fresh_policy(self.old['version'], since)
        for node in self.names:
            self.ready(node, self.old['version'])
        self.invariant()
        self.record('failed_candidate_recovered')
        self.submit('after_start_failure')

    def rollout(self):
        # Published selected-management releases require equal peer builds.
        # Stop both daemons before changing either pointer; cached health alone
        # does not prove that a mixed-build pair can synchronize policy.
        for version, phase in [(self.new['version'], 'upgrade'), (self.old['version'], 'rollback')]:
            since = int(time.time())
            for node in ['mx2', 'mx1']:
                self.command(node, 'systemctl', 'stop', 'noisefence.service')
            for node in self.names:
                self.node(node, 'switch', version)
            for node in self.names:
                self.command(node, 'systemctl', 'start', 'noisefence.service')
            self.fresh_policy(version, since)
            for node in self.names:
                self.ready(node, version)
            self.invariant()
            self.record('coordinated_pair_ready', phase=phase, version=version)
            self.submit('after_pair_'+phase)

    def finish(self, metadata):
        self.invariant()
        snapshots = self.wait_replicas()
        running = {node: self.ready(node, self.old['version']) for node in self.names}
        report = {'schema': 'noisefence-paired-lifecycle-1', 'status': 'validated_pending_cleanup',
                  'operation': self.operation, 'checks': self.checks, 'accepted': self.accepted,
                  'final_state': snapshots, 'final_running': running,
                  'staged_binary_sha256': self.binary_hashes,
                  'archive_sha256': {i['version']: i['sha256'] for i in (self.old, self.new)},
                  'archive_commits': {i['version']: i['commit'] for i in (self.old, self.new)},
                  'image_id': metadata['Id'], 'platform': self.args.platform,
                  'network': 'shared_loopback_without_external_route', 'production_affected': False,
                  'scope': 'coordinated_stop_start_archive_pair_with_synthetic_selected_authority',
                  'sequence': 'both_stopped_before_switching_either_binary',
                  'not_qualified': ['current_unreleased_binary', 'production_updater', 'external_delivery',
                                    'rolling_mixed_build_upgrade', 'live_models', 'failover_after_loss', 'performance', 'detection_accuracy']}
        (self.root/'paired-lifecycle-report.json').write_text(json.dumps(report, indent=2)+'\n')

    def close(self):
        failures = []
        for node in reversed(self.created):
            try:
                journal = self.command(node, 'journalctl', '-u', 'noisefence.service', '--no-pager', '-n', '100', timeout=20)
                (self.root/(node+'-journal.log')).write_bytes(journal)
                errors = self.command(node, 'python3', '-c',
                    "from pathlib import Path; p=Path('/root/paired-test/command-error.log'); print(p.read_text() if p.exists() else '')", timeout=20)
                (self.root/(node+'-command-error.log')).write_bytes(errors)
                migration = self.command(node, 'python3', '-c',
                    "import json; from pathlib import Path; print(json.dumps({str(p):p.read_text(errors='replace')[-32768:] for root in ['/var/lib/noisefence-migration-controller','/var/lib/noisefence-migration'] for p in Path(root).glob('*/*.log')}))", timeout=20)
                (self.root/(node+'-migration-errors.json')).write_bytes(migration)
            except Exception:
                failures.append({'node': node, 'step': 'collect_diagnostics'})
            try:
                self.run('rm', '--force', '--volumes', self.names[node], timeout=30)
            except Exception:
                failures.append({'node': node, 'step': 'remove_container'})
        (self.root/'cleanup.json').write_text(json.dumps({'containers': self.names, 'failures': failures})+'\n')
        report_path = self.root/'paired-lifecycle-report.json'
        if report_path.exists():
            report = json.loads(report_path.read_text())
            report.update(status='cleanup_failed' if failures else 'passed', cleanup=not failures)
            report_path.write_text(json.dumps(report, indent=2)+'\n')
        if failures:
            raise RuntimeError('Fixture cleanup or diagnostic collection failed; inspect cleanup.json')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--old-archive', type=Path, required=True)
    parser.add_argument('--new-archive', type=Path, required=True)
    parser.add_argument('--image', required=True)
    parser.add_argument('--platform', choices=['linux/amd64', 'linux/arm64'], required=True)
    parser.add_argument('--fixture', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(); os.umask(0o077)
    old, new = (archive(p, args.platform.split('/')[1]) for p in [args.old_archive, args.new_archive])
    if tuple(map(int, old['version'].split('.'))) >= tuple(map(int, new['version'].split('.'))):
        raise ValueError('Supply distinct releases in ascending version order')
    fixture = json.loads((args.fixture/'fixture.json').read_text())
    if (fixture.get('schema') != 'noisefence-paired-fixture-1' or fixture.get('synthetic_only') is not True
            or fixture.get('shared_loopback') is not True or fixture.get('baseline_build') != old['version']
            or fixture.get('external_delivery') is not False or fixture.get('nodes') != ['mx1', 'mx2']):
        raise ValueError('Generate a fresh synthetic fixture for this old version and network topology')
    metadata = json.loads(subprocess.check_output(['docker', 'image', 'inspect', args.image]))[0]
    if (metadata['Config'].get('Labels', {}).get('org.noisefence.test-fixture') != 'paired-release-lifecycle'
            or metadata['Os']+'/'+metadata['Architecture'] != args.platform):
        raise ValueError('Build tests/fixtures/paired.Dockerfile for this architecture first')
    lab = Lab(args, old, new)
    try:
        lab.start(); lab.submit('before_migration'); lab.migrate(); lab.submit('selected_old_pair')
        lab.maintenance_reservation(); lab.failure_recovery(); lab.rollout(); lab.finish(metadata)
    except BaseException as error:
        (lab.root/'failed.json').write_text(json.dumps({'status': 'failed', 'error': type(error).__name__,
            'checks': lab.checks, 'accepted': lab.accepted})+'\n')
        raise
    finally:
        lab.close()
    print(json.dumps({'status':'passed','accepted':len(lab.accepted),
        'report':str(lab.root/'paired-lifecycle-report.json')}),flush=True)


if __name__ == '__main__':
    main()
