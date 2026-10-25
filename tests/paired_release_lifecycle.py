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
import sys
import tarfile
import time
import uuid

SOURCE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SOURCE/'deploy/postgresql'))
from release_version import VERSION, valid as valid_version, precedence
from release_bundle import inspect_archive
sys.path.pop(0)


def digest(path):
    with Path(path).open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def archive(path, architecture):
    match = re.fullmatch(rf'noisefence-({VERSION})-linux-(amd64|arm64)\.tar\.gz', path.name)
    if not match or not valid_version(match[1]) or match[2] != architecture:
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


def validation_candidate(directory, architecture, version):
    metadata = json.loads((directory/'candidate.json').read_text())
    binary = directory/'noisefence'
    with binary.open('rb') as source:
        header = source.read(20)
    if (len(header) != 20 or header[:4] != b'\x7fELF' or header[4:6] != b'\x02\x01'
            or int.from_bytes(header[18:20], 'little') != {'arm64': 183, 'amd64': 62}[architecture]
            or metadata.get('platform') != 'linux/'+architecture or metadata.get('version') != version
            or metadata.get('features') != ['semantic'] or metadata.get('profile') != 'release'
            or not re.fullmatch('[a-f0-9]{40}', metadata.get('commit', ''))
            or metadata.get('binary_sha256') != digest(binary)
            or metadata.get('not_a_published_release') is not True):
        raise ValueError('Synthetic validation candidate identity or platform differs')
    return metadata



def archive_candidate(item, architecture, destination):
    """Inspect exact artifact bytes; never patch its binary, metadata or manifest."""
    if digest(item['path']) != item['sha256']:
        raise ValueError('Candidate archive changed after initial inspection')
    inspected = inspect_archive(item['path'], item['version'], 'linux-'+architecture,
                                item['commit'], destination=destination)
    required = ['deploy/noisefence.service', 'deploy/install.sh',
                *('deploy/postgresql/'+name for name in ['upgrade_reservation.py',
                  'upgrade_validation.py', 'upgrade_validation.service', 'upgrade_promotion.py',
                  'upgrade_activation.py', 'upgrade_exchange.py', 'release_version.py', 'rollback_check.py', 'rollback_validation.py', 'rollback_promotion.py', 'rollback_activation.py'])]
    if any(name not in inspected['files'] for name in required):
        raise ValueError('Archive lacks the native candidate maintenance helpers')
    return {'origin': 'exact_archive', 'version': item['version'], 'commit': item['commit'],
            'platform': 'linux/'+architecture, 'archive_sha256': item['sha256'],
            'binary_sha256': inspected['files']['noisefence'],
            'build_sha256': inspected['files']['build.json'],
            'manifest_sha256': inspected['files']['SHA256SUMS'],
            'helper_sha256': {str(Path(name).relative_to('deploy/postgresql')):sha
                for name,sha in inspected['files'].items() if name.startswith('deploy/postgresql/')},
            'provenance_verified': False}


def policy_is_fresh(peers, expected_build, since, digest, now):
    return any(p.get('node') == 'mx2' and p.get('build') == expected_build
               and type(p.get('seen')) is int and since < p['seen'] <= now
               and p.get('digest') == digest for p in peers)


class Lab:
    def __init__(self, args, old, new):
        self.args, self.old, self.new = args, old, new
        self.apparmor_profile = getattr(args, 'apparmor_profile', None)
        if self.apparmor_profile and not re.fullmatch(r'noisefence-test-[a-f0-9]{12}', self.apparmor_profile):
            raise ValueError('Use a unique disposable AppArmor profile name')
        self.root = args.output.resolve()
        self.root.mkdir(mode=0o700, parents=True, exist_ok=False)
        self.operation = str(uuid.uuid4())
        self.names = {node: 'nf-paired-'+self.operation[:8]+'-'+node for node in ('mx1', 'mx2')}
        self.created = []; self.checks = []; self.accepted = []
        self.binary_hashes = {}
        self.helper_hashes = {}
        self.final_release = old['version']
        self.candidate_release = new['version'] if args.archive_candidate else 'qualification-candidate'
        self.candidate_directory = '/opt/noisefence/releases/'+self.candidate_release
        self.deployment_source = SOURCE/'deploy'
        if args.archive_candidate:
            extracted = self.root/'candidate-archive'
            self.validation_metadata = archive_candidate(new, args.platform.split('/')[1], extracted)
            self.deployment_source = extracted/'deploy'
        else:
            self.validation_metadata = validation_candidate(args.validation_candidate, args.platform.split('/')[1], new['version']) if args.validation_candidate else None
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
        if getattr(self, 'apparmor_profile', None):
            self.check_confinement(result.get('confinement'), self.binary_hashes[node][version])
        return result

    def check_confinement(self, proof, binary_hash):
        if (not isinstance(proof, dict) or proof.get('profile') != self.apparmor_profile
                or proof.get('mode') != 'enforce'
                or proof.get('process_profile') != self.apparmor_profile+' (enforce)'
                or proof.get('binary_sha256') != binary_hash):
            raise RuntimeError('Missing exact running-binary AppArmor evidence')

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
                     '--env', 'FIXTURE_ARCH='+self.args.platform.split('/')[1],
                     '--env', 'NOISEFENCE_TEST_APPARMOR_PROFILE='+(self.apparmor_profile or ''), self.args.image)
            self.command(node, 'mkdir', '-p', '/root/releases', '/root/source/deploy', '/root/source/tests/fixtures')
            self.run('cp', str(self.args.fixture.resolve()), self.names[node]+':/root/fixture')
            for source, target in [(self.deployment_source/'postgresql', '/root/source/deploy/postgresql'),
                                   (self.deployment_source/'noisefence.service', '/root/source/deploy/noisefence.service'),
                                   (self.deployment_source/'install.sh', '/root/source/deploy/install.sh'),
                                   (SOURCE/'tests/fixtures/paired_node.py', '/root/source/tests/fixtures/paired_node.py'),
                                   (SOURCE/'tests/fixtures/confinement_node.py', '/root/source/tests/fixtures/confinement_node.py'),
                                   (SOURCE/'tests/fixtures/runtime_diagnostics.py', '/root/source/tests/fixtures/runtime_diagnostics.py'),
                                   (SOURCE/'tests/fixtures/exchange_node.py', '/root/source/tests/fixtures/exchange_node.py'),
                                   (SOURCE/'tests/fixtures/validation_node.py', '/root/source/tests/fixtures/validation_node.py')]:
                self.run('cp', str(source), self.names[node]+':'+target)
            for item in (self.old, self.new):
                if digest(item['path']) != item['sha256']:
                    raise RuntimeError('Archive changed before isolated copy')
                self.run('cp', str(item['path']), self.names[node]+':/root/'+item['path'].name)
                self.command(node, 'tar', '-xzf', '/root/'+item['path'].name, '-C', '/root/releases')
            if self.args.validation_candidate:
                self.command(node, 'mkdir', '/root/validation-candidate')
                for filename in ['noisefence', 'candidate.json']:
                    self.run('cp', str(self.args.validation_candidate/filename), self.names[node]+':/root/validation-candidate/'+filename)
            state = self.node(node, 'bootstrap')
            if self.apparmor_profile:
                proof = state.get('confinement')
                if (not isinstance(proof, dict) or proof.get('profile') != self.apparmor_profile
                        or not all(proof.get(key) is True for key in
                                   ('allowed_configuration', 'unconfined_canary_read', 'confined_canary_denied'))):
                    raise RuntimeError('AppArmor canary did not establish enforcement')
                self.record('apparmor_canary_enforced', node=node, **proof)
            # Exercise a real auxiliary timer without running training or feeds.
            self.command(node,'python3','-c',
                "from pathlib import Path; d=Path('/etc/systemd/system'); "
                "(d/'noisefence-quality.service').write_text('[Service]\\nType=oneshot\\nUser=noisefence\\nExecStart=/bin/true\\n'); "
                "(d/'noisefence-quality.timer').write_text('[Timer]\\nOnActiveSec=1d\\nUnit=noisefence-quality.service\\n'); "
                "(d/'noisefence-quality.service').chmod(0o644); (d/'noisefence-quality.timer').chmod(0o644)")
            self.command(node,'systemctl','daemon-reload');self.command(node,'systemctl','start','noisefence-quality.timer')
            machines.append(state['machine'])
            self.binary_hashes[node] = state['binary_sha256']
            self.helper_hashes[node] = json.loads(self.command(node, 'python3', '-c',
                "import hashlib,json; from pathlib import Path; root=Path('/usr/local/libexec/noisefence-management'); "
                "print(json.dumps({p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in root.iterdir() if p.is_file()}))"))
        if self.args.archive_candidate:
            expected = self.validation_metadata['helper_sha256']
            if any(files != expected for files in self.helper_hashes.values()):
                raise RuntimeError('Installed native helpers differ from the candidate archive')
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
        if self.validation_metadata:
            self.validate_candidate()
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

    def validation_node(self, node, action, value=None):
        args = ['python3', '/root/source/tests/fixtures/validation_node.py', action]
        if value is not None:
            args += ['--value', value]
        return json.loads(self.command(node, *args))

    def validation(self, node, action, *extra):
        return json.loads(self.command(node, 'python3', '/usr/local/libexec/noisefence-management/upgrade_validation.py',
                                      action, '--operation', self.operation, *extra))

    def validate_candidate(self):
        before = self.inspect()
        database = self.validation_node('mx1', 'database')
        for node in self.names:
            if self.args.archive_candidate:
                staged = self.validation_node(node, 'archive', self.new['version'])
                for key in ('binary_sha256', 'build_sha256', 'manifest_sha256', 'commit'):
                    if staged[key] != self.validation_metadata[key]:
                        raise RuntimeError('Installed candidate differs from its exact archive: '+key)
            else:
                staged = self.validation_node(node, 'stage', self.new['version'])
                if staged['binary_sha256'] != self.validation_metadata['binary_sha256']:
                    raise RuntimeError('Staged candidate differs from the reviewed binary')
        expires = int(time.time())+90
        descriptors = {}
        for node in self.names:
            descriptors[node] = self.validation(node, 'describe', '--candidate', self.candidate_directory, '--expires-at', str(expires))
        for node in self.names:
            peer = 'mx2' if node == 'mx1' else 'mx1'
            report = self.root/(node+'-peer-descriptor.json')
            report.write_text(json.dumps(descriptors[peer])+'\n')
            self.run('cp', str(report), self.names[node]+':/root/paired-test/validation-peer.json')
            self.command(node, 'chown', 'root:root', '/root/paired-test/validation-peer.json')
            self.command(node, 'chmod', '0600', '/root/paired-test/validation-peer.json')
            self.validation(node, 'start', '--candidate', self.candidate_directory,
                            '--expires-at', str(expires), '--peer-report', '/root/paired-test/validation-peer.json')
        deadline = time.monotonic()+40
        states = {}
        while time.monotonic() < deadline:
            states = {node: self.validation(node, 'status') for node in self.names}
            if all(state.get('validation_ready') is True for state in states.values()):
                break
            time.sleep(.5)
        else:
            raise RuntimeError('Native candidate pair did not become validation-ready')
        if self.apparmor_profile:
            for node in self.names:
                proof = self.node(node, 'confinement', 'noisefence-validation.service')
                self.check_confinement(proof, self.validation_metadata['binary_sha256'])
                self.record('candidate_apparmor_enforced', node=node, **proof)
        self.record('native_candidate_pair_validation_ready', candidate=self.validation_metadata, nodes=states)
        for node in self.names:
            self.validation_node(node, 'disabled', node)
            self.command(node, 'python3', '-c',
                "import subprocess; p=subprocess.run(['python3','/usr/local/libexec/noisefence-management/upgrade_reservation.py','cancel','--operation',"+repr(self.operation)+"],capture_output=True); assert p.returncode!=0 and b'Stop candidate validation' in p.stderr")
        self.record('candidate_cannot_open_smtp_admin_or_cancel_hold')
        self.validation('mx2', 'stop')
        deadline = time.monotonic()+20
        while time.monotonic() < deadline:
            if self.validation('mx1', 'status').get('validation_ready') is False:
                break
            time.sleep(.5)
        else:
            raise RuntimeError('Peer loss retained validation readiness')
        self.record('candidate_peer_loss_invalidates_readiness')
        # The remaining candidate must stop on its own authorization deadline.
        while int(time.time()) <= expires+8:
            state = self.command('mx1', 'systemctl', 'show', 'noisefence-validation.service', '--property=ActiveState', '--value').strip()
            if state in (b'inactive', b'failed'):
                break
            time.sleep(.5)
        else:
            raise RuntimeError('Expired candidate kept running')
        if int(time.time()) < expires:
            raise RuntimeError('Candidate stopped before its authorization deadline')
        self.validation('mx1', 'stop')
        for node in self.names:
            if self.validation(node, 'status').get('phase') != 'stopped':
                raise RuntimeError('Candidate cleanup receipt missing')
        after = self.inspect()
        if database != self.validation_node('mx1', 'database'):
            raise RuntimeError('Candidate probes changed PostgreSQL application rows')
        for node in self.names:
            for key in ['selection', 'policy_epoch', 'deliveries', 'replication_receipts', 'remote_receipts', 'bodies', 'replicas']:
                if after[node][key] != before[node][key]:
                    raise RuntimeError('Candidate altered queued messages or policy: '+key)
        self.record('candidate_expired_stopped_and_preserved_selected_data', database=database)

    def promotion(self, node, action, peer=None):
        extra = []
        if peer is not None:
            report = self.root/(node+'-promotion-peer.json')
            report.write_text(json.dumps(peer)+'\n')
            remote = '/root/paired-test/promotion-peer.json'
            self.run('cp', str(report), self.names[node]+':'+remote)
            self.command(node, 'chown', 'root:root', remote)
            self.command(node, 'chmod', '0600', remote)
            extra = ['--peer-report', remote]
        return json.loads(self.command(node, 'python3', '/usr/local/libexec/noisefence-management/upgrade_promotion.py',
                                      action, '--operation', self.operation, *extra))

    def precommit_promotion(self, abandon=False, activation_outcome=None):
        if not self.validation_metadata:
            return
        # A new authorization is mandatory after the earlier expiry test. The
        # already staged candidate remains immutable and is verified again.
        self.operation = str(uuid.uuid4())
        helper = '/usr/local/libexec/noisefence-management/upgrade_reservation.py'
        for node in ['mx2', 'mx1']:
            self.command(node, 'python3', helper, 'begin', '--operation', self.operation)
        before = self.inspect(); database = self.validation_node('mx1', 'database')
        expires = int(time.time())+180
        descriptors = {node: self.validation(node, 'describe', '--candidate',
            self.candidate_directory, '--expires-at', str(expires)) for node in self.names}
        for node in self.names:
            peer = 'mx2' if node == 'mx1' else 'mx1'
            report = self.root/(node+'-promotion-validation-peer.json')
            report.write_text(json.dumps(descriptors[peer])+'\n')
            remote = '/root/paired-test/validation-peer.json'
            self.run('cp', str(report), self.names[node]+':'+remote)
            self.command(node, 'chown', 'root:root', remote); self.command(node, 'chmod', '0600', remote)
            self.validation(node, 'start', '--candidate', self.candidate_directory,
                            '--expires-at', str(expires), '--peer-report', remote)
        deadline = time.monotonic()+40
        while time.monotonic() < deadline:
            if all(self.validation(node, 'status').get('validation_ready') is True for node in self.names):
                break
            time.sleep(.5)
        else:
            raise RuntimeError('New promotion validation did not become ready')
        if abandon:
            prepared = self.promotion('mx1', 'prepare')
            # Model a controller loss before the second prepare. Both host
            # reservations and the first prepared receipt survive the process.
            self.validation('mx2', 'stop')
            restored = {'mx1': self.promotion('mx1', 'restore')}
            restored['mx2'] = self.promotion('mx2', 'abandon', prepared)
            if restored['mx2']['descriptor']['validated_at'] is not None:
                raise RuntimeError('Abandonment fabricated a live-validation observation')
            if database != self.validation_node('mx1', 'database'):
                raise RuntimeError('Abandonment changed PostgreSQL rows')
            self.record('interrupted_pair_preparation_restored_without_invented_validation', nodes=restored)
            self.resume_precommit_original(restored, 'after_unprepared_pair_restore')
            return
        prepared = {node: self.promotion(node, 'prepare') for node in self.names}
        promoted = {}
        for node in self.names:
            peer = 'mx2' if node == 'mx1' else 'mx1'
            promoted[node] = self.promotion(node, 'promote', prepared[peer])
            # Each helper has exited. A fresh root process must recover the same
            # intent instead of relying on an in-memory controller connection.
            if promoted[node] != self.promotion(node, 'promote', prepared[peer]):
                raise RuntimeError('Lost promotion response changed the durable result')
            self.command(node, 'systemctl', 'start', 'noisefence.service')
            state = self.command(node, 'systemctl', 'show', 'noisefence.service', '--property=ActiveState', '--value').strip()
            pointer = self.command(node, 'readlink', '-f', '/opt/noisefence/current').decode().strip()
            if state != b'inactive' or pointer != self.candidate_directory:
                raise RuntimeError('Prepared release activated or changed target')
            self.command(node, 'python3', '-c',
                "import subprocess; p=subprocess.run(['python3','/usr/local/libexec/noisefence-management/upgrade_reservation.py','cancel','--operation',"+repr(self.operation)+"],capture_output=True); assert p.returncode!=0 and b'Restore and release' in p.stderr")
        after = self.inspect()
        if database != self.validation_node('mx1', 'database'):
            raise RuntimeError('Pointer promotion changed PostgreSQL rows')
        for node in self.names:
            for key in ['selection', 'policy_epoch', 'deliveries', 'replication_receipts', 'remote_receipts', 'bodies', 'replicas']:
                if after[node][key] != before[node][key]:
                    raise RuntimeError('Pre-commit promotion changed queued state: '+key)
        self.record('prepared_pair_promoted_without_normal_activation', operation=self.operation, nodes=promoted, database=database)
        if activation_outcome:
            self.activate_pair(promoted, activation_outcome)
            return
        restored = {'mx1': self.promotion('mx1', 'restore')}
        try:
            self.promotion('mx1', 'release', promoted['mx2'])
        except subprocess.CalledProcessError:
            pass
        else:
            raise RuntimeError('One restored node incorrectly released the pair')
        restored['mx2'] = self.promotion('mx2', 'restore')
        self.resume_precommit_original(restored, 'after_precommit_pair_restore')

    def resume_precommit_original(self, restored, label):
        helper = '/usr/local/libexec/noisefence-management/upgrade_reservation.py'
        released = {}
        for node in self.names:
            peer = 'mx2' if node == 'mx1' else 'mx1'
            released[node] = self.promotion(node, 'release', restored[peer])
            if released[node] != self.promotion(node, 'release', restored[peer]):
                raise RuntimeError('Lost restoration release response was not idempotent')
        since = int(time.time())
        for node in self.names:
            self.command(node, 'python3', helper, 'cancel', '--operation', self.operation)
        self.fresh_policy(self.old['version'], since)
        for node in self.names:
            self.ready(node, self.old['version'])
        self.invariant(); self.submit(label)
        self.record('prepared_pair_restored_and_released_before_cancellation', nodes=released)

    def activation(self, node, action, peer=None, outcome=None):
        extra = []
        if peer is not None:
            report = self.root/(node+'-activation-peer.json')
            report.write_text(json.dumps(peer)+'\n')
            remote = '/root/paired-test/activation-peer.json'
            self.run('cp', str(report), self.names[node]+':'+remote)
            self.command(node, 'chown', 'root:root', remote);self.command(node, 'chmod', '0600', remote)
            extra = ['--peer-report',remote]
        if outcome:extra += ['--outcome',outcome]
        return json.loads(self.command(node,'python3','/usr/local/libexec/noisefence-management/upgrade_activation.py',
                                     action,'--operation',self.operation,*extra))

    def activate_pair(self, promoted, outcome):
        armed = {'mx1':self.activation('mx1','arm',promoted['mx2'])}
        if outcome == 'activate':
            armed['mx2'] = self.activation('mx2','arm',armed['mx1'])
        decision = self.activation('mx1','decide',armed.get('mx2'),outcome)
        try:
            self.promotion('mx1','restore')
        except subprocess.CalledProcessError:pass
        else:raise RuntimeError('Pre-commit restoration bypassed a durable decision')
        if outcome == 'activate':
            try:self.activation('mx1','start',armed['mx2'])
            except subprocess.CalledProcessError:pass
            else:raise RuntimeError('Normal daemon started before peer accepted the decision')
        accepted = self.activation('mx2','accept',decision)
        if accepted != self.activation('mx2','accept',decision):
            raise RuntimeError('Lost decision response replaced its receipt')
        if outcome == 'abort':
            aborted={node:self.activation(node,'abort') for node in self.names}
            since=int(time.time())
            for node in self.names:
                peer='mx2' if node=='mx1' else 'mx1'
                done=self.activation(node,'cancel',aborted[peer])
                if done!=self.activation(node,'cancel',aborted[peer]):raise RuntimeError('Aborted decision cleanup was not idempotent')
            self.fresh_policy(self.old['version'],since)
            for node in self.names:self.ready(node,self.old['version'])
            self.invariant();self.submit('after_durable_pair_abort')
            self.record('durable_abort_restored_unarmed_peer_and_original_pair')
            return
        started={'mx1':self.activation('mx1','start',accepted)}
        self.node('mx1','deferred');self.verify_bodies()
        # Force an actual candidate startup failure, without altering its unit,
        # release or configuration. Forward recovery must retain the decision.
        self.command('mx2','systemd-run','--unit=noisefence-test-port-blocker','--property=Type=exec',
            '/usr/bin/python3','-c',
            "import socket,time; from pathlib import Path; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(('127.0.0.1',2527)); s.listen(); Path('/run/nf-port-blocker-ready').touch(); time.sleep(120)")
        for _ in range(30):
            if self.command('mx2','python3','-c',"from pathlib import Path; print(Path('/run/nf-port-blocker-ready').exists())").strip()==b'True':break
            time.sleep(.1)
        else:
            journal=self.command('mx2','journalctl','-u','noisefence-test-port-blocker.service','--no-pager','-n','40')
            (self.root/'port-blocker-journal.log').write_bytes(journal)
            raise RuntimeError('Synthetic port blocker did not listen; inspect port-blocker-journal.log')
        try:self.activation('mx2','start',decision)
        except subprocess.CalledProcessError:pass
        deadline=time.monotonic()+30
        while time.monotonic()<deadline:
            status=self.command('mx2','systemctl','show','noisefence.service','--property=ExecMainStatus','--value').strip()
            if status==b'1':break
            time.sleep(.25)
        else:raise RuntimeError('Candidate did not fail on the occupied SMTP port')
        failed=self.activation('mx2','status')
        if failed['decision']!=decision['decision']:raise RuntimeError('Startup failure replaced the activation decision')
        try:self.activation('mx2','abort')
        except subprocess.CalledProcessError:pass
        else:raise RuntimeError('Committed candidate could silently abort after startup failure')
        self.command('mx2','systemctl','stop','noisefence-test-port-blocker.service')
        started['mx2']=self.activation('mx2','start',decision)
        for node in self.names:
            self.command(node,'systemctl','start','noisefence-quality.timer')
            state=self.command(node,'systemctl','show','noisefence-quality.timer','--property=ActiveState,ConditionResult').decode()
            if 'ActiveState=inactive' not in state or 'ConditionResult=no' not in state:
                raise RuntimeError('Auxiliary timer escaped activation verification hold')
        self.record('committed_start_failure_recovered_forward_and_auxiliary_jobs_held')
        self.record('both_committed_normal_candidates_started',nodes=started)
        for node in self.names:
            self.binary_hashes[node][self.candidate_release]=self.validation_metadata['binary_sha256']
            self.ready(node,self.candidate_release)
        self.fresh_policy(self.new['version'],max(d['started_at'] for d in started.values()))
        deadline=time.monotonic()+60
        while time.monotonic()<deadline:
            try:
                proofs={node:self.activation(node,'check',started['mx2' if node=='mx1' else 'mx1']) for node in self.names}
                break
            except subprocess.CalledProcessError:time.sleep(.5)
        else:raise RuntimeError('Fresh normal policy/replica proof did not converge')
        completed = self.exchange_completion(started)
        self.final_release=self.candidate_release
        self.invariant();self.submit('after_committed_candidate_activation')
        self.record('normal_candidates_verified_and_operation_completed',proofs=proofs,nodes=completed)

    def exchange_completion(self, started):
        helper = '/root/source/tests/fixtures/exchange_node.py'
        metadata = {node:json.loads(self.command(node,'python3',helper,'prepare','--node',node,
                                                '--operation',self.operation)) for node in self.names}
        if metadata['mx1']['authorization']['proposal_sha256'] != metadata['mx2']['authorization']['proposal_sha256']:
            raise RuntimeError('SSH authorizations name different prepared pairs')
        if metadata['mx1']['host_key'].split()[:2] == metadata['mx2']['host_key'].split()[:2]:
            raise RuntimeError('Disposable SSH hosts must have distinct keys')
        public = self.root/'exchange-controller.pub';public.write_text(metadata['mx1']['client_key']+'\n')
        known = self.root/'exchange-known_hosts'
        known.write_text(''.join('noisefence-upgrade-'+node+' '+' '.join(metadata[node]['host_key'].split()[:2])+'\n' for node in self.names))
        auth = metadata['mx1']['authorization']
        config = {k:auth[k] for k in ['protocol','operation','proposal_sha256','expires_at']}
        config.update(coordinator='mx1',ssh_key='/etc/noisefence-upgrade/identity',
                      known_hosts='/etc/noisefence-upgrade/known_hosts',
                      nodes={node:{'host':'127.0.0.1','port':2221 if node=='mx1' else 2222,'user':'root'} for node in self.names})
        config_path = self.root/'exchange-controller.json';config_path.write_text(json.dumps(config)+'\n')
        for node in self.names:
            self.run('cp',str(public),self.names[node]+':/root/paired-test/exchange-controller.pub')
            self.command(node,'chown','root:root','/root/paired-test/exchange-controller.pub')
            self.command(node,'chmod','0600','/root/paired-test/exchange-controller.pub')
            self.command(node,'python3',helper,'setup','--node',node)
        for source,target in [(known,'known_hosts'),(config_path,'controller.json')]:
            remote='/etc/noisefence-upgrade/'+target
            self.run('cp',str(source),self.names['mx1']+':'+remote)
            self.command('mx1','chown','root:root',remote);self.command('mx1','chmod','0600',remote)
        command=['python3','/usr/local/libexec/noisefence-management/upgrade_exchange.py','complete',
                 '--config','/etc/noisefence-upgrade/controller.json']
        try:self.command('mx1',*command,timeout=300)
        except subprocess.CalledProcessError:pass
        else:raise RuntimeError('Injected completed SSH reply was not lost')
        # Prove the failure happened after a real durable finish, not during
        # configuration, SSH setup or proof collection.
        lost=json.loads(self.command('mx1','cat','/root/paired-test/discarded-completion.json'))
        interrupted={node:self.activation(node,'status') for node in self.names}
        if (lost['result'] != interrupted['mx1'] or interrupted['mx1']['phase']!='complete'
                or interrupted['mx2']['phase']!='verified'
                or any(interrupted[node]['decision']!=started[node]['decision'] for node in self.names)):
            raise RuntimeError('Lost SSH reply did not preserve the original completed/verified decision')
        timers={node:self.command(node,'systemctl','show','noisefence-quality.timer','--property=ActiveState','--value').decode().strip() for node in self.names}
        if timers != {'mx1':'active','mx2':'inactive'}:raise RuntimeError('Unexpected auxiliary timer boundary after lost reply')
        self.invariant();self.submit('while_completion_reply_lost')
        self.record('actual_ssh_completion_reply_lost_after_durable_finish',nodes=interrupted,timers=timers)
        # Native proof expiry must not invent a rollback or replace the durable
        # completion certificate. Exercise real elapsed time, not a mocked clock.
        deadline=max(value['verified_at'] for value in interrupted.values())+32
        while time.time() < deadline:time.sleep(min(.5,deadline-time.time()))
        output=json.loads(self.command('mx1',*command,timeout=300))
        if output.get('status')!='complete' or output.get('operation')!=self.operation:
            raise RuntimeError('SSH completion retry did not finish the same operation')
        completed={node:self.activation(node,'status') for node in self.names}
        for node in self.names:
            if (completed[node]['phase']!='complete' or completed[node]['decision']!=started[node]['decision']
                    or completed[node]['verified_at']!=interrupted[node]['verified_at']):
                raise RuntimeError('Delayed SSH completion replaced its decision or old proof')
            if self.command(node,'systemctl','show','noisefence-quality.timer','--property=ActiveState','--value').strip()!=b'active':
                raise RuntimeError('Previously active timer did not resume')
            self.command(node,'python3','-c',
                "from pathlib import Path; p=Path('/var/lib/noisefence-upgrade'); "
                "assert not any((p/n).exists() for n in ['active.json','hold.json','activation.json','activation-jobs.json','promotion.json'])")
            self.ready(node,self.candidate_release)
        replay=json.loads(self.command('mx1',*command,timeout=300))
        if replay.get('status')!='complete':raise RuntimeError('Completed SSH retry was not idempotent')
        if completed!={node:self.activation(node,'status') for node in self.names}:
            raise RuntimeError('Completed SSH retry changed durable receipts')
        # Keep only bounded operational JSON; temporary keys never leave the lab.
        receipt_text=self.command('mx1','python3','-c',
            "import json; from pathlib import Path; p=Path('/var/lib/noisefence-upgrade/exchange'); "
            "v={str(f.relative_to(p)):json.loads(f.read_text()) for f in p.glob('*/*.json')}; print(json.dumps(v))")
        if len(receipt_text)>2*1024**2:raise RuntimeError('Unexpected controller evidence size')
        (self.root/'exchange-receipts.json').write_bytes(receipt_text)
        self.record('native_pair_completed_over_pinned_ssh_after_proof_expiry',nodes=completed,attempts=3,
                    helper='upgrade_exchange.py',proofs_reused=True)
        for node in self.names:
            retired=json.loads(self.command(node,'python3',helper,'retire','--node',node,
                                            '--operation',self.operation))
            if retired != {'node':node,'operation':self.operation,'phase':'retired'}:
                raise RuntimeError('Completed temporary SSH authorization was not retired')
        return completed

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

    def nonforward_validation_refused(self, current_version):
        operation = str(uuid.uuid4())
        helper = '/usr/local/libexec/noisefence-management/upgrade_reservation.py'
        for node in ('mx2', 'mx1'):
            held = json.loads(self.command(node, 'python3', helper, 'begin', '--operation', operation))
            if held.get('phase') != 'held' or held.get('writers_stopped') is not True:
                raise RuntimeError('Non-forward refusal requires a real held installation')
        before = self.inspect()
        database = self.validation_node('mx1', 'database')
        for node in self.names:
            for version in (self.old['version'], current_version):
                self.command(node, 'python3', '-c',
                    "import subprocess,sys,time;from pathlib import Path; "
                    "p=subprocess.run(['python3','/usr/local/libexec/noisefence-management/upgrade_validation.py','describe',"
                    "'--operation',sys.argv[1],'--candidate','/opt/noisefence/releases/'+sys.argv[2],"
                    "'--expires-at',str(int(time.time())+120)],capture_output=True,timeout=30); "
                    "assert p.returncode!=0 and b'Candidate version must be newer' in p.stderr, (p.returncode,p.stderr); "
                    "assert not (Path('/var/lib/noisefence-upgrade')/(sys.argv[1]+'-validation.json')).exists(); "
                    "assert not Path('/etc/noisefence/maintenance-validation.json').exists(); print('refused')",
                    operation, version)
            if self.command(node, 'readlink', '-f', '/opt/noisefence/current').decode().strip() != '/opt/noisefence/releases/'+current_version:
                raise RuntimeError('Refused downgrade changed the installed pointer')
        if self.inspect() != before or self.validation_node('mx1', 'database') != database:
            raise RuntimeError('Refused candidate changed accepted mail or selected management data')
        since = int(time.time())
        for node in ('mx1', 'mx2'):
            cancelled = json.loads(self.command(node, 'python3', helper, 'cancel', '--operation', operation))
            if cancelled.get('phase') != 'cancelled':raise RuntimeError('Refused candidate left an unexpected hold')
        self.fresh_policy(current_version, since)
        for node in self.names:self.ready(node, current_version)
        self.invariant()
        self.record('unqualified_downgrade_and_replacement_refused', installed_version=current_version,
                    refused_versions=[self.old['version'],current_version], nodes=['mx1','mx2'])

    def rollback_identity_prerequisites(self):
        if not self.validation_metadata:
            return
        previous = self.operation
        completed = {node:self.activation(node,'status') for node in self.names}
        if any(row['phase'] != 'complete' for row in completed.values()):
            raise RuntimeError('Rollback identity inspection requires a completed native pair')
        operation = str(uuid.uuid4())
        helper = '/usr/local/libexec/noisefence-management/upgrade_reservation.py'
        for node in ('mx2','mx1'):
            held = json.loads(self.command(node,'python3',helper,'begin','--operation',operation))
            if held.get('phase') != 'held' or held.get('writers_stopped') is not True:
                raise RuntimeError('Rollback identity inspection requires a fresh stopped-service hold')
        before = self.inspect()
        database = self.validation_node('mx1','database')
        reports = {}
        for node in self.names:
            counterpart = 'mx2' if node == 'mx1' else 'mx1'
            for label, receipt in [('peer',completed[counterpart]),('self',completed[node])]:
                local = self.root/('rollback-'+node+'-'+label+'.json')
                local.write_text(json.dumps(receipt)+'\n')
                remote = '/root/paired-test/rollback-'+label+'.json'
                self.run('cp',str(local),self.names[node]+':'+remote)
                self.command(node,'chown','root:root',remote);self.command(node,'chmod','0600',remote)
            command = ['python3','/usr/local/libexec/noisefence-management/rollback_check.py',
                       '--operation',operation,'--previous-operation',previous,'--peer-completion']
            reports[node] = json.loads(self.command(node,*command,'/root/paired-test/rollback-peer.json'))
            result = reports[node]
            if (result.get('status') != 'identity_checked_rollback_unqualified'
                or result.get('activation_authorized') is not False
                or result.get('node') != node or result.get('operation') != operation
                or result.get('previous_operation') != previous
                or result.get('current',{}).get('version') != self.new['version']
                or result.get('current',{}).get('binary_sha256') != self.binary_hashes[node][self.candidate_release]
                or result.get('retained',{}).get('version') != self.old['version']
                or result.get('retained',{}).get('binary_sha256') != self.binary_hashes[node][self.old['version']]):
                raise RuntimeError('Rollback identity report differs from the completed archive pair')
            self.command(node,'python3','-c',
                "import subprocess,sys,time;from pathlib import Path; "
                "p=subprocess.run(sys.argv[1:],capture_output=True,timeout=30); "
                "assert p.returncode!=0 and b'Unexpected activation counterpart' in p.stderr; print('refused')",
                *command,'/root/paired-test/rollback-self.json')
            self.command(node,'python3','-c',
                "import subprocess,sys,time;from pathlib import Path; "
                "p=subprocess.run(['python3','/usr/local/libexec/noisefence-management/upgrade_validation.py','describe',"
                "'--operation',sys.argv[1],'--candidate','/opt/noisefence/releases/'+sys.argv[2],"
                "'--expires-at',str(int(time.time())+120)],capture_output=True,timeout=30); "
                "assert p.returncode!=0 and b'Candidate version must be newer' in p.stderr; "
                "assert not (Path('/var/lib/noisefence-upgrade')/(sys.argv[1]+'-validation.json')).exists(); print('refused')",
                operation,self.old['version'])
            if self.command(node,'readlink','-f','/opt/noisefence/current').decode().strip() != '/opt/noisefence/releases/'+self.candidate_release:
                raise RuntimeError('Rollback identity inspection changed the current release')
        if (reports['mx1']['previous_proposal_sha256'] != reports['mx2']['previous_proposal_sha256']
            or reports['mx1']['previous_decision_sha256'] != reports['mx2']['previous_decision_sha256']
            or self.inspect() != before or self.validation_node('mx1','database') != database):
            raise RuntimeError('Rollback inspection changed accepted mail, authority or paired decision')
        self.validate_retained_release(operation, previous, before, database)
        since = int(time.time())
        for node in ('mx1','mx2'):
            cancelled = json.loads(self.command(node,'python3',helper,'cancel','--operation',operation))
            if cancelled.get('phase') != 'cancelled':
                raise RuntimeError('Rollback inspection left an unexpected reservation')
        self.fresh_policy(self.new['version'],since)
        for node in self.names:self.ready(node,self.candidate_release)
        self.invariant();self.submit('after_rollback_identity_inspection')
        self.record('rollback_identities_checked_without_downgrade_authority',nodes=reports,
                    source='exact_installed_archive_helpers' if self.args.archive_candidate else 'source_checkout_helpers',
                    foreign_peer_refused=True,downgrade_refused=True)

    def validate_retained_release(self, operation, previous, before, database, *, keep_running=False):
        helper = '/usr/local/libexec/noisefence-management/rollback_validation.py'
        expiry = int(time.time())+(300 if keep_running else 120)
        common = ['--operation',operation,'--previous-operation',previous,
                  '--peer-completion','/root/paired-test/rollback-peer.json','--expires-at',str(expiry)]
        descriptors = {node:json.loads(self.command(node,'python3',helper,'describe',*common))
                       for node in self.names}
        capability = {}
        for node in self.names:
            peer = 'mx2' if node == 'mx1' else 'mx1'
            local = self.root/('retained-'+node+'-descriptor.json')
            local.write_text(json.dumps(descriptors[peer])+'\n')
            remote = '/root/paired-test/retained-peer.json'
            self.run('cp',str(local),self.names[node]+':'+remote)
            self.command(node,'chown','root:root',remote);self.command(node,'chmod','0600',remote)
            usage = self.command(node,'/opt/noisefence/releases/'+self.old['version']+'/noisefence','--help')
            capability[node] = b'validate-runtime' in usage
            # Unsupported retained binaries must fail without releasing the hold.
            result = json.loads(self.command(node,'python3','-c',
                "import json,subprocess,sys; p=subprocess.run(sys.argv[1:],capture_output=True,timeout=40); "
                "print(json.dumps({'exit_code':p.returncode}))", 'python3',helper,'start',*common,
                '--peer-report',remote))
            if capability[node] and result['exit_code'] != 0:
                raise RuntimeError('Capable retained runtime failed to start')
        if len(set(capability.values())) != 1:
            raise RuntimeError('Retained pair disagrees about the maintenance command')
        ready = False
        deadline = time.monotonic()+(30 if all(capability.values()) else 2)
        while True:
            statuses = {node:json.loads(self.command(node,'python3',helper,'status','--operation',operation))
                        for node in self.names}
            if any(row.get('activation_authorized') is not False or row.get('rollback_qualified') is not False
                   for row in statuses.values()):
                raise RuntimeError('Retained validation incorrectly authorized activation')
            ready = all(row.get('validation_ready') is True for row in statuses.values())
            if ready or time.monotonic() >= deadline:break
            time.sleep(.25)
        if keep_running and not ready:
            raise RuntimeError('Positive rollback requires capable retained runtimes on both nodes')
        if ready != all(capability.values()):
            raise RuntimeError('Retained runtime readiness differs from supported validation capability')
        for node in self.names:
            self.command(node,'python3','-c',
                "import json,socket,subprocess,sys; "
                "s=socket.socket();s.settimeout(2);assert s.connect_ex(('127.0.0.1',int(sys.argv[1])))!=0;s.close(); "
                "p=subprocess.run(['systemctl','is-active','noisefence.service'],capture_output=True); "
                "assert p.stdout.strip() in (b'inactive',b'failed'); "
                "r=json.loads(subprocess.check_output(['python3','/usr/local/libexec/noisefence-management/upgrade_reservation.py',"
                "'status','--operation',sys.argv[2]])); "
                "assert all(r[k] is True for k in ('reserved','service_hold','writers_stopped'));print('held')",
                str(2525 if node=='mx1' else 2527),operation)
            if ready:
                if self.apparmor_profile:
                    proof = self.node(node, 'confinement', 'noisefence-validation.service')
                    self.check_confinement(proof, self.binary_hashes[node][self.old['version']])
                    self.record('retained_candidate_apparmor_enforced', node=node, **proof)
                self.validation_node(node,'disabled',node)
            if not keep_running:
                stopped = json.loads(self.command(node,'python3',helper,'stop','--operation',operation))
                if stopped.get('phase') != 'stopped':raise RuntimeError('Retained validation did not stop')
            self.command(node,'python3','-c',
                "import subprocess,sys; p=subprocess.run(['python3','/usr/local/libexec/noisefence-management/upgrade_promotion.py',"
                "'prepare','--operation',sys.argv[1]],capture_output=True,timeout=20);assert p.returncode!=0;print('refused')",operation)
        if self.inspect()!=before or self.validation_node('mx1','database')!=database:
            raise RuntimeError('Retained validation changed accepted mail or the selected database')
        self.record('retained_validation_keeps_normal_writers_held',validation_ready=ready,
                    retained_command_supported=all(capability.values()),activation_authorized=False,
                    ordinary_promotion_refused=True,accepted_mail_and_database_unchanged=True,
                    rollback_qualified=False)

    def retained_call(self, node, helper, action, operation, peer=None, outcome=None, lose_reply=False):
        if helper not in ('rollback_promotion.py','rollback_activation.py'):
            raise ValueError('Unexpected retained fixture helper')
        args=['python3','/usr/local/libexec/noisefence-management/'+helper,action,'--operation',operation]
        if peer is not None:
            local=self.root/(node+'-retained-report.json')
            local.write_text(json.dumps(peer)+'\n')
            remote='/root/paired-test/retained-report.json'
            self.run('cp',str(local),self.names[node]+':'+remote)
            self.command(node,'chown','root:root',remote);self.command(node,'chmod','0600',remote)
            args+=['--peer-report',remote]
        if outcome is not None:args+=['--outcome',outcome]
        if lose_reply:
            # Execute the real helper, verify success, then discard its reply.
            # The next invocation must recover from its durable local receipt.
            self.command(node,'python3','-c',
                "import subprocess,sys; p=subprocess.run(sys.argv[1:],capture_output=True,timeout=60); "
                "assert p.returncode==0,p.stderr[-2048:]; print('reply_discarded')",*args)
            return None
        return json.loads(self.command(node,*args))

    def retained_activation_roundtrip(self):
        if not self.args.archive_candidate:
            raise RuntimeError('Positive rollback qualification requires exact archives')
        previous=self.operation
        completed={node:self.activation(node,'status') for node in self.names}
        if any(row['phase']!='complete' for row in completed.values()):
            raise RuntimeError('Complete the forward pair before rollback')
        operation=str(uuid.uuid4())
        helper='/usr/local/libexec/noisefence-management/upgrade_reservation.py'
        for node in ('mx2','mx1'):
            held=json.loads(self.command(node,'python3',helper,'begin','--operation',operation))
            if held.get('writers_stopped') is not True:raise RuntimeError('Rollback writers not held')
        before=self.inspect();database=self.validation_node('mx1','database')
        for node in self.names:
            peer='mx2' if node=='mx1' else 'mx1'
            local=self.root/(node+'-retained-completion.json')
            local.write_text(json.dumps(completed[peer])+'\n')
            remote='/root/paired-test/rollback-peer.json'
            self.run('cp',str(local),self.names[node]+':'+remote)
            self.command(node,'chown','root:root',remote);self.command(node,'chmod','0600',remote)
        self.validate_retained_release(operation,previous,before,database,keep_running=True)
        promote=lambda node,action,peer=None:self.retained_call(node,'rollback_promotion.py',action,operation,peer)
        activate=lambda node,action,peer=None,**kw:self.retained_call(node,'rollback_activation.py',action,operation,peer,**kw)
        prepared={node:promote(node,'prepare') for node in self.names}
        promoted={node:promote(node,'promote',prepared['mx2' if node=='mx1' else 'mx1']) for node in self.names}
        armed={'mx1':activate('mx1','arm',promoted['mx2'])}
        armed['mx2']=activate('mx2','arm',armed['mx1'])
        decision=activate('mx1','decide',armed['mx2'],outcome='activate')
        accepted=activate('mx2','accept',decision)
        if accepted!=activate('mx2','accept',decision):raise RuntimeError('Retained decision retry changed')
        # Compare the complete database while every normal writer is still held.
        # Once started, legitimate peer heartbeats and delivery retries change it;
        # then verify message generations, body copies and fresh policy instead.
        if self.inspect()!=before or self.validation_node('mx1','database')!=database:
            raise RuntimeError('Rollback preparation or decision changed mail or management data')
        activate('mx1','start',accepted,lose_reply=True)
        started={'mx1':activate('mx1','start',accepted)}
        self.node('mx1','deferred');self.verify_bodies()
        started['mx2']=activate('mx2','start',decision)
        for node in self.names:
            running = self.ready(node,self.old['version'])
            if self.apparmor_profile:
                self.record('retained_runtime_apparmor_enforced', node=node, **running['confinement'])
        deadline=time.monotonic()+40
        while time.monotonic()<deadline:
            try:
                proofs={node:activate(node,'check',started['mx2' if node=='mx1' else 'mx1']) for node in self.names}
                break
            except subprocess.CalledProcessError:time.sleep(.5)
        else:raise RuntimeError('Retained pair has no fresh normal policy/replica proof')
        verified={node:activate(node,'verify',proofs['mx2' if node=='mx1' else 'mx1']) for node in self.names}
        activate('mx1','finish',verified['mx2'],lose_reply=True)
        done={'mx1':activate('mx1','finish',verified['mx2'])}
        done['mx2']=activate('mx2','finish',done['mx1'])
        for node,peer in (('mx1',verified['mx2']),('mx2',done['mx1'])):
            if done[node]!=activate(node,'finish',peer) or done[node]['phase']!='complete':
                raise RuntimeError('Retained completion is not durable and idempotent')
            if done[node]['decision']['protocol']!='noisefence-retained-decision-1':
                raise RuntimeError('Rollback consumed an ordinary upgrade decision')
            self.command(node,'python3','-c',
                "from pathlib import Path; import subprocess; "
                "assert not any((Path('/var/lib/noisefence-upgrade')/n).exists() for n in "
                "['active.json','hold.json','activation.json','activation-jobs.json','promotion.json']); "
                "assert subprocess.check_output(['systemctl','is-active','noisefence-quality.timer']).strip()==b'active'")
        self.final_release=self.old['version']
        self.invariant();self.submit('after_retained_activation')
        self.record('retained_pair_activated_with_current_mail_and_lost_replies',
                    retained_version=self.old['version'],source_version=self.new['version'],
                    database_restored=False,database_unchanged_before_start=True,protocol='noisefence-retained-activation-1',
                    start_reply_lost=True,finish_reply_lost=True,normal_runtime_proofs=proofs)
        # Restore the exact newer pair through a NEW ordinary forward operation.
        # This is not an attempt to undo the committed rollback decision.
        self.precommit_promotion(activation_outcome='activate')
        self.record('new_forward_operation_after_completed_rollback',version=self.new['version'])

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
            if phase == 'upgrade':self.nonforward_validation_refused(version)

    def finish(self, metadata):
        self.invariant()
        snapshots = self.wait_replicas()
        running = {node: self.ready(node, self.final_release) for node in self.names}
        report = {'schema': 'noisefence-paired-lifecycle-1', 'status': 'validated_pending_cleanup',
                  'operation': self.operation, 'checks': self.checks, 'accepted': self.accepted,
                  'final_state': snapshots, 'final_running': running,
                  'staged_binary_sha256': self.binary_hashes, 'installed_helper_sha256': self.helper_hashes,
                  'validation_candidate': self.validation_metadata,
                  'candidate_mode': 'exact_archive' if self.args.archive_candidate else 'local_binary' if self.validation_metadata else 'none',
                  'archive_sha256': {i['version']: i['sha256'] for i in (self.old, self.new)},
                  'archive_commits': {i['version']: i['commit'] for i in (self.old, self.new)},
                  'image_id': metadata['Id'], 'platform': self.args.platform,
                  'apparmor_profile': self.apparmor_profile,
                  'confinement_scope': 'named_profile_enforcement_with_dac_canary' if self.apparmor_profile else 'not_exercised',
                  'network': 'shared_loopback_without_external_route', 'production_affected': False,
                  'scope': 'coordinated_stop_start_archive_pair_with_synthetic_selected_authority',
                  'sequence': 'both_stopped_before_switching_either_binary',
                  'not_qualified': (['other_archive_pairs', 'archive_provenance'] if self.args.archive_candidate else ['final_release_archives']) + (['post_activation_rollback'] if not getattr(self.args,'require_retained_activation',False) else []) + ['production_updater', 'external_delivery',
                                    'rolling_mixed_build_upgrade', 'live_models', 'failover_after_loss', 'performance', 'detection_accuracy']}
        (self.root/'paired-lifecycle-report.json').write_text(json.dumps(report, indent=2)+'\n')

    def close(self):
        failures = []
        for node in reversed(self.created):
            # Diagnostics cannot prevent container cleanup or publish private state.
            try:
                runtime = self.command(node, 'python3', '/root/source/tests/fixtures/runtime_diagnostics.py',
                                       '--node', node, timeout=15)
                (self.root/(node+'-runtime-diagnostic.json')).write_bytes(runtime)
            except Exception:
                pass
            if node == 'mx1':
                try:
                    management = self.command(node, 'python3', '/root/source/tests/fixtures/runtime_diagnostics.py',
                                              '--node', node, '--management', timeout=25)
                    (self.root/'mx1-management-diagnostic.json').write_bytes(management)
                except Exception:
                    pass
            try:
                journal = self.command(node, 'journalctl', '-u', 'noisefence.service', '--no-pager', '-n', '100', timeout=20)
                (self.root/(node+'-journal.log')).write_bytes(journal)
                ssh_log = self.command(node, 'journalctl', '-u', 'paired-upgrade-ssh.service', '--no-pager', '-n', '60', timeout=20)
                (self.root/(node+'-exchange-journal.log')).write_bytes(ssh_log)
                validation_log = self.command(node, 'journalctl', '-u', 'noisefence-validation.service', '--no-pager', '-n', '100', timeout=20)
                (self.root/(node+'-validation-journal.log')).write_bytes(validation_log)
                validation_paths = self.command(node, 'python3', '-c', "import json,os; from pathlib import Path; roots=['/root/paired-test/validation-peer.json','/usr/local/libexec/noisefence-management/upgrade_validation.service','/var/lib/noisefence-upgrade/validation.json']; result=[]; seen=set();\nfor root in roots:\n for p in [Path(root),*Path(root).parents]:\n  if p in seen or not p.exists():continue\n  seen.add(p);s=p.lstat();result.append({'path':str(p),'uid':s.st_uid,'mode':oct(s.st_mode&0o7777),'link':p.is_symlink()})\nprint(json.dumps(result))", timeout=20)
                (self.root/(node+'-validation-paths.json')).write_bytes(validation_paths)
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
    candidate = parser.add_mutually_exclusive_group()
    candidate.add_argument('--validation-candidate', type=Path, help='Optional locally built release-profile semantic binary plus candidate.json; never a production archive')
    candidate.add_argument('--archive-candidate', action='store_true', help='Exercise candidate activation using the exact new archive and its native helpers, without rewriting artifacts')
    parser.add_argument('--apparmor-profile', help='Unique noisefence-test-<12 hex> profile already enforced on the disposable Linux host; missing enforcement fails')
    parser.add_argument('--require-retained-activation', action='store_true', help='Require a capable retained archive and a complete reverse activation; never accept a skipped probe')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(); os.umask(0o077)
    old, new = (archive(p, args.platform.split('/')[1]) for p in [args.old_archive, args.new_archive])
    if precedence(old['version']) >= precedence(new['version']):
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
        lab.maintenance_reservation(); lab.precommit_promotion(); lab.precommit_promotion(abandon=True); lab.failure_recovery(); lab.rollout(); lab.precommit_promotion(activation_outcome='abort'); lab.precommit_promotion(activation_outcome='activate'); lab.rollback_identity_prerequisites()
        if args.require_retained_activation:lab.retained_activation_roundtrip()
        lab.finish(metadata)
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
