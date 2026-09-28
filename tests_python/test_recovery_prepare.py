"""Offline coordinator ordering/retry tests; no service or database is started."""
import hashlib
import json
import os
import types
from pathlib import Path
import sys
import tempfile
import time
import tomllib
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'deploy/postgresql'))
import recovery_prepare as recovery


class ConfigurationTests(unittest.TestCase):
    def test_console_checkpoint_reconstructs_only_offline_reciprocal_pair(self):
        raw=b'[cluster]\nrole="coordinator"\nnode_id="mx1"\n[smtp]\nlisten="127.0.0.1:0"\n'
        worker={'cluster':{'role':'worker','node_id':'mx2'},'replication':{
            'peer_id':'mx1','peer_url':'http://127.0.0.1:19080','allow_loopback_http':True,
            'credential_file':'/etc/noisefence/replica.key','timeout_seconds':30}}
        result=recovery.queue_source_config(raw,worker,'https://mx2.example.test')
        cfg=tomllib.loads(result.decode())
        self.assertEqual(cfg['smtp']['listen'],'127.0.0.1:0')
        self.assertEqual(cfg['replication'],{**worker['replication'],'peer_id':'mx2',
            'peer_url':'https://mx2.example.test','allow_loopback_http':False})
        self.assertEqual({k:v for k,v in cfg.items() if k!='replication'},tomllib.loads(raw.decode()))
        self.assertEqual(recovery.queue_source_config(result,worker,'https://mx2.example.test'),result)
        with self.assertRaises(ValueError):recovery.queue_source_config(raw,{},'https://mx2.example.test')
        with self.assertRaises(ValueError):recovery.queue_source_config(raw,worker,'http://mx2.example.test')
        worker['replication']['peer_id']='other'
        with self.assertRaises(ValueError):recovery.queue_source_config(result,worker,'https://mx2.example.test')

    def test_connection_and_queue_path_change_only_expected_values(self):
        raw = b'''hostname="mx1.example.test"
data_dir="/var/lib/noisefence"
[management]
backend="postgresql"
[management.connection]
host="/run/postgresql"
database="noisefence"
username="noisefence"
port=5432
max_connections=4
[cluster]
role="coordinator"
node_id="mx1"
'''
        connection = {'host':'/run/postgresql','database':'nf_recovery_test','username':'noisefence','port':5432,'max_connections':4}
        original = tomllib.loads(raw.decode())
        expected = json.loads(json.dumps(original))
        expected['management']['connection'] = connection
        self.assertEqual(tomllib.loads(recovery.connection_config(raw,connection).decode()), expected)
        expected['data_dir'] = '/private/stage/data'
        self.assertEqual(tomllib.loads(recovery.connection_config(raw,connection,Path(expected['data_dir'])).decode()), expected)
        with self.assertRaises(ValueError):
            recovery.connection_config(raw.replace(b'backend="postgresql"',b'backend="coordinator"'),connection)

    def test_https_console_source_preserves_other_settings_and_requires_secure_cookies(self):
        raw=b'[web]\nlisten="127.0.0.1:18080"\npublic_origin="http://127.0.0.1:18080"\nsecure_cookies=false\n[filter]\nthreshold=95\n'
        changed=recovery.console_source_config(raw,'https://mx2.example.test')
        expected=tomllib.loads(raw.decode())
        expected['web'].update(public_origin='https://mx2.example.test',secure_cookies=True)
        self.assertEqual(tomllib.loads(changed.decode()),expected)
        self.assertEqual(recovery.console_source_config(changed,'https://mx2.example.test'),changed)
        with self.assertRaises(ValueError):recovery.console_source_config(raw,'http://127.0.0.1:18081')

    def test_ambiguous_connection_layout_refuses(self):
        with self.assertRaises(ValueError):
            recovery.connection_config(b'data_dir="/data"\n[management]\nbackend="postgresql"\nconnection={host="/run/postgresql"}\n',{})

    def test_fence_must_match_operation_and_final_checkpoint_order(self):
        now = int(time.time())
        operation = '00000000-0000-4000-8000-000000000001'
        manifest = {'owner':'mx1','created':now,'fence_operation':operation,'started_ns':100}
        fence = {'owner':'mx1','operation':operation,'fenced':True,'created':now,'created_ns':90,'method':'systemd-persistent-condition'}
        recovery.fencing(fence,manifest,operation,False)
        for changed in [{**fence,'fenced':False},{**fence,'created':now-4000},{**fence,'created_ns':101}]:
            with self.assertRaises(ValueError):
                recovery.fencing(changed,manifest,operation,False)
        with self.assertRaises(ValueError):
            recovery.fencing(fence,manifest,operation,True)
        recovery.fencing({**fence,'method':'provider-poweroff','reference':'provider test receipt'},manifest,operation,True)


class QueueCommandTests(unittest.TestCase):
    def test_selected_queue_restore_uses_explicit_management_configuration(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve()
            (root/'config').mkdir();(root/'private').mkdir()
            (root/'config/config.toml').write_text('data_dir="/old"\n[management]\nbackend="postgresql"\n[management.connection]\nhost="/run/postgresql"\n[cluster]\nrole="coordinator"\nnode_id="mx1"\n')
            stage=recovery.Preparation.__new__(recovery.Preparation)
            stage.active=root;stage.private=root/'private';stage.data=root/'data'
            stage.connection={'host':'/run/postgresql','database':'restored','username':'noisefence','port':5432,'max_connections':4}
            stage.account=types.SimpleNamespace(pw_uid=os.getuid(),pw_gid=os.getgid())
            stage.plan={'operation':'test-operation','fence':{},'console_url':'https://mx2.example.test'}
            stage.manifest={'owner':'mx1'}
            stage.worker_config={'data_dir':'/worker','cluster':{'role':'worker','node_id':'mx2'},
                'replication':{'peer_id':'mx1','credential_file':'/etc/noisefence/replica.key'}}
            stage.private_file=lambda *args:None
            commands=[]
            def native(*args):
                commands.append(args)
                return {'operation':'test-operation','smtp_started':False}
            stage.native=native
            stage.queue()
            self.assertEqual(commands[0][:3],('ha-restore','--management-config',root/'private/queue.toml'))
            self.assertEqual(tomllib.loads((root/'private/queue.toml').read_text())['data_dir'],str(root/'data'))


class CheckpointTests(unittest.TestCase):
    def fixture(self, root):
        files = {}
        for name, content in {'config/config.toml':b'hostname="mx1.example.test"',
                'data/state.sqlite3':b'synthetic-checksum-fixture', 'data/mfa.key':b'x'*32,
                'data/management.postgresql.dump':b'PGDMPsynthetic'}.items():
            path = root/name
            path.parent.mkdir(parents=True,exist_ok=True)
            path.write_bytes(content)
            path.chmod(0o600)
            files[name] = {'bytes':len(content),'sha256':hashlib.sha256(content).hexdigest()}
        manifest = {'protocol':'noisefence-console-2','postgresql_restore_required':True,
            'snapshot':'00000000-0000-4000-8000-000000000001','files':files}
        raw = json.dumps(manifest).encode()
        (root/'manifest.json').write_bytes(raw)
        return hashlib.sha256(raw).hexdigest()

    def test_changed_file_and_unlisted_content_refuse(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(recovery,'protected'):
            root=Path(tmp).resolve()
            digest=self.fixture(root)
            recovery.checkpoint(root,digest)
            key=root/'data/mfa.key'
            key.write_bytes(b'z'*32)
            with self.assertRaisesRegex(ValueError,'Checkpoint file changed'):
                recovery.checkpoint(root,digest)
            key.write_bytes(b'x'*32)
            (root/'unlisted').write_text('unlisted')
            with self.assertRaisesRegex(ValueError,'Unlisted'):
                recovery.checkpoint(root,digest)

    def test_symlink_and_wrong_manifest_digest_refuse(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(recovery,'protected'):
            root=Path(tmp).resolve()
            digest=self.fixture(root)
            with self.assertRaisesRegex(ValueError,'manifest changed'):
                recovery.checkpoint(root,'0'*64)
            (root/'data/link').symlink_to(root/'data/mfa.key')
            with self.assertRaisesRegex(ValueError,'Unlisted'):
                recovery.checkpoint(root,digest)


class OrderingTests(unittest.TestCase):
    def fixture(self, root, phase='new'):
        subject = recovery.Preparation.__new__(recovery.Preparation)
        subject.plan = {'operation':'00000000-0000-4000-8000-000000000001','manifest_sha256':'a'*64}
        subject.manifest = {'snapshot':'00000000-0000-4000-8000-000000000002'}
        subject.state = {'phase':phase}
        subject.active = root/'active'
        subject.active.mkdir()
        (subject.active/'recovery-stage.json').write_text(json.dumps({'operation':subject.plan['operation'],
            'snapshot':subject.manifest['snapshot'],'manifest_sha256':'a'*64}))
        subject.credentials = root/'admin.json'
        subject.native_plan = root/'plan.json'
        subject.events = []
        for name in ('copy','database','queue','console','install','plan_native'):
            setattr(subject,name,lambda n=name:subject.events.append(n))
        subject.managed = lambda command,status,*options:subject.events.append(command+(' activate' if options else ''))
        def save(phase):
            subject.events.append('save:'+phase)
            subject.state['phase'] = phase
        subject.save = save
        return subject

    def run_subject(self, subject, root):
        with patch.object(recovery.recovery_install,'STATE',root/'fence'), \
             patch.object(recovery,'protected'), \
             patch.object(recovery.recovery_install,'fence',lambda operation:subject.events.append('fence')):
            return subject.run()

    def test_entire_offline_chain_keeps_services_stopped(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            subject=self.fixture(root)
            result=self.run_subject(subject,root)
            actual=[e for e in subject.events if e != 'plan_native' and not e.startswith('save:')]
            self.assertEqual(actual,['fence','copy','database','queue','console',
                'management-recovery-attach-workers','management-recovery-prepare','install',
                'management-recovery-prepare activate','management-recovery-release-workers'])
            self.assertFalse(result['services_started'])
            self.assertFalse(result['worker_queue_replaced'])
            self.assertFalse(result['http_routing_changed'])

    def test_failed_key_publication_does_not_authorize_console_or_worker(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            subject=self.fixture(root)
            def fail():
                raise OSError('publication interrupted')
            subject.install=fail
            with self.assertRaises(OSError):
                self.run_subject(subject,root)
            self.assertEqual(subject.state['phase'],'management_prepared')
            self.assertNotIn('management-recovery-release-workers',subject.events)
            subject.events.clear()
            subject.install=lambda:subject.events.append('install')
            self.run_subject(subject,root)
            actual=[e for e in subject.events if e != 'plan_native' and not e.startswith('save:')]
            self.assertEqual(actual,['fence','database','install','management-recovery-prepare activate','management-recovery-release-workers'])

    def test_lost_worker_release_reply_retries_release_not_access_revocation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            subject=self.fixture(root,'console_authorized')
            self.run_subject(subject,root)
            actual=[e for e in subject.events if e != 'plan_native' and not e.startswith('save:')]
            self.assertEqual(actual,['fence','database','management-recovery-release-workers'])
            subject.events.clear()
            self.run_subject(subject,root)
            self.assertEqual(subject.events,['fence','database','plan_native','management-recovery-release-workers'])

    def test_failed_database_revalidation_does_not_continue(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            subject=self.fixture(root,'keys_installed')
            subject.database=lambda:(_ for _ in ()).throw(ValueError('binding changed'))
            with self.assertRaises(ValueError):
                self.run_subject(subject,root)
            self.assertEqual(subject.events,['fence'])

    def test_native_reply_requires_matching_operation_and_status(self):
        subject=recovery.Preparation.__new__(recovery.Preparation)
        subject.plan={'operation':'expected'}
        subject.native_plan=Path('/private/plan.json')
        subject.native=lambda *args:{'operation':'other','status':'prepared_not_activated'}
        with self.assertRaises(ValueError):
            subject.managed('management-recovery-prepare','prepared_not_activated')
