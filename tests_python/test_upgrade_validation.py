"""Candidate supervision failures preserve the independent normal-service hold."""
import copy
import errno
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'deploy/postgresql'))
import upgrade_validation as validation
import upgrade_reservation as reservation
from migration_protocol import canonical

OP='00000000-0000-4000-8000-000000000001'
OTHER='00000000-0000-4000-8000-000000000002'


def descriptor(node='mx1'):
    policy={'sequence':1,'revision':1,'digest':'a'*64}
    return {'protocol':validation.DESCRIPTOR,'operation':OP,'expires_at':int(time.time())+600,
        'selection':{'protocol':'noisefence-management-selection-1','database':{'instance':OP,'source_digest':'b'*64},
          'node':{'node':node,'epoch':OP if node=='mx1' else OTHER},'role':'coordinator' if node=='mx1' else 'worker',
          'baseline':policy.copy(),'mfa_key_sha256':'c'*64 if node=='mx1' else None},
        'policy':policy,'candidate':{'directory':'/opt/noisefence/releases/candidate','binary_sha256':'d'*64,
          'manifest_sha256':'e'*64,'build_sha256':'f'*64,'version':'0.31.9','commit':'1'*40,'platform':'linux-arm64'},
        'config_sha256':'2'*64,'service_sha256':__import__('hashlib').sha256(b'synthetic unit').hexdigest(),'replica_peer':'mx2' if node=='mx1' else 'mx1'}


class ValidationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve();self.events=[];self.active='inactive'
        self.own=descriptor();self.peer=descriptor('mx2');self.peer['expires_at']=self.own['expires_at']
        self.hold=types.SimpleNamespace(owner=lambda:None)
        for module,name,value in [(reservation,'STATE',self.root),(validation,'PLAN',self.root/'plan.json'),
                (validation,'LINK',self.root/'candidate'),(validation,'UNIT',self.root/'validation.service'),
                (reservation,'protected',lambda path,directory=False:Path(path).stat()),
                (reservation,'unit_state',lambda unit:self.active if unit==validation.SERVICE else 'inactive'),
                (reservation,'execute',self.execute),(validation,'held',lambda operation:self.hold),
                (validation,'service_files',lambda **kw:None),(validation,'unit_template',lambda:b'synthetic unit'),(validation,'describe',self.describe),
                (reservation,'Reservation',lambda operation:self.hold)]:
            p=patch.object(module,name,value);p.start();self.addCleanup(p.stop)
        # Real root ownership and systemd are checked by the native paired fixture.
        def root_lstat(path):
            result=original_lstat(path)
            if Path(path) in [validation.LINK,validation.LINK.with_name(validation.LINK.name+'.next')]:
                return types.SimpleNamespace(st_mode=result.st_mode,st_uid=0)
            return result
        original_lstat=Path.lstat
        p=patch.object(Path,'lstat',root_lstat);p.start();self.addCleanup(p.stop)
        self.operation=validation.Validation(OP)

    def describe(self,operation,directory,expires_at):
        self.assertEqual(operation,OP);self.assertEqual(str(directory),self.own['candidate']['directory'])
        self.assertEqual(expires_at,self.own['expires_at'])
        return copy.deepcopy(self.own)

    def execute(self,args):
        self.events.append(args)
        if args[1]=='start':
            self.assertTrue(self.operation.marker.exists());self.assertTrue(validation.PLAN.exists())
            self.assertTrue(validation.LINK.is_symlink());self.active='active'
        if args[1]=='stop':
            self.assertFalse(validation.PLAN.exists());self.assertTrue(self.operation.marker.exists())
            self.active='inactive'
        if '--property=MainPID' in args:return b'0\n'
        return b''

    def start(self):
        return self.operation.start(Path(self.own['candidate']['directory']),self.peer,self.own['expires_at'])

    def test_same_request_resumes_but_changed_peer_never_adopts(self):
        self.assertFalse(self.start()['validation_ready'])
        self.assertEqual(self.operation.state()['phase'],'started')
        self.assertEqual(self.start()['phase'],'started')
        self.peer['candidate']['binary_sha256']='0'*64
        with self.assertRaisesRegex(ValueError,'authorization changed'):self.start()
        self.assertTrue(self.operation.marker.exists())

    def test_disconnect_after_start_is_recoverable_and_marker_blocks_cancel(self):
        actual=self.execute
        def disconnect(args):
            result=actual(args)
            if args[1]=='start':raise EOFError('lost start response')
            return result
        with patch.object(reservation,'execute',disconnect):
            with self.assertRaises(EOFError):self.start()
        self.assertEqual(self.operation.state()['phase'],'prepared');self.assertEqual(self.active,'active')
        self.assertFalse(self.operation.status()['validation_ready'])
        self.assertEqual(self.start()['phase'],'started')

    def test_full_disk_before_authorization_never_starts_and_retries(self):
        actual=validation.atomic
        def full(path,raw,**kw):
            if path==validation.PLAN:raise OSError(errno.ENOSPC,'full')
            actual(path,raw,**kw)
        with patch.object(validation,'atomic',full):
            with self.assertRaises(OSError):self.start()
        self.assertTrue(self.operation.marker.exists());self.assertEqual(self.active,'inactive')
        self.assertFalse(any(e[1]=='start' for e in self.events))
        self.start()

    def test_stop_revokes_before_wait_and_never_resumes_normal_daemon(self):
        self.start();self.events.clear()
        stopped=self.operation.stop();self.assertEqual(stopped,self.operation.stop())
        self.assertFalse(self.operation.marker.exists());self.assertFalse(validation.PLAN.exists())
        self.assertFalse(validation.LINK.is_symlink())
        self.assertEqual([e[1:3] for e in self.events],[['stop',validation.SERVICE]])
        with self.assertRaisesRegex(ValueError,'already finished'):self.start()

    def test_stop_failure_preserves_marker_and_can_resume_after_expiry(self):
        self.start();actual=self.execute
        def fail(args):
            if args[1]=='stop':raise TimeoutError('stop timeout')
            return actual(args)
        with patch.object(reservation,'execute',fail):
            with self.assertRaises(TimeoutError):self.operation.stop()
        self.assertFalse(validation.PLAN.exists());self.assertTrue(self.operation.marker.exists())
        self.assertEqual(self.operation.status()['phase'],'stopping')
        self.assertFalse(self.operation.status()['validation_ready'])
        with patch.object(validation.time,'time',return_value=self.own['expires_at']+5):
            self.operation.stop()
        self.assertFalse(self.operation.marker.exists())

    def test_lost_terminal_response_only_finishes_marker_removal(self):
        self.start();actual=reservation.remove
        def fail(path):
            if path==self.operation.marker:raise OSError('lost final sync')
            actual(path)
        with patch.object(reservation,'remove',fail):
            with self.assertRaises(OSError):self.operation.stop()
        self.assertEqual(self.operation.state()['phase'],'stopped');self.events.clear()
        self.operation.stop();self.assertFalse(self.events)

    def test_unowned_plan_and_other_operation_refuse_without_start(self):
        validation.PLAN.write_bytes(canonical(validation.authorize(self.own,self.peer)))
        with self.assertRaisesRegex(ValueError,'Unowned'):self.start()
        validation.PLAN.unlink()
        self.operation.marker.write_bytes(canonical({'protocol':validation.PROTOCOL,'operation':OTHER}))
        with self.assertRaisesRegex(ValueError,'Another operation'):self.start()
        self.assertFalse(self.events)

    def test_read_status_does_not_install_service_or_create_a_plan(self):
        self.start();validation.PLAN.unlink()
        with patch.object(validation,'service_files',side_effect=AssertionError('must not inspect revoked service')):
            self.assertFalse(self.operation.status()['validation_ready'])
        self.assertFalse(validation.PLAN.exists())


class DescriptorTests(unittest.TestCase):
    def test_exact_pair_source_and_expiry_required_but_platform_hash_can_differ(self):
        own=descriptor();peer=descriptor('mx2');peer['expires_at']=own['expires_at']
        peer['candidate']['platform']='linux-amd64';peer['candidate']['binary_sha256']='0'*64
        self.assertEqual(validation.authorize(own,peer)['peer']['binary_sha256'],'0'*64)
        for path,value in [('operation',OTHER),('expires_at',own['expires_at']+1),('replica_peer','mx3')]:
            changed=copy.deepcopy(peer);changed[path]=value
            with self.assertRaises(ValueError):validation.authorize(own,changed)
        for field in ['version','commit']:
            changed=copy.deepcopy(peer);changed['candidate'][field]='0.32.0' if field=='version' else '2'*40
            with self.assertRaises(ValueError):validation.authorize(own,changed)
        for path in ['instance','source_digest']:
            changed=copy.deepcopy(peer);changed['selection']['database'][path]=OTHER if path=='instance' else '0'*64
            with self.assertRaises(ValueError):validation.authorize(own,changed)
        changed=copy.deepcopy(peer);changed['policy']['sequence']+=1
        with self.assertRaises(ValueError):validation.authorize(own,changed)
        changed=copy.deepcopy(peer);changed['selection']['unexpected']=True
        with self.assertRaises(ValueError):validation.authorize(own,changed)


class UnitTemplateTests(unittest.TestCase):
    def test_inherit_profiles_without_command_or_newline_injection(self):
        with patch.object(reservation,'protected',lambda p,directory=False:Path(p).stat()):
            with patch.object(reservation,'execute',side_effect=[b'noisefence\n',b'system_u:system_r:mail_t:s0\n']):
                raw=validation.unit_template()
                self.assertIn(b'AppArmorProfile=noisefence\n',raw)
                self.assertIn(b'SELinuxContext=system_u:system_r:mail_t:s0\n',raw)
                self.assertIn(b'User=noisefence\n',raw)
            with patch.object(reservation,'execute',return_value=b'profile\nExecStart=/bin/false'):
                with self.assertRaisesRegex(ValueError,'Unsupported'):validation.unit_template()
