"""Pre-commit pointer changes: durable pair binding and fault recovery."""
import contextlib
import copy
import errno
import hashlib
import json
import os
from pathlib import Path
import sys
import stat
import tempfile
import time
import types
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'deploy/postgresql'))
import upgrade_promotion as promotion
import upgrade_reservation as reservation
import upgrade_validation as validation
from migration_protocol import canonical
from tests_python.test_upgrade_validation import descriptor, OP, OTHER


class Host:
    def __init__(self, root, node, expiry):
        self.root = root/node; self.root.mkdir()
        self.state_dir = self.root/'state'; self.state_dir.mkdir()
        self.current = self.root/'current'
        self.old = self.root/'releases/old'; self.old.mkdir(parents=True)
        self.new = self.root/'releases/new'; self.new.mkdir()
        self.current.symlink_to('releases/old')
        self.own = descriptor(node); self.own['expires_at'] = expiry
        self.own['candidate']['directory'] = str(self.new)
        self.old_identity = {**self.own['candidate'], 'directory': str(self.old), 'version': '0.31.8', 'commit': '3'*40,
                             'binary_sha256': '4'*64, 'manifest_sha256': '5'*64, 'build_sha256': '6'*64}
        self.installed = {'node': node, 'role': self.own['selection']['role'], 'config_sha256': self.own['config_sha256'],
            'current_link': 'releases/old', 'release_directory': str(self.old),
            **{k:self.old_identity[k] for k in ('binary_sha256', 'manifest_sha256', 'build_sha256')},
            'selection_sha256': promotion.fingerprint(self.own['selection'])}
        self.service_hash = 'a'*64; self.stopped = True; self.held = True; self.ready = True
        self.validation_stopped = False; self.events = []; self.peer = None; self.policy = copy.deepcopy(self.own['policy'])
        self.hold = types.SimpleNamespace(owner=lambda: None,
            state=lambda: {'installation': self.installed},
            status=lambda: {'phase':'held', 'reserved':True, 'service_hold':self.held, 'writers_stopped':self.stopped})

    def installation(self):
        target = self.current.resolve()
        release = self.old_identity if target == self.old else self.own['candidate']
        return {**self.installed, 'current_link':os.readlink(self.current), 'release_directory':str(target),
                **{k:release[k] for k in ('binary_sha256', 'manifest_sha256', 'build_sha256')}}

    def stop_validation(self):
        self.events.append('stop_validation'); self.validation_stopped = True
        return {'phase':'stopped'}

    @contextlib.contextmanager
    def enter(self):
        with contextlib.ExitStack() as stack:
            native = Path.lstat
            def root_link(path):
                info = native(path)
                if stat.S_ISLNK(info.st_mode):
                    return types.SimpleNamespace(st_mode=info.st_mode, st_uid=0)
                return info
            validation_path=self.state_dir/'validation-receipt.json';validation_path.touch()
            dummy = types.SimpleNamespace(path=validation_path, marker=self.state_dir/'validation.json',
                status=lambda: {'validation_ready':self.ready},
                state=lambda: {'own':self.own, 'peer':self.peer}, stop=self.stop_validation)
            for module,key,value in [
                (reservation,'STATE',self.state_dir), (reservation,'CURRENT',self.current),
                (reservation,'protected',lambda p,directory=False:Path(p).stat()),
                (reservation,'Reservation',lambda operation:self.hold), (reservation,'installation',self.installation),
                (reservation,'unit_state',lambda unit:'inactive' if self.validation_stopped else 'active'),
                (validation,'Validation',lambda operation:dummy), (validation,'held',lambda operation:self.hold),
                (validation,'policy_epoch',lambda:self.policy),
                (validation,'candidate',lambda p:copy.deepcopy(self.old_identity if p==self.old else self.own['candidate'])),
                (promotion,'service_fingerprint',lambda:self.service_hash), (Path,'lstat',root_link)]:
                stack.enter_context(patch.object(module,key,value))
            yield promotion.Promotion(OP)


class PromotionTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        root = Path(temp.name).resolve(); expiry = int(time.time())+600
        self.a, self.b = Host(root,'mx1',expiry), Host(root,'mx2',expiry)
        self.a.peer = copy.deepcopy(self.b.own); self.b.peer = copy.deepcopy(self.a.own)
        for host in [self.a,self.b]:
            with host.enter() as operation: operation.prepare()

    def report(self, host):
        with host.enter() as operation:return operation.report()

    def promote_pair(self):
        peer_a,peer_b = self.report(self.a),self.report(self.b)
        with self.a.enter() as operation: operation.promote(peer_b)
        with self.b.enter() as operation: operation.promote(peer_a)

    def test_promotion_never_starts_normal_services_and_both_restore_before_release(self):
        self.promote_pair()
        for host in [self.a,self.b]:
            self.assertEqual(host.current.resolve(),host.new)
            self.assertTrue(host.validation_stopped); self.assertTrue(host.held)
            self.assertTrue((host.state_dir/'promotion.json').exists())
            self.assertEqual(host.events,['stop_validation'])
        with self.a.enter() as operation:
            restored_a = operation.restore()
            with self.assertRaisesRegex(ValueError,'Both original'):operation.release(self.report(self.b))
        with self.b.enter() as operation:restored_b = operation.restore()
        for host,peer in [(self.a,restored_b),(self.b,restored_a)]:
            with host.enter() as operation:
                result = operation.release(peer)
                self.assertEqual(result,operation.release(peer))
                self.assertEqual(result['phase'],'released')
                self.assertFalse(operation.marker.exists())
            self.assertEqual(os.readlink(host.current),'releases/old'); self.assertTrue(host.held)

    def test_changed_peer_or_original_build_refused_before_stop_or_switch(self):
        original = self.report(self.b)
        for field in ['version','commit']:
            peer=copy.deepcopy(original); peer['descriptor']['original'][field]='0.30.0' if field=='version' else '8'*40
            with self.a.enter() as operation:
                with self.assertRaisesRegex(ValueError,'same original'): operation.promote(peer)
            self.assertFalse(self.a.events)
        peer=copy.deepcopy(original);peer['descriptor']['own']['candidate']['binary_sha256']='0'*64
        with self.a.enter() as operation:
            with self.assertRaises(ValueError):operation.promote(peer)
        self.assertEqual(self.a.current.resolve(),self.a.old)

    def test_held_writers_policy_services_and_expiry_are_separate_guards(self):
        peer=self.report(self.b)
        for key,changed in [('held',False),('stopped',False),('service_hash','0'*64),('policy',{'sequence':2,'revision':2,'digest':'0'*64})]:
            before=getattr(self.a,key);setattr(self.a,key,changed)
            with self.a.enter() as operation:
                with self.assertRaises(ValueError):operation.promote(peer)
            setattr(self.a,key,before)
        with self.a.enter() as operation, patch.object(promotion.time,'time',return_value=self.a.own['expires_at']):
            with self.assertRaisesRegex(ValueError,'expired'):operation.promote(peer)
            self.assertEqual(operation.restore()['phase'],'restored')
        self.assertEqual(self.a.current.resolve(),self.a.old)

    def test_crash_after_pointer_replace_resumes_same_intent(self):
        peer=self.report(self.b); actual=reservation.sync_directory
        def lost(path):
            actual(path)
            if path==self.a.current.parent:raise EOFError('lost response')
        with self.a.enter() as operation:
            with patch.object(reservation,'sync_directory',lost):
                with self.assertRaises(EOFError):operation.promote(peer)
            self.assertEqual(operation.state()['phase'],'promoting')
            self.assertEqual(self.a.current.resolve(),self.a.new)
            self.assertEqual(operation.promote(peer)['phase'],'promoted')
            self.assertEqual(operation.promote(peer)['phase'],'promoted')
            self.assertTrue(operation.marker.exists())

    def test_full_disk_before_durable_intent_does_not_stop_or_switch(self):
        peer=self.report(self.b); actual=promotion.atomic
        def full(path,raw,**kw):
            if b'"phase":"promoting"' in raw:raise OSError(errno.ENOSPC,'full')
            return actual(path,raw,**kw)
        with self.a.enter() as operation:
            with patch.object(promotion,'atomic',full):
                with self.assertRaises(OSError):operation.promote(peer)
            self.assertEqual(operation.state()['phase'],'prepared')
            self.assertEqual(self.a.current.resolve(),self.a.old); self.assertFalse(self.a.events)
            operation.promote(peer)

    def test_pending_replace_then_restore_preserves_original_link_text(self):
        peer=self.report(self.b)
        with self.a.enter() as operation:
            actual=promotion.os.replace
            def failed_replace(source,target):
                if target==self.a.current:raise OSError('rename failed')
                return actual(source,target)
            with patch.object(promotion.os,'replace',failed_replace):
                with self.assertRaises(OSError):operation.promote(peer)
            temporary=self.a.current.parent/('.noisefence-upgrade-'+OP)
            self.assertTrue(temporary.is_symlink())
            self.assertEqual(operation.restore()['phase'],'restored')
            self.assertFalse(temporary.exists()); self.assertEqual(os.readlink(self.a.current),'releases/old')

    def test_lost_release_response_retries_without_changing_other_paths(self):
        with self.a.enter() as operation:a=operation.restore()
        with self.b.enter() as operation:b=operation.restore()
        actual=reservation.remove
        def lost(path):
            if path.name=='promotion.json':raise EOFError('lost')
            actual(path)
        with self.a.enter() as operation:
            with patch.object(reservation,'remove',lost):
                with self.assertRaises(EOFError):operation.release(b)
            self.assertEqual(operation.state()['phase'],'released')
            self.assertTrue(operation.marker.exists())
            operation.release(b);self.assertFalse(operation.marker.exists())
            self.a.held=False # Historical retry after cancellation never touches services.
            self.assertEqual(operation.release(b)['phase'],'released')

    def test_changed_or_unknown_pointer_activation_marker_refuse_restore(self):
        self.promote_pair()
        with self.a.enter() as operation:
            marker=self.a.state_dir/'activation.json';marker.write_text('{}')
            with self.assertRaisesRegex(ValueError,'Activation'):operation.restore()
            marker.unlink();self.a.current.unlink();self.a.current.symlink_to(self.a.root/'unknown')
            with self.assertRaisesRegex(ValueError,'neither authorized'):operation.restore()
            self.assertTrue(operation.marker.exists())

    def test_prepare_requires_live_validation_and_receipt_before_marker_is_recoverable(self):
        with self.a.enter() as operation:
            operation.path.unlink();operation.marker.unlink();self.a.ready=False
            with self.assertRaisesRegex(ValueError,'Live candidate'):operation.prepare()
            self.assertFalse(operation.path.exists());self.a.ready=True
            actual=promotion.atomic
            def full(path,raw,**kw):
                if path==operation.marker:raise OSError(errno.ENOSPC,'full')
                return actual(path,raw,**kw)
            with patch.object(promotion,'atomic',full):
                with self.assertRaises(OSError):operation.prepare()
            self.assertEqual(operation.state()['phase'],'prepared');self.assertFalse(operation.marker.exists())
            self.assertEqual(operation.prepare()['phase'],'prepared');self.assertTrue(operation.marker.exists())

    def test_peer_failure_before_prepare_can_abort_without_fabricated_validation(self):
        a=self.report(self.a)
        with self.b.enter() as operation:
            operation.path.unlink();operation.marker.unlink();self.b.ready=False
            b=operation.abandon(a)
            self.assertIsNone(b['descriptor']['validated_at']);self.assertEqual(b['phase'],'restored')
            self.assertEqual(operation.abandon(a),b)
            with self.assertRaises(ValueError):operation.promote(a)
        with self.a.enter() as operation:a=operation.restore()
        with self.b.enter() as operation:operation.release(a)
        with self.a.enter() as operation:operation.release(b)
        self.assertEqual(self.a.current.resolve(),self.a.old);self.assertEqual(self.b.current.resolve(),self.b.old)

    def test_retry_must_sync_even_when_rename_already_matches_after_crash(self):
        peer=self.report(self.b);actual=reservation.sync_directory
        def crash_before_sync(path):
            if path==self.a.current.parent:raise EOFError('power loss before fsync')
            actual(path)
        with self.a.enter() as operation:
            with patch.object(reservation,'sync_directory',crash_before_sync):
                with self.assertRaises(EOFError):operation.promote(peer)
            self.assertEqual(self.a.current.resolve(),self.a.new)
            with patch.object(reservation,'sync_directory',wraps=actual) as synced:
                operation.promote(peer)
                synced.assert_any_call(self.a.current.parent)
            with patch.object(reservation,'sync_directory',crash_before_sync):
                with self.assertRaises(EOFError):operation.restore()
            self.assertEqual(self.a.current.resolve(),self.a.old)
            self.assertEqual(operation.state()['phase'],'restoring')
            with patch.object(reservation,'sync_directory',wraps=actual) as synced:
                self.assertEqual(operation.restore()['phase'],'restored')
                synced.assert_any_call(self.a.current.parent)

    def test_different_original_versions_refuse_promotion_but_can_restore_and_release(self):
        with self.b.enter() as operation:
            operation.path.unlink();operation.marker.unlink()
            self.b.old_identity['version']='0.31.7';self.b.old_identity['commit']='8'*40
            b=operation.prepare()
        with self.a.enter() as operation:
            with self.assertRaisesRegex(ValueError,'same original'):operation.promote(b)
            a=operation.restore()
        with self.b.enter() as operation:
            b=operation.restore();operation.release(a)
        with self.a.enter() as operation:operation.release(b)
        self.assertEqual(self.a.current.resolve(),self.a.old);self.assertEqual(self.b.current.resolve(),self.b.old)

    def test_same_directory_candidate_can_abandon_after_other_peer_prepares(self):
        # The peer already has the target version, while this node is still old.
        self.b.own['candidate']['directory']=str(self.b.old)
        self.b.old_identity=copy.deepcopy(self.b.own['candidate'])
        for key in ['binary_sha256','manifest_sha256','build_sha256']:
            self.b.installed[key]=self.b.old_identity[key]
        self.a.peer=copy.deepcopy(self.b.own)
        for host in [self.a,self.b]:
            with host.enter() as operation:operation.path.unlink();operation.marker.unlink()
        with self.a.enter() as operation:a=operation.prepare()
        with self.b.enter() as operation:
            with self.assertRaisesRegex(ValueError,'installation differs'):operation.prepare()
            b=operation.abandon(a)
            self.assertIsNone(b['descriptor']['validated_at'])
        with self.a.enter() as operation:a=operation.restore();operation.release(b)
        with self.b.enter() as operation:operation.release(a)
        self.assertEqual(self.b.current.resolve(),self.b.old)

    def test_pair_binding_detects_mutation_and_duplicate_nodes(self):
        a,b=self.report(self.a),self.report(self.b)
        self.assertEqual(promotion.paired(a['descriptor'],b['descriptor']),promotion.paired(b['descriptor'],a['descriptor']))
        with self.assertRaises(ValueError):promotion.paired(a['descriptor'],a['descriptor'])
        with self.a.enter() as operation:
            state=operation.state();state['pair_sha256']='f'*64
            operation.path.write_bytes(canonical(state))
            with self.assertRaisesRegex(ValueError,'Incomplete'):operation.report()


class ServiceFingerprintTests(unittest.TestCase):
    def test_root_definition_set_is_bound_and_pending_reload_is_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp).resolve(); fragment=root/'noisefence.service';fragment.write_text('[Service]\nUser=noisefence\n')
            raw=('LoadState=loaded\nFragmentPath='+str(fragment)+'\nDropInPaths=\nNeedDaemonReload=no\n').encode()
            with patch.object(reservation,'FENCED',('noisefence.service',)), \
                    patch.object(reservation,'protected',lambda p,directory=False:Path(p).stat()), \
                    patch.object(reservation,'execute',return_value=raw) as execute:
                before=promotion.service_fingerprint();fragment.write_text('[Service]\nUser=root\n')
                self.assertNotEqual(promotion.service_fingerprint(),before)
                execute.return_value=raw.replace(b'Reload=no',b'Reload=yes')
                with self.assertRaisesRegex(ValueError,'Reload'):promotion.service_fingerprint()
