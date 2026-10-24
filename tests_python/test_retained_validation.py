"""Retained validation runs under fresh holds; its reports cannot promote a pair."""
import contextlib
import copy
import errno
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from tests_python import test_paired_rollback_check as fixtures
import rollback_validation as retained
import upgrade_validation as validation
import upgrade_reservation as reservation
import upgrade_promotion as promotion
from migration_protocol import canonical

REAL_VALIDATION = validation.Validation
OP, NEW = fixtures.OP, fixtures.NEW


class RetainedValidationTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.RollbackCheckTests();self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.flow = self.fixture.flow
        self.expiry = self.flow.clock+300
        self.descriptors = []
        for index, host in enumerate((self.flow.a,self.flow.b)):
            with self.enter(host):
                self.descriptors.append(retained.describe(NEW, OP, self.fixture.reports[1-index], self.expiry))
        for host in (self.flow.a,self.flow.b):host.events.clear()

    @contextlib.contextmanager
    def enter(self,host):
        def execute(args):
            if args[1] == 'start' and args[2] == validation.SERVICE:
                self.assertTrue(reservation.HOLD.exists())
                self.assertTrue((host.state_dir/'validation.json').exists())
                self.assertTrue(validation.PLAN.exists())
                host.events.append(args);host.validation_stopped=False
                return b''
            if args[1] == 'stop' and args[2] == validation.SERVICE:
                self.assertFalse(validation.PLAN.exists())
                self.assertTrue(reservation.HOLD.exists())
                host.events.append(args);host.validation_stopped=True
                return b''
            if '--property=MainPID' in args:return b'0\n'
            return host.execute(args)
        with self.fixture.enter(host), patch.object(validation,'Validation',REAL_VALIDATION), \
             patch.object(reservation,'CONFIG',host.config), patch.object(reservation,'execute',execute), \
             patch.object(validation,'unit_template',return_value=b'synthetic unit'), \
             patch.object(validation,'service_files'):
            yield retained.RetainedValidation(NEW)

    def start(self,host=None,peer=None):
        host=host or self.flow.a;index=0 if host is self.flow.a else 1
        with self.enter(host) as operation:
            return operation.prepare(OP,self.fixture.reports[1-index],
                                     self.descriptors[1-index] if peer is None else peer,self.expiry)

    def test_only_maintenance_starts_and_proof_never_authorizes_activation(self):
        for host in (self.flow.a,self.flow.b):
            before=host.current.readlink(),host.config.read_bytes(),copy.deepcopy(host.unit_states)
            result=self.start(host)
            self.assertFalse(result['activation_authorized']);self.assertFalse(result['rollback_qualified'])
            self.assertFalse(result['validation_ready'])
            self.assertEqual((host.current.readlink(),host.config.read_bytes(),host.unit_states),before)
            self.assertTrue(all(e[2]==validation.SERVICE for e in host.events if e[1]=='start'))
            with self.enter(host) as operation:
                self.assertEqual(operation.state()['protocol'],retained.PROTOCOL)
                self.assertEqual(Path(operation.state()['own']['candidate']['directory']),host.old)
                self.assertLess(len(retained.context_path(NEW).read_bytes()),65536)
                with self.assertRaisesRegex(ValueError,'Stop candidate'):fixtures.RealReservation(NEW).cancel()

    def test_ready_maintenance_status_is_still_not_rollback_authority(self):
        with self.enter(self.flow.a) as operation, patch.object(REAL_VALIDATION,'status',return_value={'validation_ready':True}):
            result=operation.status()
            self.assertTrue(result['validation_ready'])
            self.assertFalse(result['activation_authorized']);self.assertFalse(result['rollback_qualified'])

    def test_forward_supervisor_and_promotion_cannot_consume_retained_receipts(self):
        self.start()
        with self.enter(self.flow.a):
            with self.assertRaisesRegex(ValueError,'validation receipt'):REAL_VALIDATION(NEW).state()
            with self.assertRaisesRegex(ValueError,'retained-release validation'):
                validation.describe(NEW,self.flow.a.new,self.expiry)
            with self.assertRaises(ValueError):promotion.Promotion(NEW).prepare()
            with self.assertRaises(ValueError):validation.authorize(*self.descriptors)

    def test_wrong_pair_and_different_history_refuse_before_context_or_process(self):
        for field,value in [('previous_operation','00000000-0000-4000-8000-000000000004'),
                            ('previous_decision_sha256','9'*64),('previous_proposal_sha256','9'*64)]:
            peer=copy.deepcopy(self.descriptors[1]);peer['history'][field]=value
            with self.assertRaises(ValueError):self.start(peer=peer)
        peer=copy.deepcopy(self.descriptors[1]);peer['candidate']['version']='0.31.7'
        with self.assertRaises(ValueError):self.start(peer=peer)
        self.assertFalse((self.flow.a.state_dir/(NEW+'-rollback-context.json')).exists())
        self.assertFalse(self.flow.a.events)

    def test_lost_start_reply_resumes_same_context_and_rejects_changed_history(self):
        with patch.object(retained.RetainedValidation,'status',side_effect=EOFError('lost reply')):
            with self.assertRaises(EOFError):self.start()
        self.assertFalse(self.start()['activation_authorized'])
        with self.enter(self.flow.a) as operation:
            context=retained.context_path(NEW);value=json.loads(context.read_text())
            value['inspection']['peer_completion_sha256']='0'*64;context.write_bytes(canonical(value))
            with self.assertRaisesRegex(ValueError,'historical proof changed'):self.start()
            # Revocation/stop remains available even if history cannot authorize a retry.
            self.assertEqual(operation.stop()['phase'],'stopped')

    def test_full_disk_before_context_never_starts_and_retry_is_safe(self):
        with patch.object(retained,'atomic',side_effect=OSError(errno.ENOSPC,'full')):
            with self.assertRaises(OSError):self.start()
        self.assertTrue(self.flow.a.validation_stopped);self.assertFalse(self.flow.a.events)
        self.start()

    def test_full_disk_after_context_preserves_hold_and_retries_exact_request(self):
        actual=validation.atomic
        def full(path,raw,**kw):
            if path==validation.PLAN:raise OSError(errno.ENOSPC,'full')
            return actual(path,raw,**kw)
        with patch.object(validation,'atomic',full):
            with self.assertRaises(OSError):self.start()
        self.assertTrue(self.flow.a.validation_stopped)
        with self.enter(self.flow.a):
            with self.assertRaisesRegex(ValueError,'Stop candidate'):fixtures.RealReservation(NEW).cancel()
        self.start()

    def test_stop_revokes_and_cancellation_resumes_current_version_only(self):
        self.start()
        with self.enter(self.flow.a) as operation:
            first=operation.stop();self.assertEqual(first,operation.stop())
            self.assertFalse(validation.PLAN.exists());self.assertFalse(validation.LINK.exists())
            self.assertTrue(reservation.HOLD.exists())
            result=fixtures.RealReservation(NEW).cancel()
            self.assertEqual(result['phase'],'cancelled')
            self.assertEqual(self.flow.a.current.resolve(),self.flow.a.new)

    def test_expiry_and_changed_policy_archive_or_config_block_restart(self):
        self.start()
        host=self.flow.a
        original=host.policy
        host.policy={'sequence':2,'revision':2,'digest':'8'*64}
        with self.assertRaisesRegex(ValueError,'historical proof changed'):self.start()
        host.policy=original
        host.old_identity['binary_sha256']='9'*64
        with self.assertRaisesRegex(ValueError,'Retained release differs'):self.start()
        host.old_identity['binary_sha256']='4'*64
        host.config.write_text('[replication]\npeer_id="other"\n')
        with self.assertRaisesRegex(ValueError,'Configuration changed'):self.start()
        with self.enter(host) as operation,patch.object(retained.time,'time',return_value=self.expiry+1):
            with self.assertRaisesRegex(ValueError,'expired'):self.start()
            self.assertEqual(operation.stop()['phase'],'stopped')


if __name__ == '__main__':unittest.main()
