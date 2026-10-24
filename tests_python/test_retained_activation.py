"""Independent rollback decisions retain current data and survive interruptions."""
import contextlib
import copy
import errno
import unittest
from unittest.mock import patch

from tests_python import test_retained_promotion as fixtures
import rollback_activation as rollback
import upgrade_activation as forward
import upgrade_promotion as promotion
import upgrade_reservation as reservation
from migration_protocol import canonical

NEW=fixtures.NEW


class RetainedActivationTests(unittest.TestCase):
    def setUp(self):
        self.fixture=fixtures.RetainedPromotionTests();self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.a,self.b=self.fixture.a,self.fixture.b
        self.flow=self.fixture.fixture.flow
        left,right=self.fixture.prepare()
        for host,peer in ((self.a,right),(self.b,left)):
            with self.fixture.enter(host) as operation:operation.promote(peer)

    @contextlib.contextmanager
    def enter(self,host):
        with self.fixture.enter(host):yield rollback.RetainedActivation(NEW)

    def report(self,host):
        with self.enter(host) as operation:return operation.report()

    def promoted(self,host):
        with self.enter(host) as operation:return operation.promoted.report()

    def arm(self):
        peer=self.promoted(self.b)
        with self.enter(self.a) as operation:left=operation.arm(peer)
        with self.enter(self.b) as operation:operation.arm(left)

    def commit(self):
        self.arm();right=self.report(self.b)
        with self.enter(self.a) as operation:left=operation.decide('activate',right)
        with self.enter(self.b) as operation:operation.accept(left)

    def start(self):
        left,right=self.report(self.a),self.report(self.b)
        for host,peer in ((self.a,right),(self.b,left)):
            with self.enter(host) as operation:operation.start(peer)
        self.flow.clock+=3

    def proof(self,host):
        with self.enter(host) as operation:
            state=operation.state();own=operation.own(state)['own'];now=self.flow.clock
            return {'protocol':rollback.READY,'operation':NEW,'node':state['node'],
                'proposal_sha256':promotion.fingerprint(state['proposal']),
                'checked_at':now,'process':{'pid':11 if host is self.a else 12,'boot':NEW,'ticks':123,
                                          'started_at':state['started_at']},
                'binary_sha256':own['candidate']['binary_sha256'],'last_sync':now-1,'heartbeat':now,
                'pending_replicas':0,'unprotected':0,'policy':own['policy'],
                'since':state['started_at'],'policy_window':25}

    def verify(self):
        left,right=self.proof(self.a),self.proof(self.b)
        for host,peer,own in ((self.a,right,left),(self.b,left,right)):
            with self.enter(host) as operation,patch.object(rollback.RetainedActivation,'check',return_value=own):
                operation.verify(peer)

    def test_full_pair_uses_distinct_decision_and_never_restores_database_or_policy(self):
        original=[(host.config.read_bytes(),copy.deepcopy(host.policy)) for host in (self.a,self.b)]
        self.commit();self.start();self.verify()
        left,right=self.report(self.a),self.report(self.b)
        for index,(host,peer) in enumerate(((self.a,right),(self.b,left))):
            proof=self.proof(host)
            with self.enter(host) as operation,patch.object(forward,'process_identity',return_value=(proof['process'],host.old/'noisefence')):
                result=operation.finish(peer)
                self.assertEqual(result['protocol'],rollback.REPORT)
                self.assertEqual(result['decision']['protocol'],rollback.DECISION)
                self.assertEqual(result['phase'],'complete')
                self.assertEqual(result,operation.finish(peer))
                self.assertFalse(reservation.HOLD.exists());self.assertFalse(reservation.ACTIVE.exists())
                self.assertFalse(operation.marker.exists());self.assertFalse(operation.jobs.exists())
                self.assertEqual(host.current.resolve(),host.old)
                self.assertEqual((host.config.read_bytes(),host.policy),original[index])
                self.assertEqual(host.unit_states['noisefence-train.timer'],'active')
                with self.assertRaises(ValueError):forward.Activation(NEW).state()
                with self.assertRaises(ValueError):operation.hold.cancel()

    def test_one_vote_cannot_start_and_abort_restores_current_pair(self):
        right=self.promoted(self.b)
        with self.enter(self.a) as operation:
            armed=operation.arm(right)
            with self.assertRaises(ValueError):operation.start(armed)
            aborted=operation.decide('abort')
        with self.enter(self.b) as operation:operation.accept(aborted)
        for host in (self.a,self.b):
            with self.enter(host) as operation:
                operation.abort()
                self.assertEqual(host.current.resolve(),host.new)
        left,right=self.report(self.a),self.report(self.b)
        for host,peer in ((self.a,right),(self.b,left)):
            with self.enter(host) as operation:
                result=operation.cancel(peer)
                self.assertEqual(result['phase'],'cancelled')
                self.assertEqual(result,operation.cancel(peer))
                self.assertEqual(host.current.resolve(),host.new)
                self.assertFalse(reservation.ACTIVE.exists())

    def test_commit_prevents_any_local_restoration_and_needs_peer_commit_to_start(self):
        self.arm();right=self.report(self.b)
        with self.enter(self.a) as operation:
            decision=operation.decide('activate',right)
            for action in (operation.abort,operation.promoted.restore,operation.hold.cancel):
                with self.assertRaises(ValueError):action()
            with self.assertRaises(ValueError):operation.start(right)
            self.assertTrue(reservation.HOLD.exists())
            self.assertEqual(self.a.current.resolve(),self.a.old)
        with self.enter(self.b) as operation:operation.accept(decision)
        right=self.report(self.b)
        with self.enter(self.a) as operation:self.assertEqual(operation.start(right)['phase'],'started')

    def test_broken_or_changed_history_cannot_gain_a_durable_activation_decision(self):
        self.arm();right=self.report(self.b)
        self.a.policy={'sequence':2,'revision':2,'digest':'9'*64}
        with self.enter(self.a) as operation:
            with self.assertRaisesRegex(ValueError,'history'):operation.decide('activate',right)
            self.assertIsNone(operation.state()['decision']);self.assertTrue(reservation.HOLD.exists())

    def test_forward_reports_and_renamed_wire_protocols_are_rejected(self):
        self.arm();right=self.report(self.b)
        with self.enter(self.a) as operation:
            for peer in (self.fixture.fixture.fixture.reports[1],{**right,'protocol':forward.REPORT}):
                with self.assertRaises(ValueError):operation.decide('activate',peer)
            self.assertIsNone(operation.state()['decision'])
        with self.assertRaises(ValueError):forward.checked_report(right)
        with self.assertRaises(ValueError):forward.checked_report({**right,'protocol':forward.REPORT})

    def test_expired_authorization_cannot_commit_but_abort_remains_available(self):
        self.arm();right=self.report(self.b);self.flow.clock=self.fixture.fixture.expiry+1
        with self.enter(self.a) as operation:
            with self.assertRaises(ValueError):operation.decide('activate',right)
            self.assertEqual(operation.decide('abort')['decision']['outcome'],'abort')

    def test_full_disk_before_commit_keeps_both_holds(self):
        self.arm();right=self.report(self.b)
        with self.enter(self.a) as operation:
            with patch.object(forward,'atomic',side_effect=OSError(errno.ENOSPC,'full')):
                with self.assertRaises(OSError):operation.decide('activate',right)
            self.assertIsNone(operation.state()['decision']);self.assertTrue(reservation.HOLD.exists())
            self.assertEqual(operation.decide('activate',right)['decision']['outcome'],'activate')

    def test_lost_start_response_recovers_committed_old_release_and_keeps_timers_held(self):
        self.commit();right=self.report(self.b)
        with self.enter(self.a) as operation:
            execute=reservation.execute
            def lost(args):
                result=execute(args)
                if args[1:3]==['start','noisefence.service']:raise EOFError('lost acknowledgement')
                return result
            with patch.object(reservation,'execute',lost):
                with self.assertRaises(EOFError):operation.start(right)
            self.assertEqual(operation.state()['phase'],'starting')
            self.assertTrue(operation.jobs.exists())
            self.assertEqual(self.a.unit_states['noisefence-train.timer'],'inactive')
            self.assertEqual(operation.start(right)['phase'],'started')

    def test_unprotected_wrong_binary_stale_or_forward_runtime_proofs_do_not_release_jobs(self):
        self.commit();self.start();proof=self.proof(self.b)
        with self.enter(self.a) as operation:
            for field,value in [('unprotected',1),('pending_replicas',1),('binary_sha256',self.b.own['candidate']['binary_sha256']),
                                ('checked_at',self.flow.clock-31),('protocol',forward.READY)]:
                with self.assertRaises(ValueError):operation.verify({**proof,field:value})
                self.assertEqual(operation.state()['phase'],'started');self.assertTrue(operation.jobs.exists())

    def test_lost_completion_recovers_after_policy_advancement(self):
        self.commit();self.start();self.verify();right=self.report(self.b);proof=self.proof(self.a)
        with self.enter(self.a) as operation,patch.object(forward,'process_identity',return_value=(proof['process'],self.a.old/'noisefence')):
            execute=reservation.execute
            def lost(args):
                if args[1:3]==['start','noisefence-train.timer']:raise EOFError('lost timer acknowledgement')
                return execute(args)
            with patch.object(reservation,'execute',lost):
                with self.assertRaises(EOFError):operation.finish(right)
            self.assertEqual(operation.state()['phase'],'finishing')
            self.a.policy={'sequence':2,'revision':2,'digest':'9'*64};self.flow.clock+=60
            self.assertEqual(operation.finish(right)['phase'],'complete')


if __name__=='__main__':unittest.main()
