"""Durable pair decisions, startup barriers and recoverable completion."""
import contextlib
import copy
import errno
import json
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest
from unittest.mock import patch

from tests_python.test_upgrade_promotion import Host
from tests_python.test_upgrade_validation import OP, OTHER
import upgrade_activation as activation
import upgrade_promotion as promotion
import upgrade_reservation as reservation
from migration_protocol import canonical

RealReservation = reservation.Reservation


class ActivationHost(Host):
    def __init__(self, root, node, expiry):
        super().__init__(root,node,expiry)
        self.units = self.root/'units';self.units.mkdir()
        self.unit_states = {u:'unknown' for u in reservation.FENCED}
        self.unit_states.update({'noisefence.service':'active','noisefence-train.timer':'active'})
        self.initialized=False

    def execute(self,args):
        self.events.append(args)
        if args[1]=='stop':self.unit_states[args[2]]='inactive'
        if args[1]=='start':
            unit=args[2]
            assert not reservation.HOLD.exists(), 'start while reservation held'
            if unit!='noisefence.service':assert not (self.state_dir/'activation-jobs.json').exists(), 'timer start before completion'
            self.unit_states[unit]='active'
        return b''

    @contextlib.contextmanager
    def enter(self):
        with super().enter(), contextlib.ExitStack() as stack:
            for module,key,value in [(reservation,'ACTIVE',self.state_dir/'active.json'),(reservation,'HOLD',self.state_dir/'hold.json'),
                    (reservation,'UNITS',self.units),(reservation,'execute',self.execute),
                    (reservation,'unit_state',lambda u:('inactive' if self.validation_stopped else 'active') if u==activation.validation.SERVICE else self.unit_states[u])]:
                stack.enter_context(patch.object(module,key,value))
            if not self.initialized:
                self.hold=RealReservation(OP);self.hold.begin();self.initialized=True
            yield activation.Activation(OP)


class ActivationTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.root=Path(temp.name).resolve();self.clock=int(time.time())
        p=patch.object(activation.time,'time',lambda:self.clock);p.start();self.addCleanup(p.stop)
        self.a,self.b=[ActivationHost(self.root,n,self.clock+600) for n in ['mx1','mx2']]
        self.a.peer=copy.deepcopy(self.b.own);self.b.peer=copy.deepcopy(self.a.own)
        prepared={}
        for host in [self.a,self.b]:
            with host.enter() as op:prepared[host.own['selection']['node']['node']]=op.promoted.prepare()
        for host,peer in [(self.a,'mx2'),(self.b,'mx1')]:
            with host.enter() as op:op.promoted.promote(prepared[peer])

    def promoted(self,host):
        with host.enter() as op:return op.promoted.report()

    def report(self,host):
        with host.enter() as op:return op.report()

    def arm(self):
        a,b=self.promoted(self.a),self.promoted(self.b)
        with self.a.enter() as op:armed=op.arm(b)
        with self.b.enter() as op:op.arm(armed)

    def commit(self):
        self.arm();peer=self.report(self.b)
        with self.a.enter() as op:decision=op.decide('activate',peer)
        with self.b.enter() as op:op.accept(decision)

    def start(self):
        a,b=self.report(self.a),self.report(self.b)
        with self.a.enter() as op:op.start(b)
        with self.b.enter() as op:op.start(a)
        self.clock+=3

    def proof(self,host):
        with host.enter() as op:
            s=op.state();since=s['started_at'];node=s['node'];peer='mx2' if node=='mx1' else 'mx1'
            return {'protocol':activation.READY,'operation':OP,'node':node,'proposal_sha256':promotion.fingerprint(s['proposal']),
                'checked_at':self.clock,'process':{'pid':11 if node=='mx1' else 12,'boot':OP if node=='mx1' else OTHER,'ticks':123,'started_at':since},
                'binary_sha256':host.own['candidate']['binary_sha256'],'last_sync':self.clock-1,'heartbeat':self.clock,
                'pending_replicas':0,'unprotected':0,'policy':host.own['policy'],'since':since,'policy_window':15}

    def verify(self):
        a,b=self.proof(self.a),self.proof(self.b)
        for host,peer,own in [(self.a,b,a),(self.b,a,b)]:
            with host.enter() as op,patch.object(activation.Activation,'check',return_value=own):op.verify(peer)

    def test_worker_cannot_arm_before_a_durable_coordinator_promise(self):
        with self.b.enter() as op:
            with self.assertRaises(ValueError):op.arm(self.promoted(self.a))
            self.assertFalse(op.path.exists())
        with self.a.enter() as op:armed=op.arm(self.promoted(self.b))
        with self.b.enter() as op:self.assertEqual(op.arm(armed)['phase'],'armed')

    def test_commit_needs_both_promises_and_both_decisions_before_start(self):
        self.arm();peer=self.report(self.b)
        with self.a.enter() as op:
            decision=op.decide('activate',peer)
            self.assertEqual(decision,op.decide('activate',peer))
            with self.assertRaisesRegex(ValueError,'cannot be replaced'):op.decide('abort')
            with self.assertRaisesRegex(ValueError,'Both durable'):op.start(peer)
            self.assertTrue(reservation.HOLD.exists());self.assertFalse(op.jobs.exists())
            with self.assertRaisesRegex(ValueError,'durable activation'):op.promoted.restore()
            with self.assertRaisesRegex(ValueError,'durable activation'):op.hold.cancel()
        with self.b.enter() as op:
            op.accept(decision)
            with self.assertRaisesRegex(ValueError,'Only the selected'):op.decide('activate',decision)
        self.start()
        for host in [self.a,self.b]:
            with host.enter() as op:
                self.assertEqual(op.state()['phase'],'started');self.assertTrue(op.jobs.exists())
                self.assertFalse(reservation.HOLD.exists());self.assertTrue(reservation.ACTIVE.exists())
                self.assertEqual(host.unit_states['noisefence-train.timer'],'inactive')
                with self.assertRaisesRegex(ValueError,'Committed'):op.abort()

    def test_armed_abort_and_unarmed_peer_restore_originals_then_cancel(self):
        a,b=self.promoted(self.a),self.promoted(self.b)
        with self.a.enter() as op:
            op.arm(b);decision=op.decide('abort');op.abort()
        with self.b.enter() as op:op.accept(decision);op.abort()
        a,b=self.report(self.a),self.report(self.b)
        for host,peer in [(self.a,b),(self.b,a)]:
            with host.enter() as op:
                result=op.cancel(peer);self.assertEqual(result,op.cancel(peer))
                self.assertEqual(result['phase'],'cancelled')
                self.assertFalse(op.marker.exists());self.assertFalse(reservation.ACTIVE.exists())
                self.assertEqual(host.current.resolve(),host.old)
                self.assertEqual(host.unit_states['noisefence.service'],'active')
                self.assertEqual(host.unit_states['noisefence-train.timer'],'active')

    def test_arm_crash_before_marker_still_blocks_precommit_restoration(self):
        peer=self.promoted(self.b);actual=activation.atomic
        with self.a.enter() as op:
            def full(path,raw,**kw):
                if path==op.marker:raise OSError(errno.ENOSPC,'full')
                actual(path,raw,**kw)
            with patch.object(activation,'atomic',full):
                with self.assertRaises(OSError):op.arm(peer)
            self.assertEqual(op.state()['phase'],'armed');self.assertFalse(op.marker.exists())
            with self.assertRaisesRegex(ValueError,'durable activation'):op.promoted.restore()
            self.assertEqual(op.arm(peer)['phase'],'armed');self.assertTrue(op.marker.exists())

    def test_commit_write_failure_does_not_allow_start_and_same_intent_recovers(self):
        self.arm();peer=self.report(self.b);actual=activation.atomic
        with self.a.enter() as op:
            def full(path,raw,**kw):
                if b'"phase":"decided"' in raw:raise OSError(errno.ENOSPC,'full')
                actual(path,raw,**kw)
            with patch.object(activation,'atomic',full):
                with self.assertRaises(OSError):op.decide('activate',peer)
            self.assertIsNone(op.state()['decision']);self.assertTrue(reservation.HOLD.exists())
            op.decide('activate',peer)

    def test_partial_start_setup_and_lost_start_reply_keep_job_fence(self):
        self.commit();peer=self.report(self.b);actual=self.a.execute
        def lost(args):
            result=actual(args)
            if args[1:3]==['start','noisefence.service']:raise EOFError('lost start reply')
            return result
        with self.a.enter() as op:
            with patch.object(reservation,'execute',lost):
                with self.assertRaises(EOFError):op.start(peer)
            self.assertEqual(op.state()['phase'],'starting');self.assertTrue(op.jobs.exists())
            self.assertEqual(self.a.unit_states['noisefence.service'],'active')
            self.assertEqual(op.start(peer)['phase'],'started')
            self.assertEqual(self.a.unit_states['noisefence-train.timer'],'inactive')

    def test_pair_verification_required_before_auxiliary_jobs_and_cleanup(self):
        self.commit();self.start();peer=self.report(self.b)
        with self.a.enter() as op:
            with self.assertRaisesRegex(ValueError,'Both runtime'):op.finish(peer)
        self.verify();a,b=self.report(self.a),self.report(self.b)
        for host,peer in [(self.a,b),(self.b,a)]:
            proof=self.proof(host)
            with host.enter() as op,patch.object(activation,'process_identity',return_value=(proof['process'],host.new/'noisefence')):
                done=op.finish(peer);self.assertEqual(done,op.finish(peer))
                self.assertEqual(done['phase'],'complete');self.assertFalse(reservation.ACTIVE.exists())
                self.assertFalse(op.marker.exists());self.assertFalse(op.jobs.exists());self.assertFalse(op.promoted.marker.exists())
                self.assertEqual(op.hold.state()['phase'],'upgraded');self.assertEqual(op.promoted.state()['phase'],'activated')
                self.assertEqual(host.unit_states['noisefence-train.timer'],'active')
                with self.assertRaisesRegex(ValueError,'durable activation'):op.hold.cancel()

    def test_finish_retries_after_removed_fences_without_requiring_old_policy(self):
        self.commit();self.start();self.verify();peer=self.report(self.b);proof=self.proof(self.a)
        actual=self.a.execute
        def lost(args):
            if args[1:3]==['start','noisefence-train.timer']:raise EOFError('lost timer restart')
            return actual(args)
        with self.a.enter() as op,patch.object(activation,'process_identity',return_value=(proof['process'],self.a.new/'noisefence')):
            with patch.object(reservation,'execute',lost):
                with self.assertRaises(EOFError):op.finish(peer)
            self.assertEqual(op.state()['phase'],'finishing');self.assertFalse(op.jobs.exists())
            self.a.policy={'sequence':2,'revision':2,'digest':'9'*64};self.clock+=60
            self.assertEqual(op.finish(peer)['phase'],'complete')

    def test_corrupted_completion_or_peer_vote_never_authorizes_resume(self):
        self.commit();self.start()
        with self.a.enter() as op:
            state=op.state();state['peer_vote']['node']=state['node'];op.path.write_bytes(canonical(state))
            with self.assertRaisesRegex(ValueError,'Unexpected activation counterpart'):op.report()
            self.assertTrue(op.jobs.exists());self.assertTrue(reservation.ACTIVE.exists())

    def test_stale_future_unprotected_and_wrong_binary_proofs_refuse(self):
        self.commit();self.start();proof=self.proof(self.b)
        with self.a.enter() as op:
            for field,value in [('checked_at',self.clock+1),('checked_at',self.clock-31),('pending_replicas',1),
                                ('unprotected',1),('binary_sha256','0'*64),('last_sync',proof['since'])]:
                changed=copy.deepcopy(proof);changed[field]=value
                with self.assertRaises(ValueError):op.verify(changed)
                self.assertEqual(op.state()['phase'],'started')

    def test_expired_preparation_can_abort_but_cannot_make_an_activation_decision(self):
        self.arm();peer=self.report(self.b);self.clock=self.a.own['expires_at']+1
        with self.a.enter() as op:
            with self.assertRaisesRegex(ValueError,'expiry'):op.decide('activate',peer)
            self.assertIsNone(op.state()['decision'])
            self.assertEqual(op.decide('abort')['decision']['outcome'],'abort')

    def test_foreign_coordinator_report_is_refused_before_worker_receipt_creation(self):
        with self.a.enter() as op:op.arm(self.promoted(self.b));decision=op.decide('abort')
        decision['node']='mx2'
        with self.b.enter() as op:
            with self.assertRaisesRegex(ValueError,'coordinator'):op.accept(decision)
            self.assertFalse(op.path.exists());self.assertTrue(reservation.HOLD.exists())

    def test_interrupted_job_condition_install_never_removes_normal_hold(self):
        self.commit();peer=self.report(self.b);actual=self.a.execute
        def fail(args):
            if args[1]=='daemon-reload':raise EOFError('reload disconnected')
            return actual(args)
        with self.a.enter() as op:
            with patch.object(reservation,'execute',fail):
                with self.assertRaises(EOFError):op.start(peer)
            self.assertTrue(reservation.HOLD.exists());self.assertTrue(op.jobs.exists())
            self.assertEqual(self.a.unit_states['noisefence.service'],'inactive')
            self.assertEqual(op.start(peer)['phase'],'started')

    def test_recovered_decision_is_directory_synced_before_publication(self):
        self.arm();peer=self.report(self.b);actual=activation.atomic
        with self.a.enter() as op:
            def rename_then_crash(path,raw,**kw):
                if b'"phase":"decided"' in raw:
                    path.write_bytes(raw)
                    raise EOFError('renamed but parent not synced')
                actual(path,raw,**kw)
            with patch.object(activation,'atomic',rename_then_crash):
                with self.assertRaises(EOFError):op.decide('activate',peer)
            with patch.object(reservation,'sync_directory',wraps=reservation.sync_directory) as sync:
                result=op.report();sync.assert_any_call(op.path.parent)
            self.assertEqual(result['decision']['outcome'],'activate')
            with self.assertRaisesRegex(ValueError,'cannot be replaced'):op.decide('abort')

    def test_peer_completion_allows_delayed_forward_finish_after_policy_advancement(self):
        self.commit();self.start();self.verify();b=self.report(self.b);proof=self.proof(self.a)
        with self.a.enter() as op,patch.object(activation,'process_identity',return_value=(proof['process'],self.a.new/'noisefence')):
            completed=op.finish(b)
        self.clock+=120;self.b.policy={'sequence':2,'revision':2,'digest':'9'*64}
        process={'pid':99,'boot':OTHER,'ticks':999,'started_at':self.clock-20}
        with self.b.enter() as op,patch.object(activation,'process_identity',return_value=(process,self.b.new/'noisefence')):
            self.assertEqual(op.finish(completed)['phase'],'complete')
            self.assertFalse(op.jobs.exists())

    def test_proof_expiring_during_local_check_never_replaces_readable_receipt(self):
        self.commit();self.start();peer=self.proof(self.b);self.clock+=29
        def slow(_operation,_peer):
            self.clock+=2
            return self.proof(self.a)
        with self.a.enter() as op,patch.object(activation.Activation,'check',slow):
            previous=op.path.read_bytes()
            with self.assertRaisesRegex(ValueError,'Stale'):op.verify(peer)
            self.assertEqual(op.path.read_bytes(),previous);self.assertEqual(op.state()['phase'],'started')

    def test_partial_dropin_removal_reloads_before_comparing_service_fingerprint(self):
        self.commit();self.start();self.verify();peer=self.report(self.b);proof=self.proof(self.a)
        actual_remove=reservation.remove;actual_execute=self.a.execute;pending=[False];crash=[True]
        def remove(path):
            actual_remove(path)
            if path.name==activation.DROPIN:
                pending[0]=True
                if crash[0]:crash[0]=False;raise EOFError('removed before reload')
        def execute(args):
            if args[1]=='daemon-reload':pending[0]=False
            return actual_execute(args)
        def fingerprint(**kwargs):
            if pending[0]:raise ValueError('NeedDaemonReload=yes')
            return self.a.service_hash
        with self.a.enter() as op,patch.object(activation,'process_identity',return_value=(proof['process'],self.a.new/'noisefence')), \
                patch.object(reservation,'remove',remove),patch.object(reservation,'execute',execute),patch.object(promotion,'service_fingerprint',fingerprint):
            with self.assertRaises(EOFError):op.finish(peer)
            self.assertTrue(pending[0]);self.assertEqual(op.state()['phase'],'finishing')
            self.assertEqual(op.finish(peer)['phase'],'complete')

    def test_malformed_job_hold_is_rejected_before_any_condition_is_removed(self):
        self.commit();self.start();self.verify();peer=self.report(self.b)
        with self.a.enter() as op:
            op.jobs.write_bytes(canonical({'protocol':activation.PROTOCOL,'operation':OTHER}))
            conditions=[self.a.units/(u+'.d')/activation.DROPIN for u in reservation.FENCED if u!='noisefence.service']
            self.assertTrue(all(p.exists() for p in conditions))
            with self.assertRaisesRegex(ValueError,'Unexpected job hold'):op.finish(peer)
            self.assertTrue(all(p.exists() for p in conditions));self.assertEqual(op.state()['phase'],'verified')

    def test_recovered_finishing_intent_is_synced_before_releasing_conditions(self):
        self.commit();self.start();self.verify();peer=self.report(self.b);proof=self.proof(self.a)
        actual_atomic=activation.atomic
        with self.a.enter() as op,patch.object(activation,'process_identity',return_value=(proof['process'],self.a.new/'noisefence')):
            def rename_then_crash(path,raw,**kw):
                if b'"phase":"finishing"' in raw:
                    path.write_bytes(raw);raise EOFError('intent renamed before sync')
                actual_atomic(path,raw,**kw)
            with patch.object(activation,'atomic',rename_then_crash):
                with self.assertRaises(EOFError):op.finish(peer)
            self.assertEqual(op.state()['phase'],'finishing')
            with patch.object(reservation,'sync_directory',side_effect=OSError('sync failed')):
                with self.assertRaises(OSError):op.finish(peer)
            self.assertTrue(op.jobs.exists())
            self.assertTrue(all((self.a.units/(u+'.d')/activation.DROPIN).exists() for u in reservation.FENCED if u!='noisefence.service'))
            self.assertEqual(op.finish(peer)['phase'],'complete')

    def test_catchup_certificate_matches_retained_local_verification_on_read_and_use(self):
        self.commit();self.clock+=2;self.start();self.verify();b=self.report(self.b);proof=self.proof(self.a)
        with self.a.enter() as op,patch.object(activation,'process_identity',return_value=(proof['process'],self.a.new/'noisefence')):
            completed=op.finish(b)
        proof=self.proof(self.b)
        with self.b.enter() as op,patch.object(activation,'process_identity',return_value=(proof['process'],self.b.new/'noisefence')):
            original=op.path.read_bytes();state=op.state()
            for timestamp in [state['started_at']-1,state['verified_at']+1]:
                invalid=copy.deepcopy(completed);invalid['peer_completion']['verified_at']=timestamp
                with self.assertRaisesRegex(ValueError,'retained local verification'):op.finish(invalid)
                self.assertEqual(op.path.read_bytes(),original);self.assertTrue(op.jobs.exists())
                op.save(state,'finishing',peer_finish=invalid)
                with self.assertRaisesRegex(ValueError,'retained local verification'):op.state()
                op.path.write_bytes(original)
            self.assertEqual(op.finish(completed)['phase'],'complete')

    def test_corrupt_held_or_promoted_receipt_never_releases_job_conditions(self):
        self.commit();self.start();self.verify();peer=self.report(self.b);proof=self.proof(self.a)
        with self.a.enter() as op,patch.object(activation,'process_identity',return_value=(proof['process'],self.a.new/'noisefence')):
            for receipt in [op.hold.path,op.promoted.path]:
                previous=receipt.read_bytes();receipt.write_text('{')
                with self.assertRaises(ValueError):op.finish(peer)
                self.assertEqual(op.state()['phase'],'verified');self.assertTrue(op.jobs.exists())
                self.assertTrue(all((self.a.units/(u+'.d')/activation.DROPIN).exists() for u in reservation.FENCED if u!='noisefence.service'))
                self.assertEqual(self.a.unit_states['noisefence-train.timer'],'inactive')
                receipt.write_bytes(previous)
            self.assertEqual(op.finish(peer)['phase'],'complete')

    def test_rounded_process_start_does_not_predate_the_protocol_decision(self):
        self.commit();self.start();peer=self.proof(self.b);own=self.proof(self.a)
        peer['process']['started_at']-=1
        def observe(_operation,report):
            activation.checked_report(report)
            self.assertGreaterEqual(report['started_at'],report['decision']['decided_at'])
            return own
        with self.a.enter() as op,patch.object(activation.Activation,'check',observe):
            self.assertEqual(op.verify(peer)['phase'],'verified')

    def test_lost_terminal_cleanup_does_not_change_the_decision(self):
        self.commit();self.start();self.verify();peer=self.report(self.b);proof=self.proof(self.a)
        actual=reservation.remove
        def lost(path):
            if path==reservation.ACTIVE:raise EOFError('lost cleanup')
            actual(path)
        with self.a.enter() as op,patch.object(activation,'process_identity',return_value=(proof['process'],self.a.new/'noisefence')):
            with patch.object(reservation,'remove',lost):
                with self.assertRaises(EOFError):op.finish(peer)
            self.assertEqual(op.state()['phase'],'complete');self.assertTrue(reservation.ACTIVE.exists())
            self.assertEqual(op.finish(peer)['phase'],'complete');self.assertFalse(reservation.ACTIVE.exists())


class RuntimeCounters(unittest.TestCase):
    def test_policy_polling_default_matches_the_native_configuration(self):
        self.assertEqual(activation.policy_window({'cluster':{}}),25)
        self.assertEqual(activation.policy_window({'cluster':{'poll_seconds':2}}),15)
        self.assertEqual(activation.policy_window({'cluster':{'poll_seconds':300}}),605)
        for value in [True,1,301,'10']:
            with self.assertRaises(ValueError):activation.policy_window({'cluster':{'poll_seconds':value}})

    def test_query_only_snapshot_checks_two_copies_and_generation_integrity(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp).resolve();path=root/'state.sqlite3'
            with sqlite3.connect(path) as db:
                db.executescript("CREATE TABLE cluster_state(key TEXT,value TEXT); CREATE TABLE ha_local(generation,acked); INSERT INTO cluster_state VALUES('ha_required','1'),('last_sync','123'),('ha_last_success','124'); INSERT INTO ha_local VALUES(2,2);")
            with patch.object(reservation,'DATA',root):
                self.assertEqual(activation.runtime_counters(),{'last_sync':123,'heartbeat':124,'unprotected':0,'pending_replicas':0})
                with sqlite3.connect(path) as db:db.execute('UPDATE ha_local SET acked=0')
                self.assertEqual(activation.runtime_counters()['unprotected'],1)
                with sqlite3.connect(path) as db:db.execute('UPDATE ha_local SET acked=3')
                with self.assertRaisesRegex(ValueError,'generations'):activation.runtime_counters()
