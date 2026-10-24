"""Rollback identity inspection cannot authorize a downgrade or change a queue."""
import contextlib
import copy
from pathlib import Path
import unittest
from unittest.mock import patch

from tests_python import test_upgrade_activation as fixtures

RealReservation = fixtures.RealReservation
from tests_python.test_upgrade_validation import OP
import upgrade_activation as activation
import upgrade_reservation as reservation
import upgrade_validation as validation
import rollback_check as rollback
from migration_protocol import canonical

NEW = '00000000-0000-4000-8000-000000000003'
REAL_HELD = validation.held


class RollbackCheckTests(unittest.TestCase):
    def setUp(self):
        self.flow = fixtures.ActivationTests()
        self.flow.setUp()
        self.addCleanup(self.flow.doCleanups)
        self.flow.commit()
        self.flow.start()
        self.flow.verify()
        reports = [self.flow.report(h) for h in (self.flow.a, self.flow.b)]
        for host, peer in ((self.flow.a, reports[1]), (self.flow.b, reports[0])):
            proof = self.flow.proof(host)
            with host.enter() as op, patch.object(activation, 'process_identity', return_value=(proof['process'], host.new/'noisefence')):
                op.finish(peer)
        self.reports = [self.flow.report(h) for h in (self.flow.a, self.flow.b)]
        for host in (self.flow.a, self.flow.b):
            with self.enter(host):
                RealReservation(NEW).begin()

    @contextlib.contextmanager
    def enter(self, host):
        with host.enter(), patch.object(reservation, 'Reservation', RealReservation), \
             patch.object(validation, 'held', REAL_HELD), \
             patch.object(reservation, 'read_selection', return_value=host.own['selection']), \
             patch.object(validation, 'PLAN', host.root/'validation-plan.json'), \
             patch.object(validation, 'LINK', host.root/'validation-link'):
            yield

    def snapshot(self, host):
        return {str(p.relative_to(host.root)): ('link', p.readlink().as_posix()) if p.is_symlink()
                else ('file', p.read_bytes(), p.stat().st_mode) for p in host.root.rglob('*') if p.is_symlink() or p.is_file()}

    def inspect(self, host=None, peer=None):
        host = host or self.flow.a
        with self.enter(host):
            before, events = self.snapshot(host), list(host.events)
            try:
                return rollback.inspect(NEW, OP, self.reports[1] if peer is None else peer)
            finally:
                self.assertEqual(self.snapshot(host), before)
                self.assertEqual(host.events, events)

    def test_complete_pair_binds_both_archives_but_never_authorizes_activation(self):
        left = self.inspect()
        right = self.inspect(self.flow.b, self.reports[0])
        for result, host in ((left, self.flow.a), (right, self.flow.b)):
            self.assertEqual(result['status'], 'identity_checked_rollback_unqualified')
            self.assertIs(result['activation_authorized'], False)
            self.assertEqual(result['current'], host.own['candidate'])
            self.assertEqual(result['retained'], host.old_identity)
            self.assertEqual(len(result['remaining_gates']), 3)
            with self.assertRaisesRegex(ValueError, 'must be newer'):
                validation.require_forward_upgrade(result['current'], result['retained'])
        self.assertEqual(left['previous_proposal_sha256'], right['previous_proposal_sha256'])
        self.assertEqual(left['previous_decision_sha256'], right['previous_decision_sha256'])
        self.assertNotEqual(left['peer_completion_sha256'], right['peer_completion_sha256'])

    def test_policy_advancement_is_recorded_without_replaying_old_state(self):
        self.flow.a.policy = {'sequence': 2, 'revision': 2, 'digest': '9'*64}
        result = self.inspect()
        self.assertEqual(result['policy'], self.flow.a.policy)
        self.assertFalse(result['activation_authorized'])

    def test_incomplete_wrong_node_and_changed_peer_decision_are_refused(self):
        cases = []
        peer = copy.deepcopy(self.reports[1]);peer['phase'] = 'finishing';cases.append(peer)
        cases.append(self.reports[0])
        peer = copy.deepcopy(self.reports[1]);peer['decision']['decided_at'] -= 1;cases.append(peer)
        peer = copy.deepcopy(self.reports[1]);peer['operation'] = NEW;cases.append(peer)
        for peer in cases:
            with self.subTest(peer=peer['phase']):
                with self.assertRaises(ValueError):self.inspect(peer=peer)

    def test_current_and_retained_archive_changes_are_refused(self):
        for object_, key, changed in ((self.flow.a.own['candidate'], 'binary_sha256', '9'*64),
                                      (self.flow.a.old_identity, 'build_sha256', '9'*64),
                                      (self.flow.a.old_identity, 'version', '0.31.7')):
            original = object_[key]
            try:
                object_[key] = changed
                with self.assertRaisesRegex(ValueError, 'Reserved installation changed|release differs'):self.inspect()
            finally:object_[key] = original

    def test_changed_selection_or_config_is_not_accepted_from_an_old_completion(self):
        host = self.flow.a
        for object_, key, changed in ((host.own['selection']['node'], 'epoch', NEW),
                                      (host.installed, 'config_sha256', '9'*64)):
            original = object_[key]
            try:
                object_[key] = changed
                with self.assertRaises(ValueError):self.inspect()
            finally:object_[key] = original

    def test_another_candidate_or_activation_must_be_resolved_first(self):
        host = self.flow.a
        names = ('validation.json', 'promotion.json', 'activation.json', 'activation-jobs.json',
                 NEW+'-validation.json', NEW+'-promotion.json', NEW+'-activation.json')
        for name in names:
            path = host.state_dir/name
            try:
                path.write_text('{}')
                with self.assertRaisesRegex(ValueError, 'existing candidate'):self.inspect()
            finally:path.unlink()
        for name in ('validation-plan.json', 'validation-link'):
            path = host.root/name
            try:
                path.write_text('{}')
                with self.assertRaisesRegex(ValueError, 'candidate validation'):self.inspect()
            finally:path.unlink()
        host.validation_stopped = False
        with self.assertRaisesRegex(ValueError, 'candidate validation'):self.inspect()

    def test_corrupt_historical_runtime_proof_is_not_just_a_complete_phase(self):
        host = self.flow.a
        path = host.state_dir/(OP+'-activation.json')
        import json
        state = json.loads(path.read_text())
        state['verification']['own']['binary_sha256'] = '0'*64
        path.write_bytes(canonical(state))
        with self.assertRaisesRegex(ValueError, 'Runtime proof'):self.inspect()

    def test_corrupt_historical_reservation_and_promotion_are_refused(self):
        import json
        host = self.flow.a
        for name, phase in ((OP+'.json', 'cancelled'), (OP+'-promotion.json', 'promoted')):
            path = host.state_dir/name;before = path.read_bytes()
            try:
                state = json.loads(before);state['phase'] = phase;path.write_bytes(canonical(state))
                with self.assertRaisesRegex(ValueError, 'no longer matches'):self.inspect()
            finally:path.write_bytes(before)

    def test_reservation_owner_and_stopped_writer_requirement_still_apply(self):
        host = self.flow.a
        with self.enter(host):
            reservation.HOLD.unlink()
        with self.assertRaisesRegex(ValueError, 'must remain held'):self.inspect()

    def test_old_operation_cannot_be_reused_and_missing_completion_is_refused(self):
        with self.enter(self.flow.a):
            for operation, previous in ((OP, OP), ('../../bad', OP), (NEW, 'not-a-uuid')):
                with self.assertRaisesRegex(ValueError, 'new operation'):
                    rollback.inspect(operation, previous, self.reports[1])
            with self.assertRaises(FileNotFoundError):
                rollback.inspect(NEW, '00000000-0000-4000-8000-000000000004', self.reports[1])


if __name__ == '__main__':
    unittest.main()
