"""Retained preparation keeps all writers held and cannot become a forward upgrade."""
import contextlib
import copy
import errno
import json
import unittest
from unittest.mock import patch

from tests_python import test_retained_validation as fixtures
import rollback_promotion as retained_promotion
import rollback_validation as retained
import upgrade_activation as activation
import upgrade_promotion as promotion
import upgrade_reservation as reservation
from migration_protocol import canonical

NEW=fixtures.NEW


class RetainedPromotionTests(unittest.TestCase):
    def setUp(self):
        self.fixture=fixtures.RetainedValidationTests();self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.a,self.b=self.fixture.flow.a,self.fixture.flow.b
        for host in (self.a,self.b):
            self.fixture.start(host)
            host.events.clear()

    @contextlib.contextmanager
    def enter(self,host,ready=True):
        with self.fixture.enter(host), patch.object(retained.RetainedValidation,'status',return_value={'validation_ready':ready}):
            yield retained_promotion.RetainedPromotion(NEW)

    def prepare(self):
        reports=[]
        for host in (self.a,self.b):
            with self.enter(host) as operation:reports.append(operation.prepare())
        return reports

    def test_preparation_switch_and_restore_preserve_selected_data_and_stopped_writers(self):
        left,right=self.prepare()
        for host,peer in ((self.a,right),(self.b,left)):
            with self.enter(host) as operation:
                changed=operation.promote(peer)
                self.assertEqual(changed['protocol'],retained_promotion.REPORT)
                self.assertEqual(changed['phase'],'promoted')
                self.assertEqual(host.current.resolve(),host.old)
                self.assertTrue(reservation.HOLD.exists())
                self.assertEqual(operation.promote(peer),changed)
                self.assertTrue(all(e[1]!='start' for e in host.events if isinstance(e,list)))
                with self.assertRaises(ValueError):promotion.Promotion(NEW).state()
                with self.assertRaises(ValueError):activation.Activation(NEW).arm(peer)
                restored=operation.restore()
                self.assertEqual(host.current.resolve(),host.new)
                self.assertEqual(restored['phase'],'restored')
        restored=[]
        for host in (self.a,self.b):
            with self.enter(host) as operation:restored.append(operation.report())
        for index,host in enumerate((self.a,self.b)):
            with self.enter(host) as operation:
                released=operation.release(restored[1-index])
                self.assertEqual(released['phase'],'released')
                result=reservation.Reservation(NEW).cancel()
                self.assertEqual(result['phase'],'cancelled')
                self.assertEqual(host.current.resolve(),host.new)
                self.assertEqual(operation.release(restored[1-index]),released)

    def test_fresh_validator_readiness_is_required_before_any_preparation_receipt(self):
        with self.enter(self.a,ready=False) as operation:
            with self.assertRaisesRegex(ValueError,'Live candidate'):operation.prepare()
            self.assertFalse(operation.path.exists());self.assertFalse(operation.marker.exists())
        self.assertEqual(self.a.current.resolve(),self.a.new)

    def test_forward_and_retained_wire_contracts_are_not_interchangeable(self):
        left,right=self.prepare()
        with self.enter(self.a) as operation:
            for peer in [self.fixture.fixture.reports[1],{**right,'protocol':promotion.REPORT}]:
                with self.assertRaises(ValueError):operation.promote(peer)
            with self.assertRaises(ValueError):promotion.checked_report(left)
            with self.assertRaises(ValueError):activation.checked_report(left)
            self.assertEqual(self.a.current.resolve(),self.a.new)
            self.assertTrue(reservation.HOLD.exists())

    def test_history_changes_block_before_pointer_switch(self):
        left,right=self.prepare()
        with self.enter(self.a) as operation:
            context=retained.context_path(NEW);original=context.read_bytes()
            value=json.loads(original);value['inspection']['previous_decision_sha256']='9'*64
            context.write_bytes(canonical(value))
            with self.assertRaisesRegex(ValueError,'history'):operation.promote(right)
            context.write_bytes(original)
            self.a.policy={'sequence':2,'revision':2,'digest':'9'*64}
            with self.assertRaisesRegex(ValueError,'history'):operation.promote(right)
            self.assertEqual(self.a.current.resolve(),self.a.new)
            self.assertTrue(reservation.HOLD.exists())

    def test_retained_archive_change_blocks_before_preparation(self):
        self.a.old_identity['binary_sha256']='9'*64
        with self.enter(self.a) as operation:
            with self.assertRaisesRegex(ValueError,'Validated candidate files changed'):operation.prepare()
            self.assertFalse(operation.path.exists())

    def test_full_disk_before_durable_preparation_never_changes_pointer(self):
        with self.enter(self.a) as operation, patch.object(promotion,'atomic',side_effect=OSError(errno.ENOSPC,'full')):
            with self.assertRaises(OSError):operation.prepare()
            self.assertFalse(operation.path.exists())
            self.assertEqual(self.a.current.resolve(),self.a.new)
            self.assertTrue(reservation.HOLD.exists())

    def test_rename_before_reply_retries_with_the_same_history_and_binding(self):
        left,right=self.prepare()
        with self.enter(self.a) as operation:
            actual=operation.save
            def lost(state,phase):
                if phase=='promoted':raise EOFError('lost result after pointer rename')
                return actual(state,phase)
            with patch.object(operation,'save',side_effect=lost):
                with self.assertRaises(EOFError):operation.promote(right)
            self.assertEqual(self.a.current.resolve(),self.a.old)
            self.assertEqual(operation.state()['phase'],'promoting')
            self.assertEqual(operation.promote(right)['phase'],'promoted')
            self.assertEqual(operation.restore()['phase'],'restored')

    def test_expiry_preserves_hold_and_allows_restoration(self):
        left,right=self.prepare()
        self.fixture.flow.clock=self.fixture.expiry+1
        with self.enter(self.a) as operation:
            with self.assertRaisesRegex(ValueError,'expired'):operation.promote(right)
            self.assertEqual(self.a.current.resolve(),self.a.new)
            self.assertEqual(operation.restore()['phase'],'restored')


if __name__=='__main__':unittest.main()
