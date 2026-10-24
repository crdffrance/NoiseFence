"""New upgrades advance versions; old durable recovery decisions stay readable."""
import contextlib
import copy
import io
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tests_python.test_upgrade_validation import descriptor, OP
from tests_python.test_upgrade_promotion import Host
from tests_python.test_upgrade_activation import ActivationHost
import upgrade_validation as validation
import upgrade_reservation as reservation


class DirectionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()

    def test_semantic_order_includes_prereleases_and_refuses_replacements(self):
        for before,after in [('0.31.9','0.32.0-rc.1'),('0.32.0-rc.9','0.32.0-rc.10'),
                             ('0.32.0-rc.10','0.32.0'),('0.32.0','0.32.1')]:
            with self.subTest(before=before,after=after):
                validation.require_forward_upgrade({'version':before},{'version':after})
                with self.assertRaisesRegex(ValueError,'must be newer'):
                    validation.require_forward_upgrade({'version':after},{'version':before})
                with self.assertRaisesRegex(ValueError,'must be newer'):
                    validation.require_forward_upgrade({'version':after},{'version':after})
        for invalid in (None,'0.32.0+changed','v0.32.0','0.32.0-rc.01'):
            with self.assertRaises(ValueError):validation.require_forward_upgrade({'version':'0.32.0'},{'version':invalid})

    def test_descriptor_and_start_refuse_before_candidate_execution_or_receipts(self):
        own=descriptor();own['candidate']['version']='0.32.0'
        old={**own['candidate'],'directory':'/opt/noisefence/releases/installed','version':'0.32.1'}
        hold=SimpleNamespace(state=lambda:{'installation':{'release_directory':old['directory']}})
        with patch.object(reservation,'STATE',self.root),patch.object(validation,'held',return_value=hold), \
             patch.object(validation,'candidate',side_effect=lambda p:copy.deepcopy(old if str(p)==old['directory'] else own['candidate'])), \
             patch.object(reservation,'execute') as execute,patch.object(validation,'service_files') as services, \
             patch.object(reservation,'private_read') as read,patch.object(validation,'link_to') as link:
            for original in ('0.32.1','0.32.0'):
                old['version']=original
                with self.subTest(original=original):
                    with self.assertRaisesRegex(ValueError,'must be newer'):
                        validation.describe(OP,Path(own['candidate']['directory']),own['expires_at'])
                    with self.assertRaisesRegex(ValueError,'must be newer'):
                        validation.Validation(OP).start(Path(own['candidate']['directory']),descriptor('mx2'),own['expires_at'])
            execute.assert_not_called();services.assert_not_called();read.assert_not_called();link.assert_not_called()
            self.assertEqual(list(self.root.iterdir()),[])

    def test_forward_descriptor_retains_exact_identity(self):
        own=descriptor();own['candidate']['version']='0.32.0-rc.2'
        old={**own['candidate'],'directory':'/opt/noisefence/releases/installed','version':'0.32.0-rc.1'}
        hold=SimpleNamespace(state=lambda:{'installation':{'release_directory':old['directory']}})
        raw=b'[replication]\npeer_id="mx2"\n'
        with patch.object(validation,'held',return_value=hold), \
             patch.object(validation,'candidate',side_effect=lambda p:copy.deepcopy(old if str(p)==old['directory'] else own['candidate'])), \
             patch.object(reservation,'read_selection',return_value=own['selection']), \
             patch.object(reservation,'private_read',side_effect=lambda *a:contextlib.nullcontext(io.BytesIO(raw))), \
             patch.object(validation,'policy_epoch',return_value=own['policy']), \
             patch.object(validation,'unit_template',return_value=b'synthetic unit'):
            result=validation.describe(OP,Path(own['candidate']['directory']),own['expires_at'])
            self.assertEqual(result['candidate'],own['candidate'])
            self.assertEqual(result['selection'],own['selection'])

    def hosts(self,kind=Host):
        hosts=[kind(self.root,node,int(time.time())+600) for node in ('mx1','mx2')]
        for host in hosts:
            host.old_identity['version']='0.32.1';host.own['candidate']['version']='0.32.0'
        hosts[0].peer=copy.deepcopy(hosts[1].own);hosts[1].peer=copy.deepcopy(hosts[0].own)
        return hosts

    def test_new_preparation_is_refused_without_changing_a_pointer(self):
        for host in self.hosts():
            with host.enter() as operation:
                with self.assertRaisesRegex(ValueError,'must be newer'):operation.prepare()
                self.assertFalse(operation.path.exists());self.assertFalse(operation.marker.exists())
            self.assertEqual(host.current.resolve(),host.old);self.assertEqual(host.events,[])

    def test_historical_preparation_cannot_advance_but_can_restore_and_release(self):
        hosts=self.hosts();prepared=[]
        # Simulate receipts created by a helper predating the direction gate.
        with patch.object(validation,'require_forward_upgrade'):
            for host in hosts:
                with host.enter() as operation:prepared.append(operation.prepare())
        restored=[]
        for index,host in enumerate(hosts):
            with host.enter() as operation:
                with self.assertRaisesRegex(ValueError,'must be newer'):operation.promote(prepared[1-index])
                self.assertEqual(host.events,[]);restored.append(operation.restore())
        for index,host in enumerate(hosts):
            with host.enter() as operation:self.assertEqual(operation.release(restored[1-index])['phase'],'released')
            self.assertEqual(host.current.resolve(),host.old)

    def legacy_activated(self, *, arm=False, commit=False):
        hosts=self.hosts(ActivationHost);prepared=[];promoted=[];armed=[]
        with patch.object(validation,'require_forward_upgrade'):
            for host in hosts:
                with host.enter() as op:prepared.append(op.promoted.prepare())
            for index,host in enumerate(hosts):
                with host.enter() as op:promoted.append(op.promoted.promote(prepared[1-index]))
            if arm or commit:
                with hosts[0].enter() as op:armed.append(op.arm(promoted[1]))
                with hosts[1].enter() as op:armed.append(op.arm(armed[0]))
            if commit:
                with hosts[0].enter() as op:decision=op.decide('activate',armed[1])
                with hosts[1].enter() as op:op.accept(decision)
        return hosts,promoted,armed

    def test_historical_promoted_downgrade_cannot_gain_a_new_promise(self):
        hosts,promoted,_=self.legacy_activated()
        with hosts[0].enter() as op:
            with self.assertRaisesRegex(ValueError,'must be newer'):op.arm(promoted[1])
            self.assertFalse(op.path.exists());self.assertFalse(op.marker.exists())
            self.assertEqual(op.promoted.restore()['phase'],'restored')

    def test_historical_promises_can_abort_but_cannot_commit_downgrade(self):
        hosts,_,armed=self.legacy_activated(arm=True)
        with hosts[0].enter() as op:
            with self.assertRaisesRegex(ValueError,'must be newer'):op.decide('activate',armed[1])
            self.assertIsNone(op.state()['decision'])
            decision=op.decide('abort')
        with hosts[1].enter() as op:op.accept(decision)
        aborted=[]
        for host in hosts:
            with host.enter() as op:aborted.append(op.abort())
        for index,host in enumerate(hosts):
            with host.enter() as op:self.assertEqual(op.cancel(aborted[1-index])['phase'],'cancelled')
            self.assertEqual(host.current.resolve(),host.old)

    def test_already_committed_decision_is_immutable_and_forward_recoverable(self):
        hosts,_,_=self.legacy_activated(commit=True)
        reports=[]
        for host in hosts:
            with host.enter() as op:reports.append(op.report())
        with hosts[0].enter() as op:
            self.assertEqual(op.decide('activate'),reports[0])
            with self.assertRaisesRegex(ValueError,'cannot be replaced'):op.decide('abort')
        for index,host in enumerate(hosts):
            with host.enter() as op:self.assertEqual(op.start(reports[1-index])['phase'],'started')
            self.assertEqual(host.current.resolve(),host.new)


if __name__ == '__main__':unittest.main()
