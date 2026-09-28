"""Checkpoint scheduling only follows exact source and transfer confirmation."""
import contextlib
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'deploy/postgresql'))
import recovery_checkpoint as checkpoint

OP='00000000-0000-4000-8000-000000000001'
SNAP='00000000-0000-4000-8000-000000000002'


class SchedulingTests(unittest.TestCase):
    def setUp(self):
        self.stack=contextlib.ExitStack();self.addCleanup(self.stack.close)
        self.root=Path(self.stack.enter_context(tempfile.TemporaryDirectory())).resolve()
        self.state=self.root/'standby';(self.state/'active/data').mkdir(parents=True)
        self.operation=self.root/'operation';self.operation.mkdir()
        self.plan={'protocol':'noisefence-recovery-checkpoint-1','operation':OP,
            'runtime_authorization':str(self.root/'runtime.json'),'runtime_identity':'a'*64,
            'receiver':'standby@mx1.example.test','key_sha256':'b'*64,'known_hosts_sha256':'c'*64,
            'service_sha256':'d'*64,'timer_sha256':'e'*64,'expires_at':int(time.time())+600}
        self.auth=self.root/'checkpoint.json';self.write_plan()
        self.runtime=types.SimpleNamespace(plan={'operation':OP},binding='a'*64,state={'phase':'running'},
            manifest={'owner':'mx1'},root=self.operation,run=Mock())
        self.stack.enter_context(patch.object(checkpoint,'Runtime',return_value=self.runtime))
        self.stack.enter_context(patch.object(checkpoint,'STATE',self.state))
        self.stack.enter_context(patch.object(checkpoint,'root_json',side_effect=lambda p:json.loads(Path(p).read_bytes())))
        self.install=self.stack.enter_context(patch.object(checkpoint,'installation',return_value={'owner':'mx1'}))
        self.states={checkpoint.SERVICE:'inactive',checkpoint.TIMER:'inactive'}
        self.stack.enter_context(patch.object(checkpoint,'unit_state',side_effect=lambda unit:self.states.get(unit,'unknown')))
        self.run=self.stack.enter_context(patch.object(checkpoint,'execute',side_effect=self.execute))
        self.failed_transfer=False;self.stale=False

    def write_plan(self):
        self.auth.write_text(json.dumps(self.plan));self.auth.chmod(0o600)

    def execute(self,args,**kwargs):
        if args[1:] == ['start',checkpoint.SERVICE]:
            if self.failed_transfer:raise ValueError('Receiver unavailable')
            path=self.state/'active/data/ha-standby-status.json'
            path.write_text(json.dumps({'owner':'mx1','snapshot':SNAP,'received':int(time.time()),
                'bytes':1000,'postgresql_restore_required':True,'last_error':None}))
            path.chmod(0o600)
            if self.stale:
                import os
                os.utime(path,ns=(1,1))
        if args[1:]==['enable','--now',checkpoint.TIMER]:self.states[checkpoint.TIMER]='active'
        return b'enabled\n' if args[1:]==['is-enabled',checkpoint.TIMER] else b''

    def test_success_transfers_before_enabling_and_retry_does_not_export(self):
        self.assertEqual(checkpoint.configure(self.auth)['status'],'checkpoint_timer_enabled')
        commands=[call.args[0] for call in self.run.call_args_list]
        self.assertLess(commands.index(['/usr/bin/systemctl','start',checkpoint.SERVICE]),
                        commands.index(['/usr/bin/systemctl','enable','--now',checkpoint.TIMER]))
        self.run.reset_mock()
        self.assertEqual(checkpoint.configure(self.auth)['status'],'checkpoint_timer_verified')
        self.assertEqual([c.args[0] for c in self.run.call_args_list],[['/usr/bin/systemctl','is-enabled',checkpoint.TIMER]])

    def test_failed_or_stale_receipt_never_enables_timer(self):
        for failure in ('failed_transfer','stale'):
            setattr(self,failure,True)
            with self.assertRaises(ValueError):checkpoint.configure(self.auth)
            self.assertFalse(any(c.args[0][1:]==['enable','--now',checkpoint.TIMER] for c in self.run.call_args_list))
            setattr(self,failure,False);self.run.reset_mock()

    def test_wrong_runtime_and_changed_transport_refuse(self):
        self.runtime.binding='f'*64
        with self.assertRaises(ValueError):checkpoint.configure(self.auth)
        self.run.assert_not_called()
        self.runtime.binding='a'*64
        checkpoint.configure(self.auth)
        self.run.reset_mock();self.plan['key_sha256']='f'*64;self.write_plan()
        with self.assertRaises(ValueError):checkpoint.configure(self.auth)
        self.run.assert_not_called()

    def test_disabled_completed_timer_is_not_silently_reenabled(self):
        checkpoint.configure(self.auth);self.run.reset_mock()
        self.states[checkpoint.TIMER]='inactive'
        with self.assertRaises(ValueError):checkpoint.configure(self.auth)
        self.run.assert_not_called()


if __name__=='__main__':unittest.main()
