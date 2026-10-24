"""Restricted, exact-pair report exchange; synthetic receipts and no live SSH."""
import contextlib
import copy
import io
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from tests_python import test_upgrade_activation as activation_fixtures
import upgrade_activation as activation
import upgrade_exchange as exchange
import upgrade_reservation as reservation
from migration_protocol import canonical


class ExchangeTests(unittest.TestCase):
    def setUp(self):
        fixture = activation_fixtures.ActivationTests();fixture.setUp();self.addCleanup(fixture.doCleanups)
        fixture.commit();fixture.start();self.clock = fixture.clock
        self.reports = {'mx1':fixture.report(fixture.a),'mx2':fixture.report(fixture.b)}
        self.proofs = {'mx1':fixture.proof(fixture.a),'mx2':fixture.proof(fixture.b)}
        own = self.reports['mx1']
        self.cfg = {'protocol':exchange.PROTOCOL,'operation':own['operation'],
                    'proposal_sha256':activation.checked_proposal(own['proposal'],own['operation']),
                    'expires_at':self.clock+600,'coordinator':'mx1','ssh_key':'/root/key','known_hosts':'/root/hosts',
                    'nodes':{node:{'host':'127.0.0.1','port':2200+i,'user':'root'} for i,node in enumerate(self.reports)}}
        self.auth = exchange.binding(self.cfg)|{'node':'mx1','expires_at':self.cfg['expires_at']}
        self.request = exchange.binding(self.cfg)|{'node':'mx1','nonce':str(exchange.uuid.uuid4()),'action':'status','peer':None}
        self.events=[]

    def backend(self,node,action,peer):
        self.events.append((node,action))
        if action=='status':return copy.deepcopy(self.reports[node])
        if action=='check':return copy.deepcopy(self.proofs[node])
        report=self.reports[node]
        if action=='verify':
            report.update(phase='verified',verified_at=self.clock)
        if action=='finish':
            self.assertIn(peer['phase'],('verified','finishing','complete'))
            report.update(phase='complete',peer_completion={'node':peer['node'],'verified_at':peer['verified_at'],'outcome':'activate'})
        return copy.deepcopy(report)

    def test_completes_both_with_fresh_proofs_and_records_each_response(self):
        records=[]
        result=exchange.complete(self.cfg,self.backend,lambda *args:records.append(args))
        self.assertEqual([r['phase'] for r in result.values()],['complete','complete'])
        self.assertEqual(len(self.events),8);self.assertEqual(len(records),8)
        self.assertEqual(self.events[-2:],[('mx1','finish'),('mx2','finish')])
        for node,report in result.items():exchange.checked_report(report,self.cfg,node)

    def test_lost_completion_reply_resumes_without_replacing_proofs(self):
        original=self.backend
        def interrupted(node,action,peer):
            result=original(node,action,peer)
            if (node,action)==('mx1','finish'):raise EOFError('lost reply')
            return result
        with self.assertRaises(EOFError):exchange.complete(self.cfg,interrupted,lambda *_:None)
        self.events=[]
        result=exchange.complete(self.cfg,self.backend,lambda *_:None)
        self.assertEqual([r['phase'] for r in result.values()],['complete','complete'])
        self.assertFalse(any(action in ('check','verify') for _,action in self.events))

    def test_unstarted_pair_and_changed_binding_never_complete(self):
        self.reports['mx1']['phase']='decided';self.reports['mx1']['started_at']=None
        with self.assertRaises(ValueError):exchange.complete(self.cfg,self.backend,lambda *_:None)
        self.assertEqual({action for _,action in self.events},{'status'})
        self.reports['mx1']['phase']='started';self.reports['mx1']['started_at']=self.clock
        self.cfg['proposal_sha256']='f'*64
        with self.assertRaises(ValueError):exchange.complete(self.cfg,self.backend,lambda *_:None)

    def test_node_authorization_precedes_all_actions(self):
        for change in [{'expires_at':self.clock-1},{'node':'other'},{'proposal_sha256':'e'*64}]:
            with patch.object(activation,'Activation') as operation:
                with self.assertRaises(ValueError):exchange.handle(self.auth|change,self.request)
                operation.assert_not_called()

    def test_agent_refuses_unlisted_actions_and_argument_injection(self):
        for change in [{'action':'start'},{'action':'decide'},{'action':'__getattribute__'},
                       {'peer':self.reports['mx2']},{'path':'/etc/shadow'}, {'nonce':'bad'}]:
            with patch.object(activation,'Activation') as operation:
                with self.assertRaises(ValueError):exchange.handle(self.auth,self.request|change)
                operation.assert_not_called()

    def test_agent_uses_native_report_and_proof_validation(self):
        op=MagicMock();op.report.return_value=self.reports['mx1'];op.check.return_value=self.proofs['mx1']
        request=self.request|{'action':'check','peer':self.reports['mx2']}
        with patch.object(reservation,'operation_lock',contextlib.nullcontext),patch.object(activation,'Activation',return_value=op):
            result=exchange.handle(self.auth,request)
            self.assertEqual(result['nonce'],request['nonce']);op.check.assert_called_once_with(self.reports['mx2'])
            op.check.reset_mock();bad=copy.deepcopy(request);bad['peer']['node']='mx1'
            with self.assertRaises(ValueError):exchange.handle(self.auth,bad)
            op.check.assert_not_called()

    def test_local_authorization_cannot_exchange_a_different_pair(self):
        op=MagicMock();op.report.return_value=copy.deepcopy(self.reports['mx1']);op.report.return_value['operation']=str(exchange.uuid.uuid4())
        with patch.object(reservation,'operation_lock',contextlib.nullcontext),patch.object(activation,'Activation',return_value=op):
            with self.assertRaises(ValueError):exchange.handle(self.auth,self.request)

    def test_exact_ssh_flags_disable_agent_config_forwarding_and_fallback(self):
        args=exchange.ssh_command(self.cfg,'mx2')
        self.assertEqual(args[:5],['/usr/bin/ssh','-F','/dev/null','-T','-o'])
        for value in ['StrictHostKeyChecking=yes','IdentityAgent=none','IdentitiesOnly=yes','ForwardAgent=no',
                      'PasswordAuthentication=no','ClearAllForwardings=yes','ProxyCommand=none',
                      'ControlPath=none','HostKeyAlias=noisefence-upgrade-mx2','GlobalKnownHostsFile=/dev/null']:
            self.assertIn(value,args)
        self.assertEqual(args[-1],exchange.COMMAND);self.assertNotIn('sudo',args)

    def test_config_checks_private_key_numeric_hosts_and_expiry(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve();key=root/'key';key.write_text('synthetic');key.chmod(0o600)
            hosts=root/'hosts';hosts.write_text('synthetic')
            cfg=self.cfg|{'ssh_key':str(key),'known_hosts':str(hosts)}
            with patch.object(reservation,'protected',side_effect=lambda path:path.stat()):
                exchange.configuration(cfg)
                key.chmod(0o644)
                with self.assertRaises(ValueError):exchange.configuration(cfg)
                key.chmod(0o600)
                for host in ['-oProxyCommand=wrong','host.example','127.00.0.1','127.0.0.1;id']:
                    other=copy.deepcopy(cfg);other['nodes']['mx1']['host']=host
                    with self.assertRaises(ValueError):exchange.configuration(other)
                with self.assertRaises(ValueError):exchange.configuration(cfg|{'expires_at':self.clock-1})

    def test_frame_rejects_overflow_duplicates_and_nonfinite_json(self):
        for raw in [b'{"a":1,"a":2}',b'{"x":NaN}',b'[]']:
            channel=MagicMock();channel.read.side_effect=[struct.pack('!I',len(raw)),raw]
            with self.assertRaises(ValueError):exchange.receive(channel)
        channel=MagicMock();channel.read.return_value=struct.pack('!I',exchange.MAX_FRAME+1)
        with self.assertRaises(ValueError):exchange.receive(channel)
        self.assertEqual(channel.read.call_count,1)
        with self.assertRaises(ValueError):exchange.send(channel,{'x':'x'*exchange.MAX_FRAME})

    def child(self, suffix=''):
        code='import sys,json,struct\nn=struct.unpack("!I",sys.stdin.buffer.read(4))[0]\nr=json.loads(sys.stdin.buffer.read(n))\n'
        code+='v={k:r[k] for k in r if k!="peer"}\nv["result"]='+repr(self.reports['mx1'])+'\n'
        code+=suffix or 'b=json.dumps(v).encode();sys.stdout.buffer.write(struct.pack("!I",len(b))+b);sys.stdout.buffer.flush()'
        return [sys.executable,'-c',code]

    def test_real_subprocess_frames_reject_replay_trailing_bytes_and_failure(self):
        with patch.object(exchange,'ssh_command',return_value=self.child()):
            self.assertEqual(exchange.call(self.cfg,'mx1','status'),self.reports['mx1'])
        endings=[
            'v["nonce"]="wrong";b=json.dumps(v).encode();sys.stdout.buffer.write(struct.pack("!I",len(b))+b)',
            'b=json.dumps(v).encode();sys.stdout.buffer.write(struct.pack("!I",len(b))+b+b"extra")',
            'b=json.dumps(v).encode();sys.stdout.buffer.write(struct.pack("!I",len(b))+b);sys.stdout.buffer.flush();sys.exit(1)',
            'sys.stdout.buffer.write(struct.pack("!I",100)+b"short")']
        for ending in endings:
            with patch.object(exchange,'ssh_command',return_value=self.child(ending)):
                with self.assertRaises((ValueError,EOFError)):exchange.call(self.cfg,'mx1','status')

    def test_hung_subprocess_is_terminated_at_deadline(self):
        with patch.object(exchange,'TRANSPORT_SECONDS',.1),patch.object(exchange,'ssh_command',return_value=self.child('import time;time.sleep(30)')):
            with self.assertRaises(TimeoutError):exchange.call(self.cfg,'mx1','status')

    def test_serve_rejects_unrestricted_invocations_before_loading_authorization(self):
        with patch.dict(exchange.os.environ,{},clear=True),patch.object(reservation,'read_json') as read:
            with self.assertRaises(ValueError):exchange.serve()
            read.assert_not_called()

    def test_agent_refuses_expired_runtime_proof_before_verification(self):
        op=MagicMock();op.report.return_value=self.reports['mx1']
        stale=self.proofs['mx2']|{'checked_at':self.clock-31}
        request=self.request|{'action':'verify','peer':stale}
        with patch.object(reservation,'operation_lock',contextlib.nullcontext),patch.object(activation,'Activation',return_value=op):
            with self.assertRaises(ValueError):exchange.handle(self.auth,request)
            op.verify.assert_not_called()

    def test_successful_sibling_reply_is_recorded_if_other_node_fails(self):
        records=[]
        def fail(node,action,peer):
            if node=='mx1':raise EOFError('synthetic peer unavailable')
            return self.backend(node,action,peer)
        with self.assertRaises(EOFError):exchange.complete(self.cfg,fail,lambda *args:records.append(args))
        self.assertEqual([name for name,_ in records],['status-mx2'])
