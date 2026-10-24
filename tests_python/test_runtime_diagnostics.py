"""Read-only fixture diagnostics retain no identifiers, messages or secrets."""
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sqlite3
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('runtime_diagnostics',ROOT/'tests/fixtures/runtime_diagnostics.py')
runtime=importlib.util.module_from_spec(spec);spec.loader.exec_module(runtime)
from tests_python.test_rehearsal_diagnostics import diag


class RuntimeDiagnosticTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);self.root=Path(temp.name)

    def test_query_only_diagnostic_reports_flags_and_age_categories_without_values(self):
        path=self.root/'state.sqlite3'
        with sqlite3.connect(path) as db:
            db.executescript('CREATE TABLE cluster_state(key TEXT PRIMARY KEY,value TEXT); CREATE TABLE ha_local(message_id TEXT,generation INTEGER,acked INTEGER);')
            db.executemany('INSERT INTO cluster_state VALUES(?,?)',[
                ('management_selection','PRIVATE-IDENTITY'),('ha_required','1'),
                ('ha_last_success','990'),('last_sync','950'),('secret','PRIVATE-KEY')])
            db.execute("INSERT INTO ha_local VALUES('PRIVATE-MESSAGE',2,0)")
        before=hashlib.sha256(path.read_bytes()).hexdigest()
        with patch.object(runtime.time,'time',return_value=1000):result=runtime.database(path)
        self.assertEqual(result,{'selected':True,'replication_required':True,'pending_updates':True,
                                 'unprotected':True,'heartbeat':'fresh','policy_sync':'stale'})
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(),before)
        self.assertEqual(list(self.root.iterdir()),[path])
        self.assertNotIn('PRIVATE',json.dumps(result));self.assertNotIn('990',json.dumps(result))

    def test_missing_and_invalid_database_are_unavailable_and_never_created(self):
        path=self.root/'state.sqlite3'
        for exists in (False,True):
            if exists:path.write_bytes(b'not-a-database')
            result=runtime.database(path)
            self.assertTrue(all(v is None for k,v in result.items() if k not in ('heartbeat','policy_sync')))
            self.assertEqual(result['heartbeat'],'unavailable');self.assertEqual(path.exists(),exists)
        self.assertEqual(path.read_bytes(),b'not-a-database')

    def test_freshness_never_accepts_future_invalid_or_missing_timestamps(self):
        for value,expected in [(None,'missing'),('secret','invalid'),('0','invalid'),('-1','invalid'),
                               ('1001','invalid'),('1000','fresh'),('970','fresh'),('969','stale')]:
            self.assertEqual(runtime.freshness(value,1000),expected)

    def test_health_uses_only_bounded_loopback_without_redirects_or_proxy(self):
        class Response(io.BytesIO):status=200
        for value,expected in [({'status':'ok','smtp_ready':True},'ready'),
                               ({'status':'ok','smtp_ready':False},'not_ready'),
                               ({'status':'ok','smtp_ready':'true'},'invalid'),([], 'invalid')]:
            response=Response(json.dumps(value).encode())
            opener=SimpleNamespace(open=lambda url,timeout: response)
            with patch.object(runtime.urllib.request,'build_opener',return_value=opener) as build:
                self.assertEqual(runtime.health('mx1'),expected)
                self.assertEqual(build.call_args.args[0].proxies,{})
                self.assertIsInstance(build.call_args.args[1],runtime.NoRedirect)
        class Opener:
            def open(self,url,timeout):
                self.url=url;self.timeout=timeout
                return Response(b'x'*4097)
        opener=Opener()
        with patch.object(runtime.urllib.request,'build_opener',return_value=opener):
            self.assertEqual(runtime.health('mx2'),'invalid')
        self.assertEqual(opener.url,'http://127.0.0.1:18081/healthz');self.assertEqual(opener.timeout,2)

    def test_unknown_service_output_or_failures_never_leak_command_output(self):
        with patch.object(runtime,'database',return_value={}),patch.object(runtime,'health',return_value='unavailable'):
            for stdout in (b'active\n',b'PRIVATE-SERVICE\n'):
                with patch.object(runtime.subprocess,'run',return_value=SimpleNamespace(stdout=stdout)):
                    result=runtime.observe('mx1')
                    self.assertEqual(result['service'],'active' if stdout.startswith(b'active') else 'unavailable')
                    self.assertNotIn('PRIVATE',json.dumps(result))
            with patch.object(runtime.subprocess,'run') as command:
                with self.assertRaises(ValueError):runtime.observe('PRIVATE-NODE')
                command.assert_not_called()

    def test_public_renderer_accepts_only_closed_schema_and_enum_values(self):
        value={'schema':'noisefence-fixture-runtime-diagnostic-1','service':'active','health':'not_ready',
               'database':{'selected':True,'replication_required':True,'pending_updates':False,'unprotected':False,
                           'heartbeat':'fresh','policy_sync':'stale'}}
        self.assertEqual(diag.runtime_observation(json.dumps(value)),value)
        for bad in (None,'broken',json.dumps({**value,'secret':'PRIVATE'}),
                    json.dumps({**value,'service':'PRIVATE'}),
                    json.dumps({**value,'database':{**value['database'],'selected':1}}),
                    json.dumps({**value,'database':{**value['database'],'policy_sync':'PRIVATE'}})):
            self.assertEqual(diag.runtime_observation(bad),{'status':'unavailable'})

    def test_migration_failure_identifies_public_source_without_its_private_value(self):
        folder=self.root/'paired';folder.mkdir()
        (folder/'failure-command.log').write_text('ValueError: MX readiness deadline exceeded; no legacy rollback is permitted PRIVATE-HOST')
        (folder/'mx1-journal.log').write_text('central management synchronization pending PRIVATE-TOKEN\ndurable replication unavailable PRIVATE-MESSAGE')
        result=diag.diagnose(self.root,'paired')
        self.assertTrue(any(x['source']=='deploy/postgresql/migrate.py' for x in result['logs']['paired/failure-command.log']['assertions']))
        self.assertEqual(result['logs']['paired/mx1-journal.log']['indicators'],['central_sync_pending','replication_unavailable'])
        self.assertNotIn('PRIVATE',json.dumps(result));self.assertEqual(result['status'],'failed')


if __name__ == '__main__':unittest.main()
