"""Runtime recovery ordering, installation binding and credential handling."""
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'deploy/postgresql'))
import recovery_runtime as runtime

OP = '00000000-0000-4000-8000-000000000001'


class AuthorizationTests(unittest.TestCase):
    def test_renewed_fence_time_does_not_change_operation_identity(self):
        plan={'operation':OP,'preparation_sha256':'a'*64,'expires_at':10,
              'fence':{'operation':OP,'owner':'mx1','created':1,'created_ns':100,'method':'systemd-persistent-condition'}}
        original=runtime.authorization_identity(plan)
        renewed={**plan,'expires_at':20,'fence':{**plan['fence'],'created':2}}
        self.assertEqual(runtime.authorization_identity(renewed),original)
        for key,value in {'owner':'mx9','operation':'another','created_ns':200,'method':'provider-poweroff'}.items():
            self.assertNotEqual(runtime.authorization_identity({**renewed,'fence':{**renewed['fence'],key:value}}),original)
        self.assertNotEqual(runtime.authorization_identity({**renewed,'preparation_sha256':'b'*64}),original)


class UnitTests(unittest.TestCase):
    def fixture(self):
        result = {key:'' for key in ('ExecStartPre','ExecStartPost','ExecCondition','ExecStop','ExecStopPost',
                                   'DropInPaths','CapabilityBoundingSet')}
        result.update(User='noisefence',Group='noisefence',NoNewPrivileges='yes',PrivateTmp='yes',
            PrivateDevices='yes',RestrictSUIDSGID='yes',ProtectSystem='strict',ProtectHome='yes',
            AppArmorProfile='noisefence-console',FragmentPath='/etc/systemd/system/noisefence-console.service',
            MainPID='123',ExecStart='{ path=/opt/release/noisefence ; argv[]=/opt/release/noisefence --config '
                +str(runtime.ACTIVE/'console.toml')+' serve-console ; ignore_errors=no ; }')
        return result

    def test_empty_systemd_exec_arrays_are_omitted_but_security_fields_are_required(self):
        fields = self.fixture()
        raw = '\n'.join(k+'='+v for k,v in fields.items() if v or not k.startswith('Exec'))
        with patch.object(runtime,'execute',return_value=raw.encode()):
            self.assertEqual(runtime.unit_properties(),fields)
        with patch.object(runtime,'execute',return_value=raw.replace('NoNewPrivileges=yes\n','').encode()), self.assertRaises(ValueError):
            runtime.unit_properties()

    def test_actual_command_and_protections_must_match(self):
        fields = self.fixture()
        with patch.object(runtime,'fingerprint') as checked:
            runtime.validate_unit(fields,'noisefence','/opt/release/noisefence','a'*64)
            checked.assert_called_once()
            for key,value in {'User':'root','Group':'root','NoNewPrivileges':'no','PrivateTmp':'no',
                    'PrivateDevices':'no','RestrictSUIDSGID':'no','ProtectSystem':'full','ProtectHome':'no',
                    'AppArmorProfile':'-noisefence-console','DropInPaths':'/tmp/override.conf',
                    'CapabilityBoundingSet':'cap_sys_admin','ExecStartPre':'/bin/true',
                    'ExecStartPost':'/bin/true','ExecCondition':'/bin/true','ExecStop':'/bin/true',
                    'ExecStopPost':'/bin/true','ExecStart':fields['ExecStart'].replace('serve-console','serve')}.items():
                with self.subTest(key=key), self.assertRaises(ValueError):
                    runtime.validate_unit({**fields,key:value},'noisefence','/opt/release/noisefence','a'*64)
            with self.assertRaises(ValueError):
                runtime.validate_unit(fields,'noisefence','/different/noisefence','a'*64)


class OrderingTests(unittest.TestCase):
    def fixture(self, phase='prepared'):
        obj = runtime.Runtime.__new__(runtime.Runtime)
        obj.plan = {'operation':OP}
        obj.binding = 'a'*64
        obj.preparation = {'hostname':'mx2.example.test','console_url':'https://mx2.example.test','binary':'/opt/release/noisefence'}
        obj.root = Path('/root/recovery');obj.credentials = Path('/private/credentials')
        obj.state = {'phase':phase};obj.account = types.SimpleNamespace(pw_uid=1000)
        obj.events = []
        for name in ('verify','fence','console','release','worker_health','persist_boot'):
            setattr(obj,name,Mock(side_effect=lambda n=name:obj.events.append(n)))
        def save(phase):
            obj.events.append('save:'+phase);obj.state['phase']=phase
        obj.save = save
        return obj

    @contextlib.contextmanager
    def dependencies(self, obj):
        with contextlib.ExitStack() as stack:
            mocks={}
            for module,name in [(runtime,'login'),(runtime.recovery_proxy,'switch'),
                    (runtime.recovery_proxy,'console_health'),(runtime.recovery_proxy,'probe'),
                    (runtime,'loaded_profile'),(runtime,'process_profile'),(runtime,'unit_properties')]:
                mocks[name]=stack.enter_context(patch.object(module,name,
                    side_effect=lambda *a,n=name,**k:obj.events.append(n)))
            stack.enter_context(patch.object(runtime,'unit_state',return_value='active'))
            yield mocks

    def test_success_requires_login_and_routing_before_worker_release(self):
        obj=self.fixture()
        with self.dependencies(obj):result=obj.run()
        self.assertEqual(obj.events,['fence','verify','console','save:console_started','login',
            'save:login_verified','switch','save:proxy_verified','release','persist_boot','save:running'])
        self.assertTrue(result['console_smtp_fenced'])
        self.assertFalse(result['two_copy_smtp_availability_verified'])
        self.assertFalse(result['checkpoint_transport_resumed'])

    def test_login_or_proxy_failure_never_releases_worker(self):
        for failure in ('login','switch'):
            obj=self.fixture()
            with self.dependencies(obj) as mocks:
                mocks[failure].side_effect=ValueError('synthetic failure')
                with self.assertRaises(ValueError):obj.run()
            obj.release.assert_not_called()
            self.assertEqual(obj.events[-1],'fence')
            self.assertNotEqual(obj.state['phase'],'running')

    def test_failed_start_reinstalls_fence_and_resumes_same_operation(self):
        obj=self.fixture('worker_releasing')
        obj.release.side_effect=ValueError('synthetic startup failure')
        with self.dependencies(obj), self.assertRaises(ValueError):obj.run()
        self.assertEqual(obj.events[-1],'fence')
        obj.release.side_effect=lambda:obj.events.append('release')
        with self.dependencies(obj):obj.run()
        self.assertEqual(obj.state['phase'],'running')

    def test_completed_retry_does_not_restart_or_login(self):
        obj=self.fixture('running')
        with self.dependencies(obj) as mocks:obj.run()
        obj.fence.assert_not_called();obj.console.assert_not_called();obj.release.assert_not_called()
        mocks['login'].assert_not_called();mocks['switch'].assert_not_called()
        self.assertIn('process_profile',obj.events)
        self.assertIn('probe',obj.events)

    def test_changed_completed_authority_is_not_silently_reactivated(self):
        obj=self.fixture('running')
        obj.verify.side_effect=ValueError('central authority changed')
        with self.dependencies(obj), self.assertRaises(ValueError):obj.run()
        obj.console.assert_not_called();obj.release.assert_not_called()


class BootTests(unittest.TestCase):
    def test_new_or_earlier_runtime_gets_persistent_dependencies_once(self):
        obj=runtime.Runtime.__new__(runtime.Runtime)
        obj.state={'phase':'running'}
        receipt={'target':'multi-user.target','services':[runtime.UNIT,'noisefence.service']}
        obj.boot_persistence=Mock(return_value=receipt);obj.save=Mock()
        obj.persist_boot()
        obj.boot_persistence.assert_called_once_with(install=True)
        self.assertEqual(obj.state['boot'],receipt)
        obj.boot_persistence.reset_mock();obj.save.reset_mock()
        obj.persist_boot()
        obj.boot_persistence.assert_called_once_with()
        obj.save.assert_not_called()

    def test_missing_persisted_dependency_is_not_silently_reenabled(self):
        obj=runtime.Runtime.__new__(runtime.Runtime)
        obj.state={'phase':'running','boot':{'target':'multi-user.target','services':[runtime.UNIT,'noisefence.service']}}
        obj.boot_persistence=Mock(side_effect=ValueError('Removed by administrator'))
        obj.save=Mock()
        with self.assertRaises(ValueError):obj.persist_boot()
        obj.boot_persistence.assert_called_once_with();obj.save.assert_not_called()


class ReleaseTests(unittest.TestCase):
    @contextlib.contextmanager
    def fixture(self):
        with tempfile.TemporaryDirectory() as tmp, contextlib.ExitStack() as stack:
            root=Path(tmp).resolve()
            state=root/'state';state.mkdir();units=root/'units';units.mkdir()
            hold=state/'hold.json';hold.write_text(json.dumps({'operation':OP}));hold.chmod(0o600)
            expected=('[Unit]\nConditionPathExists=!'+str(hold)+'\n').encode()
            paths=[]
            for unit in runtime.SERVICES:
                directory=units/(unit+'.d');directory.mkdir()
                path=directory/runtime.recovery_install.DROPIN;path.write_bytes(expected);paths.append(path)
            obj=runtime.Runtime.__new__(runtime.Runtime)
            obj.plan={'operation':OP};obj.preparation={'hostname':'mx2.example.test','binary':'/release/noisefence'}
            obj.worker_data=root/'data';obj.account=types.SimpleNamespace(pw_uid=1000)
            obj.verify=Mock();obj.save=Mock();obj.worker_health=Mock()
            stack.enter_context(patch.object(runtime.recovery_install,'STATE',state))
            stack.enter_context(patch.object(runtime.recovery_install,'UNITS',units))
            stack.enter_context(patch.object(runtime,'protected',side_effect=lambda p:Path(p).stat()))
            stack.enter_context(patch.object(runtime.recovery_install,'source_locks',return_value=contextlib.nullcontext()))
            for module,name in [(runtime,'loaded_profile'),(runtime,'process_profile'),(runtime,'unit_properties'),
                    (runtime.recovery_proxy,'console_health'),(runtime.recovery_proxy,'probe')]:
                stack.enter_context(patch.object(module,name))
            stack.enter_context(patch.object(runtime,'unit_state',return_value='active'))
            run=stack.enter_context(patch.object(runtime,'execute'))
            yield obj,hold,paths,run

    def test_release_removes_only_matching_hold_and_preserves_all_conditions(self):
        with self.fixture() as (obj,hold,paths,run):
            before={path:path.read_bytes() for path in paths}
            obj.release()
            self.assertFalse(hold.exists())
            self.assertEqual({path:path.read_bytes() for path in paths},before)
            obj.save.assert_called_once_with('worker_releasing')
            self.assertEqual(run.call_args_list[-1].args[0],['/usr/bin/systemctl','start','noisefence.service'])
            obj.worker_health.assert_called_once()

    def test_other_fence_or_changed_condition_never_releases(self):
        for change in ('owner','condition'):
            with self.fixture() as (obj,hold,paths,run):
                if change=='owner':hold.write_text(json.dumps({'operation':'another-operation'}))
                else:paths[0].write_text('[Unit]\nConditionPathExists=/different\n')
                with self.assertRaises(ValueError):obj.release()
                self.assertTrue(hold.exists());run.assert_not_called()


class LoginTests(unittest.TestCase):
    def response(self, data, cookie=None):
        response=io.BytesIO(json.dumps(data).encode())
        response.status=200
        response.headers={'Set-Cookie':cookie} if cookie else {}
        return response

    def test_session_is_checked_and_retired_without_redirects(self):
        with tempfile.TemporaryDirectory() as tmp:
            credentials=Path(tmp).resolve()/'credentials.json'
            credentials.write_text(json.dumps({'username':'recovery','password':'synthetic-only'}))
            credentials.chmod(0o600)
            user={'username':'recovery','admin':True,'csrf':'synthetic-csrf'}
            client=Mock()
            client.open.side_effect=[self.response(user,'noisefence_session=test-token; Secure; HttpOnly; SameSite=Strict'),
                self.response(user),self.response({'ok':True})]
            with patch.object(runtime.urllib.request,'build_opener',return_value=client):
                runtime.login(credentials,'https://mx2.example.test')
            requests=[call.args[0] for call in client.open.call_args_list]
            self.assertEqual([r.full_url for r in requests],['http://127.0.0.1:18081/api/v1/'+p
                for p in ('login','me','logout')])
            self.assertEqual([r.get_method() for r in requests],['POST','GET','POST'])
            self.assertEqual(requests[2].get_header('X-csrf-token'),'synthetic-csrf')
            self.assertNotIn('synthetic-only',str(requests))

    def test_wrong_session_identity_still_logs_out(self):
        with tempfile.TemporaryDirectory() as tmp:
            credentials=Path(tmp).resolve()/'credentials.json'
            credentials.write_text(json.dumps({'username':'recovery','password':'synthetic-only'}))
            credentials.chmod(0o600)
            client=Mock()
            client.open.side_effect=[self.response({'username':'recovery','admin':True,'csrf':'csrf'},
                'noisefence_session=token; Secure; HttpOnly; SameSite=Strict'),
                self.response({'username':'other','admin':True}),self.response({'ok':True})]
            with patch.object(runtime.urllib.request,'build_opener',return_value=client), self.assertRaises(ValueError):
                runtime.login(credentials,'https://mx2.example.test')
            self.assertEqual(client.open.call_count,3)


if __name__ == '__main__':
    unittest.main()
