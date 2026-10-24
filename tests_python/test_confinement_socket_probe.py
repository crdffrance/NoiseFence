"""The short connectivity diagnostic cannot weaken native qualification."""
import contextlib
import io
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tests'))
import confinement_socket_probe as probe
sys.path.pop(0)


class SocketProbeTests(unittest.TestCase):
    def test_output_is_closed_and_must_agree_with_exit_status(self):
        for category in probe.CATEGORIES:
            code=0 if category=='query_ok' else 1
            self.assertEqual(probe.classify(SimpleNamespace(stdout=(category+'\n').encode(),returncode=code)),category)
            self.assertEqual(probe.classify(SimpleNamespace(stdout=category.encode(),returncode=1-code)),'unexpected_result')
        for text in [b'PRIVATE-PASSWORD',b'query_ok\nprivate',b'',b'\xff']:
            self.assertEqual(probe.classify(SimpleNamespace(stdout=text,returncode=0)),'unexpected_result')

    def test_socket_access_and_database_authentication_are_not_conflated(self):
        self.assertIn('socket_permission_denied',probe.CATEGORIES)
        self.assertIn('authentication_refused',probe.CATEGORIES)
        for boundary in ('socket_permission_denied','authentication_refused'):
            code,result=self.exercise(SimpleNamespace(stdout=b'query_ok',returncode=0),
                                     SimpleNamespace(stdout=boundary.encode(),returncode=1))
            self.assertEqual(code,1)
            self.assertEqual(result['service_context']['confined'],boundary)
            self.assertEqual(result['status'],'failed')

    def test_no_native_action_before_disposable_host_guard(self):
        for env in [{},{'GITHUB_ACTIONS':'true','RUNNER_ENVIRONMENT':'self-hosted','RUNNER_OS':'Linux'}]:
            with patch.dict(os.environ,env,clear=True),patch.object(probe.sys,'platform','linux'), \
                 patch.object(probe.confined,'command') as command:
                with self.assertRaisesRegex(RuntimeError,'ephemeral'):
                    probe.run(SimpleNamespace())
                command.assert_not_called()

    def exercise(self, confined_result, service_confined=None):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);binary=root/'probe';binary.write_bytes(b'synthetic-never-executed')
            args=SimpleNamespace(binary=binary,image='synthetic',output=root/'result')
            events=[];active=[];profile=[];ownership={}
            def command(*arguments,timeout=30):
                events.append(arguments)
                if arguments[:2]==('docker','run'):
                    name=arguments[arguments.index('--name')+1];active.append(name)
                    ownership[name]=arguments[arguments.index('--label')+1].split('=',1)[1]
                if arguments[:2]==('docker','ps'):return '\n'.join(active).encode()
                if arguments[:2]==('docker','inspect'):return ownership[arguments[-1]].encode()
                if arguments[:2]==('docker','rm'):active.remove(arguments[-1])
                if '--add' in arguments:profile.append('loaded')
                if '--remove' in arguments:profile.clear()
                return b''
            def read(path,*a,**kw):
                if str(path)=='/sys/module/apparmor/parameters/enabled':return 'Y'
                return original(path,*a,**kw)
            original=Path.read_text
            environment={'GITHUB_ACTIONS':'true','RUNNER_ENVIRONMENT':'github-hosted','RUNNER_OS':'Linux'}
            def profiles():
                # The controller generates the name before its first profile read.
                return [] if not profile else ['noisefence-test-0123456789ab (enforce)']
            import uuid
            with patch.dict(os.environ,environment,clear=True),patch.object(probe.sys,'platform','linux'), \
                 patch.object(probe.uuid,'uuid4',return_value=uuid.UUID('01234567-89ab-4cde-8f01-23456789abcd')), \
                 patch.object(Path,'read_text',read),patch.object(probe.confined,'profiles',profiles), \
                 patch.object(probe.confined,'policy',return_value=b'synthetic profile'), \
                 patch.object(probe.confined,'command',side_effect=command), \
                 patch.object(probe.confined,'collect_denials',return_value='unavailable'), \
                 patch.object(probe.subprocess,'run',side_effect=[SimpleNamespace(stdout=b'query_ok',returncode=0),confined_result]), \
                 patch.object(probe,'service_query',side_effect=['query_ok',probe.classify(service_confined) if service_confined else 'query_ok',*(['query_ok']*len(probe.CONTEXT_VARIANTS))]), \
                 contextlib.redirect_stdout(io.StringIO()):
                code=probe.run(args)
            result=json.loads((args.output/'probe.json').read_text())
            self.assertFalse(active);self.assertFalse(profile)
            run=next(args for args in events if args[:2]==('docker','run'))
            self.assertEqual(run[run.index('--network')+1],'none')
            self.assertEqual(run[run.index('--memory')+1],'512m')
            self.assertTrue(result['container_removed']);self.assertTrue(result['profile_removed'])
            self.assertLess(next(i for i,e in enumerate(events) if e[:2]==('docker','rm')),
                            next(i for i,e in enumerate(events) if '--remove' in e))
            self.assertNotIn('PRIVATE',json.dumps(result))
            return code,result

    def test_success_is_bounded_and_cleans_container_before_its_own_profile(self):
        code,result=self.exercise(SimpleNamespace(stdout=b'query_ok',returncode=0))
        self.assertEqual(code,0);self.assertEqual(result['status'],'passed')

    def test_native_refusal_is_not_hidden_by_successful_cleanup(self):
        code,result=self.exercise(SimpleNamespace(stdout=b'permission_denied',stderr=b'PRIVATE',returncode=1))
        self.assertEqual(code,1);self.assertEqual(result['status'],'failed')
        self.assertEqual(result['confined'],'permission_denied')

    def test_service_namespace_refusal_is_visible_even_when_runuser_queries_succeed(self):
        code,result=self.exercise(SimpleNamespace(stdout=b'query_ok',returncode=0),
                                 SimpleNamespace(stdout=b'permission_denied',returncode=1))
        self.assertEqual(code,1)
        self.assertEqual(result['unconfined'],result['confined'])
        self.assertEqual(result['service_context'],{'unconfined':'query_ok','confined':'permission_denied'})

    def test_service_context_copies_shipped_hardening_and_refuses_unknown_changes(self):
        raw=(ROOT/'deploy/noisefence.service').read_text()
        properties=probe.service_properties(raw)
        self.assertIn('PrivateTmp=true',properties)
        self.assertIn('ProtectSystem=strict',properties)
        self.assertIn('NoNewPrivileges=true',properties)
        self.assertIn('RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK',properties)
        for mode in ('unconfined','confined'):
            unit=probe.service_unit(mode,'test-profile','/opt/noisefence/probe',properties).splitlines()
            self.assertIn('ExecStart=/opt/noisefence/probe',unit)
            self.assertIn('Type=oneshot',unit);self.assertIn('Restart=no',unit)
            self.assertIn('TimeoutStartSec=8s',unit)
            self.assertIn('SyslogIdentifier=noisefence-socket-'+mode,unit)
            self.assertEqual('AppArmorProfile=test-profile' in unit,mode=='confined')
            for item in properties:self.assertIn(item,unit)
        for changed in (raw.replace('PrivateTmp=true','PrivateTmp=true\nPrivateDevices=true'),
                        raw.replace('PrivateTmp=true',''),raw.replace('User=noisefence','User=root')):
            with self.assertRaises(RuntimeError):probe.service_properties(changed)
        with self.assertRaises(RuntimeError):probe.service_unit('invalid','x','y',[])

    def test_namespace_variants_are_fixed_and_keep_the_confined_identity(self):
        props=probe.service_properties((ROOT/'deploy/noisefence.service').read_text())
        for mode,changes in probe.CONTEXT_VARIANTS.items():
            unit=probe.service_unit(mode,'synthetic-profile','/opt/noisefence/probe',props)
            self.assertIn('AppArmorProfile=synthetic-profile',unit)
            self.assertIn('User=noisefence',unit)
            self.assertIn('NoNewPrivileges=true',unit)
            for key,value in changes.items():self.assertIn(key+'='+value+'\n',unit)
            for item in props:
                if item.split('=',1)[0] not in changes:self.assertIn(item+'\n',unit)
        self.assertNotIn('attach_disconnected',unit)

    def test_systemd_query_uses_private_manager_and_fixed_journal_identifier(self):
        for output,code,expected in [(b'query_ok\n',0,'query_ok'),
                                     (b'permission_denied\n',1,'permission_denied'),
                                     (b'PRIVATE',0,'unexpected_result')]:
            with patch.object(probe.subprocess,'run',return_value=SimpleNamespace(returncode=code)) as start, \
                 patch.object(probe.confined,'command',side_effect=[b'',output]) as read:
                self.assertEqual(probe.service_query('fixture','confined'),expected)
            self.assertEqual(start.call_args.args[0],['docker','exec','fixture','systemctl','start','noisefence-socket-confined.service'])
            self.assertEqual(start.call_args.kwargs['timeout'],15)
            self.assertEqual(read.call_args_list[0].args[-2:],('journalctl','--sync'))
            self.assertEqual(read.call_args.args[-2:],('-t','noisefence-socket-confined'))

    def test_workflow_diagnostic_is_separate_from_required_exact_archive_checks(self):
        diagnostic=(ROOT/'.github/workflows/confinement-probe.yml').read_text()
        required=(ROOT/'.github/workflows/check.yml').read_text()
        self.assertIn('timeout-minutes: 15',diagnostic)
        self.assertIn('contents: read',diagnostic)
        self.assertIn('persist-credentials: false',diagnostic)
        self.assertIn('result/probe.json',diagnostic)
        self.assertNotIn('path: var/confinement-socket/result\n',diagnostic)
        self.assertIn('NOISEFENCE_REHEARSAL_APPARMOR:',required)
        self.assertIn('scripts/check_release_lifecycle.sh',required)
