"""Recovery routing checks and failure handling; no live service changes."""
import contextlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'deploy/postgresql'))
import recovery_proxy as proxy

HOST = 'mx2.example.test'
OP = '00000000-0000-4000-8000-000000000001'
CONFIG = '''events {} http { server {
listen 443 ssl; server_name mx2.example.test;
include /etc/nginx/noisefence-console-upstream.conf;
location ^~ /api/v1/replication/ { proxy_pass http://127.0.0.1:18080; }
location = /healthz { proxy_pass http://127.0.0.1:18080; }
location ^~ /api/v1/cluster/ { proxy_pass http://$noisefence_console; }
location = /api/v1/login { proxy_pass http://$noisefence_console; }
location = / { proxy_pass http://$noisefence_console; }
location / { proxy_pass http://$noisefence_console; }
} }
# configuration file /etc/nginx/noisefence-console-upstream.conf:
set $noisefence_console 127.0.0.1:18080;
'''


class ProfileTests(unittest.TestCase):
    def test_standard_routes_and_ipv6(self):
        for raw in (CONFIG, CONFIG.replace('listen 443 ssl;', 'listen [::]:443 ssl;')):
            result=proxy.profile(raw,HOST)
            self.assertEqual(result['replication_target'],'127.0.0.1:18080')
            self.assertEqual(result['console_target'],'127.0.0.1:18080')

    def test_wrong_or_ambiguous_routing_refuses(self):
        changes=[
            CONFIG.replace('proxy_pass http://127.0.0.1:18080;', 'proxy_pass http://127.0.0.1:18081;',1),
            CONFIG.replace('location = /healthz { proxy_pass http://127.0.0.1:18080;',
                           'location = /healthz { proxy_pass http://127.0.0.1:18081;'),
            CONFIG.replace('location ^~ /api/v1/cluster/ {', 'location ^~ /api/v1/cluster/ { return 302 /;'),
            CONFIG.replace('location = /api/v1/login', 'location = /different'),
            CONFIG.replace('server_name mx2.example.test;', 'server_name mx2.example.test; return 302 https://elsewhere.test;'),
            CONFIG.replace('location / {', 'location /api/v1/me { return 401; } location / {'),
            CONFIG+'set $noisefence_console 127.0.0.1:18081;',
        ]
        for raw in changes:
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                proxy.profile(raw,HOST)

    def test_parser_refuses_incomplete_and_deep_input(self):
        for raw in ('server {', 'server }', 'thing "unterminated', 'x {'*34+'}'*34):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                proxy.parse(raw)
        self.assertEqual(proxy.parse('x "quoted;{}#"; # comment\n'),[(('x','quoted;{}#'),None)])

    def test_probes_use_matching_methods_and_verified_loopback_tls(self):
        with patch.object(proxy,'execute',return_value=b'401') as run:
            proxy.probe(HOST)
        commands=[call.args[0] for call in run.call_args_list]
        self.assertEqual([cmd[cmd.index('--request')+1] for cmd in commands],['GET','POST'])
        for command in commands:
            self.assertNotIn('--insecure',command)
            self.assertIn(HOST+':443:127.0.0.1',command)
        with patch.object(proxy,'execute',return_value=b'405'), self.assertRaises(ValueError):
            proxy.probe(HOST)

    def test_graceful_reload_retries_old_worker_and_rechecks_both_routes(self):
        with patch.object(proxy,'execute',side_effect=[b'502',b'401',b'404',b'401',b'401']) as run, \
             patch.object(proxy.time,'sleep'):
            proxy.probe(HOST)
        methods=[call.args[0][call.args[0].index('--request')+1] for call in run.call_args_list]
        self.assertEqual(methods,['GET','GET','POST','GET','POST'])

    def test_probe_deadline_and_tls_failure_do_not_pass(self):
        with patch.object(proxy,'execute',return_value=b'502'), \
             patch.object(proxy.time,'monotonic',side_effect=[0,0,11]), self.assertRaises(ValueError):
            proxy.probe(HOST)
        with patch.object(proxy,'execute',side_effect=ValueError('TLS verification failed')), \
             patch.object(proxy.time,'sleep') as sleep, self.assertRaises(ValueError):
            proxy.probe(HOST)
        sleep.assert_not_called()


class SwitchTests(unittest.TestCase):
    def setUp(self):
        self.stack=contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.root=Path(self.stack.enter_context(tempfile.TemporaryDirectory())).resolve()
        self.switch=self.root/'upstream.conf'
        self.switch.write_bytes(proxy.BEFORE)
        self.switch.chmod(0o640)
        self.stack.enter_context(patch.object(proxy,'SWITCH',self.switch))
        self.stack.enter_context(patch.object(proxy,'protected',side_effect=lambda path,*args:Path(path).stat()))
        self.stack.enter_context(patch.object(proxy,'inspect',side_effect=lambda host:{'console_target':
            '127.0.0.1:18080' if self.switch.read_bytes()==proxy.BEFORE else '127.0.0.1:18081'}))
        self.health=self.stack.enter_context(patch.object(proxy,'console_health'))
        self.probe=self.stack.enter_context(patch.object(proxy,'probe'))
        self.run=self.stack.enter_context(patch.object(proxy,'execute'))

    def receipt(self):
        return json.loads((self.root/(OP+'-proxy.json')).read_bytes())

    def test_success_and_completed_retry_have_no_extra_mutations(self):
        result=proxy.switch(self.root,OP,HOST)
        self.assertFalse(result['worker_start_authorized'])
        self.assertEqual(self.switch.read_bytes(),proxy.AFTER)
        self.assertEqual(self.switch.stat().st_mode&0o777,0o640)
        self.assertEqual(self.receipt()['status'],'verified')
        self.run.reset_mock()
        proxy.switch(self.root,OP,HOST)
        self.run.assert_not_called()
        self.probe.side_effect=ValueError('temporary failure')
        with self.assertRaises(ValueError):proxy.switch(self.root,OP,HOST)
        self.assertEqual(self.switch.read_bytes(),proxy.AFTER)
        self.assertEqual(self.receipt()['status'],'verified')

    def test_failed_probe_restores_old_route_then_can_retry(self):
        self.probe.side_effect=ValueError('wrong destination')
        with self.assertRaises(ValueError):proxy.switch(self.root,OP,HOST)
        self.assertEqual(self.switch.read_bytes(),proxy.BEFORE)
        self.assertEqual(self.receipt()['status'],'rolled_back')
        self.probe.side_effect=None
        proxy.switch(self.root,OP,HOST)
        self.assertEqual(self.receipt()['status'],'verified')

    def reentry(self):
        self.switch.write_bytes(proxy.AFTER)
        (self.root/'reentry.json').write_text(json.dumps({
            'protocol':'noisefence-reentry-1','operation':OP,'phase':'replaced',
            'authorization':'a'*64,
            'retired_operation':'00000000-0000-4000-8000-000000000002'}))

    def test_reentry_adopts_existing_route_with_bound_authority(self):
        self.reentry()
        proxy.switch(self.root,OP,HOST,reentry_binding='a'*64)
        self.assertEqual(self.receipt()['original_target'],'after')
        self.run.reset_mock()
        proxy.switch(self.root,OP,HOST,reentry_binding='a'*64)
        self.run.assert_not_called()
        with self.assertRaises(ValueError):
            proxy.switch(self.root,OP,HOST,reentry_binding='b'*64)

    def test_reentry_wrong_authority_does_not_mutate(self):
        self.reentry()
        with self.assertRaises(ValueError):
            proxy.switch(self.root,OP,HOST,reentry_binding='b'*64)
        self.run.assert_not_called()
        self.assertFalse((self.root/(OP+'-proxy.json')).exists())

    def test_reentry_failure_preserves_previous_console_route(self):
        self.reentry()
        self.probe.side_effect=ValueError('probe unavailable')
        with self.assertRaises(ValueError):
            proxy.switch(self.root,OP,HOST,reentry_binding='a'*64)
        self.assertEqual(self.switch.read_bytes(),proxy.AFTER)
        self.assertEqual(self.receipt()['status'],'rolled_back')
        self.probe.side_effect=None
        proxy.switch(self.root,OP,HOST,reentry_binding='a'*64)
        self.assertEqual(self.receipt()['status'],'verified')

    def test_unhealthy_console_and_unowned_switch_never_write(self):
        self.health.side_effect=ValueError('unhealthy')
        with self.assertRaises(ValueError):proxy.switch(self.root,OP,HOST)
        self.assertEqual(self.switch.read_bytes(),proxy.BEFORE)
        self.run.assert_not_called()
        self.health.side_effect=None
        self.switch.write_bytes(proxy.AFTER)
        with self.assertRaises(ValueError):proxy.switch(self.root,OP,HOST)
        self.run.assert_not_called()

    def test_external_edit_during_failure_is_not_overwritten(self):
        def external_change(host):
            self.switch.write_bytes(b'# operator changed route\n')
            raise ValueError('probe failed')
        self.probe.side_effect=external_change
        with self.assertRaisesRegex(ValueError,'changed externally'):
            proxy.switch(self.root,OP,HOST)
        self.assertEqual(self.switch.read_bytes(),b'# operator changed route\n')
        self.assertEqual(self.receipt()['status'],'planned')

    def test_reload_rollback_failure_is_recorded(self):
        self.run.side_effect=ValueError('nginx unavailable')
        with self.assertRaises(ValueError):proxy.switch(self.root,OP,HOST)
        self.assertEqual(self.receipt()['status'],'rollback_failed')
        self.assertEqual(self.switch.read_bytes(),proxy.BEFORE)


if __name__=='__main__':unittest.main()
