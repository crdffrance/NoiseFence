"""Confinement evidence must fail closed; mocks are not native qualification."""
import hashlib
import importlib.util
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from tests_python.test_paired_lifecycle import paired

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('confinement_fixture', ROOT/'tests/fixtures/confinement_node.py')
confinement = importlib.util.module_from_spec(spec); spec.loader.exec_module(confinement)
PROFILE = 'noisefence-test-0123456789ab'
render_spec = importlib.util.spec_from_file_location('render_fixture', ROOT/'tests/render_apparmor_fixture.py')
render_fixture = importlib.util.module_from_spec(render_spec); render_spec.loader.exec_module(render_fixture)


class ConfinementTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_names_cannot_target_an_existing_production_profile_or_disable_enforcement(self):
        for value in ('noisefence', '-noisefence', PROFILE+' (complain)', PROFILE+'\nOther=value', ':namespace://noisefence'):
            with self.subTest(value=value), patch.dict(os.environ, {confinement.ENVIRONMENT:value}):
                with self.assertRaises(RuntimeError): confinement.expected_profile()
                with self.assertRaises(ValueError):
                    paired.Lab(SimpleNamespace(apparmor_profile=value), {}, {})
        with patch.dict(os.environ, {confinement.ENVIRONMENT:PROFILE}):
            self.assertEqual(confinement.expected_profile(), PROFILE)

    def test_render_names_only_one_profile_without_rewriting_allowed_paths(self):
        header = "# Managed by NoiseFence. No profile attaches to another product's binary.\n#include <tunables/global>\n"
        body = '  /opt/noisefence/** mr,\n  signal (send, receive) peer=noisefence,'
        source = header+'profile noisefence {\n'+body+'\n}\nprofile noisefence-other {\n}\n'
        result = render_fixture.render(source, PROFILE)
        self.assertEqual(sum(line.startswith('profile ') for line in result.splitlines()), 1)
        self.assertIn('/opt/noisefence/** mr,', result)
        self.assertIn('peer='+PROFILE+',', result)
        self.assertNotIn('noisefence-other', result)
        for invalid in [source.replace('profile noisefence {','profile noisefence flags=(complain) {'),
                        source+source, source.replace('#include <tunables/global>','#include <unexpected>')]:
            with self.assertRaises(ValueError):render_fixture.render(invalid, PROFILE)
        with self.assertRaises(ValueError):render_fixture.render(source,'noisefence')

    def test_real_policy_generator_preserves_main_rules(self):
        spec = importlib.util.spec_from_file_location('fixture_isolation', ROOT/'deploy/hardening/isolation.py')
        isolation = importlib.util.module_from_spec(spec); spec.loader.exec_module(isolation)
        original = isolation.profiles('enforce')
        result = render_fixture.render(original, PROFILE)
        flag=' flags=(attach_disconnected.path=/att/noisefence/)'
        original_body = original.split('profile noisefence'+flag+' {\n', 1)[1].split('\n}\n', 1)[0]
        rendered_body = result.split('profile '+PROFILE+flag+' {\n', 1)[1].split('\n}\n', 1)[0]
        self.assertEqual(rendered_body.replace('peer='+PROFILE+',', 'peer=noisefence,'), original_body)
        self.assertNotIn('flags=(complain)', result)
        self.assertNotIn('flags=(attach_disconnected)', result)

    def test_process_identity_and_enforcement_are_required(self):
        proc = self.root/'proc'; target = proc/'123'; (target/'attr').mkdir(parents=True)
        binary = target/'exe'; binary.write_bytes(b'synthetic executable')
        current = target/'attr/current'; current.write_text(PROFILE+' (enforce)\n')
        active = SimpleNamespace(returncode=0, stdout=('MainPID=123\nActiveState=active\nAppArmorProfile='+PROFILE+'\n').encode())
        stable = SimpleNamespace(returncode=0, stdout=b'123\n')
        with patch.dict(os.environ, {confinement.ENVIRONMENT:PROFILE}), patch.object(confinement, 'PROC', proc):
            with patch.object(confinement, 'call', side_effect=[active, stable]):
                proof = confinement.inspect('noisefence.service')
                self.assertEqual(proof['binary_sha256'], hashlib.sha256(binary.read_bytes()).hexdigest())
            for label in ('unconfined', PROFILE+' (complain)', 'noisefence (enforce)'):
                current.write_text(label+'\n')
                with self.subTest(label=label), patch.object(confinement, 'call', return_value=active):
                    with self.assertRaisesRegex(RuntimeError, 'not confined'):confinement.inspect('noisefence.service')
            current.write_text(PROFILE+' (enforce)\n')
            with patch.object(confinement, 'call', side_effect=[active, SimpleNamespace(returncode=0,stdout=b'124\n')]):
                with self.assertRaisesRegex(RuntimeError, 'Service changed'):confinement.inspect('noisefence-validation.service')
            with patch.object(confinement, 'call') as call:
                with self.assertRaisesRegex(RuntimeError, 'Unknown test service'):confinement.inspect('ssh.service')
                call.assert_not_called()

    def test_default_has_no_confinement_claim_or_system_calls(self):
        with patch.dict(os.environ, {confinement.ENVIRONMENT:''}), patch.object(confinement, 'call') as call:
            self.assertIsNone(confinement.install(self.root/'binary', self.root/'config'))
            self.assertIsNone(confinement.inspect('noisefence.service'))
            call.assert_not_called()

    def test_canary_needs_unconfined_success_allowed_success_and_actual_denial(self):
        for index,(baseline,allowed,denied,error,success) in enumerate([(0,0,1,b'Permission denied',True),
                (1,0,1,b'Permission denied',False), (0,1,1,b'Permission denied',False),
                (0,0,0,b'',False), (0,0,1,b'profile not found',False)]):
            with self.subTest(values=(baseline,allowed,denied,error)):
                unit=self.root/('unit-'+str(index))
                canary=self.root/('canary-'+unit.name);config=self.root/'config.toml';config.write_text('synthetic = true\n')
                responses=[SimpleNamespace(returncode=rc,stderr=err) for rc,err in
                           ((baseline,b''),(allowed,b''),(denied,error))]
                with patch.dict(os.environ,{confinement.ENVIRONMENT:PROFILE,'NOISEFENCE_DISPOSABLE_PAIRED_TEST':'1'}), \
                     patch.object(confinement.Path,'is_file',return_value=True), \
                     patch.object(confinement,'DROPIN_DIRECTORY',unit),patch.object(confinement,'CANARY',canary), \
                     patch.object(confinement,'call',side_effect=responses) as call:
                    if success:
                        result=confinement.install(self.root/'binary',config)
                        self.assertTrue(result['confined_canary_denied'])
                        self.assertEqual(result['profile'],PROFILE)
                    else:
                        with self.assertRaises(RuntimeError):confinement.install(self.root/'binary',config)
                    self.assertFalse(canary.exists())
                    self.assertEqual(call.call_count,3)
                    self.assertIn('/usr/bin/aa-exec',call.call_args_list[1].args)
                    self.assertEqual((unit/'95-fixture-confinement.conf').read_text(),
                                     '[Service]\nAppArmorProfile='+PROFILE+'\n')

    def test_configuration_only_complain_and_other_binary_are_not_runtime_evidence(self):
        lab=object.__new__(paired.Lab);lab.apparmor_profile=PROFILE
        proof={'profile':PROFILE,'process_profile':PROFILE+' (enforce)','mode':'enforce','binary_sha256':'a'*64}
        lab.check_confinement(proof,'a'*64)
        for invalid in [None,{}, {**proof,'mode':'complain'}, {**proof,'process_profile':'unconfined'},
                        {**proof,'profile':'noisefence'}, {**proof,'binary_sha256':'b'*64}]:
            with self.subTest(proof=invalid), self.assertRaises(RuntimeError):lab.check_confinement(invalid,'a'*64)

    def test_readiness_requires_confinement_when_requested(self):
        lab=object.__new__(paired.Lab);lab.apparmor_profile=PROFILE
        lab.binary_hashes={'mx1':{'0.31.9':'a'*64}}
        result={'running_release':'0.31.9','binary_sha256':'a'*64}
        lab.node=lambda *args:result
        with self.assertRaises(RuntimeError):lab.ready('mx1','0.31.9')
        result['confinement']={'profile':PROFILE,'mode':'enforce','process_profile':PROFILE+' (enforce)','binary_sha256':'a'*64}
        self.assertEqual(lab.ready('mx1','0.31.9'),result)


    def test_reserved_attachment_path_collision_stops_before_any_service_change(self):
        prefix=self.root/'attachment';prefix.mkdir()
        with patch.dict(os.environ,{confinement.ENVIRONMENT:PROFILE,'NOISEFENCE_DISPOSABLE_PAIRED_TEST':'1'}), \
             patch.object(confinement.Path,'is_file',return_value=True), \
             patch.object(confinement,'DISCONNECTED_ROOT',prefix),patch.object(confinement,'call') as call:
            with self.assertRaisesRegex(RuntimeError,'prefix must not exist'):
                confinement.install(self.root/'binary',self.root/'config')
            call.assert_not_called()


if __name__ == '__main__':unittest.main()
