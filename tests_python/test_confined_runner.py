"""The CI controller may unload only its own unused test profile."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import uuid

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('confined_runner', ROOT/'tests/confined_paired_release.py')
runner = importlib.util.module_from_spec(spec); spec.loader.exec_module(runner)
IDENTITY = uuid.UUID('01234567-89ab-4cde-8f01-23456789abcd')
NAME = 'noisefence-test-'+IDENTITY.hex[:12]
ENV = {'GITHUB_ACTIONS':'true','RUNNER_ENVIRONMENT':'github-hosted','RUNNER_OS':'Linux'}


class ConfinedRunnerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.args = SimpleNamespace(output=self.root/'paired',evidence=self.root/'apparmor',
            image='synthetic',platform='linux/arm64',old_archive=self.root/'old.tar.gz',
            new_archive=self.root/'new.tar.gz',fixture=self.root/'fixture')

    def context(self, *, child_error=None, removed=True, listing=None, command_error=None):
        original = Path.read_text
        def read(path,*args,**kwargs):
            if str(path) == '/sys/module/apparmor/parameters/enabled':return 'Y\n'
            return original(path,*args,**kwargs)
        patches = [patch.dict(os.environ,ENV,clear=True), patch.object(runner.sys,'platform','linux'),
            patch.object(runner.uuid,'uuid4',return_value=IDENTITY), patch.object(Path,'read_text',read),
            patch.object(runner.platform,'release',return_value='fixture-kernel'),
            patch.object(runner,'policy',return_value=b'synthetic policy'),
            patch.object(runner,'profiles',side_effect=listing if listing is not None else [[],[NAME+' (enforce)'],[]]),
            patch.object(runner,'containers_removed',return_value=removed),
            patch.object(runner,'command',side_effect=command_error),
            patch.object(runner.subprocess,'run',side_effect=child_error)]
        values = [item.start() for item in patches]
        for item in patches:self.addCleanup(item.stop)
        return values[-2:]

    def test_isolated_policy_bundle_runs_the_real_generator(self):
        # Docker itself is exercised by native CI. This executes the real CLI
        # against the exact minimal source mount assembled by policy(), so
        # omitted imports cannot hide behind a mocked policy result.
        def execute_generator(*arguments, timeout):
            self.assertEqual(arguments[:2], ('docker', 'run'))
            self.assertEqual(arguments[arguments.index('--network')+1], 'none')
            self.assertIn('--read-only', arguments)
            self.assertIn('no-new-privileges', arguments)
            self.assertEqual(timeout, 60)
            mount = arguments[arguments.index('--mount')+1]
            self.assertTrue(mount.startswith('type=bind,src='))
            self.assertTrue(mount.endswith(',dst=/source,readonly'))
            source = Path(mount.removeprefix('type=bind,src=').removesuffix(',dst=/source,readonly'))
            rendered = subprocess.check_output([sys.executable, '-B',
                str(source/'tests/render_apparmor_fixture.py'), '--name', NAME], timeout=10,
                env={'PATH':runner.PATH, 'HOME':str(self.root), 'TMPDIR':str(self.root),
                     'PYTHONDONTWRITEBYTECODE':'1'})
            self.assertEqual({str(p.relative_to(source)) for p in source.rglob('*') if p.is_file()},
                {'tests/render_apparmor_fixture.py', 'deploy/hardening/isolation.py',
                 'deploy/hardening/network.py'})
            return rendered
        with patch.object(runner, 'command', side_effect=execute_generator):
            result = runner.policy('fixture-image', NAME).decode()
        self.assertIn('profile '+NAME+' {', result)
        self.assertEqual(sum(line.startswith('profile ') for line in result.splitlines()), 1)
        self.assertIn('/opt/noisefence/** mr,', result)
        self.assertIn('peer='+NAME+',', result)
        self.assertNotIn('flags=(complain)', result)

    def test_explicit_host_guard_before_any_privileged_action(self):
        for environment in ({}, {**ENV,'RUNNER_ENVIRONMENT':'self-hosted'}, {**ENV,'RUNNER_OS':'Windows'}):
            with patch.dict(os.environ,environment,clear=True), patch.object(runner.sys,'platform','linux'), \
                 patch.object(runner,'command') as command:
                with self.assertRaisesRegex(RuntimeError,'ephemeral'):runner.run(self.args)
                command.assert_not_called()

    def test_success_adds_never_replaces_removes_and_strips_child_environment(self):
        command,child = self.context()
        proof = runner.run(self.args)
        self.assertEqual(proof['status'],'passed');self.assertTrue(proof['profile_removed'])
        self.assertEqual([c.args[3] for c in command.call_args_list],['--add','--remove'])
        self.assertTrue(all('--skip-cache' in c.args for c in command.call_args_list))
        self.assertEqual(set(child.call_args.kwargs['env']),{'PATH','HOME','LANG','PYTHONDONTWRITEBYTECODE'})
        self.assertEqual(child.call_args.kwargs['timeout'],1800)
        self.assertIn('--apparmor-profile',child.call_args.args[0])

    def test_child_failure_is_preserved_after_cleanup(self):
        command,child = self.context(child_error=subprocess.CalledProcessError(7,['fixture']))
        with self.assertRaises(subprocess.CalledProcessError):runner.run(self.args)
        proof = json.loads((self.args.evidence/'confinement.json').read_text())
        self.assertEqual(proof['status'],'failed');self.assertTrue(proof['profile_removed'])
        self.assertEqual(command.call_args.args[3],'--remove')

    def test_collision_and_failed_add_never_remove_an_existing_profile(self):
        command,child = self.context(listing=[[NAME+' (enforce)']])
        with self.assertRaisesRegex(RuntimeError,'already exists'):runner.run(self.args)
        command.assert_not_called();child.assert_not_called()

    def test_unconfirmed_add_is_retained_without_removal(self):
        command,child = self.context(command_error=subprocess.CalledProcessError(1,['add']))
        with self.assertRaises(subprocess.CalledProcessError):runner.run(self.args)
        self.assertEqual(command.call_count,1);child.assert_not_called()
        self.assertEqual(json.loads((self.args.evidence/'confinement.json').read_text())['status'],'load_not_confirmed')

    def test_complain_cannot_launch_the_paired_fixture(self):
        command,child = self.context(listing=[[],[NAME+' (complain)'],[]])
        with self.assertRaisesRegex(RuntimeError,'not enforcing'):runner.run(self.args)
        child.assert_not_called();self.assertEqual(command.call_args.args[3],'--remove')

    def test_surviving_containers_keep_their_profile_and_fail_the_run(self):
        command,child = self.context(removed=False)
        with self.assertRaisesRegex(RuntimeError,'containers remain'):runner.run(self.args)
        self.assertEqual(command.call_count,1)
        proof = json.loads((self.args.evidence/'confinement.json').read_text())
        self.assertEqual(proof['status'],'cleanup_failed');self.assertFalse(proof['profile_removed'])

    def test_only_bound_container_identities_are_used_for_cleanup_evidence(self):
        self.args.output.mkdir()
        self.assertTrue(runner.containers_removed(self.args.output))
        names={n:'nf-paired-'+str(IDENTITY)[:8]+'-'+n for n in ('mx1','mx2')}
        receipt=self.args.output/'operation.json'
        receipt.write_text(json.dumps({'operation':str(IDENTITY),'containers':names}))
        with patch.object(runner,'command',return_value=b'other-container\n'):
            self.assertTrue(runner.containers_removed(self.args.output))
        with patch.object(runner,'command',return_value=(names['mx1']+'\n').encode()):
            self.assertFalse(runner.containers_removed(self.args.output))
        receipt.write_text(json.dumps({'operation':str(IDENTITY),'containers':{'mx1':'production'}}))
        with patch.object(runner,'command') as command:
            with self.assertRaisesRegex(RuntimeError,'identities'):runner.containers_removed(self.args.output)
            command.assert_not_called()


if __name__ == '__main__':unittest.main()
