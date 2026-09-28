"""A planned fence must stop and persistently block every installed writer."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'deploy/ha'))
spec = importlib.util.spec_from_file_location('ha_fence', ROOT / 'deploy/ha/fence.py')
fence = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fence)


class FenceTests(unittest.TestCase):
    def exercise(self, stuck=None, absent=(), failed_flush=False):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = root / 'state'; state.mkdir()
            config = root / 'config'; config.mkdir()
            systemd = root / 'systemd'
            (config / 'config.toml').write_text('hostname="mx1.example.test"\n[cluster]\nrole="coordinator"\nnode_id="mx1"\n')
            def inspect(args, **kwargs):
                unit, prop = args[2], args[4]
                if prop == 'LoadState': return 'not-found\n' if unit in absent else 'loaded\n'
                if prop == 'ActiveState': return 'active\n' if unit == stuck else 'inactive\n'
                if prop == 'MainPID': return '0\n'
                raise AssertionError(args)
            with patch.object(fence, 'STATE', state), patch.object(fence, 'CONFIG', config), \
                    patch.object(fence, 'SYSTEMD', systemd), \
                    patch.object(fence.subprocess, 'check_output', side_effect=inspect), \
                    patch.object(fence.subprocess, 'run') as run:
                if stuck:
                    with self.assertRaisesRegex(ValueError, 'Service did not stop'):
                        fence.fence()
                    self.assertFalse(json.loads((state / 'fenced.json').read_text())['fenced'])
                    self.assertFalse(any(c.args[0][0]=='runuser' for c in run.call_args_list))
                else:
                    operation=None
                    if failed_flush:
                        def fail(args, **kwargs):
                            if args[0]=='runuser':raise RuntimeError('Interrupted flush')
                        run.side_effect=fail
                        with self.assertRaisesRegex(RuntimeError,'Interrupted flush'):fence.fence()
                        pending=json.loads((state/'fenced.json').read_bytes())
                        self.assertFalse(pending['fenced']);operation=pending['operation']
                        run.side_effect=None;run.reset_mock()
                    receipt=fence.fence()
                    self.assertTrue(receipt['fenced'])
                    if operation:self.assertEqual(receipt['operation'],operation)
                    self.assertEqual(fence.fence(),receipt)
                    self.assertEqual(sum(c.args[0][0]=='runuser' for c in run.call_args_list),1)
                commands = [c.args[0] for c in run.call_args_list]
                for unit in (*fence.TIMERS, *fence.SERVICES):
                    path = systemd / (unit + '.d') / '99-ha-fenced.conf'
                    if unit in absent:
                        self.assertFalse(path.exists())
                        self.assertNotIn(['systemctl', 'stop', unit], commands)
                    else:
                        self.assertIn('ConditionPathExists=!/var/lib/noisefence-standby/fenced.json', path.read_text())
                        self.assertIn(['systemctl', 'stop', unit], commands)

    def test_all_writers_and_schedules_are_stopped_and_blocked(self):
        self.exercise()

    def test_optional_missing_units_are_not_required(self):
        self.exercise(absent=('noisefence-recovered-standby-push.service', 'noisefence-recovered-standby-push.timer'))

    def test_interrupted_flush_resumes_same_persistent_fence(self):
        self.exercise(failed_flush=True)

    def test_active_quality_or_checkpoint_prevents_fencing_receipt(self):
        for unit in ('noisefence-quality.service', 'noisefence-recovered-standby-push.service', 'noisefence-standby-push.timer'):
            with self.subTest(unit=unit): self.exercise(stuck=unit)

    def test_recovered_source_checks_native_authority_and_preserves_worker_flush_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); config=root/'worker'; config.mkdir()
            worker=config/'config.toml';worker.write_text('[cluster]\nrole="worker"\nnode_id="mx2"\n')
            console=root/'console.toml';console.write_text('hostname="mx2.example.test"\n[cluster]\nrole="coordinator"\nnode_id="mx1"\n')
            with patch.object(fence,'CONFIG',config),patch.object(fence.standby,'recovered_source') as select, \
                    patch.object(fence.standby,'selected_state',return_value={'recovery':'expected'}), \
                    patch.object(fence.standby,'verify_recovered_source') as verify, \
                    patch.object(fence.standby,'config_path',return_value=console):
                cfg,path,binding=fence.source(True)
                select.assert_called_once();verify.assert_called_once_with({'recovery':'expected'})
                self.assertEqual(cfg['cluster']['node_id'],'mx1')
                self.assertEqual(path,worker);self.assertEqual(binding['source'],'recovered')
                with self.assertRaises(ValueError):fence.source(False)
                verify.side_effect=ValueError('Invalid recovery')
                with self.assertRaises(ValueError):fence.source(True)


if __name__ == '__main__': unittest.main()
