"""Research work follows the authorized restored management database only."""
import importlib.util
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('recovered_job', ROOT/'deploy/recovered-job.py')
job = importlib.util.module_from_spec(spec); spec.loader.exec_module(job)


class RecoveredJobTests(unittest.TestCase):
    def test_dispatch_pins_release_authority_and_private_output(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); cfg=root/'console.toml'; data=root/'data'; binary=root/'noisefence'
            binary.touch()
            cfg.write_text('data_dir='+json.dumps(str(data))+'\n[cluster]\nrole="coordinator"\n[management]\nbackend="postgresql"\n')
            result={'status':'console_authorization_verified','smtp_enabled':False,'state_changed':False}
            with patch.object(job,'CONFIG',cfg),patch.object(job,'DATA',data),patch.object(job,'BINARY',binary), \
                    patch.object(job.subprocess,'run',return_value=types.SimpleNamespace(stdout=json.dumps(result))) as run:
                for kind in ('quality','train'):
                    args=job.command(kind)
                    self.assertIn(str(cfg),args);self.assertIn(str(binary.resolve()),args)
                    self.assertEqual(args[1],str(binary.resolve().parent/'deploy'/('quality-worker.py' if kind=='quality' else 'train-feedback.py')))
                    if kind=='train':self.assertEqual(args[-2:],['--directory',str(data/'models')])
                self.assertEqual(run.call_args.args[0][-1],'management-recovery-check-console')
                run.return_value.stdout=json.dumps({**result,'smtp_enabled':True})
                with self.assertRaises(ValueError):job.command('quality')
                run.reset_mock()
                cfg.write_text(cfg.read_text().replace('coordinator','worker'))
                with self.assertRaises(ValueError):job.command('train')
                run.assert_not_called()

    def test_recovery_units_use_native_checked_wrapper_and_local_socket_network(self):
        for kind in ('train','quality'):
            service=(ROOT/f'deploy/ha/noisefence-recovered-{kind}.service').read_text()
            self.assertIn(f'ExecStart=/usr/bin/python3 /opt/noisefence/current/deploy/recovered-job.py {kind}',service)
            self.assertIn('ReadWritePaths=/var/lib/noisefence-standby/active/data',service)
            self.assertIn('PrivateNetwork=true',service)
            self.assertIn('ConditionPathExists=!/var/lib/noisefence-recovery-install/hold.json',service)
            timer=(ROOT/f'deploy/ha/noisefence-recovered-{kind}.timer').read_text()
            self.assertIn(f'Unit=noisefence-recovered-{kind}.service',timer)

if __name__=='__main__':unittest.main()
