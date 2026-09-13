import importlib.util
from pathlib import Path
import unittest
spec=importlib.util.spec_from_file_location('monitor',Path(__file__).resolve().parents[1]/'deploy/hardening/monitor.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class MonitorTests(unittest.TestCase):
    def test_secret_argv_and_path_are_never_exported(self):
        event=m.audit_event('type=SYSCALL msg=audit(1789293448.641:1): uid=0 pid=11 key="noisefence_config" name="SECRET" proctitle="API_TOKEN=SECRET"')
        self.assertEqual(event,{'category':'configuration_change','pid':11,'uid':0,'key':'noisefence_config','time':1789293448.641})
        self.assertIsNone(m.audit_event('type=PROCTITLE msg=audit(1:2): proctitle=SECRET'))
    def test_denials_remain_visible_except_exact_known_stdin_case(self):
        prefix='type=AVC msg=audit(1789293448:1): apparmor="DENIED" profile="noisefence-vision" operation="getattr" '
        self.assertEqual(m.audit_event(prefix+'name="/etc/shadow"')['category'],'apparmor_denied')
        self.assertEqual(m.audit_event(prefix+'name="dev/null" info="Failed name lookup - disconnected path"')['category'],'ocr_inherited_stdin_diagnostic')
