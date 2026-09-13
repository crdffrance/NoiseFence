import importlib.util
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('isolation_hardening',ROOT/'deploy/hardening/isolation.py')
isolation=importlib.util.module_from_spec(spec);spec.loader.exec_module(isolation)


class IsolationHardening(unittest.TestCase):
    def test_complain_cannot_be_mistaken_for_protected_commit(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory=Path(tmp);ident='b'*32
            (directory/(ident+'.json')).write_text(json.dumps({'id':ident,'status':'pending','mode':'complain','deadline':time.time()+300}))
            with patch.object(isolation,'STATE',directory),patch.object(isolation,'run') as run:
                with self.assertRaises(ValueError):isolation.commit(ident)
                run.assert_not_called()

    def test_profile_rejects_unknown_modes(self):
        with self.assertRaises(ValueError):isolation.profiles('unconfined')
        self.assertEqual(isolation.profiles('complain').count('flags=(complain)'),4)
        self.assertNotIn('flags=(complain)',isolation.profiles('enforce'))

    def test_only_named_profiles_and_expected_executables(self):
        p=isolation.profiles('enforce')
        self.assertNotIn('/usr/** ix',p)
        self.assertNotIn('capability sys_admin',p)
        self.assertNotIn('profile /usr/bin/python',p)
        self.assertIn('network netlink raw',p)
        self.assertIn('owner /var/lib/noisefence/** rwkl',p)
        self.assertIn('profile noisefence-clamav',p)

    def test_ocr_stays_local_and_scanner_cannot_gain_capabilities(self):
        values=isolation.files(True,'enforce')
        scanner=values['/etc/systemd/system/clamav-daemon.service.d/90-hardening.conf']
        self.assertIn('PrivateNetwork=yes',scanner)
        self.assertIn('CapabilityBoundingSet=\n',scanner)
        # ClamAV's signed-bytecode JIT is deliberately not broken by an NX override.
        self.assertNotIn('MemoryDenyWriteExecute=yes',scanner)
        self.assertNotIn('PrivateNetwork=no',str(values))

    def test_four_gb_host_has_aggregate_budget_and_spare_capacity(self):
        small=isolation.files(True,'enforce')['/etc/systemd/system/noisefence-processing.slice']
        self.assertIn('MemoryMax=3300M',small)
        self.assertIn('MemoryHigh=3000M',small)
        self.assertNotIn('MemoryOOMGroup=yes',small)


if __name__=='__main__':unittest.main()
