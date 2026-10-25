import importlib.util
import json
import hashlib
import stat
from types import SimpleNamespace
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
        self.assertEqual(isolation.profiles('complain').count('flags=(complain)'),3)
        self.assertIn('flags=(complain,attach_disconnected.path=/att/noisefence/)',isolation.profiles('complain'))
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

    def test_gateway_memory_budget_leaves_room_for_resident_models(self):
        path='/etc/systemd/system/noisefence.service.d/90-hardening.conf'
        for small,high,maximum in [(True,'1800M','2G'),(False,'2500M','3G')]:
            with self.subTest(small=small):
                unit=isolation.files(small,'enforce')[path]
                self.assertIn('MemoryHigh='+high+'\n',unit)
                self.assertIn('MemoryMax='+maximum+'\n',unit)


    def test_scoped_paths_only_mirror_existing_local_sockets_on_main_profile(self):
        source=isolation.profiles('enforce');main=source.split('profile noisefence-clamav',1)[0]
        expected=['/run/postgresql/.s.PGSQL.[0-9]*','/run/clamav/clamd.ctl',
                  '/run/noisefence-signatures/clamd.ctl','/run/noisefence-vision/worker.sock']
        scoped=[line.strip() for line in main.splitlines() if line.strip().startswith('/att/')]
        self.assertEqual(scoped,['/att/noisefence'+path+' rw,' for path in expected])
        for path in expected:self.assertIn('  '+path+' rw,',main)
        self.assertNotIn('flags=(attach_disconnected)',source)
        self.assertNotIn('/att/',source.split('profile noisefence-clamav',1)[1])

    def test_enforcement_preserves_scoping_and_every_non_mode_rule(self):
        learning=isolation.profiles('complain')
        self.assertEqual(isolation.enforcing_profiles(learning),isolation.profiles('enforce'))
        legacy=learning.replace('flags=(complain,'+isolation.DISCONNECTED_FLAG+')','flags=(complain)')
        self.assertEqual(isolation.enforcing_profiles(legacy),legacy.replace(' flags=(complain)',''))
        for invalid in (learning+learning,learning.replace('complain,attach_disconnected.path=/att/noisefence/','complain,unconfined')):
            with self.assertRaises(ValueError):isolation.enforcing_profiles(invalid)

    def test_reserved_prefix_rejects_real_paths_symlinks_and_writable_or_foreign_parents(self):
        prefix=Path('/fixture-att/noisefence');parent=prefix.parent
        def run_case(info,exists):
            def lstat(path):
                if path==parent:return info
                if path==prefix and exists:return SimpleNamespace(st_mode=stat.S_IFLNK|0o777,st_uid=0)
                raise FileNotFoundError()
            with patch.object(isolation,'DISCONNECTED_ROOT',prefix),patch.object(Path,'lstat',lstat):
                return isolation.require_reserved_prefix()
        for mode,uid in [(stat.S_IFLNK|0o777,0),(stat.S_IFDIR|0o777,0),(stat.S_IFDIR|0o755,1000)]:
            with self.assertRaisesRegex(ValueError,'unsafe parent'):run_case(SimpleNamespace(st_mode=mode,st_uid=uid),False)
        safe=SimpleNamespace(st_mode=stat.S_IFDIR|0o755,st_uid=0)
        with self.assertRaisesRegex(ValueError,'must not exist'):run_case(safe,True)
        run_case(safe,False)
        with patch.object(Path,'lstat',side_effect=FileNotFoundError):isolation.require_reserved_prefix()

    def test_collision_refuses_apply_before_rollback_timer_or_file_writes(self):
        with patch.object(isolation,'require_reserved_prefix',side_effect=ValueError('collision')), \
             patch.object(isolation,'save') as save,patch.object(isolation,'run') as run,patch.object(isolation,'atomic') as atomic:
            with self.assertRaises(ValueError):isolation.apply(600)
            save.assert_not_called();run.assert_not_called();atomic.assert_not_called()

    def test_collision_refuses_revision_enforcement_and_commit(self):
        with tempfile.TemporaryDirectory() as tmp:
            profile=Path(tmp)/'profile';profile.write_text('synthetic profile')
            digest=hashlib.sha256(profile.read_bytes()).hexdigest()
            for action,mode in [(isolation.revise,'complain'),(isolation.enforce,'complain'),(isolation.commit,'enforce')]:
                state={'status':'pending','mode':mode,'deadline':time.time()+300,'applied_hashes':{str(profile):digest}}
                with patch.object(isolation,'PROFILE',profile),patch.object(isolation,'read',return_value=state), \
                     patch.object(isolation,'require_reserved_prefix',side_effect=ValueError('collision')), \
                     patch.object(isolation,'atomic') as atomic,patch.object(isolation,'run') as run:
                    with self.assertRaisesRegex(ValueError,'collision'):action('a'*32)
                    atomic.assert_not_called();run.assert_not_called()

    def test_prefix_collision_does_not_block_automatic_rollback(self):
        with tempfile.TemporaryDirectory() as tmp:
            state={'id':'a'*32,'status':'pending','files':{}}
            with patch.object(isolation,'PROFILE',Path(tmp)/'missing'),patch.object(isolation,'read',return_value=state), \
                 patch.object(isolation,'require_reserved_prefix',side_effect=ValueError('collision')) as guard, \
                 patch.object(isolation,'run'),patch.object(isolation,'save'), \
                 patch.object(isolation.subprocess,'run',return_value=SimpleNamespace(returncode=0)):
                self.assertEqual(isolation.rollback('a'*32)['status'],'rolled_back')
                guard.assert_not_called()


if __name__=='__main__':unittest.main()
