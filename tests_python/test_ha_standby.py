import importlib.util
import io
import json
from pathlib import Path
import sqlite3
import sys
import tarfile
import tempfile
import time
import unittest
from unittest.mock import patch
import uuid

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('standby',ROOT/'deploy/ha/standby.py')
standby=importlib.util.module_from_spec(spec);spec.loader.exec_module(standby)
sys.modules['standby']=standby
spec=importlib.util.spec_from_file_location('ha_promote',ROOT/'deploy/ha/promote.py')
promote=importlib.util.module_from_spec(spec);spec.loader.exec_module(promote)

class StandbyTests(unittest.TestCase):
    def test_managed_candidate_is_included_and_digest_checked(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);job=str(uuid.uuid4());folder=root/'calibration'/job/'candidate';folder.mkdir(parents=True)
            model=folder/'model.json';model.write_text('{"synthetic":true}')
            selection={'quality_candidate':{'job':job,'sha256':standby.digest(model)}}
            with patch.object(standby,'DATA',root):
                self.assertIn(folder,list(standby.data_paths(selection)))
                model.write_text('{"synthetic":false}')
                with self.assertRaises(ValueError):list(standby.data_paths(selection))
                selection['quality_candidate']['job']='../../escape'
                with self.assertRaises(ValueError):list(standby.data_paths(selection))

    def test_paths_never_escape_or_include_mail_bodies(self):
        for path in ['/etc/shadow','../secret','data/../config/key','data/spool/id.eml','data/incoming/tmp','data/replicas/id.eml','data/research-archive/archive.key','data/research-archive/objects/id/message.enc','config\\key']:
            with self.subTest(path=path),self.assertRaises(ValueError):standby.safe_name(path)
        self.assertEqual(standby.safe_name('data/models/active.json'),'data/models/active.json')

    def test_planned_promotion_requires_final_checkpoint_after_fence(self):
        now=int(time.time());f={'owner':'mx1','fenced':True,'created':now,'operation':'test','created_ns':now*1_000_000_000+500,'method':'systemd-persistent-condition'}
        settings={'owner':'mx1'};m={'created':now,'started':now,'started_ns':now*1_000_000_000+100,'fence_operation':'test'}
        with self.assertRaises(ValueError):promote.validate_fence(f,settings,m,False,now)
        m['started_ns']=now*1_000_000_000+501;promote.validate_fence(f,settings,m,False,now)
        with self.assertRaises(ValueError):promote.validate_fence(f,settings,m,False,now+3601)
        m['fence_operation']='different'
        with self.assertRaises(ValueError):promote.validate_fence(f,settings,m,False,now)

    def test_disaster_requires_poweroff_reference_and_recent_checkpoint(self):
        now=int(time.time());f={'owner':'mx1','fenced':True,'created':now,'method':'network-timeout','reference':'ping failed'}
        with self.assertRaises(ValueError):promote.validate_fence(f,{'owner':'mx1'},{'created':now},True,now)
        f['method']='provider-poweroff';f['reference']='provider-operation-fixture'
        promote.validate_fence(f,{'owner':'mx1'},{'created':now},True,now)
        with self.assertRaises(ValueError):promote.validate_fence(f,{'owner':'mx1'},{'created':now-86401},True,now)

    def fixture(self,root):
        data=root/'input';(data/'data').mkdir(parents=True);(data/'config').mkdir()
        db=sqlite3.connect(data/'data/state.sqlite3');db.executescript("CREATE TABLE cluster_state(key,value); INSERT INTO cluster_state VALUES('role','coordinator'),('node_id','mx1');");db.close()
        (data/'data/mfa.key').write_bytes(b'k'*32);(data/'config/config.toml').write_text('hostname="mx1.example.test"\n')
        files={str(p.relative_to(data)):{'bytes':p.stat().st_size,'sha256':standby.digest(p)} for p in data.rglob('*') if p.is_file()}
        m={'protocol':'noisefence-console-1','owner':'mx1','created':int(time.time()),'revision':7,'snapshot':str(uuid.uuid4()),'build':'noisefence test','files':files}
        (data/'manifest.json').write_text(json.dumps(m));return data,m

    def archive(self,data,extra=None):
        out=io.BytesIO()
        with tarfile.open(fileobj=out,mode='w') as tar:
            for p in data.rglob('*'):
                if p.is_file():tar.add(p,arcname=str(p.relative_to(data)))
            if extra:
                e=tarfile.TarInfo(extra);e.type=tarfile.SYMTYPE;e.linkname='/etc/shadow';tar.addfile(e)
        out.seek(0);return out

    def test_atomic_receive_verifies_checksums_and_preserves_previous_generation(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);state=root/'state';state.mkdir();(state/'settings.json').write_text(json.dumps({'owner':'mx1','console_url':'https://mx2.example.test'}))
            data,m=self.fixture(root)
            with patch.object(standby,'STATE',state),patch.object(standby.subprocess,'check_output',return_value='noisefence test\n'):
                result=standby.receive(self.archive(data));self.assertEqual(result['snapshot'],m['snapshot'])
                previous=(state/'current').resolve()
                (data/'data/mfa.key').write_bytes(b'x'*32)
                with self.assertRaises(ValueError):standby.receive(self.archive(data))
                self.assertEqual((state/'current').resolve(),previous)
                with self.assertRaises(ValueError):standby.receive(self.archive(data,'config/escape'))
                self.assertEqual((state/'current').resolve(),previous)
                (state/'promoted.json').write_text('{}')
                with self.assertRaises(ValueError):standby.receive(self.archive(data))

if __name__=='__main__':unittest.main()
