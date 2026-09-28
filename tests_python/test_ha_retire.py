"""Retirement preserves data/fences and requires the exact final transfer."""
import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import uuid

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'deploy/ha'))
spec=importlib.util.spec_from_file_location('ha_retire',ROOT/'deploy/ha/retire.py')
retire=importlib.util.module_from_spec(spec);spec.loader.exec_module(retire)

class RetirementTests(unittest.TestCase):
    def setUp(self):
        self.stack=contextlib.ExitStack();self.addCleanup(self.stack.close)
        previous=os.umask(0o077);self.addCleanup(os.umask,previous)
        self.root=Path(self.stack.enter_context(tempfile.TemporaryDirectory())).resolve()
        self.stack.enter_context(patch.object(retire,'STATE',self.root))
        self.stack.enter_context(patch.object(retire,'protected',side_effect=lambda p,directory=False:p.stat()))
        self.stopped=self.stack.enter_context(patch.object(retire,'stopped'))
        (self.root/'active/data').mkdir(parents=True)
        (self.root/'active/data/preserved').write_bytes(b'never delete recovery material')
        self.config=b'root reviewed console configuration';(self.root/'active/console.toml').write_bytes(self.config)
        self.operation=str(uuid.uuid4());self.snapshot=str(uuid.uuid4())
        self.digest=hashlib.sha256(self.config).hexdigest()
        self.fence={'owner':'mx1','operation':self.operation,'fenced':True,'created_ns':10,
            'method':'systemd-persistent-condition','automatic_restart_blocked':True,
            'source_binding':{'source':'recovered','config_sha256':self.digest}}
        self.transfer={'protocol':'noisefence-checkpoint-transfer-1','receiver':'receiver@example.test',
            'checkpoint_protocol':'noisefence-console-2','started_ns':11,'fence_operation':self.operation,
            'config_sha256':self.digest,'report':{'owner':'mx1','snapshot':self.snapshot,
            'last_error':None,'postgresql_restore_required':True}}
        self.write('fenced.json',self.fence);self.write('last-transfer.json',self.transfer)
        self.write('settings.json',{'receiver':self.transfer['receiver'],'owner':'mx1'})
        self.write('promoted.json',{'owner':'mx1'})

    def write(self,name,value):
        (self.root/name).write_text(json.dumps(value));(self.root/name).chmod(0o600)

    def test_archive_and_repeat_preserve_all_data_and_fence(self):
        result=retire.retire(self.snapshot)
        archive=Path(result['archive'])
        self.assertEqual((archive/'active/data/preserved').read_bytes(),b'never delete recovery material')
        self.assertFalse((self.root/'active').exists());self.assertFalse((self.root/'promoted.json').exists())
        self.assertEqual(json.loads((self.root/'fenced.json').read_bytes()),self.fence)
        self.assertFalse(result['database_dropped']);self.assertFalse(result['worker_queue_replaced'])
        self.assertEqual(retire.retire(self.snapshot),result)

    def test_interrupted_rename_resumes_without_overwrite(self):
        original=retire.os.rename
        def fail(source,destination):
            if source.name=='promoted.json':raise OSError('simulated interruption')
            original(source,destination)
        with patch.object(retire.os,'rename',side_effect=fail),self.assertRaises(OSError):
            retire.retire(self.snapshot)
        self.assertFalse((self.root/'active').exists());self.assertTrue((self.root/'promoted.json').exists())
        self.assertEqual(retire.retire(self.snapshot)['status'],'console_archived')

    def test_unconfirmed_or_changed_handoff_refuses_before_move(self):
        for change in ('snapshot','fence','timing','config','destination'):
            with self.subTest(change=change):
                altered=json.loads(json.dumps(self.transfer))
                if change=='snapshot':altered['report']['snapshot']=str(uuid.uuid4())
                if change=='fence':altered['fence_operation']=str(uuid.uuid4())
                if change=='timing':altered['started_ns']=10
                if change=='config':altered['config_sha256']='f'*64
                if change=='destination':altered['receiver']='other@example.test'
                self.write('last-transfer.json',altered)
                with self.assertRaises(ValueError):retire.retire(self.snapshot)
                self.assertTrue((self.root/'active/data/preserved').exists())
        self.write('last-transfer.json',self.transfer)
        self.stopped.side_effect=ValueError('Service running')
        with self.assertRaises(ValueError):retire.retire(self.snapshot)
        self.assertTrue((self.root/'active').exists())

if __name__=='__main__':unittest.main()
