"""Old source guards are replaced only under the new native authority and hold."""
import contextlib,json,os
from pathlib import Path
import sys,tempfile,types,unittest
from unittest.mock import Mock,patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'deploy/postgresql'))
import recovery_reentry as reentry

OP='00000000-0000-4000-8000-000000000001'
OLD='00000000-0000-4000-8000-000000000002'
class ReentryTests(unittest.TestCase):
 def setUp(self):
  self.stack=contextlib.ExitStack();self.addCleanup(self.stack.close)
  self.root=Path(self.stack.enter_context(tempfile.TemporaryDirectory())).resolve()
  self.state=self.root/'standby';self.state.mkdir();self.units=self.root/'units';self.units.mkdir()
  archive=self.state/'retired'/OLD;archive.mkdir(parents=True)
  self.old={'operation':OLD,'fenced':True,'source_binding':{'config_sha256':'a'*64}}
  def write(p,v):p.write_text(json.dumps(v));p.chmod(0o600)
  write(archive/'fenced.json',self.old);write(self.state/'fenced.json',self.old)
  write(archive/'retirement.json',{'protocol':'noisefence-retired-console-1','phase':'archived','operation':OLD,'owner':'mx1','config_sha256':'a'*64})
  self.paths=[]
  for unit in reentry.UNITS:
   p=self.units/(unit+'.d')/reentry.GUARD;p.parent.mkdir();p.write_bytes(reentry.CONTENT);self.paths.append(p)
  self.runtime=types.SimpleNamespace(state={'phase':'prepared'},root=self.root,plan={'operation':OP,'console_unit_sha256':'b'*64},
   manifest={'owner':'mx1'},binding='c'*64,preparation={'user':'noisefence','binary':'/trusted/binary'},verify_native=Mock(),verify=Mock())
  self.stack.enter_context(patch.object(reentry,'STANDBY',self.state))
  self.stack.enter_context(patch.object(reentry.recovery_install,'UNITS',self.units))
  self.stack.enter_context(patch.object(reentry,'Runtime',return_value=self.runtime))
  self.stack.enter_context(patch.object(reentry,'root_json',side_effect=lambda p:json.loads(p.read_bytes())))
  self.stack.enter_context(patch.object(reentry,'protected'))
  self.stack.enter_context(patch.object(reentry,'fingerprint'))
  self.hold=self.stack.enter_context(patch.object(reentry,'verify_hold'))
  self.stack.enter_context(patch.object(reentry,'unit_state',return_value='inactive'))
  self.run=self.stack.enter_context(patch.object(reentry,'execute'))
  self.stack.enter_context(patch.object(reentry.recovery_runtime,'validate_unit'))
  fragment=self.units/'noisefence-console.service';fragment.write_text('ConditionPathExists=/var/lib/noisefence-standby/promoted.json\n')
  self.stack.enter_context(patch.object(reentry.recovery_runtime,'unit_properties',side_effect=lambda:{'DropInPaths':str(self.paths[1]) if self.paths[1].exists() else '', 'FragmentPath':str(fragment)}))
 def test_replaces_only_old_guards_preserving_archive_and_new_hold(self):
  result=reentry.replace_guards(self.root/'authorization',OLD)
  self.assertTrue(all(not p.exists() for p in self.paths));self.assertFalse((self.state/'fenced.json').exists())
  self.assertTrue((self.state/'retired'/OLD/'fenced.json').exists());self.assertFalse(result['services_started'])
  self.assertFalse(any('start' in c.args[0] or 'restart' in c.args[0] for c in self.run.call_args_list))
  self.run.reset_mock();self.assertEqual(reentry.replace_guards(self.root/'authorization',OLD),result)
  self.run.assert_not_called()
 def test_authority_hold_or_changed_guard_refuses(self):
  self.hold.side_effect=ValueError('Hold missing')
  with self.assertRaises(ValueError):reentry.replace_guards(self.root/'authorization',OLD)
  self.assertTrue(all(p.exists() for p in self.paths));self.hold.side_effect=None
  self.runtime.verify_native.side_effect=ValueError('Native authority mismatch')
  with self.assertRaises(ValueError):reentry.replace_guards(self.root/'authorization',OLD)
  self.runtime.verify_native.side_effect=None;self.paths[-1].write_text('unreviewed')
  with self.assertRaises(ValueError):reentry.replace_guards(self.root/'authorization',OLD)
  self.assertTrue(all(p.exists() for p in self.paths))
 def test_partial_removal_retry_keeps_old_fence_until_verified(self):
  real=Path.unlink
  def interrupted(path,*args,**kwargs):
   if path==self.paths[2]:raise OSError('interruption')
   return real(path,*args,**kwargs)
  with patch.object(Path,'unlink',interrupted),self.assertRaises(OSError):reentry.replace_guards(self.root/'authorization',OLD)
  self.assertTrue((self.state/'fenced.json').exists())
  reentry.replace_guards(self.root/'authorization',OLD)
  self.assertFalse((self.state/'fenced.json').exists())
if __name__=='__main__':unittest.main()
