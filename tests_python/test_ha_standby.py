import importlib.util
import hashlib
import io
import json
from pathlib import Path
import sqlite3
import sys
import tarfile
import tempfile
import time
import types
import copy
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
    def test_private_transfer_record_binds_handoff_to_exported_configuration(self):
        manifest={'owner':'mx1','created':100,'revision':2,'snapshot':str(uuid.uuid4()),
                  'build':'noisefence test','protocol':'noisefence-console-2','started_ns':100000000000,
                  'fence_operation':str(uuid.uuid4()),'management':{'database':'test'},
                  'files':{'config/config.toml':{'sha256':'a'*64}}}
        report={**{key:manifest[key] for key in ('owner','created','revision','snapshot','build')},
                'bytes':1000,'received':101,'last_error':None,'postgresql_restore_required':True}
        settings={'owner':'mx1','receiver':'backup@example.test'}
        record=standby.transfer_record(settings,manifest,report,1000)
        self.assertEqual(record['config_sha256'],'a'*64)
        self.assertEqual(record['fence_operation'],manifest['fence_operation'])
        self.assertEqual(record['receiver'],settings['receiver'])
        with self.assertRaises(ValueError):standby.transfer_record(settings,manifest,{**report,'snapshot':'old'},1000)

    def test_transfer_receipt_binds_exact_checkpoint_and_backend(self):
        manifest={'owner':'mx1','created':100,'revision':2,'snapshot':str(uuid.uuid4()),
                  'build':'noisefence test','protocol':'noisefence-console-2'}
        report={**{key:manifest[key] for key in ('owner','created','revision','snapshot','build')},
                'bytes':1000,'received':101,'last_error':None,'postgresql_restore_required':True}
        standby.verify_receipt(report,manifest,1000)
        for key,value in {'snapshot':str(uuid.uuid4()),'created':99,'revision':1,'build':'old',
                'bytes':999,'postgresql_restore_required':False,'received':True,'last_error':'failed'}.items():
            with self.subTest(key=key), self.assertRaises(ValueError):
                standby.verify_receipt({**report,key:value},manifest,1000)

    def test_legacy_promotion_rejects_selected_checkpoint_before_creating_active_copy(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);state=root/'state';state.mkdir()
            data,_=self.selected_fixture(root)
            (state/'current').symlink_to(data)
            (state/'settings.json').write_text('{}')
            fence=state/'fence.json';fence.write_text('{}')
            with patch.object(promote,'STATE',state),patch.object(promote.subprocess,'run') as run:
                with self.assertRaisesRegex(ValueError,'coordinated database recovery'):promote.promote(fence)
                run.assert_not_called()
            self.assertFalse((state/'active').exists())

    def test_selected_export_streams_bound_dump_without_stopping_smtp_or_copying_bodies(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);data,m=self.selected_fixture(root)
            state=root/'state';state.mkdir();(data/'data/spool').mkdir()
            (data/'data/spool/private.eml').write_bytes(b'never archive this body')
            config=(data/'config/config.toml').read_bytes()
            import tomllib
            cfg=tomllib.loads(config.decode());central=m['management'];out=io.BytesIO();calls=[]
            tools=types.SimpleNamespace(postgres_target=lambda _: {},postgres_bytes=lambda _:100,
                dump_postgres=lambda target,path,timeout:path.write_bytes(b'PGDMPsynthetic'))
            def snapshot(args,**kwargs):
                calls.append(args)
                self.assertEqual(args[1],'ha-snapshot')
                with sqlite3.connect(args[2]) as source,sqlite3.connect(args[3]) as dest:source.backup(dest)
            with patch.object(standby,'DATA',data/'data'),patch.object(standby,'CONFIG',data/'config'),patch.object(standby,'STATE',state), \
                patch.object(standby,'backup_tools',return_value=tools),patch.object(standby,'postgres_state',return_value=central), \
                patch.object(standby.subprocess,'run',side_effect=snapshot),patch.object(standby.subprocess,'check_output',return_value='noisefence test\n'), \
                patch.object(standby.sys,'stdout',types.SimpleNamespace(buffer=out)):
                standby.export_selected(cfg,config,time.time_ns())
            out.seek(0)
            with tarfile.open(fileobj=out) as archive:
                names=archive.getnames()
                self.assertIn('data/management.postgresql.dump',names)
                self.assertTrue(any('/models/' in n for n in names))
                self.assertTrue(any('/credentials/' in n for n in names))
                self.assertFalse(any('/spool/' in n for n in names))
                manifest=json.load(archive.extractfile('manifest.json'))
                self.assertEqual(manifest['management'],central)
                self.assertEqual(manifest['protocol'],'noisefence-console-2')
                self.assertTrue(manifest['postgresql_restore_required'])
            self.assertEqual(len(calls),1)
            changed=copy.deepcopy(central);changed['policy_sequence']+=1;out=io.BytesIO()
            with patch.object(standby,'DATA',data/'data'),patch.object(standby,'CONFIG',data/'config'),patch.object(standby,'STATE',state), \
                patch.object(standby,'backup_tools',return_value=tools),patch.object(standby,'postgres_state',side_effect=[central,changed]), \
                patch.object(standby.subprocess,'run',side_effect=snapshot),patch.object(standby.sys,'stdout',types.SimpleNamespace(buffer=out)):
                with self.assertRaisesRegex(ValueError,'Policy changed'):standby.export_selected(cfg,config,time.time_ns())
            self.assertEqual(out.getvalue(),b'')

    def test_received_wal_mode_snapshot_stays_immutable(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);data,manifest=self.selected_fixture(root)
            path=data/'data/state.sqlite3'
            db=sqlite3.connect(path)
            self.assertEqual(db.execute('PRAGMA journal_mode=WAL').fetchone()[0],'wal')
            db.close()
            self.refresh_manifest(data,manifest)
            state=root/'state';state.mkdir()
            (state/'settings.json').write_text(json.dumps({'owner':'mx1','console_url':'https://mx2.example.test'}))
            with patch.object(standby,'STATE',state),patch.object(standby.subprocess,'check_output',return_value='noisefence test\n'):
                standby.receive(self.archive(data))
                installed=(state/'current').resolve()
                standby.selected_state(installed/'data/state.sqlite3',immutable=True)
                names={str(p.relative_to(installed)) for p in installed.rglob('*') if p.is_file()}
                self.assertEqual(names,set(manifest['files'])|{'manifest.json'})
                (installed/'data/state.sqlite3-wal').write_bytes(b'not a complete standalone backup')
                with self.assertRaisesRegex(ValueError,'sidecars'):
                    standby.selected_state(installed/'data/state.sqlite3',immutable=True)

    def recovered_fixture(self,root):
        data,manifest=self.selected_fixture(root)
        local=standby.selected_state(data/'data/state.sqlite3')
        operation=str(uuid.uuid4())
        pending={'protocol':'noisefence-management-recovery-1','operation':operation}
        receipt={'protocol':'noisefence-management-console-1','operation':operation,
            'database':local['selection']['database'],'node':local['selection']['node'],
            'console_only':True,'config_sha256':'e'*64,'fingerprint':'f'*64}
        with sqlite3.connect(data/'data/state.sqlite3') as db:
            db.executemany('INSERT INTO cluster_state VALUES(?,?)',[
                ('management_recovery_required',json.dumps(pending)),
                ('management_console_activation',json.dumps(receipt))])
        return data,manifest,receipt

    def test_recovered_checkpoint_preserves_fence_and_rejects_incomplete_authority(self):
        with tempfile.TemporaryDirectory() as tmp:
            data,_,receipt=self.recovered_fixture(Path(tmp));path=data/'data/state.sqlite3'
            self.assertEqual(standby.selected_state(path)['recovery'],receipt)
            with sqlite3.connect(path) as db:
                pending=db.execute("SELECT value FROM cluster_state WHERE key='management_recovery_required'").fetchone()[0]
                changed={**receipt,'operation':str(uuid.uuid4())}
                db.execute("UPDATE cluster_state SET value=? WHERE key='management_console_activation'",[json.dumps(changed)])
            with self.assertRaises(ValueError):standby.selected_state(path)
            with sqlite3.connect(path) as db:
                db.execute("DELETE FROM cluster_state WHERE key='management_console_activation'")
            with self.assertRaisesRegex(ValueError,'unfinished'):standby.selected_state(path)
            with sqlite3.connect(path) as db:
                self.assertEqual(db.execute("SELECT value FROM cluster_state WHERE key='management_recovery_required'").fetchone()[0],pending)

    def test_recovered_export_checks_live_authorization_and_archives_actual_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);data,manifest,receipt=self.recovered_fixture(root)
            state=root/'state';state.mkdir()
            original=(data/'config/config.toml').read_bytes()
            console=data/'console.toml';console.write_bytes(original+b'\n# current restored console\n')
            raw=console.read_bytes()
            import tomllib
            cfg=tomllib.loads(raw.decode());out=io.BytesIO();verified=[]
            tools=types.SimpleNamespace(postgres_target=lambda _: {},postgres_bytes=lambda _:100,
                dump_postgres=lambda target,path,timeout:path.write_bytes(b'PGDMPsynthetic'))
            report={'status':'console_authorization_verified','receipt':receipt,'smtp_enabled':False,'state_changed':False}
            def run(args,**kwargs):
                if args[-1]=='management-recovery-check-console':
                    self.assertEqual(args[:3],['/usr/sbin/runuser','-u','noisefence'])
                    self.assertIn(str(console),args)
                    verified.append(True)
                    return types.SimpleNamespace(stdout=json.dumps(report).encode())
                self.assertEqual(args[1],'ha-snapshot')
                with sqlite3.connect(args[2]) as source,sqlite3.connect(args[3]) as dest:source.backup(dest)
            with patch.object(standby,'DATA',data/'data'),patch.object(standby,'CONFIG',data/'config'),patch.object(standby,'CONFIG_FILE',console), \
                patch.object(standby,'STATE',state),patch.object(standby,'backup_tools',return_value=tools), \
                patch.object(standby,'postgres_state',return_value=manifest['management']), \
                patch.object(standby.subprocess,'run',side_effect=run),patch.object(standby.subprocess,'check_output',return_value='noisefence test\n'), \
                patch.object(standby.sys,'stdout',types.SimpleNamespace(buffer=out)):
                standby.export_selected(cfg,raw,time.time_ns())
                self.assertEqual(len(verified),2)
                out.seek(0)
                with tarfile.open(fileobj=out) as archive:
                    self.assertEqual(archive.extractfile('config/config.toml').read(),raw)
                    self.assertFalse(any('recovery-private' in name for name in archive.getnames()))
                # Central revocation must abort before any archive bytes are emitted.
                out.seek(0);out.truncate()
                report['receipt']={**receipt,'operation':str(uuid.uuid4())}
                with self.assertRaisesRegex(ValueError,'authorization differs'):
                    standby.export_selected(cfg,raw,time.time_ns())
                self.assertEqual(out.getvalue(),b'')
            self.assertEqual((data/'config/config.toml').read_bytes(),original)
            self.assertEqual(standby.selected_state(data/'data/state.sqlite3')['recovery'],receipt)

    def selected_fixture(self,root):
        data,m=self.fixture(root)
        key_hash=standby.digest(data/'data/mfa.key')
        credential=hashlib.sha256(b'{}').hexdigest()
        model=b'synthetic-model'
        files={'model.json':{'sha256':hashlib.sha256(model).hexdigest(),'size':len(model)}}
        generation=hashlib.sha256(json.dumps(files,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        folder=data/'data/cluster/models'/generation;folder.mkdir(parents=True)
        (folder/'model.json').write_bytes(model)
        keys=data/'data/cluster/credentials';keys.mkdir(parents=True)
        (keys/(credential+'.json')).write_bytes(b'{}')
        epoch={'sequence':4,'revision':7,'digest':'b'*64}
        selection={'protocol':'noisefence-management-selection-1','role':'coordinator',
            'node':{'node':'mx1','epoch':str(uuid.uuid4())},'database':{'instance':str(uuid.uuid4()),'source_digest':'a'*64},
            'mfa_key_sha256':key_hash}
        bundle={'revision':7,'digest':'b'*64,'files':files,'credential_generation':credential}
        local={'version':1,'node':'mx1','installed':bundle,'installed_epoch':epoch,
            'authority':{'owner':'mx1','sequence':4,'current_sequence':4,'current':bundle,'rollout':{'phase':'released'}}}
        with sqlite3.connect(data/'data/state.sqlite3') as db:
            db.execute('PRAGMA user_version=7')
            db.executemany('INSERT INTO cluster_state VALUES(?,?)',[('management_selection',json.dumps(selection)),('activation_participant',json.dumps(local))])
        (data/'config/config.toml').write_text('[cluster]\nrole="coordinator"\nnode_id="mx1"\n[management]\nbackend="postgresql"\n')
        (data/'data/management.postgresql.dump').write_bytes(b'PGDMPsynthetic-not-a-restorable-dump')
        m.update(protocol='noisefence-console-2',postgresql_restore_required=True,
            management={'database':selection['database'],'node':selection['node'],'epoch':epoch,'revision':7,'phase':'released','policy_sequence':4})
        self.refresh_manifest(data,m)
        return data,m

    def refresh_manifest(self,data,m):
        m['files']={str(p.relative_to(data)):{'bytes':p.stat().st_size,'sha256':standby.digest(p)} for p in data.rglob('*') if p.is_file() and p.name!='manifest.json'}
        (data/'manifest.json').write_text(json.dumps(m))

    def test_selected_receiver_requires_dump_authority_artifacts_and_mfa(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);state=root/'state';state.mkdir()
            (state/'settings.json').write_text(json.dumps({'owner':'mx1','console_url':'https://mx2.example.test'}))
            data,m=self.selected_fixture(root)
            with patch.object(standby,'STATE',state),patch.object(standby.subprocess,'check_output',return_value='noisefence test\n'):
                result=standby.receive(self.archive(data));self.assertTrue(result['postgresql_restore_required'])
                original=(state/'current').resolve()
                m['snapshot']=str(uuid.uuid4());m['protocol']='noisefence-console-1';self.refresh_manifest(data,m)
                with self.assertRaises(ValueError):standby.receive(self.archive(data))
                m['protocol']='noisefence-console-2';m['management']['database']['instance']=str(uuid.uuid4());self.refresh_manifest(data,m)
                with self.assertRaises(ValueError):standby.receive(self.archive(data))
                local=standby.selected_state(data/'data/state.sqlite3')
                m['management']['database']=local['selection']['database']
                (data/'data/management.postgresql.dump').write_bytes(b'not-a-dump');self.refresh_manifest(data,m)
                with self.assertRaises(ValueError):standby.receive(self.archive(data))
                (data/'data/management.postgresql.dump').write_bytes(b'PGDMPfixture')
                (data/'data/mfa.key').write_bytes(b'x'*32);self.refresh_manifest(data,m)
                with self.assertRaises(ValueError):standby.receive(self.archive(data))
                self.assertEqual((state/'current').resolve(),original)

    def test_selected_snapshot_never_uses_legacy_models_or_unreleased_policy(self):
        with tempfile.TemporaryDirectory() as tmp:
            data,_=self.selected_fixture(Path(tmp));path=data/'data/state.sqlite3'
            state=standby.selected_state(path)
            artifacts=standby.selected_artifacts(data/'data',state)
            self.assertEqual(len(artifacts),2)
            model=next(path for name,path in artifacts.items() if '/models/' in name)
            model.write_bytes(b'wrong')
            with self.assertRaises(ValueError):standby.selected_artifacts(data/'data',state)
            with sqlite3.connect(path) as db:
                row=json.loads(db.execute("SELECT value FROM cluster_state WHERE key='activation_participant'").fetchone()[0])
                row['authority']['rollout']['phase']='committed'
                db.execute("UPDATE cluster_state SET value=? WHERE key='activation_participant'",[json.dumps(row)])
            with self.assertRaises(ValueError):standby.selected_state(path)
            with sqlite3.connect(path) as db:
                row['authority']['rollout']['phase']='aborted';row['authority']['sequence']=5
                db.execute("UPDATE cluster_state SET value=? WHERE key='activation_participant'",[json.dumps(row)])
            aborted=standby.selected_state(path)
            self.assertEqual(aborted['policy_sequence'],5)
            self.assertEqual(aborted['epoch']['sequence'],4)
            central={'database':aborted['selection']['database'],'node':aborted['selection']['node'],
                'epoch':aborted['epoch'],'revision':7,'phase':'aborted','policy_sequence':5}
            standby.match_central(aborted,central)
            central['policy_sequence']=4
            with self.assertRaises(ValueError):standby.match_central(aborted,central)

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
