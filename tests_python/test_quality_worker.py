"""Offline worker recovery, authorization, privacy and publication contracts."""
import importlib.util,json,os,sqlite3,subprocess,tempfile,time,types,unittest,uuid
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]

class WorkerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec=importlib.util.spec_from_file_location('quality_worker',ROOT/'deploy/quality-worker.py')
        cls.worker=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.worker)

    def setup_database(self,root):
        db=sqlite3.connect(root/'state.sqlite3')
        db.executescript('''CREATE TABLE users(username TEXT PRIMARY KEY,admin INTEGER,disabled INTEGER);
          INSERT INTO users VALUES('admin',1,0);
          CREATE TABLE quality_jobs(id TEXT PRIMARY KEY,username TEXT,batch_id TEXT,operation TEXT,candidate_id TEXT,status TEXT,created INTEGER,started INTEGER,finished INTEGER,report TEXT,model_sha256 TEXT);
          CREATE TABLE quality_worker_status(id INTEGER PRIMARY KEY,heartbeat INTEGER,build TEXT);
          CREATE TABLE console_revisions(settings TEXT);
          CREATE TABLE audit(created INTEGER,username TEXT,action TEXT,object_id TEXT);''')
        job=str(uuid.uuid4());batch=str(uuid.uuid4())
        db.execute("INSERT INTO quality_jobs(id,username,batch_id,operation,status,created) VALUES(?,'admin',?,'compare','queued',?)",(job,batch,int(time.time())))
        db.commit();return db,job

    def test_abandoned_running_jobs_are_not_retried_and_revoked_jobs_are_cancelled(self):
        with tempfile.TemporaryDirectory() as tmp:
            db,job=self.setup_database(Path(tmp))
            db.execute("UPDATE quality_jobs SET status='running'");db.commit()
            self.assertIsNone(self.worker.claim(db))
            self.assertEqual(db.execute('SELECT status FROM quality_jobs').fetchone()[0],'interrupted')
            db.execute("UPDATE quality_jobs SET status='queued'");db.execute('UPDATE users SET disabled=1');db.commit()
            self.assertIsNone(self.worker.claim(db))
            self.assertEqual(db.execute('SELECT status FROM quality_jobs').fetchone()[0],'cancelled')

    def test_worker_exports_privately_publishes_only_aggregates_and_preserves_active_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);db,job=self.setup_database(root)
            binary=root/'release/noisefence';binary.parent.mkdir();binary.touch()
            config=root/'config.toml';config.write_text('data_dir = '+json.dumps(str(root))+'\n')
            original=config.read_bytes();args=types.SimpleNamespace(config=config,binary=binary,python=Path('/trusted/python'))
            snapshots=[]
            def execute(command,**kwargs):
                if 'quality-export' in command:
                    snapshot=Path(command[-1]);snapshots.append(snapshot);snapshot.write_text('private synthetic features')
                else:
                    self.assertEqual(command[1],str(binary.resolve().parent/'research/run_quality.py'))
                    self.assertEqual(kwargs['env']['OMP_NUM_THREADS'],'2')
                    directory=Path(command[3]);directory.mkdir(mode=0o700)
                    (directory/'report.json').write_text(json.dumps({'schema':'test','baseline':{'fp':0},'may_activate':False}))
                return subprocess.CompletedProcess(command,0,'')
            with patch.object(self.worker.subprocess,'run',side_effect=execute):result=self.worker.run(args)
            self.assertEqual(result['status'],'complete');self.assertFalse(result['activated'])
            self.assertEqual(config.read_bytes(),original)
            self.assertTrue(all(not p.exists() for p in snapshots))
            report=db.execute('SELECT report FROM quality_jobs').fetchone()[0]
            self.assertNotIn('private synthetic',report)
            self.assertFalse(json.loads(report)['may_activate'])

    def test_failure_never_publishes_traceback_or_secret_and_cleans_scratch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);db,job=self.setup_database(root);binary=root/'noisefence';binary.touch()
            config=root/'config.toml';config.write_text('data_dir = '+json.dumps(str(root))+'\n')
            args=types.SimpleNamespace(config=config,binary=binary,python=Path('/trusted/python'))
            with patch.object(self.worker.subprocess,'run',side_effect=RuntimeError('PRIVATE MESSAGE BODY')):
                result=self.worker.run(args)
            self.assertEqual(result['status'],'failed')
            report=db.execute('SELECT report FROM quality_jobs').fetchone()[0]
            self.assertNotIn('PRIVATE',report);self.assertIsNone(db.execute('SELECT model_sha256 FROM quality_jobs').fetchone()[0])

    def test_worker_refuses_mx_worker_role_and_symlinked_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);config=root/'config.toml';config.write_text('data_dir = '+json.dumps(str(root))+'\n[cluster]\nrole="worker"\n')
            with self.assertRaisesRegex(ValueError,'coordinator'):
                self.worker.run(types.SimpleNamespace(config=config,binary=root/'binary',python=root/'python'))
            target=root/'target';target.mkdir(mode=0o700);link=root/'link';link.symlink_to(target)
            with self.assertRaises(ValueError):self.worker.private_directory(link)

    @unittest.skipUnless(os.environ.get('NOISEFENCE_BINARY'),'Requires a native binary and research dependencies')
    def test_real_export_train_and_rust_parity_pipeline(self):
        import shutil,sys
        sys.path.insert(0,str(ROOT/'research'))
        import train_quality
        import test_quality as fixtures
        fixtures.QualityTests.q=train_quality
        rows=fixtures.QualityTests.fixture()
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);state=root/'state';state.mkdir(mode=0o700)
            release=root/'release';release.mkdir();binary=release/'noisefence'
            shutil.copyfile(Path(os.environ['NOISEFENCE_BINARY']).resolve(),binary);binary.chmod(0o700)
            (release/'research').symlink_to(ROOT/'research',target_is_directory=True)
            config=root/'config.toml'
            config.write_text((ROOT/'config/development.toml').read_text().replace('data_dir = "var/development"','data_dir = '+json.dumps(str(state))))
            subprocess.run([str(binary),'--config',str(config),'queue'],check=True,capture_output=True,timeout=30)
            db=sqlite3.connect(state/'state.sqlite3');db.execute('PRAGMA foreign_keys=ON')
            db.execute("INSERT INTO users(username,password,admin) VALUES('admin','test',1)")
            batch=str(uuid.uuid4());now=int(time.time())
            db.execute("INSERT INTO quality_batches VALUES(?,'admin',?,?,?,'','synthetic-seed',1020,1020)",(batch,now,rows[0]['since'],rows[0]['until']))
            db.execute("INSERT INTO quality_purposes VALUES(?,'development','')",(batch,))
            for rank,row in enumerate(rows[1:-1]):
                identifier=str(uuid.uuid4())
                scan={'score':50.,'tagged':False,'complete':True,'model':'synthetic','reasons':[],'features':[],
                      'subject':'Synthetic calibration fixture','sender':'sender@example.org','fingerprint':row['fingerprint'],
                      'campaign_simhash':row['simhash'],'elapsed_ms':1,'quality':row['quality']}
                db.execute("INSERT INTO messages(id,created,sender,scan,raw_present) VALUES(?,?,'sender@example.org',?,0)",(identifier,row['observed_at'],json.dumps(scan)))
                db.execute("INSERT INTO deliveries(message_id,address,destination,hosts,next_attempt) VALUES(?,'alice@example.test','alice@example.test','[]',0)",(identifier,))
                db.execute('INSERT INTO quality_members VALUES(?,?,?)',(batch,identifier,rank))
                db.execute("INSERT INTO quality_labels VALUES('admin',?,?,?,?)",(identifier,row['risk'],row['kind'],now))
            job=str(uuid.uuid4());db.execute("INSERT INTO quality_jobs(id,username,batch_id,operation,status,created) VALUES(?,'admin',?,'train','queued',?)",(job,batch,now));db.commit()
            result=self.worker.run(types.SimpleNamespace(config=config,binary=binary,python=Path(sys.executable)))
            report=json.loads(db.execute('SELECT report FROM quality_jobs WHERE id=?',(job,)).fetchone()[0])
            self.assertEqual(result['status'],'complete',report)
            self.assertEqual(report['native_parity'],'passed')
            self.assertFalse(report['may_activate'])
            self.assertEqual(db.execute('SELECT COUNT(*) FROM console_revisions').fetchone()[0],0)
            self.assertFalse((state/'calibration'/job/'candidate/parity.json').exists())
            self.assertTrue((state/'calibration'/job/'candidate/model.json').is_file())
            evaluation_job=str(uuid.uuid4())
            db.execute("INSERT INTO quality_jobs(id,username,batch_id,operation,candidate_id,status,created) VALUES(?,'admin',?,'evaluate',?,'queued',?)",(evaluation_job,batch,job,now));db.commit()
            result=self.worker.run(types.SimpleNamespace(config=config,binary=binary,python=Path(sys.executable)))
            report=json.loads(db.execute('SELECT report FROM quality_jobs WHERE id=?',(evaluation_job,)).fetchone()[0])
            self.assertEqual(result['status'],'complete',report)
            self.assertTrue(report['exposure']['candidate_bound'])
            self.assertFalse(report['exposure']['not_previously_exposed'])
            self.assertFalse(report['acceptance']['independent'])
            self.assertFalse(report['may_activate'])



if __name__=='__main__':unittest.main()
