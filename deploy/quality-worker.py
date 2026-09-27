#!/usr/bin/env python3
"""Run one durable calibration job offline. Never modifies delivery or active models."""
import argparse,fcntl,hashlib,json,os,shutil,sqlite3,stat,subprocess,tempfile,time,tomllib,uuid
from pathlib import Path


def identifier(value):
    if not isinstance(value,str):return False
    try:return str(uuid.UUID(value))==value
    except ValueError:return False


def private_directory(path):
    path.mkdir(mode=0o700,parents=True,exist_ok=True)
    info=path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or info.st_mode&0o077:
        raise ValueError('Research directories must be private and owned by this user')


def claim(db):
    now=int(time.time())
    with db:
        db.execute('BEGIN IMMEDIATE')
        # The process-wide flock proves the previous worker is no longer running.
        db.execute("UPDATE quality_jobs SET status='interrupted',finished=? WHERE status='running'",(now,))
        db.execute("UPDATE quality_jobs SET status='cancelled',finished=? WHERE status='queued' AND (created<? OR NOT EXISTS(SELECT 1 FROM users u WHERE u.username=quality_jobs.username AND u.admin=1 AND u.disabled=0))",(now,now-30*86400))
        row=db.execute("SELECT j.id,j.username,j.batch_id,j.operation,j.candidate_id FROM quality_jobs j JOIN users u ON u.username=j.username WHERE j.status='queued' AND u.admin=1 AND u.disabled=0 AND j.created>=? ORDER BY j.created,j.id LIMIT 1",(now-30*86400,)).fetchone()
        if row:db.execute("UPDATE quality_jobs SET status='running',started=? WHERE id=? AND status='queued'",(now,row[0]))
    return row


def cleanup(root,db):
    # Keep aggregate models referenced by retained revisions for explicit rollback.
    retained={r[0] for r in db.execute('SELECT id FROM quality_jobs')}
    for (raw,) in db.execute('SELECT settings FROM console_revisions'):
        selection=json.loads(raw).get('quality_candidate') or {}
        if selection.get('job'):retained.add(selection['job'])
    for path in root.iterdir():
        if path.is_dir() and not path.is_symlink() and len(path.name)==36 and identifier(path.name) and path.name not in retained and path.stat().st_mtime<time.time()-30*86400:shutil.rmtree(path)


def run(a):
    config=tomllib.loads(a.config.read_text())
    if config.get('cluster',{}).get('role')=='worker':raise ValueError('Calibration runs on the coordinator only')
    root=Path(config['data_dir'])/'calibration';private_directory(root)
    binary=a.binary.resolve(strict=True)
    with os.fdopen(os.open(root/'worker.lock',os.O_CREAT|os.O_WRONLY|os.O_NOFOLLOW,0o600),'w') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        db=sqlite3.connect(Path(config['data_dir'])/'state.sqlite3',timeout=10)
        db.execute('PRAGMA foreign_keys=ON');db.execute('PRAGMA synchronous=FULL')
        with db:
            db.execute('INSERT OR REPLACE INTO quality_worker_status VALUES(1,?,?)',(int(time.time()),binary.parent.name))
        cleanup(root,db)
        row=claim(db)
        if row is None:
            db.close();return {'status':'idle'}
        job,user,batch,operation,candidate=row
        result={'status':'failed','may_activate':False};model_hash=None;state='failed'
        try:
            if not identifier(job) or not identifier(batch) or operation not in ('train','compare','evaluate'):raise ValueError('Invalid job')
            candidate_path=None;candidate_hash=None
            if operation=='evaluate':
                if not identifier(candidate):raise ValueError('Invalid candidate')
                saved=db.execute("SELECT model_sha256 FROM quality_jobs WHERE id=? AND username=? AND operation='train' AND status='complete'",(candidate,user)).fetchone()
                candidate_path=root/candidate/'candidate'
                if not saved or hashlib.sha256((candidate_path/'model.json').read_bytes()).hexdigest()!=saved[0]:raise ValueError('Candidate changed')
                candidate_hash=saved[0]
            scratch=Path(os.environ['RUNTIME_DIRECTORY']) if os.environ.get('RUNTIME_DIRECTORY') else None
            with tempfile.TemporaryDirectory(prefix='quality-',dir=scratch) as temporary:
                snapshot=Path(temporary)/'dataset.jsonl'
                export_command=[str(binary),'--config',str(a.config),'quality-export','--username',user,'--batch',batch]
                if candidate_hash:export_command+=['--candidate-sha256',candidate_hash]
                export_command+=['--output',str(snapshot)]
                subprocess.run(export_command,check=True,capture_output=True,timeout=120)
                command=[str(a.python),str(binary.parent/'research/run_quality.py'),str(snapshot),str(root/job),'--operation',operation]
                if candidate_path:command+=['--candidate',str(candidate_path)]
                subprocess.run(command,check=True,capture_output=True,timeout=1800,env=dict(os.environ,OPENBLAS_NUM_THREADS='2',OMP_NUM_THREADS='2'))
                raw=(root/job/'report.json').read_bytes()
                if len(raw)>512*1024:raise ValueError('Oversized aggregate report')
                result=json.loads(raw);state=result['status'] if result.get('status') in ('insufficient_labels','failed') else 'complete'
                if operation=='train' and state=='complete':
                    model_path=root/job/'candidate/model.json'
                    model_hash=hashlib.sha256(model_path.read_bytes()).hexdigest()
                    # The same immutable Rust release must agree with every Python probe.
                    probes=json.loads((model_path.parent/'parity.json').read_text())
                    if not probes:raise ValueError('Native parity probes missing')
                    for n,probe in enumerate(probes):
                        observation=Path(temporary)/f'probe-{n}.json';observation.write_text(json.dumps(probe['observation']))
                        native=subprocess.run([str(binary),'quality-predict','--model',str(model_path),'--observation',str(observation)],capture_output=True,text=True,check=True,timeout=30)
                        prediction=json.loads(native.stdout)
                        if abs(prediction['risk_probability']-probe['risk_probability'])>1e-8:raise ValueError('Native risk parity failed')
                        if len(prediction['kind_probabilities'])!=len(probe['kind_probabilities']) or any(abs(x-y)>1e-8 for x,y in zip(prediction['kind_probabilities'],probe['kind_probabilities'])):raise ValueError('Native kind parity failed')
                    (model_path.parent/'parity.json').unlink()
                    result['native_parity']='passed'
            result['may_activate']=False;result['observation_only']=True
        except Exception as error:
            # No exception text: exporters or libraries may include message-derived data.
            result={'status':'failed','error_code':type(error).__name__,'may_activate':False,'observation_only':True}
            state='failed';model_hash=None
        with db:
            db.execute("UPDATE quality_jobs SET status=?,finished=?,report=?,model_sha256=? WHERE id=? AND status='running'",(state,int(time.time()),json.dumps(result,allow_nan=False),model_hash,job))
            db.execute("INSERT INTO audit(created,username,action,object_id) VALUES(?,?,'quality_result',?)",(int(time.time()),user,job))
        db.close();return {'job':job,'status':state,'activated':False}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary',type=Path,default=Path('/opt/noisefence/noisefence'))
    p.add_argument('--config',type=Path,default=Path('/etc/noisefence/config.toml'))
    p.add_argument('--python',type=Path,default=Path(os.environ.get('NOISEFENCE_TRAIN_PYTHON','/opt/noisefence-learning/bin/python')))
    p.add_argument('--loop',action='store_true',help='Container worker: check for user-requested jobs every minute')
    a=p.parse_args();os.umask(0o077)
    while True:
        print(json.dumps(run(a)),flush=True)
        if not a.loop:break
        time.sleep(60)

if __name__=='__main__':main()
