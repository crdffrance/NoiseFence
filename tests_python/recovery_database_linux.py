"""Run only in a disposable container: creates synthetic PostgreSQL databases."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid

assert os.geteuid() == 0 and os.environ.get('NOISEFENCE_DISPOSABLE_DATABASE_TEST') == '1'
assert Path('/.dockerenv').exists()
sys.path.insert(0, '/usr/local/libexec/noisefence-management')
import recovery_database as recovery
from migration_protocol import atomic, canonical

subprocess.run(['pg_ctlcluster','17','main','start'], check=True, stdout=subprocess.DEVNULL)
base = Path('/etc/noisefence-recovery')
base.mkdir(mode=0o700)
pg = '/usr/lib/postgresql/17/bin/'
def query(database, sql, user='postgres'):
    return subprocess.check_output(['runuser','-u',user,'--',pg+'psql','-X','-A','-t','-v','ON_ERROR_STOP=1',
        '--host=/var/run/postgresql','--dbname='+database,'-c',sql], text=True).strip()
query('postgres', 'CREATE ROLE noisefence LOGIN')
query('postgres', 'CREATE DATABASE source_nf OWNER noisefence')
binding = {'instance':str(uuid.uuid4()),'source_digest':'a'*64}
query('source_nf', "CREATE SCHEMA noisefence; CREATE TABLE noisefence.migration_state(id integer PRIMARY KEY,source_digest text, activated_at bigint,report jsonb); INSERT INTO noisefence.migration_state VALUES(1,'"+binding['source_digest']+"',1,'"+json.dumps({'instance':binding['instance']})+"'); CREATE TABLE noisefence.sample(id integer PRIMARY KEY,content text); INSERT INTO noisefence.sample SELECT i,repeat('synthetic-',i) FROM generate_series(1,8) i;", 'noisefence')
dump = base / 'source.dump'
with dump.open('xb') as output:
    subprocess.run(['runuser','-u','noisefence','--',pg+'pg_dump','--host=/var/run/postgresql','--dbname=source_nf','--format=custom'],stdout=output,check=True)
dump.chmod(0o600)
source_rows = query('source_nf','SELECT json_agg(s ORDER BY id) FROM noisefence.sample s','noisefence')

def plan():
    operation = str(uuid.uuid4())
    return {'protocol':'noisefence-recovery-database-1','operation':operation,'binding':binding,
        'dump':str(dump),'dump_sha256':hashlib.sha256(dump.read_bytes()).hexdigest(),'host':'/var/run/postgresql',
        'port':5432,'username':'noisefence','database':'nf_recovery_'+operation.replace('-',''),'expires_at':int(time.time())+600}

def apply(value):
    path = base / (value['operation']+'.json')
    atomic(path,canonical(value))
    return recovery.restore(path)

existing = plan()
query('postgres','CREATE DATABASE '+existing['database']+' OWNER noisefence')
query(existing['database'],'CREATE TABLE untouched(id integer); INSERT INTO untouched VALUES(47)', 'noisefence')
try:
    apply(existing)
    raise AssertionError('unowned existing target accepted')
except ValueError as error:
    assert 'already exists' in str(error)
assert query(existing['database'],'SELECT id FROM untouched','noisefence') == '47'

wrong = plan()
wrong['binding'] = {**binding,'instance':str(uuid.uuid4())}
try:
    apply(wrong)
    raise AssertionError('wrong authority accepted')
except ValueError:
    pass
assert query(wrong['database'],"SELECT count(*) FROM pg_namespace WHERE nspname='noisefence'",'noisefence') == '0'

valid = plan()
result = apply(valid)
assert result == apply(valid)
assert result['status'] == 'restored_not_activated'
assert query(valid['database'],'SELECT json_agg(s ORDER BY id) FROM noisefence.sample s','noisefence') == source_rows
assert query('source_nf','SELECT json_agg(s ORDER BY id) FROM noisefence.sample s','noisefence') == source_rows
# Simulate a lost client reply after the atomic PostgreSQL commit.
state_path = recovery.STATE / valid['operation'] / 'state.json'
saved = json.loads(state_path.read_bytes())
saved['restored'] = False
atomic(state_path,canonical(saved))
assert apply(valid) == result
assert json.loads(state_path.read_bytes())['restored'] is True
# The receipt does not override a subsequently changed management identity.
query(valid['database'],"UPDATE noisefence.migration_state SET source_digest='"+'b'*64+"'",'noisefence')
try:
    apply(valid)
    raise AssertionError('changed authority accepted')
except ValueError:
    pass
query(valid['database'],"UPDATE noisefence.migration_state SET source_digest='"+binding['source_digest']+"'",'noisefence')
# A later missing receipt is never interpreted as permission to overwrite a target.
query(valid['database'],"UPDATE noisefence.migration_state SET report=report-'database_restore_receipts'",'noisefence')
try:
    apply(valid)
    raise AssertionError('missing receipt accepted')
except ValueError:
    pass
assert query(valid['database'],'SELECT count(*) FROM noisefence.sample','noisefence') == '8'
print(json.dumps({'restored':True,'idempotent':True,'existing_database_preserved':True,
    'wrong_binding_rolled_back':True,'lost_reply_recovered':True,'missing_receipt_refused':True,
    'source_unchanged':True,'changed_authority_refused':True,'services_started':False,'synthetic_only':True}))
