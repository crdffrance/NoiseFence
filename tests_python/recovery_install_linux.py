"""Explicit destructive fixture: run ONLY in the disposable no-network systemd container.

This writes fixed /etc and /var/lib paths. It is not a production check.
"""
import hashlib
import json
import os
from pathlib import Path
import pwd
import sqlite3
import subprocess
import sys
import time

assert os.geteuid() == 0 and os.environ.get('NOISEFENCE_DISPOSABLE_INSTALLER_TEST') == '1'
assert Path('/run/systemd/container').read_text().strip() == 'docker'
sys.path.insert(0, '/usr/local/libexec/noisefence-management')
import recovery_install as installer
from migration_protocol import atomic, canonical

account = pwd.getpwnam('noisefence')
data = Path('/var/lib/noisefence')
data.chmod(0o700)
(data / 'calibration').mkdir(mode=0o700, exist_ok=True)
os.chown(data / 'calibration', account.pw_uid, account.pw_gid)
for name in ('daemon.lock', 'calibration/worker.lock'):
    atomic(data / name, b'', uid=account.pw_uid, gid=account.pw_gid)
selection = {'protocol':'noisefence-management-selection-1',
    'database':{'instance':'00000000-0000-4000-8000-000000000001','source_digest':'a'*64},
    'node':{'node':'mx2','epoch':'00000000-0000-4000-8000-000000000002'},
    'role':'worker','baseline':{'sequence':1,'revision':1,'digest':'b'*64},'mfa_key_sha256':None}
with sqlite3.connect(data / 'state.sqlite3') as db:
    db.execute('PRAGMA user_version=7')
    db.execute('CREATE TABLE cluster_state(key TEXT PRIMARY KEY,value TEXT NOT NULL)')
    db.execute('INSERT INTO cluster_state VALUES(?,?)', ('management_selection',json.dumps(selection)))
os.chown(data / 'state.sqlite3', account.pw_uid, account.pw_gid)
os.chmod(data / 'state.sqlite3', 0o600)
key = Path('/etc/noisefence/worker.key')
atomic(key, b'1'*64, uid=account.pw_uid, gid=account.pw_gid)
config = Path('/etc/noisefence/config.toml')
original = (f'data_dir="{data}"\n[management]\nbackend="coordinator"\n'
            f'[cluster]\nrole="worker"\nnode_id="mx2"\ncredential_file="{key}"\n'
            'coordinator_url = "https://old.example.test"\n').encode()
atomic(config, original, uid=0, gid=account.pw_gid, mode=0o640)
# Harmless stand-in: exercises systemd service ownership/config selection, no SMTP.
binary = Path('/usr/local/bin/noisefence')
atomic(binary, b'#!/bin/sh\nexec /bin/sleep infinity\n', mode=0o755)
unit = Path('/etc/systemd/system/noisefence.service')
atomic(unit, (f'[Unit]\nDescription=Disposable installer fixture\n[Service]\nUser=noisefence\nExecStart={binary} --config {config} serve\n').encode(), mode=0o644)
subprocess.run(['systemctl','daemon-reload'], check=True)
subprocess.run(['systemctl','start','noisefence.service'], check=True)
assert subprocess.check_output(['systemctl','is-active','noisefence.service'], text=True).strip() == 'active'
operation = '00000000-0000-4000-8000-000000000003'
keys = {'protocol':'noisefence-recovery-worker-credentials-1','operation':operation,
    'database':selection['database'],'workers':{'mx2':{'epoch':selection['node']['epoch'],'token':'2'*64}}}
bundle = Path('/etc/noisefence/test-keys.json')
atomic(bundle, canonical(keys))
authorization = Path('/etc/noisefence/test-install.json')
plan = {'protocol':'noisefence-recovery-install-1','operation':operation,'selection':selection,
    'config':str(config),'config_sha256':hashlib.sha256(original).hexdigest(),
    'bundle_sha256':hashlib.sha256(bundle.read_bytes()).hexdigest(),
    'coordinator_url':'https://new.example.test','user':'noisefence','expires_at':int(time.time())+600}
atomic(authorization, canonical(plan))
# Real root-protection check: service ownership of the authorization is refused.
os.chown(authorization, account.pw_uid, account.pw_gid)
try:
    installer.install(authorization, bundle)
    raise AssertionError('service-owned authorization accepted')
except ValueError:
    pass
assert key.read_bytes() == b'1'*64
os.chown(authorization, 0, 0)
result = installer.install(authorization, bundle)
assert result == installer.install(authorization, bundle)
assert key.read_bytes() == b'2'*64 and key.stat().st_uid == account.pw_uid
assert config.stat().st_uid == 0 and config.stat().st_gid == account.pw_gid
assert config.read_bytes() == installer.rewrite(original, plan['coordinator_url'])
subprocess.run(['systemctl','start','noisefence.service'], check=True)
fields = subprocess.check_output(['systemctl','show','--property=ActiveState,ConditionResult','noisefence.service'], text=True)
assert 'ActiveState=inactive' in fields and 'ConditionResult=no' in fields
print(json.dumps({'installed':True,'idempotent':True,'untrusted_authorization_refused':True,
    'service_restart_blocked':True,'worker_uid':account.pw_uid,'config_uid':config.stat().st_uid,
    'native_verification_required':result['native_verification_required'], 'smtp_tested':False}))
