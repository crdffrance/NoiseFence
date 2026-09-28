#!/usr/bin/python3
"""Enable recovered-console checkpoints only after a verified transfer.

Receiver installation and its restricted SSH account must already be prepared.
This command pins the existing transport and installed units; it never creates
remote accounts, replaces keys or changes the selected console/worker queues.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import time

from migration_agent import execute, unit_state
from migration_protocol import atomic, canonical, identity, private_read, require, sha
from recovery_install import protected
from recovery_runtime import Runtime, fingerprint, root_json

STATE = Path('/var/lib/noisefence-standby')
SERVICE = 'noisefence-recovered-standby-push.service'
TIMER = 'noisefence-recovered-standby-push.timer'


def properties(unit, names):
    raw=execute(['/usr/bin/systemctl','show','--all','--property='+','.join(names),unit]).decode()
    fields={}
    for line in raw.splitlines():
        key,separator,value=line.partition('=')
        require(separator and key in names and key not in fields,'Invalid checkpoint unit inspection')
        fields[key]=value
    require(set(fields)==set(names),'Incomplete checkpoint unit inspection')
    return fields


def installation(plan):
    service=properties(SERVICE,('ExecStart','FragmentPath','DropInPaths','User','NoNewPrivileges','ProtectSystem'))
    require(service['User'] in ('','root') and service['NoNewPrivileges']=='yes'
            and service['ProtectSystem']=='strict' and not service['DropInPaths'], 'Unsupported checkpoint service')
    commands=re.findall(r'argv\[\]=([^;]+);',service['ExecStart'])
    require(len(commands)==1 and shlex.split(commands[0])==[
        '/usr/bin/python3','/usr/local/libexec/noisefence-ha/standby.py','push','--recovered-console'],
        'Checkpoint service selects another source or command')
    fingerprint(Path(service['FragmentPath']).resolve(),plan['service_sha256'],65536)
    timer=properties(TIMER,('Unit','FragmentPath','DropInPaths'))
    require(timer['Unit']==SERVICE and not timer['DropInPaths'],'Checkpoint timer targets another service')
    fingerprint(Path(timer['FragmentPath']).resolve(),plan['timer_sha256'],65536)
    for path,key in ((STATE/'transport.key','key_sha256'),(STATE/'known_hosts','known_hosts_sha256')):
        fingerprint(path,plan[key],65536)
    require(not protected(STATE/'transport.key').st_mode & 0o077, 'Transport key must be root-private')
    settings=root_json(STATE/'settings.json')
    require(settings.get('receiver')==plan['receiver'], 'Checkpoint receiver differs from authorization')
    return settings


def transfer_report(path, started_ns, owner):
    with private_read(path,65536) as source:
        info=os.fstat(source.fileno())
        require(not info.st_mode & 0o077 and info.st_mtime_ns>=started_ns,
                'Checkpoint service did not publish a fresh private transfer receipt')
        report=json.load(source)
    require(report.get('owner')==owner and identity(report.get('snapshot'))
            and report.get('postgresql_restore_required') is True and report.get('last_error') is None
            and type(report.get('received')) is int and type(report.get('bytes')) is int and report['bytes']>0,
            'Selected checkpoint transfer was not confirmed')
    return report


def configure(authorization):
    plan=root_json(authorization)
    require(set(plan)=={'protocol','operation','runtime_authorization','runtime_identity','receiver',
        'key_sha256','known_hosts_sha256','service_sha256','timer_sha256','expires_at'},
        'Invalid checkpoint installation authorization')
    require(plan['protocol']=='noisefence-recovery-checkpoint-1' and identity(plan['operation'])
        and all(sha(plan[key]) for key in ('runtime_identity','key_sha256','known_hosts_sha256','service_sha256','timer_sha256'))
        and isinstance(plan['receiver'],str) and re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}@[A-Za-z0-9][A-Za-z0-9.-]{0,252}',plan['receiver'])
        and type(plan['expires_at']) is int and time.time()<plan['expires_at']<=time.time()+3600,
        'Invalid or expired checkpoint authorization')
    runtime=Runtime(Path(plan['runtime_authorization']))
    require(runtime.plan['operation']==plan['operation'] and runtime.binding==plan['runtime_identity']
            and runtime.state['phase']=='running','Matching completed runtime recovery required')
    runtime.run()  # Real native authority, confinement, routing and worker checks.
    settings=installation(plan)
    require(settings.get('owner')==runtime.manifest['owner'],'Checkpoint source authority differs')
    path=runtime.root/'checkpoint.json'
    binding=hashlib.sha256(canonical({key:value for key,value in plan.items() if key!='expires_at'})).hexdigest()
    if path.exists():
        saved=root_json(path)
        require(saved.get('authorization')==binding and saved.get('status') in ('planned','enabled'),
                'Checkpoint installation changed during retry')
        if saved['status']=='enabled':
            require(unit_state(TIMER)=='active' and execute(['/usr/bin/systemctl','is-enabled',TIMER]).strip()==b'enabled',
                    'Recovered checkpoint timer was disabled; explicit repair required')
            return {'operation':plan['operation'],'status':'checkpoint_timer_verified','snapshot':saved['snapshot']}
    else:
        atomic(path,canonical({'authorization':binding,'status':'planned'}))
    # The normal source selector is wrong after promotion. Stop its timer and
    # wait for both possible exporters before establishing the new schedule.
    for unit in ('noisefence-standby-push.timer',TIMER):
        if unit_state(unit)!='unknown':execute(['/usr/bin/systemctl','disable','--now',unit])
    for unit in ('noisefence-standby-push.service',SERVICE):
        if unit_state(unit)!='unknown':execute(['/usr/bin/systemctl','stop',unit],timeout=370)
    started=time.time_ns()
    execute(['/usr/bin/systemctl','start',SERVICE],timeout=370)
    report=transfer_report(STATE/'active/data/ha-standby-status.json',started,runtime.manifest['owner'])
    # Recheck pinned configuration and live authority before enabling future runs.
    installation(plan);runtime.run()
    execute(['/usr/bin/systemctl','enable','--now',TIMER])
    require(unit_state(TIMER)=='active','Recovered checkpoint timer did not start')
    atomic(path,canonical({'authorization':binding,'status':'enabled','snapshot':report['snapshot']}))
    return {'operation':plan['operation'],'status':'checkpoint_timer_enabled','snapshot':report['snapshot']}


if __name__=='__main__':
    os.umask(0o077)
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--authorization',type=Path,required=True)
    args=parser.parse_args()
    require(os.geteuid()==0,'Root required')
    with open('/run/noisefence-upgrade.lock','a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        print(json.dumps(configure(args.authorization)))
