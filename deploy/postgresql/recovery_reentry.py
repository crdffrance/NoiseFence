#!/usr/bin/python3
"""Replace retired-source HA guards only under a new, verified installation hold.

Starts no service. Timers remain disabled for explicit post-recovery setup.
"""
import argparse
import fcntl
import json
import os
from pathlib import Path
import shlex

from migration_agent import execute, unit_state, SERVICES
from migration_protocol import atomic, canonical, identity, require
import recovery_install
import recovery_runtime
from recovery_runtime import Runtime, root_json, fingerprint
from recovery_install import protected

STANDBY=Path('/var/lib/noisefence-standby')
NAMES=('noisefence','noisefence-console','noisefence-train','noisefence-url-feed',
       'noisefence-quality','noisefence-standby-push','noisefence-recovered-standby-push',
       'noisefence-recovered-train','noisefence-recovered-quality')
TIMERS=tuple(name+'.timer' for name in NAMES if name not in ('noisefence','noisefence-console'))
UNITS=tuple(name+'.service' for name in NAMES)+TIMERS
GUARD='99-ha-fenced.conf'
CONTENT=b'[Unit]\nConditionPathExists=!/var/lib/noisefence-standby/fenced.json\n'


def sync(directory):
    fd=os.open(directory,os.O_RDONLY)
    try:os.fsync(fd)
    finally:os.close(fd)


def verify_hold(runtime):
    hold=recovery_install.STATE/'hold.json'
    require(root_json(hold)=={'operation':runtime.plan['operation']},'New installation hold required')
    expected=('[Unit]\nConditionPathExists=!'+str(hold)+'\n').encode()
    for unit in SERVICES:
        path=recovery_install.UNITS/(unit+'.d')/recovery_install.DROPIN
        protected(path);require(path.read_bytes()==expected,'New installation guard changed')
    require(not (STANDBY/'promoted.json').exists(),'Do not replace guards on a started console')
    for unit in UNITS:
        require(unit_state(unit) in ('inactive','failed','unknown'),'Stop source units before re-entry')


def replace_guards(authorization, retired_operation):
    require(identity(retired_operation),'Canonical retired operation required')
    runtime=Runtime(authorization)
    require(runtime.state['phase']=='prepared','Re-entry precedes runtime startup')
    archive=STANDBY/'retired'/retired_operation
    retired=root_json(archive/'retirement.json')
    old=root_json(archive/'fenced.json')
    require(retired.get('phase')=='archived' and retired.get('operation')==retired_operation
            and retired.get('protocol')=='noisefence-retired-console-1'
            and retired.get('owner')==runtime.manifest['owner'] and old.get('operation')==retired_operation
            and old.get('fenced') is True and old.get('source_binding',{}).get('config_sha256')==retired.get('config_sha256'),
            'Matching completed retirement required')
    fingerprint(archive/'active/console.toml',retired['config_sha256'],1024**2)
    verify_hold(runtime);runtime.verify_native()
    receipt=runtime.root/'reentry.json'
    expected={'protocol':'noisefence-reentry-1','authorization':runtime.binding,
              'operation':runtime.plan['operation'],'retired_operation':retired_operation}
    if receipt.exists():
        saved=root_json(receipt)
        require({k:saved.get(k) for k in expected}==expected and saved.get('phase') in ('prepared','replaced'),
                'Re-entry changed during retry')
    else:
        require(root_json(STANDBY/'fenced.json')==old,'Live source fence differs from retirement')
        saved={**expected,'phase':'prepared'}
        atomic(receipt,canonical(saved))
    if (STANDBY/'fenced.json').exists():
        require(root_json(STANDBY/'fenced.json')==old,'Another source fence is active')
    else:
        require(receipt.exists(),'Missing unrecorded source fence')
    console_guard=recovery_install.UNITS/'noisefence-console.service.d'/GUARD
    fields=recovery_runtime.unit_properties()
    require(shlex.split(fields['DropInPaths']) in ([],[str(console_guard)]),'Unreviewed console overrides')
    recovery_runtime.validate_unit({**fields,'DropInPaths':''},runtime.preparation['user'],
        runtime.preparation['binary'],runtime.plan['console_unit_sha256'])
    require('ConditionPathExists=/var/lib/noisefence-standby/promoted.json' in
            Path(fields['FragmentPath']).read_text().splitlines(),'Console startup marker guard missing')
    paths=[]
    for unit in UNITS:
        path=recovery_install.UNITS/(unit+'.d')/GUARD
        if path.exists():
            protected(path);require(path.read_bytes()==CONTENT,'Old HA guard changed')
            paths.append(path)
    if saved['phase']=='replaced':
        require(not paths and not (STANDBY/'fenced.json').exists(),'Old guards were restored externally')
        runtime.verify()
        return {**expected,'status':'new_installation_hold_retained','services_started':False}
    # No scheduled work may resume merely because the old guards disappear.
    for timer in TIMERS:
        if unit_state(timer)!='unknown':execute(['/usr/bin/systemctl','disable','--now',timer])
    verify_hold(runtime);runtime.verify_native()
    for path in paths:
        path.unlink();sync(path.parent)
    execute(['/usr/bin/systemctl','daemon-reload'])
    runtime.verify();verify_hold(runtime)
    fence=STANDBY/'fenced.json'
    if fence.exists():fence.unlink();sync(STANDBY)
    atomic(receipt,canonical({**expected,'phase':'replaced'}))
    return {**expected,'status':'new_installation_hold_retained','services_started':False}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--authorization',type=Path,required=True)
    parser.add_argument('--retired-operation',required=True)
    args=parser.parse_args();os.umask(0o077)
    require(os.geteuid()==0,'Root required')
    with open('/run/noisefence-upgrade.lock','a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        print(json.dumps(replace_guards(args.authorization,args.retired_operation)))
