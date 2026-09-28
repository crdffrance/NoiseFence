#!/usr/bin/env python3
"""Archive a fenced restored console after its exact final checkpoint was received.

Never drops a database, replaces the local worker queue or clears service fences.
The operator must arrange the replacement authority before retiring this source.
"""
import argparse
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import uuid
import fence
from standby import STATE, private_json


def require(value, message):
    if not value:raise ValueError(message)


def protected(path, directory=False):
    require(path.is_absolute() and path.resolve()==path,'Physical retirement path required')
    for item in (path,*path.parents):
        info=item.lstat()
        require(info.st_uid==0 and not info.st_mode&0o022,'Root-protected retirement paths required')
        require(stat.S_ISDIR(info.st_mode) if item!=path or directory else stat.S_ISREG(info.st_mode),
                'Invalid retirement path type')
    return path.stat()


def private(path):
    info=protected(path)
    require(not info.st_mode&0o077 and info.st_size<=65536,'Private bounded retirement receipt required')
    return json.loads(path.read_bytes())


def sync(path):
    fd=os.open(path,os.O_RDONLY)
    try:os.fsync(fd)
    finally:os.close(fd)


def stopped():
    expected='[Unit]\nConditionPathExists=!/var/lib/noisefence-standby/fenced.json\n'
    for unit in (*fence.TIMERS,*fence.SERVICES):
        fields=subprocess.check_output(['systemctl','show',unit,'--property=LoadState,ActiveState,MainPID'],text=True)
        fields=dict(line.split('=',1) for line in fields.splitlines())
        if fields.get('LoadState')=='not-found':continue
        require(fields.get('ActiveState') in ('inactive','failed') and fields.get('MainPID','0')=='0',
                'Installed source unit is still running: '+unit)
        path=fence.SYSTEMD/(unit+'.d')/'99-ha-fenced.conf'
        protected(path)
        require(path.read_text()==expected,'Persistent source fence changed')


def retire(snapshot):
    require(str(uuid.UUID(snapshot))==snapshot,'Canonical checkpoint UUID required')
    protected(STATE,True)
    old=private(STATE/'fenced.json');transfer=private(STATE/'last-transfer.json')
    binding=old.get('source_binding',{})
    require(old.get('fenced') is True and old.get('method')=='systemd-persistent-condition'
            and old.get('automatic_restart_blocked') is True and binding.get('source')=='recovered',
            'Completed recovered-source fence required')
    operation=old['operation'];require(str(uuid.UUID(operation))==operation,'Invalid fence identity')
    report=transfer.get('report',{})
    require(transfer.get('protocol')=='noisefence-checkpoint-transfer-1'
            and transfer.get('checkpoint_protocol')=='noisefence-console-2'
            and transfer.get('fence_operation')==operation and report.get('snapshot')==snapshot
            and report.get('owner')==old['owner'] and report.get('last_error') is None
            and report.get('postgresql_restore_required') is True
            and type(transfer.get('started_ns')) is int and transfer['started_ns']>old['created_ns']
            and transfer.get('config_sha256')==binding.get('config_sha256'),
            'Exact final checkpoint after fencing has not been confirmed')
    settings=private(STATE/'settings.json')
    require(transfer.get('receiver')==settings.get('receiver') and settings.get('owner')==old['owner'],
            'Checkpoint destination changed')
    stopped()
    parent=STATE/'retired';parent.mkdir(mode=0o700,exist_ok=True);protected(parent,True)
    archive=parent/operation
    archive.mkdir(mode=0o700,exist_ok=True);protected(archive,True)
    sync(parent);sync(STATE)
    record=archive/'retirement.json'
    expected={'protocol':'noisefence-retired-console-1','operation':operation,'snapshot':snapshot,
              'config_sha256':binding['config_sha256'],'owner':old['owner'],'receiver':transfer['receiver']}
    if record.exists():
        saved=private(record)
        require({key:saved.get(key) for key in expected}==expected and saved.get('phase') in ('prepared','archived'),
                'Retirement changed during retry')
    else:
        require((STATE/'active').is_dir() and (STATE/'promoted.json').is_file(),
                'Installed restored console required')
        private_json(record,{**expected,'phase':'prepared'})
    current=STATE/'active' if (STATE/'active').exists() else archive/'active'
    protected(current,True);protected(current/'console.toml')
    require(hashlib.sha256((current/'console.toml').read_bytes()).hexdigest()==binding['config_sha256'],
            'Restored console configuration changed')
    marker=STATE/'promoted.json' if (STATE/'promoted.json').exists() else archive/'promoted.json'
    require(private(marker).get('owner')==old['owner'],'Promotion belongs to another coordinator')
    for name in ('active','promoted.json'):
        source,destination=STATE/name,archive/name
        require(source.exists()!=destination.exists(),'Ambiguous retired source location')
        if source.exists():
            os.rename(source,destination);sync(archive);sync(STATE)
    private_json(archive/'fenced.json',old)
    private_json(archive/'last-transfer.json',transfer)
    private_json(record,{**expected,'phase':'archived'})
    return {**expected,'status':'console_archived','archive':str(archive),
            'worker_queue_replaced':False,'database_dropped':False,'service_fence_retained':True}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--snapshot',required=True,help='Reviewed final checkpoint UUID accepted by the receiver')
    args=parser.parse_args();os.umask(0o077)
    require(os.geteuid()==0,'Root required')
    with contextlib.ExitStack() as stack:
        for path in (Path('/run/noisefence-upgrade.lock'),*(STATE/(name+'.lock') for name in ('push','export','receive'))):
            fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_NOFOLLOW,0o600)
            stream=stack.enter_context(os.fdopen(fd,'a'))
            fcntl.flock(stream,fcntl.LOCK_EX|fcntl.LOCK_NB)
        print(json.dumps(retire(args.snapshot)))


if __name__=='__main__':main()
