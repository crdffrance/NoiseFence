#!/usr/bin/env python3
"""Local, content-free host security report. No mail, credentials or raw audit argv."""
import argparse
import collections
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import time
import tomllib

ROOT=Path('/var/lib/noisefence-hardening')
SERVICES=['ssh','nginx','noisefence','clamav-daemon','clamav-freshclam','noisefence-signature-scanner','noisefence-vision','auditd','noisefence-firewall']

def command(*args):
    return subprocess.run(args,capture_output=True,text=True,timeout=20)

def audit_event(line):
    """Allowlisted fields only. Never propagate PROCTITLE, EXECVE, paths or MESSAGE."""
    if not line.startswith(('type=AVC ','type=SYSCALL ')):return None
    if 'apparmor=' in line and 'profile="noisefence' in line:
        category='apparmor_denied' if 'apparmor="DENIED"' in line else 'apparmor_learning'
    elif 'key="noisefence_' in line:
        category='configuration_change'
    else:return None
    result={'category':category}
    for field in ['pid','uid','auid','exit']:
        value=re.search(r'\b'+field+r'=(-?\d+)\b',line)
        if value:result[field]=int(value[1])
    for field in ['profile','operation','key']:
        value=re.search(r'\b'+field+r'="([a-zA-Z0-9_-]{1,80})"',line)
        if value:result[field]=value[1]
    stamp=re.search(r'msg=audit\((\d+(?:\.\d+)?):',line)
    if stamp:result['time']=float(stamp[1])
    # This benign startup fstat is separate, never hide other OCR denials.
    if result.get('profile')=='noisefence-vision' and result.get('operation')=='getattr' and 'name="dev/null"' in line and 'Failed name lookup - disconnected path' in line:
        result['category']='ocr_inherited_stdin_diagnostic'
    return result

def report(since):
    now=int(time.time());result={'version':1,'time':now,'services':{},'issues':[]}
    for name in SERVICES:
        state=command('systemctl','is-active',name).stdout.strip()
        if name=='noisefence-vision' and state=='inactive' and command('systemctl','is-active','noisefence-vision.socket').returncode==0:
            state='socket_waiting'
        result['services'][name]=state
        if state not in ['active','socket_waiting']:result['issues'].append('service:'+name+':'+state)
    fs=os.statvfs('/var/lib/noisefence');free=fs.f_bavail*fs.f_frsize
    result['disk']={'free_bytes':free,'free_percent':round(100*fs.f_bavail/max(1,fs.f_blocks),1)}
    if free<2*1024**3 or result['disk']['free_percent']<15:result['issues'].append('disk_low')
    result['reboot_required']=Path('/var/run/reboot-required').exists()
    if result['reboot_required']:result['issues'].append('reboot_required')
    cfg=tomllib.loads(Path('/etc/noisefence/config.toml').read_text())
    cert=cfg.get('smtp',{}).get('tls_cert')
    result['tls_valid_14_days']=bool(cert) and command('openssl','x509','-in',cert,'-noout','-checkend','1209600').returncode==0
    if not result['tls_valid_14_days']:result['issues'].append('tls_renewal_required')
    result['memory_pressure']=Path('/proc/pressure/memory').read_text().strip() if Path('/proc/pressure/memory').exists() else None
    result['queue']={}
    try:
        with sqlite3.connect('file:/var/lib/noisefence/state.sqlite3?mode=ro',uri=True,timeout=1) as db:
            for kind,states,count,oldest in db.execute("SELECT m.is_dsn,d.status,COUNT(*),MIN(m.created) FROM deliveries d JOIN messages m ON m.id=d.message_id WHERE d.status IN ('pending','sending','failed','quarantined') GROUP BY m.is_dsn,d.status"):
                key=('dsn_' if kind else 'mail_')+states
                result['queue'][key]={'count':count,'oldest_age_seconds':now-oldest}
                if states!='quarantined' and now-oldest>1800:result['issues'].append('queue_age:'+key)
    except sqlite3.Error:result['issues'].append('queue_check_failed')
    result['signatures']={}
    for name,path in [('official','/var/lib/clamav/daily.cld'),('official_cvd','/var/lib/clamav/daily.cvd'),('advisory','/var/lib/noisefence-signatures')]:
        p=Path(path)
        if p.is_dir():files=[x for x in p.iterdir() if x.is_file() and x.suffix in ['.ndb','.hdb','.ldb','.hsb']]
        else:files=[p] if p.exists() else []
        if files:result['signatures'][name]=max(0,now-int(max(x.stat().st_mtime for x in files)))
    official=min([result['signatures'].get(k,10**10) for k in ['official','official_cvd']])
    if official>3*86400:result['issues'].append('signatures_official_stale')
    if result['signatures'].get('advisory',10**10)>3*86400:result['issues'].append('signatures_advisory_stale')
    if Path('/etc/noisefence-hardening/central.json').exists():
        for filename,age_limit,label in [('backup-status.json',36*3600,'backup'),('restore-status.json',8*86400,'restore_test')]:
            try:
                stamp=json.loads((ROOT/filename).read_text())['time']
                if now-int(stamp)>age_limit:result['issues'].append(label+'_stale')
            except (OSError,ValueError,KeyError):result['issues'].append(label+'_missing')
        if command('systemctl','show','noisefence-central-backup','-p','Result','--value').stdout.strip() not in ['','success']:result['issues'].append('backup_failed')
    result['audit_counts']={};events=[]
    path=Path('/var/log/audit/audit.log')
    if path.exists():
        with path.open('rb') as f:
            size=f.seek(0,2);f.seek(max(0,size-8*1024*1024))
            if size>8*1024*1024:f.readline()
            for line in f:
                event=audit_event(line.decode(errors='replace'))
                if event and event.get('time',0)>=since:events.append(event)
    result['audit_counts']=dict(collections.Counter(e['category'] for e in events));result['audit_events']=events[-100:]
    if result['audit_counts'].get('apparmor_denied'):result['issues'].append('apparmor_denied')
    raw=command('journalctl','--since=@'+str(since),'--until=@'+str(now),'--no-pager','-o','json','-n','4000').stdout
    counts=collections.Counter()
    for line in raw.splitlines():
        try:item=json.loads(line)
        except ValueError:continue
        msg=item.get('MESSAGE','');msg=msg if isinstance(msg,str) else ''
        unit=item.get('_SYSTEMD_UNIT','')
        if unit=='ssh.service':
            if 'Failed publickey' in msg or 'Invalid user' in msg:counts['ssh_failed']+=1
            elif 'Accepted publickey' in msg:counts['ssh_key_login']+=1
        if item.get('SYSLOG_IDENTIFIER')=='sudo' and 'COMMAND=' in msg:counts['sudo_command']+=1
        if item.get('_TRANSPORT')=='kernel' and ('oom-kill' in msg or 'Out of memory' in msg):counts['oom']+=1
        if unit in ['apt-daily-upgrade.service','unattended-upgrades.service'] and ('error' in msg.lower() or 'failed' in msg.lower()):counts['update_error']+=1
    result['journal_counts']=dict(counts)
    for name in ['oom','update_error']:
        if counts[name]:result['issues'].append(name)
    return result

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--stdout',action='store_true');args=parser.parse_args()
    if os.geteuid()!=0:parser.error('root required')
    os.umask(0o077);ROOT.mkdir(mode=0o700,parents=True,exist_ok=True)
    path=ROOT/'monitor.json';since=int(time.time())-300
    if path.exists():
        try:since=max(since-86400,int(json.loads(path.read_text())['time']))
        except (ValueError,KeyError):pass
    result=report(since);tmp=path.with_suffix('.tmp');tmp.write_text(json.dumps(result)+'\n');os.replace(tmp,path)
    if args.stdout:print(json.dumps(result))
    else:print(json.dumps({'security_status':'attention' if result['issues'] else 'ok','issues':result['issues']}))

if __name__=='__main__':main()
