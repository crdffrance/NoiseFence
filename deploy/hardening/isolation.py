#!/usr/bin/env python3
"""Stage, exercise and enforce MX process confinement with timed rollback."""
import argparse
import base64
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import time
import uuid

spec=importlib.util.spec_from_file_location('network_hardening',Path(__file__).with_name('network.py'))
network=importlib.util.module_from_spec(spec);spec.loader.exec_module(network)
atomic=network.atomic
run=network.run
STATE=Path('/var/lib/noisefence-hardening/isolation')
SELF=Path('/usr/local/libexec/noisefence-hardening/isolation.py')
PROFILE=Path('/etc/apparmor.d/noisefence-services')
SERVICES=['clamav-daemon','noisefence-signature-scanner','noisefence-vision','nginx','noisefence']


def profiles(mode):
    if mode not in ['complain','enforce']:raise ValueError('Invalid profile mode')
    flag=' flags=(complain)' if mode=='complain' else ''
    header='''# Managed by NoiseFence. No profile attaches to another product's binary.
#include <tunables/global>
'''
    base='''  #include <abstractions/base>
  /etc/ld.so.cache r,
  /etc/ld.so.preload r,
  /usr/lib/** mr,
  /lib/** mr,
  /usr/share/** r,
  /etc/localtime r,
  /etc/timezone r,
  /sys/devices/system/cpu/** r,
  /sys/fs/cgroup/** r,
  owner /proc/** r,
  signal (receive) peer=unconfined,
  ptrace (readby, tracedby) peer=unconfined,
'''
    main='''  #include <abstractions/nameservice>
  capability net_bind_service,
  network inet stream,
  network inet6 stream,
  network inet dgram,
  network inet6 dgram,
  network netlink raw,
  network unix,
  signal (send, receive) peer=noisefence,
  /opt/noisefence/** mr,
  /opt/noisefence/{current,releases/*}/noisefence ix,
  /etc/noisefence/ r,
  /etc/noisefence/** r,
  /var/lib/noisefence/ rw,
  /var/lib/noisefence/research/*/{model.json,native-combination.json} r,
  /var/lib/noisefence/research/*/encoder/{config.json,tokenizer.json,model.safetensors} r,
  owner /var/lib/noisefence/** rwkl,
  /run/clamav/clamd.ctl rw,
  /run/noisefence-signatures/clamd.ctl rw,
  /run/noisefence-vision/worker.sock rw,
  owner /tmp/** rwk,
  owner /var/tmp/** rwk,
'''
    scanner='''  network unix,
  signal (send, receive) peer=noisefence-clamav,
  /usr/local/sbin/clamd mrix,
  /usr/sbin/clamd mrix,
  /usr/local/lib/** mr,
  /etc/clamav/** r,
  /etc/nsswitch.conf r,
  /etc/group r,
  /var/lib/clamav/ r,
  /var/lib/clamav/** mr,
  /var/lib/noisefence-signatures/ r,
  /var/lib/noisefence-signatures/** mr,
  /var/log/clamav/** rw,
  /run/clamav/ rw,
  /run/clamav/** rwk,
  /run/noisefence-signatures/ rw,
  /run/noisefence-signatures/** rwk,
  owner /tmp/** rwkm,
  owner /var/tmp/** rwkm,
'''
    vision='''  network unix,
  signal (send, receive) peer=noisefence-vision,
  /usr/bin/python3* mrix,
  /usr/bin/{tesseract,zbarimg,pdftoppm,pdfinfo} mrix,
  /usr/local/lib/python*/dist-packages/ r,
  /opt/noisefence/** r,
  /etc/fonts/** r,
  /var/cache/fontconfig/** r,
  /etc/papersize r,
  /etc/python3*/** r,
  /etc/ImageMagick-*/** r,
  /etc/{nsswitch.conf,host.conf,hosts,gai.conf,resolv.conf} r,
  /run/systemd/resolve/stub-resolv.conf r,
  /run/noisefence-vision/** rw,
  owner /tmp/** rwk,
  owner /var/tmp/** rwk,
'''
    nginx='''  #include <abstractions/nameservice>
  capability net_bind_service,
  capability setuid,
  capability setgid,
  capability chown,
  capability dac_override,
  network inet stream,
  network inet6 stream,
  network inet dgram,
  network inet6 dgram,
  network unix,
  signal (send, receive) peer=noisefence-nginx,
  /usr/sbin/nginx mrix,
  /etc/nginx/** r,
  /etc/ssl/** r,
  /etc/letsencrypt/** r,
  /opt/noisefence/** r,
  /var/www/** r,
  /var/log/nginx/ rw,
  /var/log/nginx/** rw,
  /var/lib/nginx/ rw,
  /var/lib/nginx/** rw,
  /var/cache/nginx/** rw,
  /run/nginx.pid rw,
  /run/nginx/ rw,
  /run/nginx/** rw,
'''
    return header+'\n'.join('profile '+name+flag+' {\n'+base+body+'}\n' for name,body in [('noisefence',main),('noisefence-clamav',scanner),('noisefence-vision',vision),('noisefence-nginx',nginx)])


def files(small,mode):
    common='''[Service]
PrivateDevices=yes
ProtectClock=yes
ProtectKernelLogs=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
ProtectProc=invisible
ProcSubset=pid
RestrictSUIDSGID=yes
LockPersonality=yes
LimitCORE=0
'''
    scanner=common+'''PrivateNetwork=yes
CapabilityBoundingSet=
AmbientCapabilities=
AppArmorProfile=noisefence-clamav
Slice=noisefence-processing.slice
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
OOMScoreAdjust=300
'''
    main=common+'''AppArmorProfile=noisefence
Slice=noisefence-processing.slice
TasksMax=256
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
OOMScoreAdjust=-300
'''+('MemoryHigh=1300M\nMemoryMax=1700M\nCPUQuota=150%\n' if small else 'MemoryHigh=1600M\nMemoryMax=2G\nCPUQuota=350%\n')
    nginx=common+'''NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/run /var/log/nginx /var/lib/nginx
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_SETUID CAP_SETGID CAP_CHOWN CAP_DAC_OVERRIDE
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
AppArmorProfile=noisefence-nginx
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
MemoryHigh=128M
MemoryMax=256M
TasksMax=128
CPUQuota=100%
'''
    values={
        str(PROFILE):profiles(mode),
        '/etc/systemd/system/noisefence.service.d/90-hardening.conf':main,
        '/etc/systemd/system/clamav-daemon.service.d/90-hardening.conf':scanner+'MemoryHigh=1200M\nMemoryMax=1700M\n',
        '/etc/systemd/system/noisefence-signature-scanner.service.d/90-hardening.conf':scanner+'MemoryHigh=256M\nMemoryMax=512M\n',
        '/etc/systemd/system/noisefence-vision.service.d/90-hardening.conf':'[Service]\nAppArmorProfile=noisefence-vision\nSlice=noisefence-processing.slice\nLimitCORE=0\nSystemCallFilter=@system-service\nSystemCallErrorNumber=EPERM\nOOMScoreAdjust=500\n',
        '/etc/systemd/system/nginx.service.d/90-hardening.conf':nginx,
        '/etc/systemd/system/clamav-freshclam.service.d/90-hardening.conf':common+'''Slice=noisefence-processing.slice
OOMScoreAdjust=600
MemoryHigh=1200M
MemoryMax=1700M
''',
        '/etc/systemd/system/noisefence-signatures.service.d/90-hardening.conf':'[Service]\nSlice=noisefence-processing.slice\nLimitCORE=0\nOOMScoreAdjust=600\n',
        '/etc/systemd/system/noisefence-train.service.d/90-hardening.conf':'[Service]\nSlice=noisefence-processing.slice\nLimitCORE=0\nMemoryHigh=3G\nTasksMax=128\n',
        '/etc/systemd/system/noisefence-processing.slice':'[Slice]\nMemoryAccounting=yes\nCPUAccounting=yes\nTasksAccounting=yes\nTasksMax=512\n'+('MemoryHigh=3000M\nMemoryMax=3300M\nMemorySwapMax=1G\nCPUQuota=180%\n' if small else 'MemoryHigh=6G\nMemoryMax=6800M\nMemorySwapMax=1G\nCPUQuota=380%\n'),
    }
    return values


def save(state):atomic(STATE/(state['id']+'.json'),(json.dumps(state,indent=2)+'\n').encode(),0o600)


def read(ident):
    if not re.fullmatch(r'[a-f0-9]{32}',ident or ''):raise ValueError('Invalid transaction')
    return json.loads((STATE/(ident+'.json')).read_text())


def apply(seconds):
    if not 300<=seconds<=1800:raise ValueError('Deadline must be 300..1800 seconds')
    if any(json.loads(p.read_text()).get('status')=='pending' for p in STATE.glob('*.json')):raise ValueError('Pending isolation transaction')
    small=int(Path('/proc/meminfo').read_text().split('MemTotal:',1)[1].split()[0])<6*1024*1024
    content=files(small,'complain')
    state={'id':uuid.uuid4().hex,'status':'pending','mode':'complain','created':int(time.time()),'deadline':int(time.time())+seconds,'small':small,'files':{}}
    for name in content:
        p=Path(name)
        if p.is_symlink():raise ValueError('Unexpected symlink')
        if p.exists():
            s=p.stat();state['files'][name]={'data':base64.b64encode(p.read_bytes()).decode(),'mode':s.st_mode&0o777,'uid':s.st_uid,'gid':s.st_gid}
        else:state['files'][name]=None
    save(state)
    run('systemd-run','--unit=noisefence-isolation-rollback-'+state['id'],'--on-active='+str(seconds)+'s','--timer-property=AccuracySec=1s','--property=TimeoutStartSec=180',str(SELF),'rollback','--id',state['id'])
    try:
        for name,text in content.items():atomic(name,text.encode())
        run('apparmor_parser','-Q',str(PROFILE))
        run('apparmor_parser','-r',str(PROFILE))
        run('systemctl','daemon-reload')
        # One service at a time, never a simultaneous stop of SMTP and all scanners.
        for service in ['clamav-daemon','noisefence-signature-scanner','noisefence-vision','nginx','noisefence','clamav-freshclam']:
            subprocess.run(['systemctl','restart',service],check=True,timeout=90,capture_output=True,text=True)
        state['applied_hashes']={name:hashlib.sha256(Path(name).read_bytes()).hexdigest() for name in content};save(state)
    except BaseException:
        rollback(state['id']);raise
    return {'id':state['id'],'status':state['status'],'mode':state['mode'],'deadline':state['deadline']}


def rollback(ident):
    state=read(ident)
    if state['status']!='pending':return {'id':ident,'status':state['status']}
    # Remove our profiles before restoring former service definitions.
    if PROFILE.exists():run('apparmor_parser','-R',str(PROFILE),check=False)
    for name,old in state['files'].items():
        if old is None:Path(name).unlink(missing_ok=True)
        else:atomic(name,base64.b64decode(old['data']),old['mode'],old['uid'],old['gid'])
    if PROFILE.exists():run('apparmor_parser','-r',str(PROFILE))
    run('systemctl','daemon-reload')
    failures=[]
    for service in SERVICES+['clamav-freshclam']:
        r=subprocess.run(['systemctl','restart',service],timeout=90,capture_output=True,text=True)
        if r.returncode:failures.append(service)
    state['status']='rollback_needs_attention' if failures else 'rolled_back';state['failed_services']=failures;save(state)
    return {'id':ident,'status':state['status'],'failed_services':failures}


def enforce(ident):
    state=read(ident)
    if state['status']!='pending' or time.time()>state['deadline']-60:raise ValueError('Not pending or deadline too close')
    if state['mode']!='complain':raise ValueError('Already enforced')
    current=PROFILE.read_text()
    if hashlib.sha256(PROFILE.read_bytes()).hexdigest()!=state['applied_hashes'][str(PROFILE)]:raise ValueError('Profile changed outside transaction')
    atomic(PROFILE,current.replace(' flags=(complain)','').encode())
    run('apparmor_parser','-r',str(PROFILE))
    state['mode']='enforce';state['applied_hashes'][str(PROFILE)]=hashlib.sha256(PROFILE.read_bytes()).hexdigest();save(state)
    return {'id':ident,'status':'pending','mode':'enforce'}


def revise(ident):
    """Replace a draft profile only; never weaken an enforced/committed policy."""
    state=read(ident)
    if state['status']!='pending' or state['mode']!='complain' or time.time()>state['deadline']-60:raise ValueError('Only live learning profiles can be revised')
    if hashlib.sha256(PROFILE.read_bytes()).hexdigest()!=state['applied_hashes'][str(PROFILE)]:raise ValueError('Profile changed outside transaction')
    atomic(PROFILE,profiles('complain').encode())
    run('apparmor_parser','-Q',str(PROFILE));run('apparmor_parser','-r',str(PROFILE))
    state['applied_hashes'][str(PROFILE)]=hashlib.sha256(PROFILE.read_bytes()).hexdigest();save(state)
    return {'id':ident,'status':'pending','mode':'complain','revised':True}


def commit(ident):
    state=read(ident)
    if state['status']!='pending' or state['mode']!='enforce' or time.time()>state['deadline']-10:raise ValueError('Only a live enforced transaction can commit')
    for name,digest in state['applied_hashes'].items():
        if hashlib.sha256(Path(name).read_bytes()).hexdigest()!=digest:raise ValueError('File changed: '+name)
    for service in SERVICES:run('systemctl','is-active','--quiet',service)
    state['status']='committed';state['resolved_at']=int(time.time());save(state)
    run('systemctl','stop','noisefence-isolation-rollback-'+ident+'.timer')
    return {'id':ident,'status':'committed','mode':'enforce'}


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('action',choices=['apply','revise','enforce','commit','rollback']);parser.add_argument('--id');parser.add_argument('--timeout',type=int,default=1800);args=parser.parse_args()
    if os.geteuid()!=0:parser.error('root required')
    os.umask(0o077);STATE.mkdir(mode=0o700,parents=True,exist_ok=True)
    with (STATE/'lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        result=apply(args.timeout) if args.action=='apply' else {'revise':revise,'enforce':enforce,'commit':commit,'rollback':rollback}[args.action](args.id)
        print(json.dumps(result))


if __name__=='__main__':main()
