#!/usr/bin/env python3
"""Install bounded local auditing and reports without a remote alert channel."""
import os
from pathlib import Path
import re
import subprocess
from network import atomic,run

def install():
    if os.geteuid()!=0:raise PermissionError('root required')
    own=Path('/etc/audit/rules.d/70-noisefence.rules')
    rules='''# Targeted file change auditing. No broad exec/argv capture, no immutable policy.
'''+''.join('-w '+p+' -p wa -k noisefence_'+kind+'\n' for p,kind in [('/etc/noisefence','config'),('/etc/ssh','ssh'),('/etc/sudoers.d','sudo'),('/opt/noisefence','binary'),('/home/debian/.ssh','keys')] if Path(p).exists())
    previous=own.read_text() if own.exists() else ''
    if previous!=rules:
        if previous:
            temporary=Path('/run/noisefence-audit-remove.rules');atomic(temporary,previous.replace('-w ','-W ').encode(),0o600)
            run('auditctl','-R',str(temporary),check=False);temporary.unlink()
        atomic(own,rules.encode(),0o600);run('auditctl','-R',str(own))
    cfg=Path('/etc/audit/auditd.conf');content=cfg.read_text()
    for key,value in [('max_log_file','32'),('num_logs','5'),('max_log_file_action','ROTATE'),('space_left_action','SYSLOG'),('admin_space_left_action','SYSLOG'),('disk_full_action','SYSLOG'),('disk_error_action','SYSLOG')]:
        content=re.sub(r'(?m)^\s*'+key+r'\s*=.*$',key+' = '+value,content)
    atomic(cfg,content.encode(),0o640);run('service','auditd','restart')
    service='''[Unit]
Description=NoiseFence content-free security report
After=noisefence.service
[Service]
Type=oneshot
ExecStart=/usr/local/libexec/noisefence-hardening/monitor.py
UMask=0077
TimeoutStartSec=60
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=yes
ReadWritePaths=/var/lib/noisefence-hardening
PrivateNetwork=yes
MemoryMax=128M
CPUQuota=25%
LimitCORE=0
'''
    timer='''[Unit]
Description=Refresh local NoiseFence security report
[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
RandomizedDelaySec=20s
[Install]
WantedBy=timers.target
'''
    atomic('/etc/systemd/system/noisefence-security-report.service',service.encode())
    atomic('/etc/systemd/system/noisefence-security-report.timer',timer.encode())
    run('systemctl','daemon-reload');run('systemctl','enable','--now','noisefence-security-report.timer');run('systemctl','start','noisefence-security-report.service')
    print('Targeted audit rules and local security reports installed')

if __name__=='__main__':install()
