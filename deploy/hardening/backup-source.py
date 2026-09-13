#!/usr/bin/env python3
"""Forced SSH command: normalized report or a fixed read-only snapshot export."""
import os
import subprocess
import sys
BASE='/usr/local/libexec/noisefence-hardening/'
ALLOWED={
    'report':['/usr/bin/cat','/var/lib/noisefence-hardening/monitor.json'],
    'snapshot-metadata':[BASE+'snapshot.py','--mode','metadata'],
    'snapshot-full':[BASE+'snapshot.py','--mode','full'],
}
command=os.environ.get('SSH_ORIGINAL_COMMAND','')
if command not in ALLOWED:
    print('Unsupported backup operation',file=sys.stderr);sys.exit(64)
os.execv('/usr/bin/sudo',['sudo','-n','--',*ALLOWED[command]])
