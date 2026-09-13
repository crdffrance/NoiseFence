#!/usr/bin/env python3
"""Forced command for the dedicated deployment SSH key."""
import os,re,shlex,sys
try:args=shlex.split(os.environ.get('SSH_ORIGINAL_COMMAND',''))
except ValueError:args=[]
valid=args in [['status'],['check'],['restart']] or (len(args)==2 and args[0]=='activate' and re.fullmatch(r'\d+\.\d+\.\d+(?:-[a-zA-Z0-9.-]+)?',args[1]))
if not valid:
    print('Allowed: status, check, restart, activate VERSION',file=sys.stderr);sys.exit(64)
os.execv('/usr/bin/sudo',['sudo','-n','--','/usr/local/libexec/noisefence-hardening/deploy-control.py',*args])
