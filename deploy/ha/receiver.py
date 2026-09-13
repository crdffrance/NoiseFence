#!/usr/bin/env python3
"""Forced SSH command with no shell, path argument or arbitrary root operation."""
import os
import sys
if os.environ.get('SSH_ORIGINAL_COMMAND') != 'standby-receive':
    sys.exit('Unsupported standby operation')
os.execv('/usr/bin/sudo',['sudo','-n','--','/usr/bin/python3','/usr/local/libexec/noisefence-ha/standby.py','receive'])
