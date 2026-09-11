#!/usr/bin/env python3
"""Check local-address discovery under the shipped SMTP service confinement."""
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
PROBE = '''import ctypes,errno,json,socket
lib=ctypes.CDLL(None,use_errno=True)
head=ctypes.c_void_p()
rc=lib.getifaddrs(ctypes.byref(head))
error=ctypes.get_errno() if rc else 0
if rc==0: lib.freeifaddrs(head)
blocked=False
try: socket.socket(socket.AF_PACKET,socket.SOCK_RAW)
except OSError: blocked=True
print(json.dumps(dict(result=rc,errno=error,packet_blocked=blocked)))
'''


def main():
    if os.geteuid() != 0:
        raise SystemExit('Run as root on a systemd Linux host')
    properties = []
    for line in (ROOT/'deploy/noisefence.service').read_text().splitlines():
        key = line.split('=', 1)[0]
        if key in {'RestrictAddressFamilies', 'NoNewPrivileges', 'ProtectSystem',
                   'ProtectHome', 'PrivateTmp', 'ProtectKernelTunables',
                   'ProtectKernelModules', 'ProtectControlGroups',
                   'RestrictSUIDSGID', 'LockPersonality', 'MemoryDenyWriteExecute',
                   'CapabilityBoundingSet', 'AmbientCapabilities'}:
            properties.extend(['--property', line])
    result = subprocess.run(['systemd-run', '--quiet', '--wait', '--pipe', '--collect',
                             '--property=DynamicUser=yes', *properties,
                             '/usr/bin/python3', '-c', PROBE],
                            check=True, text=True, capture_output=True, timeout=20)
    data = json.loads(result.stdout)
    assert data['result'] == 0, data
    assert data['packet_blocked'], data
    print(json.dumps({'local_inventory': 'ok', 'raw_packet_socket': 'blocked'}))


if __name__ == '__main__':
    main()
