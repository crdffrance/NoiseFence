#!/usr/bin/env python3
"""Record a successful installation outside immutable release assets (no secrets)."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time


def record(base):
    base = Path(base)
    engine = json.loads(subprocess.check_output([str(base / 'noisefence'), 'build-identity'], timeout=10))
    console = json.loads((base / 'web/version.json').read_text())
    if console['schema'] != 'noisefence-console-1' or not all(
        re.fullmatch(r'[0-9a-f]{64}', value) for value in [engine['engine_build'], console['source_sha256']]
    ):
        raise ValueError('Installed engine and console identity mismatch')
    receipt = dict(schema='noisefence-deployment-1', deployed_at=int(time.time()),
                   engine_version=engine['version'], engine_build=engine['engine_build'],
                   console_source_sha256=console['source_sha256'])
    fd, temporary = tempfile.mkstemp(prefix='.deployment-', dir=base)
    try:
        with os.fdopen(fd, 'w') as output:
            os.fchmod(output.fileno(), 0o644)
            json.dump(receipt, output, sort_keys=True)
            output.write('\n')
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, base / 'deployment.json')
        directory = os.open(base, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


if __name__ == '__main__':
    record(sys.argv[1])
