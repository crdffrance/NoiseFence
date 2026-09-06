#!/usr/bin/env python3
"""Download pinned third-party sources and check every digest before publishing them.

This command does not execute the updater, install packages or start a service.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parent


def fetch(destination, download=None):
    manifest = json.loads((ROOT / 'unofficial-sigs.sources.json').read_text())
    if destination.exists():
        raise ValueError('Destination already exists; verify or choose a new directory')
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix='.unofficial-', dir=destination.parent))
    try:
        entries = [(name, digest, 'https://raw.githubusercontent.com/extremeshok/clamav-unofficial-sigs/'
                    + manifest['commit'] + '/' + name) for name, digest in manifest['files'].items()]
        key = manifest['sanesecurity_key']
        entries.append(('sanesecurity-publickey.gpg', key['sha256'], key['url']))
        for name, digest, url in entries:
            if download:
                content = download(url)
            else:
                with urllib.request.urlopen(url, timeout=30) as response:
                    if not response.geturl().startswith('https://'):
                        raise ValueError('Unexpected source redirect')
                    content = response.read(2_000_001)
            if len(content) > 2_000_000 or hashlib.sha256(content).hexdigest() != digest:
                raise ValueError('Source digest mismatch: ' + name)
            path = temporary / name
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open('xb') as output:
                output.write(content)
                output.flush()
                os.fsync(output.fileno())
        shutil.copy2(ROOT / 'unofficial-sigs.sources.json', temporary / 'sources.json')
        temporary.rename(destination)
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('destination', type=Path)
    args = parser.parse_args()
    fetch(args.destination)
    print('Sources downloaded and verified; nothing installed or executed.')


if __name__ == '__main__':
    main()
