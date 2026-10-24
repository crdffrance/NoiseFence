#!/usr/bin/env python3
"""Authenticate and stage a native release without executing or activating it."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import sys
import tempfile
import time

import release_bundle as bundle
import upgrade_reservation as reservation
from migration_protocol import atomic, canonical, require, sha

GH = Path('/usr/bin/gh')
RELEASES = Path('/opt/noisefence/releases')
PROTOCOL = 'noisefence-staged-release-1'


def stage(archive, version, commit, expected_sha256):
    require(platform.system() == 'Linux', 'Native release staging requires Linux')
    host = {'x86_64': 'linux-amd64', 'aarch64': 'linux-arm64'}.get(platform.machine())
    bundle.identity(version, host, commit)
    require(sha(expected_sha256), 'Expected SHA-256 is required')
    require(not reservation.exists(reservation.ACTIVE), 'Finish the owning upgrade before staging another release')
    reservation.protected(RELEASES, True)
    reservation.protected(GH)
    require(os.access(GH, os.X_OK), 'Install a trusted GitHub CLI at /usr/bin/gh')
    archive = Path(archive)
    reservation.protected(archive)
    # Reserve enough headroom before copying into the release filesystem.
    require(shutil.disk_usage(RELEASES).free >= bundle.MAX_ARCHIVE + bundle.MAX_EXPANDED + 256*1024**2,
            'Insufficient release-filesystem headroom')
    destination = RELEASES/version
    with tempfile.TemporaryDirectory(prefix='.noisefence-staging-', dir=RELEASES) as temporary:
        temporary = Path(temporary)
        snapshot = temporary/'archive.tar.gz'
        with reservation.private_read(archive, bundle.MAX_ARCHIVE) as source, snapshot.open('xb') as output:
            checksum = hashlib.sha256(); size = 0
            for block in iter(lambda: source.read(bundle.CHUNK), b''):
                size += len(block); require(size <= bundle.MAX_ARCHIVE, 'Archive grew beyond its limit')
                checksum.update(block); output.write(block)
            output.flush(); os.fsync(output.fileno())
        require(checksum.hexdigest() == expected_sha256, 'Transferred archive checksum mismatch')
        config = temporary/'gh'; config.mkdir(mode=0o700)
        environment = {'PATH': '/usr/bin:/bin', 'GH_HOST': 'github.com',
                       'GH_CONFIG_DIR': str(config), 'GH_PROMPT_DISABLED': '1'}
        if os.environ.get('GH_TOKEN'): environment['GH_TOKEN'] = os.environ['GH_TOKEN']
        verification = bundle.verify_provenance(snapshot, version, commit, executable=str(GH), env=environment)
        tree = temporary/'release'
        inspected = bundle.inspect_archive(snapshot, version, host, commit, destination=tree)
        if reservation.exists(destination):
            files, _ = reservation.release_inventory(destination)
            require({**files, 'SHA256SUMS': bundle.digest(destination/'SHA256SUMS')} == inspected['files'],
                    'A different or partial build already occupies this version')
        else:
            directories = [p for p in tree.rglob('*') if p.is_dir()]
            for directory in sorted(directories, key=lambda p: len(p.parts), reverse=True):
                directory.chmod(0o755); reservation.sync_directory(directory)
            tree.chmod(0o755); reservation.sync_directory(tree)
            # The host lock and root-only parent exclude supported concurrent writers.
            require(not reservation.exists(destination), 'Release destination appeared during staging')
            tree.rename(destination)
        reservation.sync_directory(RELEASES)
        receipt = {'protocol': PROTOCOL, 'version': version, 'commit': commit, 'platform': host,
                   'directory': str(destination), 'archive_sha256': expected_sha256,
                   'manifest_sha256': inspected['files']['SHA256SUMS'],
                   'binary_sha256': inspected['files']['noisefence'],
                   'build_sha256': inspected['files']['build.json'],
                   'provenance': verification, 'verified_at': int(time.time())}
        reservation.STATE.mkdir(mode=0o700, exist_ok=True); reservation.protected(reservation.STATE, True)
        atomic(reservation.STATE/('release-'+expected_sha256+'.json'), canonical(receipt))
        return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--version', required=True)
    parser.add_argument('--commit', required=True)
    parser.add_argument('--sha256', required=True)
    args = parser.parse_args()
    require(os.geteuid() == 0, 'Root is required'); os.umask(0o077)
    with reservation.operation_lock():
        print(json.dumps(stage(args.archive, args.version, args.commit, args.sha256)))


if __name__ == '__main__':
    try: main()
    except Exception as error:
        print('Release staging stopped: '+type(error).__name__+': '+str(error)[:300], file=sys.stderr)
        sys.exit(1)
