#!/usr/bin/env python3
"""Validate both release archives, then publish; never replace published assets."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import sys

from version import SEMVER, cargo_version

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/"deploy/postgresql"))
from release_bundle import inspect_archive, verify_provenance
sys.path.pop(0)

PLATFORMS = {'linux-amd64': 62, 'linux-arm64': 183}


def stream_digest(stream):
    result = hashlib.sha256()
    for chunk in iter(lambda: stream.read(1024 * 1024), b''):
        result.update(chunk)
    return result.hexdigest()


def digest(path):
    with path.open('rb') as stream:
        return stream_digest(stream)


def validate_assets(directory, tag, commit):
    if not re.fullmatch('v' + SEMVER, tag):
        raise ValueError('Invalid release tag')
    assets = []
    for platform, machine in PLATFORMS.items():
        name = f'noisefence-{tag[1:]}-{platform}'
        archive = directory / (name + '.tar.gz')
        checksum = directory / (archive.name + '.sha256')
        if checksum.read_text().strip() != f'{digest(archive)}  {archive.name}':
            raise ValueError(f'Archive checksum mismatch: {platform}')
        inspected = inspect_archive(archive, tag[1:], platform, commit)
        if inspected['rehearsal_only']:
            raise ValueError('Host-built rehearsal archives cannot be published')
        assets.extend([archive, checksum])
    return assets


def gh(*args):
    return subprocess.check_output(['gh', *args], text=True)


def publish(tag, directory, assets, repo):
    releases = json.loads(gh('release', 'list', '--repo', repo, '--limit', '1000',
                            '--json', 'tagName,isDraft'))
    existing = next((r for r in releases if r['tagName'] == tag), None)
    if existing and not existing['isDraft']:
        verify_download(tag, assets, repo)
        print(f'{tag} already published with identical assets; left unchanged')
        return
    if not existing:
        gh('release', 'create', tag, '--repo', repo, '--verify-tag', '--draft',
           '--title', f'NoiseFence {tag}', '--notes-file', str(directory / 'NOTES.md'))
    gh('release', 'upload', tag, '--repo', repo, '--clobber', *map(str, assets))
    verify_download(tag, assets, repo)
    prerelease = '-' in tag
    gh('release', 'edit', tag, '--repo', repo, '--draft=false',
       f'--prerelease={str(prerelease).lower()}', f'--latest={str(not prerelease).lower()}',
       '--notes-file', str(directory / 'NOTES.md'))
    print(f'Published {tag}: both architectures verified')


def verify_download(tag, assets, repo):
    with tempfile.TemporaryDirectory() as temp:
        for asset in assets:
            gh('release', 'download', tag, '--repo', repo, '--pattern', asset.name, '--dir', temp)
            if digest(Path(temp) / asset.name) != digest(asset):
                raise ValueError('Uploaded asset differs; refusing publication or replacement')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tag', required=True)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--verify-only', action='store_true', help='Validate archive contents without publication or attestation lookup')
    args = parser.parse_args()
    if args.tag != 'v' + cargo_version():
        parser.error('Tag must match the product version')
    repo = os.environ['GH_REPO']
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repo):
        parser.error('Invalid repository')
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    assets = validate_assets(args.directory, args.tag, commit)
    if args.verify_only:
        print('Both release archives validated; nothing published')
        return
    for asset in assets:
        if asset.name.endswith('.tar.gz'):
            verify_provenance(asset, args.tag[1:], commit)
    publish(args.tag, args.directory, assets, repo)


if __name__ == '__main__':
    main()
