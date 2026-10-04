#!/usr/bin/env python3
"""Validate both release archives, then publish; never replace published assets."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile
import tempfile

from version import SEMVER, cargo_version

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
        with tarfile.open(archive, 'r:gz') as tar:
            files = {}
            for member in tar.getmembers():
                path = PurePosixPath(member.name)
                if path.is_absolute() or '..' in path.parts or path.parts[0] != name:
                    raise ValueError('Unsafe archive path')
                if member.isdir():
                    continue
                if not member.isfile() or member.name in files:
                    raise ValueError('Non-regular or duplicate archive entry')
                files[member.name] = member
            def read(relative):
                return tar.extractfile(files[f'{name}/{relative}']).read()
            metadata = json.loads(read('build.json'))
            if (metadata['version'], metadata['platform'], metadata['commit']) != (tag[1:], platform, commit):
                raise ValueError(f'Archive provenance mismatch: {platform}')
            elf = read('noisefence')[:20]
            if elf[:4] != b'\x7fELF' or int.from_bytes(elf[18:20], 'little') != machine:
                raise ValueError('Binary architecture mismatch')
            if not read('web/index.html'):
                raise ValueError('Missing console')
            declared = {}
            for line in read('SHA256SUMS').decode().splitlines():
                sha, path = line.split('  ', 1)
                if path in declared:
                    raise ValueError('Duplicate checksum entry')
                declared[path] = sha
            expected = {p.removeprefix(name + '/') for p in files} - {'SHA256SUMS'}
            if set(declared) != expected:
                raise ValueError('Incomplete archive checksums')
            for path, sha in declared.items():
                with tar.extractfile(files[f'{name}/{path}']) as stream:
                    if stream_digest(stream) != sha:
                        raise ValueError(f'Internal checksum mismatch: {path}')
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
    args = parser.parse_args()
    if args.tag != 'v' + cargo_version():
        parser.error('Tag must match the product version')
    repo = os.environ['GH_REPO']
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repo):
        parser.error('Invalid repository')
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    assets = validate_assets(args.directory, args.tag, commit)
    publish(args.tag, args.directory, assets, repo)


if __name__ == '__main__':
    main()
