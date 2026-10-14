#!/usr/bin/env python3
"""Bind a probe artifact to a clean checkout, including every tracked source file."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess


SCHEMA = 'noisefence-probe-build-2'
SOURCE_SCHEMA = 'noisefence-tracked-source-1'


def git(root, *arguments):
    return subprocess.check_output(['git', '-C', str(root), *arguments])


def require_clean(root):
    if git(root, 'status', '--porcelain', '--untracked-files=all').strip():
        raise ValueError('Probe provenance requires a clean tracked and untracked checkout')


def source_manifest(root):
    require_clean(root)
    entries = []
    for row in git(root, 'ls-files', '--stage', '-z').split(b'\0'):
        if not row:
            continue
        metadata, relative = row.split(b'\t', 1)
        mode, _, stage = metadata.decode('ascii').split()
        if mode not in ('100644', '100755') or stage != '0':
            raise ValueError('Source manifest refuses symlinks, submodules and merge conflicts')
        name = relative.decode('utf-8')
        path = root / name
        if path.is_symlink() or not path.is_file():
            raise ValueError('Source manifest requires regular tracked files')
        entries.append({'path': name, 'mode': mode,
                        'sha256': hashlib.sha256(path.read_bytes()).hexdigest()})
    entries.sort(key=lambda row: row['path'])
    if not entries:
        raise ValueError('Source manifest cannot be empty')
    require_clean(root)
    return {'schema': SOURCE_SCHEMA, 'files': entries}


def encode(value):
    return (json.dumps(value, indent=2, ensure_ascii=True) + '\n').encode()


def write(root, output, image):
    root, output = root.resolve(), output.resolve()
    if not re.fullmatch(r'rust@sha256:[0-9a-f]{64}', image):
        raise ValueError('Build image must use an immutable Rust image digest')
    if (output / 'build.json').exists() or (output / 'sources.json').exists():
        raise ValueError('Refusing to replace existing probe provenance')
    binary = output / 'pipeline_probe'
    if binary.is_symlink() or not binary.is_file():
        raise ValueError('Probe executable must be a regular file')
    raw = binary.read_bytes()
    if len(raw) < 64 or raw[:7] != b'\x7fELF\x02\x01\x01' or int.from_bytes(raw[18:20], 'little') != 62:
        raise ValueError('Expected a Linux x86-64 ELF executable')
    commit = git(root, 'rev-parse', 'HEAD').decode().strip()
    sources = encode(source_manifest(root))
    result = {
        'schema': SCHEMA, 'commit': commit,
        'git_tree': git(root, 'rev-parse', 'HEAD^{tree}').decode().strip(),
        'source_manifest': 'sources.json', 'source_schema': SOURCE_SCHEMA,
        'source_manifest_sha256': hashlib.sha256(sources).hexdigest(),
        'source_file_count': len(json.loads(sources)['files']),
        'probe_source_sha256': hashlib.sha256((root / 'examples/pipeline_probe.rs').read_bytes()).hexdigest(),
        'binary_sha256': hashlib.sha256(raw).hexdigest(),
        'platform': 'linux-amd64', 'profile': 'release', 'features': ['semantic'],
        'image': image,
    }
    if git(root, 'rev-parse', 'HEAD').decode().strip() != commit:
        raise ValueError('Checkout changed during provenance capture')
    require_clean(root)
    # build.json is written last: its absence means capture did not complete.
    with (output / 'sources.json').open('xb') as stream:
        stream.write(sources)
    with (output / 'build.json').open('xb') as stream:
        stream.write(encode(result))
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--image', required=True)
    args = parser.parse_args()
    print(json.dumps(write(args.root, args.output, args.image)))
