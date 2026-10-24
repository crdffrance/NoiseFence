#!/usr/bin/env python3
"""Render one uniquely named test policy; never load or replace kernel policy.

Run this source-controlled generator in the isolated fixture image. The owner of
an explicitly disposable Linux test host must load and remove the result.
"""
import argparse
import importlib.util
from pathlib import Path
import re

SOURCE = Path(__file__).resolve().parents[1]
NAME = re.compile(r'noisefence-test-[a-f0-9]{12}')


def render(source, name):
    if not NAME.fullmatch(name):
        raise ValueError('Use a unique disposable profile name')
    marker = 'profile noisefence {\n'
    if source.count(marker) != 1:
        raise ValueError('Expected exactly one enforcing daemon profile')
    header, remaining = source.split(marker)
    body, separator, _ = remaining.partition('\n}\n')
    if not separator or any(line.strip().startswith('profile ') for line in body.splitlines()):
        raise ValueError('Unexpected profile structure')
    if header != '# Managed by NoiseFence. No profile attaches to another product\'s binary.\n#include <tunables/global>\n':
        raise ValueError('Unexpected profile preamble')
    body = body.replace('peer=noisefence,', 'peer='+name+',')
    return header+'profile '+name+' {\n'+body+'\n}\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--name', required=True)
    args = parser.parse_args()
    if not NAME.fullmatch(args.name):
        parser.error('Use noisefence-test- followed by 12 lowercase hex digits')
    spec = importlib.util.spec_from_file_location('fixture_isolation', SOURCE/'deploy/hardening/isolation.py')
    isolation = importlib.util.module_from_spec(spec); spec.loader.exec_module(isolation)
    print(render(isolation.profiles('enforce'), args.name), end='')


if __name__ == '__main__':main()
