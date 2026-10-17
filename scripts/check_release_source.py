#!/usr/bin/env python3
"""Require a version tag at the run commit, already merged into the default branch."""
import argparse
from pathlib import Path
import re
import subprocess

from version import SEMVER


def git(root, *args):
    result = subprocess.run(['git', *args], cwd=root, text=True, capture_output=True)
    if result.returncode:
        raise ValueError('Release source verification failed: git ' + args[0])
    return result.stdout.strip()


def verify(root, tag, default_branch, commit):
    if not re.fullmatch('v' + SEMVER, tag):
        raise ValueError('Release source requires a semantic version tag')
    if not re.fullmatch(r'[0-9a-f]{40}', commit):
        raise ValueError('Release source requires the full workflow commit SHA')
    git(root, 'check-ref-format', 'refs/heads/' + default_branch)
    if git(root, 'rev-parse', '--is-shallow-repository') != 'false':
        raise ValueError('Fetch complete history before checking release ancestry')
    head = git(root, 'rev-parse', '--verify', 'HEAD^{commit}')
    tagged = git(root, 'rev-parse', '--verify', 'refs/tags/' + tag + '^{commit}')
    if head != commit or tagged != commit:
        raise ValueError('Workflow commit, checkout and version tag must match')
    reviewed = git(root, 'rev-parse', '--verify',
                   'refs/remotes/origin/' + default_branch + '^{commit}')
    git(root, 'merge-base', '--is-ancestor', commit, reviewed)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tag', required=True)
    parser.add_argument('--default-branch', required=True)
    parser.add_argument('--commit', required=True)
    args = parser.parse_args()
    try:
        verify(Path.cwd(), args.tag, args.default_branch, args.commit)
    except ValueError as error:
        parser.exit(1, str(error) + '\n')
    print('Release source matches the run and is merged into the default branch')


if __name__ == '__main__':
    main()
