#!/usr/bin/env python3
"""Extract the exact release section; never publish the entire changelog."""
import argparse
import re
from pathlib import Path

from version import ROOT, SEMVER, cargo_version


def notes_for(changelog, version):
    heading = re.compile(r'^## (?:\[' + re.escape(version) + r'\]|'
                         + re.escape(version) + r')(?=\s|$)[^\n]*$', re.M)
    matches = list(heading.finditer(changelog))
    if len(matches) != 1:
        raise ValueError(f'Expected exactly one changelog section for {version}')
    body = changelog[matches[0].end():]
    body = re.split(r'^## ', body, maxsplit=1, flags=re.M)[0].strip()
    if not body:
        raise ValueError(f'Empty changelog section for {version}')
    return body + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tag', required=True)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if not re.fullmatch('v' + SEMVER, args.tag) or args.tag != 'v' + cargo_version():
        parser.error('Tag must match the product version')
    try:
        notes = notes_for((ROOT / 'CHANGELOG.md').read_text(), args.tag[1:])
    except ValueError as error:
        parser.error(str(error))
    args.output.write_text(notes)


if __name__ == '__main__':
    main()
