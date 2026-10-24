"""NoiseFence artifact versions: bounded SemVer core plus optional prerelease.

Build metadata is deliberately excluded from published artifact identities.
Version precedence orders a rehearsal; it never establishes data compatibility.
"""
import re

NUMBER = r'(?:0|[1-9][0-9]*)'
IDENTIFIER = r'(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)'
VERSION = rf'{NUMBER}\.{NUMBER}\.{NUMBER}(?:-{IDENTIFIER}(?:\.{IDENTIFIER})*)?'
MAX_LENGTH = 64


def valid(value):
    return isinstance(value, str) and 0 < len(value) <= MAX_LENGTH and re.fullmatch(VERSION, value) is not None


def precedence(value):
    """Comparable key; numeric prerelease components precede lexical components."""
    if not valid(value):
        raise ValueError('Invalid NoiseFence release version')
    core, separator, prerelease = value.partition('-')
    parts = tuple((0, int(item)) if item.isdigit() else (1, item) for item in prerelease.split('.')) if separator else ()
    return tuple(map(int, core.split('.'))), not separator, parts
