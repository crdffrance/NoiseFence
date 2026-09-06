#!/usr/bin/env python3
"""Keep NoiseFence manifests aligned with Cargo.toml; validate release tags."""
import argparse
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SEMVER = r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?'

def cargo_version():
    return re.search(r'^version = "([^"]+)"', (ROOT/'Cargo.toml').read_text(), re.M)[1]

def lock_version(path):
    return re.search(r'\[\[package\]\]\nname = "noisefence"\nversion = "([^"]+)"', path.read_text())[1]

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--set', dest='version')
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--tag')
    args = parser.parse_args()
    if args.version:
        if not re.fullmatch(SEMVER, args.version):
            parser.error('Use a semantic version, e.g. 0.1.1 or 0.2.0-rc.1')
        p = ROOT/'Cargo.toml'
        p.write_text(re.sub(r'^version = "[^"]+"', f'version = "{args.version}"', p.read_text(), count=1, flags=re.M))
        for name in ['Cargo.lock','fuzz/Cargo.lock']:
            p=ROOT/name
            s,n=re.subn(r'(\[\[package\]\]\nname = "noisefence"\nversion = ")[^"]+', lambda m:m[1]+args.version, p.read_text())
            if n!=1: raise SystemExit(f'Missing NoiseFence entry in {name}; refresh its lock first')
            p.write_text(s)
        for name in ['web/package.json','web/package-lock.json']:
            p=ROOT/name; data=json.loads(p.read_text()); data['version']=args.version
            if 'packages' in data: data['packages']['']['version']=args.version
            p.write_text(json.dumps(data,indent=2)+'\n')
    version=cargo_version()
    if not re.fullmatch(SEMVER,version): raise SystemExit('Invalid Cargo version')
    values={p:lock_version(ROOT/p) for p in ['Cargo.lock','fuzz/Cargo.lock']}
    for name in ['web/package.json','web/package-lock.json']:
        data=json.loads((ROOT/name).read_text()); values[name]=data['version']
        if 'packages' in data: values[name+' root']=data['packages']['']['version']
    for name,value in values.items():
        if value!=version: raise SystemExit(f'{name}: {value} differs from Cargo.toml {version}')
    if args.tag and args.tag!='v'+version: raise SystemExit('Tag does not match the release version')
    if args.check: print(f'NoiseFence v{version}: manifests aligned')
    else: print(version)

if __name__=='__main__': main()
