#!/usr/bin/env python3
"""Collect third-party notices from the exact dependency sources used in a build."""
import json
import shutil
import subprocess
from pathlib import Path

ROOT=Path(__file__).resolve().parent.parent
OUT=ROOT/'release/third-party-licenses'

def collect(kind,name,version,license_name,directory):
    destination=OUT/kind/(name.replace('/','_')+'-'+version)
    notices=[]
    for p in sorted(directory.iterdir()):
        if p.is_file() and p.name.lower().startswith(('license','licence','copying','copyright','notice')):
            destination.mkdir(parents=True,exist_ok=True)
            shutil.copy2(p,destination/p.name)
            notices.append(str((destination/p.name).relative_to(OUT)))
    return {'name':name,'version':version,'license':license_name,'notices':notices}

def main():
    OUT.mkdir(parents=True,exist_ok=True)
    metadata=json.loads(subprocess.check_output(['cargo','metadata','--locked','--all-features','--format-version','1'],cwd=ROOT))
    manifest=[]
    for package in metadata['packages']:
        if package['source']:
            manifest.append(collect('rust',package['name'],package['version'],package['license'],Path(package['manifest_path']).parent))
    lock=json.loads((ROOT/'web/package-lock.json').read_text())
    for relative,package in lock['packages'].items():
        if not relative: continue
        directory=ROOT/'web'/relative
        if not directory.is_dir(): continue
        name=relative.rsplit('node_modules/',1)[-1]
        manifest.append(collect('npm',name,package['version'],package.get('license'),directory))
    (OUT/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(f'{len(manifest)} dependency notices indexed')

if __name__=='__main__': main()
