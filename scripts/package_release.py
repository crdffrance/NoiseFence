#!/usr/bin/env python3
"""Package a verified Linux binary and the static console, without local secrets."""
import argparse
import hashlib
import json
import shutil
import subprocess
import tarfile
from pathlib import Path
from version import cargo_version

ROOT = Path(__file__).resolve().parent.parent

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary',type=Path,required=True)
    parser.add_argument('--platform',choices=['linux-amd64','linux-arm64'],required=True)
    args=parser.parse_args()
    version=cargo_version()
    name=f'noisefence-{version}-{args.platform}'
    output=ROOT/'release'/name
    if output.exists(): raise SystemExit(f'{output} already exists')
    if not args.binary.is_file() or not (ROOT/'web/dist/client/index.html').is_file():
        raise SystemExit('Build the binary and static console first')
    elf=args.binary.read_bytes()[:20]
    machine=62 if args.platform=='linux-amd64' else 183
    if elf[:4]!=b'\x7fELF' or int.from_bytes(elf[18:20],'little')!=machine:
        raise SystemExit('Binary architecture does not match the requested platform')
    output.mkdir(parents=True)
    shutil.copy2(args.binary,output/'noisefence')
    shutil.copytree(ROOT/'web/dist/client',output/'web')
    (output/'config').mkdir()
    for filename in ['development.toml','production.example.toml']:
        shutil.copy2(ROOT/'config'/filename,output/'config'/filename)
    for directory in ['deploy','docs']:
        shutil.copytree(ROOT/directory,output/directory)
    for filename in ['README.md','LICENSE','THIRD_PARTY.md','CHANGELOG.md','Cargo.lock']:
        shutil.copy2(ROOT/filename,output/filename)
    shutil.copytree(ROOT/'licenses',output/'licenses')
    if (ROOT/'release/third-party-licenses').is_dir():
        shutil.copytree(ROOT/'release/third-party-licenses',output/'third-party-licenses')
    source=hashlib.sha256()
    for p in [ROOT/'Cargo.toml', ROOT/'Cargo.lock', *sorted((ROOT/'src').glob('*.rs'))]:
        source.update(p.name.encode()); source.update(p.read_bytes())
    commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
    (output/'build.json').write_text(json.dumps({
        'project':'NoiseFence','platform':args.platform,'version':version,
        'rust':'1.98.0','minimum_glibc':'2.36','commit':commit,
        'source_sha256':source.hexdigest(),
        'source_url':f'https://github.com/crdffrance/NoiseFence/tree/{commit}',
        'image':'rust@sha256:82150a52ec202c1b14d7817e14516c392bb7f5cfebd88f1ed531cb37ebd39922',
        'license':'GPL-3.0-only','default_mode':'observe','proton_validated':False,
    },indent=2)+'\n')
    checksums={str(p.relative_to(output)):hashlib.sha256(p.read_bytes()).hexdigest()
               for p in sorted(output.rglob('*')) if p.is_file()}
    (output/'SHA256SUMS').write_text(''.join(f'{sha}  {path}\n' for path,sha in checksums.items()))
    archive=Path(str(output)+'.tar.gz')
    with tarfile.open(archive,'w:gz') as tar: tar.add(output,arcname=name)
    digest=hashlib.sha256(archive.read_bytes()).hexdigest()
    Path(str(archive)+'.sha256').write_text(f'{digest}  {archive.name}\n')
    print(archive)

if __name__=='__main__': main()
