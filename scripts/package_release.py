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


def archive_metadata(member):
    """Public release permissions must not inherit the builder's private umask."""
    if not (member.isdir() or member.isfile()):
        raise ValueError('Release archives may only contain directories and regular files')
    member.mode = 0o755 if member.isdir() or member.mode & 0o111 else 0o644
    member.uid = member.gid = 0
    member.uname = member.gname = 'root'
    return member


def write_archive(directory, archive):
    with tarfile.open(archive, 'w:gz') as output:
        output.add(directory, arcname=directory.name, filter=archive_metadata)


def build_environment(rehearsal_only):
    if rehearsal_only:
        return {'rehearsal_only': True, 'image': None, 'minimum_glibc': None}
    return {'rehearsal_only': False, 'minimum_glibc': '2.36',
            'image': 'rust@sha256:82150a52ec202c1b14d7817e14516c392bb7f5cfebd88f1ed531cb37ebd39922'}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary',type=Path,required=True)
    parser.add_argument('--platform',choices=['linux-amd64','linux-arm64'],required=True)
    parser.add_argument('--rehearsal-only', action='store_true', help='Host-built CI fixture; forbidden from release publication, no Bookworm compatibility claim')
    args=parser.parse_args()
    if subprocess.check_output(['git','status','--porcelain'],cwd=ROOT).strip():
        raise SystemExit('Commit all release sources before packaging; build.json must identify their exact commit')
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
    for filename in ['development.toml','production.example.toml','cluster-coordinator.example.toml','cluster-worker.example.toml','replication.example.toml','docker.example.toml','rspamd.example.toml']:
        shutil.copy2(ROOT/'config'/filename,output/'config'/filename)
    for directory in ['deploy','docs']:
        shutil.copytree(ROOT/directory,output/directory,ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
    (output/'scripts').mkdir()
    shutil.copy2(ROOT/'scripts/smtp_load.py',output/'scripts/smtp_load.py')
    # Data-only feedback fitting runtime, without corpora, private models or hub clients.
    (output/'research').mkdir()
    for filename in ['train_feedback.py','train_linear.py','adapt_feedback.py','calibrate_evidence.py','semantic-protocol.json','requirements.txt',
                     'train_fusion.py','evaluate_population.py','fusion-protocol.json','fusion.md','labeling-protocol.md',
                     'train_quality.py','quality-protocol.json','quality_metrics.py',
                     'quality_runtime.py','evaluate_quality.py','compare_quality.py','score_tradeoffs.py','run_quality.py',
                     'recorded_decisions.py','quality_exposure.py']:
        shutil.copy2(ROOT/'research'/filename,output/'research'/filename)
    # Public research documentation linked from README; use only tracked files.
    research_docs = subprocess.check_output(
        ['git', 'ls-files', '-z', 'research/*.md', 'research/*.json'], cwd=ROOT
    ).decode().split('\0')
    for filename in filter(None, research_docs):
        destination = output/filename
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT/filename, destination)
    for filename in ['README.md','LICENSE','THIRD_PARTY.md','CHANGELOG.md','SECURITY.md','CONTRIBUTING.md','Cargo.lock']:
        shutil.copy2(ROOT/filename,output/filename)
    shutil.copytree(ROOT/'licenses',output/'licenses')
    if (ROOT/'release/third-party-licenses').is_dir():
        shutil.copytree(ROOT/'release/third-party-licenses',output/'third-party-licenses')
    source=hashlib.sha256()
    inputs = [ROOT/'Cargo.toml', ROOT/'Cargo.lock', ROOT/'build.rs', ROOT/'build_support.rs', *sorted((ROOT/'src').rglob('*.sql')), *sorted((ROOT/'src').rglob('*.rs')),
              ROOT/'research/fusion-protocol.json', ROOT/'research/quality-protocol.json', ROOT/'research/semantic-protocol.json', ROOT/'research/encoder-runtime.lock.json',
              ROOT/'deploy/vision-worker.py', ROOT/'deploy/update-url-feed.py']
    for p in sorted(inputs):
        source.update(str(p.relative_to(ROOT)).encode() + b'\0')
        source.update(hashlib.sha256(p.read_bytes()).digest())
    commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
    (output/'build.json').write_text(json.dumps({
        'project':'NoiseFence','platform':args.platform,'version':version,
        'rust':'1.98.0','commit':commit,
        **build_environment(args.rehearsal_only),
        'storage_schema':7,
        'source_sha256':source.hexdigest(),
        'source_digest_schema':'noisefence-build-inputs-2',
        'source_inputs':[str(p.relative_to(ROOT)) for p in sorted(inputs)],
        'source_url':f'https://github.com/crdffrance/NoiseFence/tree/{commit}',
        'license':'GPL-3.0-only','default_mode':'observe','proton_validated':False,
    },indent=2)+'\n')
    checksums={str(p.relative_to(output)):hashlib.sha256(p.read_bytes()).hexdigest()
               for p in sorted(output.rglob('*')) if p.is_file()}
    (output/'SHA256SUMS').write_text(''.join(f'{sha}  {path}\n' for path,sha in checksums.items()))
    archive=Path(str(output)+'.tar.gz')
    write_archive(output, archive)
    digest=hashlib.sha256(archive.read_bytes()).hexdigest()
    Path(str(archive)+'.sha256').write_text(f'{digest}  {archive.name}\n')
    print(archive)

if __name__=='__main__': main()
