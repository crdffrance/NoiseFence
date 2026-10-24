"""Synthetic-only native candidate staging and operational assertions."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import urllib.error
import urllib.request
import paired_node as node


def stage(version):
    source=Path('/root/validation-candidate')
    metadata=json.loads((source/'candidate.json').read_text())
    node.require(node.digest(source/'noisefence')==metadata['binary_sha256'] and metadata['version']==version,
                 'Candidate metadata differs')
    target=node.BASE/'releases/qualification-candidate'
    node.require(not target.exists(),'Candidate already staged')
    shutil.copytree(node.BASE/'releases'/version,target)
    shutil.copyfile(source/'noisefence',target/'noisefence');(target/'noisefence').chmod(0o755)
    build=json.loads((target/'build.json').read_text())
    build.update(commit=metadata['commit'],qualification_candidate=True,profile=metadata['profile'])
    (target/'build.json').write_text(json.dumps(build)+'\n')
    lines=[]
    for path in sorted(target.rglob('*')):
        node.require(not path.is_symlink(),'Candidate fixture cannot contain symlinks')
        os.chown(path,0,0);path.chmod(path.stat().st_mode & 0o755)
        if path.is_file() and path.name!='SHA256SUMS':
            lines.append(node.digest(path)+'  '+str(path.relative_to(target)))
    (target/'SHA256SUMS').write_text('\n'.join(lines)+'\n')
    return {'directory':str(target),'binary_sha256':node.digest(target/'noisefence'),'commit':metadata['commit']}



def archive_identity(version):
    node.require(node.valid_version(version), 'Invalid candidate archive version')
    target=node.BASE/'releases'/version
    node.require(target.is_dir() and not target.is_symlink(), 'Missing exact archive directory')
    subprocess.run(['sha256sum','-c','SHA256SUMS'],cwd=target,
                   stdout=subprocess.DEVNULL,check=True)
    build=json.loads((target/'build.json').read_text())
    node.require(build['version']==version and build['project']=='NoiseFence', 'Candidate archive metadata differs')
    return {'directory':str(target),'binary_sha256':node.digest(target/'noisefence'),
            'build_sha256':node.digest(target/'build.json'),
            'manifest_sha256':node.digest(target/'SHA256SUMS'),'commit':build['commit']}


def database_snapshot():
    tables=json.loads(node.sql("SELECT jsonb_agg(tablename ORDER BY tablename) FROM pg_tables WHERE schemaname='noisefence'",'noisefence_test','noisefence'))
    node.require(all(re.fullmatch('[a-z_]+',name) for name in tables),'Unexpected synthetic table')
    fields=["'"+name+"',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]'::jsonb) FROM noisefence.\""+name+'" r)' for name in tables]
    # jsonb_build_object has a bounded argument count; concatenate small objects.
    chunks=['jsonb_build_object('+','.join(fields[i:i+20])+')' for i in range(0,len(fields),20)]
    result=node.sql('SELECT '+ ' || '.join(chunks),'noisefence_test','noisefence')
    return {'tables':len(tables),'sha256':hashlib.sha256(result.encode()).hexdigest()}


def disabled(name):
    api=18080 if name=='mx1' else 18081
    smtp=2525 if name=='mx1' else 2527
    with socket.socket() as connection:
        connection.settimeout(2)
        node.require(connection.connect_ex(('127.0.0.1',smtp))!=0,'Validation opened SMTP')
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    for path in ['/api/admin/settings','/api/quarantine/release','/api/login']:
        try:
            opener.open(urllib.request.Request(f'http://127.0.0.1:{api}'+path,data=b'{}',headers={'Content-Type':'application/json'}),timeout=3)
        except urllib.error.HTTPError as error:
            node.require(error.code==503,'Normal API not blocked during validation')
        else:raise RuntimeError('Normal API accepted a maintenance request')
    output=node.run('python3','/usr/local/libexec/noisefence-management/upgrade_reservation.py','status','--operation',json.loads(Path('/var/lib/noisefence-upgrade/active.json').read_text())['operation'])
    held=json.loads(output)
    node.require(all(held[k] is True for k in ('reserved','service_hold','writers_stopped')),'Normal service hold disappeared')
    return {'smtp_closed':True,'normal_apis_blocked':True,'normal_writers_held':True}


def main():
    node.require(os.geteuid()==0 and Path('/.dockerenv').exists()
        and os.environ.get('NOISEFENCE_DISPOSABLE_PAIRED_TEST')=='1'
        and Path('/run/systemd/container').read_text().strip()=='docker','Disposable container required')
    parser=argparse.ArgumentParser();parser.add_argument('action',choices=['stage','archive','database','disabled'])
    parser.add_argument('--value');args=parser.parse_args()
    result=stage(args.value) if args.action=='stage' else archive_identity(args.value) if args.action=='archive' else database_snapshot() if args.action=='database' else disabled(args.value)
    print(json.dumps(result))

if __name__=='__main__':main()
