#!/usr/bin/env python3
"""Diagnose the fixed local PostgreSQL boundary on an ephemeral CI VM only.

This uses no production state, network route, credentials or candidate mail.
A successful socket probe cannot qualify a complete archive or migration.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid
import confined_paired_release as confined

CATEGORIES = {'query_ok','permission_denied','missing_socket','connection_refused','timeout','protocol_or_io_error'}
PATH = confined.PATH


def classify(result):
    text = result.stdout.decode(errors='replace').strip()
    if text not in CATEGORIES or bool(result.returncode == 0) != (text == 'query_ok'):
        return 'unexpected_result'
    return text


def run(args):
    confined.require(sys.platform == 'linux' and os.environ.get('GITHUB_ACTIONS') == 'true'
        and os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted'
        and os.environ.get('RUNNER_OS') == 'Linux', 'Use only an ephemeral GitHub-hosted Linux runner')
    confined.require(Path('/sys/module/apparmor/parameters/enabled').read_text().strip() == 'Y',
                     'The runner kernel does not enable AppArmor')
    root=args.output.resolve();root.mkdir(mode=0o700,parents=True,exist_ok=False)
    identity=uuid.uuid4().hex; name='nf-pg-probe-'+identity[:12]; profile='noisefence-test-'+identity[:12]
    raw=confined.policy(args.image,profile); policy=root/'profile';policy.write_bytes(raw);policy.chmod(0o600)
    proof={'schema':'noisefence-postgres-confinement-probe-1','status':'running',
           'scope':'fixed_peer_authenticated_socket_query_only','production_affected':False,
           'binary_sha256':hashlib.sha256(args.binary.read_bytes()).hexdigest(),
           'profile_sha256':hashlib.sha256(raw).hexdigest(),'unconfined':None,'confined':None,
           'container_removed':False,'profile_removed':False}
    confined.require(not any(x.split(' ',1)[0]==profile for x in confined.profiles()),'Profile already exists')
    loaded=False;created=False
    def docker(*cmd,timeout=30):return confined.command('docker',*cmd,timeout=timeout)
    def inside(*cmd,timeout=30):return docker('exec',name,*cmd,timeout=timeout)
    try:
        confined.command('sudo','-n',confined.PARSER,'--add','--skip-cache',str(policy));loaded=True
        confined.require(profile+' (enforce)' in confined.profiles(),'Profile is not enforcing')
        confined.require(name not in docker('ps','-a','--format','{{.Names}}').decode().splitlines(),
                         'Diagnostic container name already exists')
        created=True
        docker('run','-d','--name',name,'--network','none','--cgroupns','private','--privileged',
               '--cpus','1','--memory','512m','--pids-limit','128','--tmpfs','/run','--tmpfs','/tmp',
               '--label','org.noisefence.socket-probe='+identity,args.image)
        inside('useradd','--system','--no-create-home','--shell','/usr/sbin/nologin','noisefence')
        inside('install','-d','-m','0700','-o','postgres','-g','postgres','/var/lib/postgresql/probe')
        inside('install','-d','-m','0775','-o','postgres','-g','postgres','/run/postgresql')
        pg='/usr/lib/postgresql/17/bin/'
        inside('runuser','-u','postgres','--',pg+'initdb','-D','/var/lib/postgresql/probe',
               '--auth-local=peer','--auth-host=reject','--no-instructions')
        inside('runuser','-u','postgres','--',pg+'pg_ctl','-D','/var/lib/postgresql/probe',
               '-l','/var/lib/postgresql/probe/log','-o',"-k /run/postgresql -c listen_addresses=''",'-w','start')
        inside('runuser','-u','postgres','--',pg+'psql','-h','/run/postgresql','-d','postgres',
               '-v','ON_ERROR_STOP=1','-c','CREATE ROLE noisefence LOGIN')
        directory='/opt/noisefence/releases/socket-probe';inside('mkdir','-p',directory)
        docker('cp',str(args.binary.resolve()),name+':'+directory+'/noisefence')
        inside('chmod','0755',directory+'/noisefence')
        for mode in ('unconfined','confined'):
            command=['docker','exec',name,'runuser','-u','noisefence','--']
            if mode=='confined':command+=['aa-exec','-p',profile,'--']
            command+=[directory+'/noisefence']
            result=subprocess.run(command,capture_output=True,timeout=12,env={'PATH':PATH,'LANG':'C'})
            proof[mode]=classify(result)
        proof['denial_diagnostics']=confined.collect_denials(root,profile)
        from importlib.util import spec_from_file_location,module_from_spec
        spec=spec_from_file_location('rehearsal_diagnostics',confined.SOURCE/'scripts/rehearsal_diagnostics.py')
        module=module_from_spec(spec);spec.loader.exec_module(module)
        proof['denials']=module.denial_categories((root/'denials.log').read_text() if (root/'denials.log').exists() else '')
        proof['status']='passed' if proof['unconfined']==proof['confined']=='query_ok' else 'failed'
    finally:
        if created:
            existing=set(docker('ps','-a','--format','{{.Names}}').decode().splitlines())
            if name in existing:
                owner=docker('inspect','--format','{{ index .Config.Labels "org.noisefence.socket-probe" }}',name).decode().strip()
                confined.require(owner==identity,'Container ownership changed; retain its profile')
                docker('rm','--force','--volumes',name)
            existing=set(docker('ps','-a','--format','{{.Names}}').decode().splitlines())
            proof['container_removed']=name not in existing
        else:proof['container_removed']=True
        if loaded and proof['container_removed']:
            confined.require(policy.read_bytes()==raw,'Generated policy changed')
            confined.command('sudo','-n',confined.PARSER,'--remove','--skip-cache',str(policy))
            proof['profile_removed']=not any(x.split(' ',1)[0]==profile for x in confined.profiles())
        if not proof['container_removed'] or not proof['profile_removed']:proof['status']='cleanup_failed'
        if proof['status']=='running':proof['status']='failed'
        (root/'probe.json').write_text(json.dumps(proof,sort_keys=True,indent=2)+'\n')
        print(json.dumps(proof,sort_keys=True))
    return 0 if proof['status']=='passed' else 1


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary',type=Path,required=True);parser.add_argument('--image',required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();os.umask(0o077);return run(args)


if __name__=='__main__':raise SystemExit(main())
