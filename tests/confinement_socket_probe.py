#!/usr/bin/env python3
"""Diagnose the fixed local PostgreSQL boundary on an ephemeral CI VM only.

This uses no production state, network route, credentials or candidate mail.
A successful socket probe cannot qualify a complete archive or migration.
"""
import argparse
import configparser
import hashlib
import json
import os
import re
from pathlib import Path
import subprocess
import sys
import uuid
import confined_paired_release as confined

CATEGORIES = {'query_ok','authentication_refused','socket_permission_denied','permission_denied','missing_socket','connection_refused','timeout','protocol_or_io_error'}
PATH = confined.PATH


def classify(result):
    text = result.stdout.decode(errors='replace').strip()
    if text not in CATEGORIES or bool(result.returncode == 0) != (text == 'query_ok'):
        return 'unexpected_result'
    return text


# Copy the actual shipped daemon isolation properties. Runtime commands and
# restart behavior differ because this is a bounded, read-only oneshot probe.
SERVICE_CONTEXT = frozenset({
    'User', 'Group', 'WorkingDirectory', 'StateDirectory', 'StateDirectoryMode',
    'UMask', 'AmbientCapabilities', 'CapabilityBoundingSet', 'NoNewPrivileges',
    'ProtectSystem', 'ProtectHome', 'PrivateTmp', 'ProtectKernelTunables',
    'ProtectKernelModules', 'ProtectControlGroups', 'RestrictSUIDSGID',
    'RestrictAddressFamilies', 'LockPersonality', 'MemoryDenyWriteExecute',
    'LimitNOFILE', 'MemoryMax',
})
PROBE_OVERRIDES = frozenset({
    'Type', 'EnvironmentFile', 'Environment', 'ExecStartPre', 'ExecStart',
    'Restart', 'RestartSec', 'TimeoutStopSec',
})


def service_properties(raw):
    unit = configparser.RawConfigParser(interpolation=None, strict=True)
    unit.optionxform = str
    unit.read_string(raw)
    values = dict(unit.items('Service'))
    confined.require(set(values) == SERVICE_CONTEXT | PROBE_OVERRIDES,
                     'Review changed daemon service properties before probing')
    confined.require(values['User'] == values['Group'] == 'noisefence'
                     and values['WorkingDirectory'] == '/opt/noisefence',
                     'Unexpected daemon identity or working directory')
    return [key+'='+values[key] for key in sorted(SERVICE_CONTEXT)]


# Diagnostic-only variants on the ephemeral, network-isolated fixture. The
# required full-context result remains mandatory; variants never qualify it.
CONTEXT_VARIANTS = {
    'confined-no-private-tmp': {'PrivateTmp':'false'},
    'confined-no-protect-system': {'ProtectSystem':'false'},
    'confined-no-protect-home': {'ProtectHome':'false'},
    'confined-no-mount-isolation': {
        'PrivateTmp':'false', 'ProtectSystem':'false', 'ProtectHome':'false',
        'ProtectKernelTunables':'false', 'ProtectKernelModules':'false', 'ProtectControlGroups':'false',
    },
    'confined-explicit-pg-bind': {'BindReadOnlyPaths':'/run/postgresql'},
}


DEBUG_ATTACHMENT = 'confined-debug-attachment'
SCOPED_ATTACHMENT = 'confined-scoped-attachment'
SCOPED_NEGATIVE = 'confined-scoped-negative'


def attachment_diagnostic(raw, original, diagnostic):
    """Confirm a disconnected-name hypothesis only on the disposable fixture.

    AppArmor documents root attachment as unsafe due to aliasing. This variant
    is never shipped, never qualifies the required profile, and runs only the
    fixed no-network socket probe under unchanged systemd isolation.
    """
    for name in (original,diagnostic):
        confined.require(re.fullmatch(r'noisefence-test-[a-f0-9]{12}',name),
                         'Invalid diagnostic profile')
    flags=('', ' flags=(attach_disconnected.path=/att/noisefence/)')
    markers=[('profile '+original+flag+' {\n').encode() for flag in flags]
    present=[marker for marker in markers if marker in raw]
    confined.require(len(present)==1,'Unexpected diagnostic profile structure')
    marker=present[0]
    confined.require(original != diagnostic and raw.count(marker)==1,
                     'Unexpected diagnostic profile structure')
    confined.require(raw.count(b'flags=(')==int(b'flags=(' in marker), 'Unexpected existing profile flags')
    return raw.replace(marker,('profile '+diagnostic+' flags=(attach_disconnected) {\n').encode()).replace(
        ('peer='+original+',').encode(),('peer='+diagnostic+',').encode())


def scoped_attachment_diagnostic(raw, original, diagnostic, port=5432):
    """Test a separately named prefix with one disconnected socket permission.

    Support depends on the installed parser, kernel and distribution backports.
    Parser acceptance must be followed by positive and wrong-port socket tests.
    Refusal never authorizes relaxing the real profile. A socket query alone
    does not qualify full daemon confinement.
    """
    confined.require(port in (5432,5433),'Unexpected diagnostic socket port')
    changed=attachment_diagnostic(raw,original,diagnostic)
    confined.require(changed.count(b'\n}\n')==1 and changed.endswith(b'\n}\n'),
                     'Unexpected scoped profile structure')
    prefix='/att/'+diagnostic+'/'
    changed=changed.replace(b'flags=(attach_disconnected)',
        ('flags=(attach_disconnected.path='+prefix+')').encode())
    permission=('  '+prefix+'run/postgresql/.s.PGSQL.'+str(port)+' rw,\n').encode()
    return changed[:-2]+permission+b'}\n'


def parser_version():
    """Keep a bounded public version identifier, never arbitrary parser output."""
    try:
        result=subprocess.run([confined.PARSER,'--version'],capture_output=True,
            timeout=5,env={'PATH':PATH,'LANG':'C'})
    except (OSError,subprocess.TimeoutExpired):
        return None
    if result.returncode or len(result.stdout)>4096:
        return None
    match=re.search(rb'^AppArmor parser version ([0-9]{1,3}\.[0-9]{1,3}(?:\.[0-9]{1,3})?(?:[~+.-][A-Za-z0-9.+~-]{1,64})?)\r?$',
                    result.stdout,re.MULTILINE)
    return match.group(1).decode('ascii') if match else None


def supported_profile(path):
    # Do not load a policy or echo parser errors during this capability check.
    result=subprocess.run(['sudo','-n',confined.PARSER,'--skip-kernel-load','--skip-cache',str(path)],
        capture_output=True,timeout=15,env={'PATH':PATH,'LANG':'C'})
    return result.returncode==0


def service_unit(mode, profile, binary, properties):
    confined.require(mode in ('unconfined', 'confined', DEBUG_ATTACHMENT, SCOPED_ATTACHMENT, SCOPED_NEGATIVE) or mode in CONTEXT_VARIANTS, 'Invalid diagnostic mode')
    values=dict(item.split('=',1) for item in properties)
    values.update(CONTEXT_VARIANTS.get(mode,{}))
    properties=[key+'='+value for key,value in sorted(values.items())]
    lines = ['[Service]', 'Type=oneshot', 'TimeoutStartSec=8s', 'Restart=no',
             *properties, 'StandardOutput=journal', 'StandardError=journal',
             'SyslogIdentifier=noisefence-socket-'+mode, 'ExecStart='+binary]
    if mode != 'unconfined':
        lines.append('AppArmorProfile='+profile)
    return '\n'.join(lines)+'\n'


def service_query(container, mode):
    # systemd-run --wait requires a system D-Bus daemon. The minimal lifecycle
    # image deliberately has none; systemctl uses PID1's private manager socket.
    unit='noisefence-socket-'+mode+'.service'
    started=subprocess.run(['docker','exec',container,'systemctl','start',unit],
        capture_output=True,timeout=15,env={'PATH':PATH,'LANG':'C'})
    confined.command('docker','exec',container,'journalctl','--sync',timeout=5)
    output=confined.command('docker','exec',container,'journalctl','--no-pager',
        '-o','cat','-n','8','-u',unit,'-t','noisefence-socket-'+mode,timeout=5)
    return classify(subprocess.CompletedProcess([],started.returncode,stdout=output))


def run(args):
    confined.require(sys.platform == 'linux' and os.environ.get('GITHUB_ACTIONS') == 'true'
        and os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted'
        and os.environ.get('RUNNER_OS') == 'Linux', 'Use only an ephemeral GitHub-hosted Linux runner')
    confined.require(Path('/sys/module/apparmor/parameters/enabled').read_text().strip() == 'Y',
                     'The runner kernel does not enable AppArmor')
    confined.require(not Path('/att/noisefence').exists() and not Path('/att/noisefence').is_symlink(),
                     'Reserved AppArmor prefix must not exist on the fixture host')
    service_raw=(confined.SOURCE/'deploy/noisefence.service').read_text()
    properties=service_properties(service_raw)
    root=args.output.resolve();root.mkdir(mode=0o700,parents=True,exist_ok=False)
    identity=uuid.uuid4().hex; name='nf-pg-probe-'+identity[:12]; profile='noisefence-test-'+identity[:12]
    raw=confined.policy(args.image,profile); policy=root/'profile';policy.write_bytes(raw);policy.chmod(0o600)
    proof={'schema':'noisefence-postgres-confinement-probe-3','status':'running',
           'scope':'fixed_peer_authenticated_socket_query_only','production_affected':False,
           'binary_sha256':hashlib.sha256(args.binary.read_bytes()).hexdigest(),
           'profile_sha256':hashlib.sha256(raw).hexdigest(),'unconfined':None,'confined':None,
           'generator_sha256':hashlib.sha256((confined.SOURCE/'deploy/hardening/isolation.py').read_bytes()).hexdigest(),
           'renderer_sha256':hashlib.sha256((confined.SOURCE/'tests/render_apparmor_fixture.py').read_bytes()).hexdigest(),
           'container_removed':False,'profile_removed':False,
           'service_sha256':hashlib.sha256(service_raw.encode()).hexdigest(),
           'service_context':{'unconfined':None,'confined':None},
           'apparmor_parser_version':parser_version(),
           'namespace_diagnostics':{key:None for key in CONTEXT_VARIANTS},
           'service_probe_scope':'same_identity_and_isolation_read_only_oneshot_no_daemon_start'}
    confined.require(not any(x.split(' ',1)[0]==profile for x in confined.profiles()),'Profile already exists')
    attached_profile='noisefence-test-'+identity[12:24]
    attached_raw=attachment_diagnostic(raw,profile,attached_profile)
    attached_file=root/'attachment-debug-profile';attached_file.write_bytes(attached_raw);attached_file.chmod(0o600)
    confined.require(not any(x.split(' ',1)[0]==attached_profile for x in confined.profiles()),'Diagnostic profile already exists')
    proof['attachment_diagnostic']={'result':None,'profile_sha256':hashlib.sha256(attached_raw).hexdigest(),
        'scope':'debug_only_root_attachment_not_a_production_policy','denials':[]}
    scoped_profile='noisefence-test-'+identity[20:32]
    confined.require(scoped_profile not in (profile,attached_profile), 'Diagnostic identity collision')
    scoped_raw=scoped_attachment_diagnostic(raw,profile,scoped_profile)
    scoped_file=root/'attachment-scoped-profile';scoped_file.write_bytes(scoped_raw);scoped_file.chmod(0o600)
    confined.require(not any(x.split(' ',1)[0]==scoped_profile for x in confined.profiles()),'Scoped profile already exists')
    proof['scoped_attachment_diagnostic']={'result':None,'profile_sha256':hashlib.sha256(scoped_raw).hexdigest(),
        'scope':'one_disconnected_postgresql_socket_under_separate_prefix_diagnostic_only','parser':'not_checked','denials':[]}
    negative_profile='noisefence-test-'+identity[4:16]
    confined.require(negative_profile not in (profile,attached_profile,scoped_profile), 'Negative identity collision')
    negative_raw=scoped_attachment_diagnostic(raw,profile,negative_profile,port=5433)
    negative_file=root/'attachment-negative-profile';negative_file.write_bytes(negative_raw);negative_file.chmod(0o600)
    confined.require(not any(x.split(' ',1)[0]==negative_profile for x in confined.profiles()),'Negative profile already exists')
    proof['scope_boundary_diagnostic']={'result':None,'profile_sha256':hashlib.sha256(negative_raw).hexdigest(),
        'scope':'query5432_with_only_disconnected5433_allowed_must_be_denied','verified':False,'denials':[]}
    loaded=False;attached_loaded=False;scoped_loaded=False;negative_loaded=False;created=False
    def docker(*cmd,timeout=30):return confined.command('docker',*cmd,timeout=timeout)
    def inside(*cmd,timeout=30):return docker('exec',name,*cmd,timeout=timeout)
    try:
        confined.command('sudo','-n',confined.PARSER,'--add','--skip-cache',str(policy));loaded=True
        confined.require(profile+' (enforce)' in confined.profiles(),'Profile is not enforcing')
        confined.command('sudo','-n',confined.PARSER,'--add','--skip-cache',str(attached_file));attached_loaded=True
        confined.require(attached_profile+' (enforce)' in confined.profiles(),'Diagnostic profile is not enforcing')
        if supported_profile(scoped_file):
            proof['scoped_attachment_diagnostic']['parser']='supported'
            confined.command('sudo','-n',confined.PARSER,'--add','--skip-cache',str(scoped_file));scoped_loaded=True
            confined.require(scoped_profile+' (enforce)' in confined.profiles(),'Scoped profile is not enforcing')
            confined.command('sudo','-n',confined.PARSER,'--add','--skip-cache',str(negative_file));negative_loaded=True
            confined.require(negative_profile+' (enforce)' in confined.profiles(),'Negative profile is not enforcing')
        else:
            proof['scoped_attachment_diagnostic']['parser']='rejected'
            proof['scoped_attachment_diagnostic']['result']='parser_rejected'

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
        modes=('unconfined','confined',*CONTEXT_VARIANTS,DEBUG_ATTACHMENT,*((SCOPED_ATTACHMENT,SCOPED_NEGATIVE) if scoped_loaded else ()))
        for mode in modes:
            unit_file=root/('noisefence-socket-'+mode+'.service')
            unit_file.write_text(service_unit(mode,negative_profile if mode==SCOPED_NEGATIVE else scoped_profile if mode==SCOPED_ATTACHMENT else attached_profile if mode==DEBUG_ATTACHMENT else profile,
                directory+'/noisefence',properties))
            docker('cp',str(unit_file),name+':/etc/systemd/system/'+unit_file.name)
        inside('test','!','-e','/att/noisefence')
        inside('test','!','-L','/att/noisefence')
        inside('systemctl','daemon-reload')
        for mode in ('unconfined','confined'):
            proof['service_context'][mode]=service_query(name,mode)
        for mode in CONTEXT_VARIANTS:
            proof['namespace_diagnostics'][mode]=service_query(name,mode)
        proof['attachment_diagnostic']['result']=service_query(name,DEBUG_ATTACHMENT)
        if scoped_loaded:
            # A real path must not alias the reserved diagnostic attachment root.
            inside('test','!','-e','/att/'+scoped_profile)
            inside('test','!','-L','/att/'+scoped_profile)
            proof['scoped_attachment_diagnostic']['result']=service_query(name,SCOPED_ATTACHMENT)
            inside('test','!','-e','/att/'+negative_profile)
            inside('test','!','-L','/att/'+negative_profile)
            proof['scope_boundary_diagnostic']['result']=service_query(name,SCOPED_NEGATIVE)
            proof['scope_boundary_diagnostic']['verified']=(
                proof['scoped_attachment_diagnostic']['result']=='query_ok' and
                proof['scope_boundary_diagnostic']['result']=='socket_permission_denied')

        if negative_loaded:
            negative_logs=root/'attachment-negative';negative_logs.mkdir(mode=0o700)
            proof['scope_boundary_diagnostic']['collection']=confined.collect_denials(negative_logs,negative_profile)
        proof['denial_diagnostics']=confined.collect_denials(root,profile)
        attached_logs=root/'attachment-debug';attached_logs.mkdir(mode=0o700)
        proof['attachment_diagnostic']['collection']=confined.collect_denials(attached_logs,attached_profile)
        from importlib.util import spec_from_file_location,module_from_spec
        spec=spec_from_file_location('rehearsal_diagnostics',confined.SOURCE/'scripts/rehearsal_diagnostics.py')
        module=module_from_spec(spec);spec.loader.exec_module(module)
        proof['denials']=module.denial_categories((root/'denials.log').read_text() if (root/'denials.log').exists() else '')
        proof['attachment_diagnostic']['denials']=module.denial_categories(
            (attached_logs/'denials.log').read_text() if (attached_logs/'denials.log').exists() else '')
        if scoped_loaded:
            scoped_logs=root/'attachment-scoped';scoped_logs.mkdir(mode=0o700)
            proof['scoped_attachment_diagnostic']['collection']=confined.collect_denials(scoped_logs,scoped_profile)
            proof['scoped_attachment_diagnostic']['denials']=module.denial_categories(
                (scoped_logs/'denials.log').read_text() if (scoped_logs/'denials.log').exists() else '')
        if negative_loaded:
            proof['scope_boundary_diagnostic']['denials']=module.denial_categories(
                (negative_logs/'denials.log').read_text() if (negative_logs/'denials.log').exists() else '')
        checks=[proof['unconfined'],proof['confined'],*proof['service_context'].values()]
        proof['status']='passed' if all(value=='query_ok' for value in checks) and proof['scope_boundary_diagnostic']['verified'] else 'failed'
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
        negative_removed=not negative_loaded
        if negative_loaded and proof['container_removed']:
            confined.require(negative_file.read_bytes()==negative_raw,'Negative profile changed')
            confined.command('sudo','-n',confined.PARSER,'--remove','--skip-cache',str(negative_file))
            negative_removed=not any(x.split(' ',1)[0]==negative_profile for x in confined.profiles())
        scoped_removed=not scoped_loaded
        if scoped_loaded and proof['container_removed']:
            confined.require(scoped_file.read_bytes()==scoped_raw,'Scoped profile changed')
            confined.command('sudo','-n',confined.PARSER,'--remove','--skip-cache',str(scoped_file))
            scoped_removed=not any(x.split(' ',1)[0]==scoped_profile for x in confined.profiles())
        attached_removed=not attached_loaded
        if attached_loaded and proof['container_removed']:
            confined.require(attached_file.read_bytes()==attached_raw,'Diagnostic profile changed')
            confined.command('sudo','-n',confined.PARSER,'--remove','--skip-cache',str(attached_file))
            attached_removed=not any(x.split(' ',1)[0]==attached_profile for x in confined.profiles())
        if loaded and proof['container_removed']:
            confined.require(policy.read_bytes()==raw,'Generated policy changed')
            confined.command('sudo','-n',confined.PARSER,'--remove','--skip-cache',str(policy))
            proof['profile_removed']=negative_removed and scoped_removed and attached_removed and not any(x.split(' ',1)[0]==profile for x in confined.profiles())
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
