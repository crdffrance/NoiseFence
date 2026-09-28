"""Narrow Nginx handoff for an already authorized and healthy recovery console.

Caller holds the upgrade lock and keeps workers fenced. No service starts here.
The standard installed standby routes must be present; custom layouts are refused.
"""
import hashlib
import json
from pathlib import Path
import re
import shlex
import time
import urllib.request

from migration_agent import execute
from migration_protocol import atomic, canonical, identity, private_read, require
from recovery_install import protected

SWITCH = Path('/etc/nginx/noisefence-console-upstream.conf')
BEFORE = b'set $noisefence_console 127.0.0.1:18080;\n'
AFTER = b'set $noisefence_console 127.0.0.1:18081;\n'


def parse(raw):
    """Parse only Nginx directive structure, never expand or execute configuration."""
    require(len(raw.encode()) <= 2*1024**2, 'Nginx configuration exceeds inspection bound')
    pattern = re.compile(r'''\s+|\#[^\n]*|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[{};]|[^\s{};\#"']+''')
    tokens=[]
    position=0
    for match in pattern.finditer(raw):
        require(match.start() == position, 'Unsupported Nginx syntax')
        position=match.end()
        token=match.group()
        if token.isspace() or token.startswith('#'):continue
        if token[0] in ('"',"'"):
            values=shlex.split(token)
            require(len(values)==1, 'Invalid quoted Nginx token')
            tokens.append((values[0],False))
        else:tokens.append((token,token in ('{','}',';')))
    require(position == len(raw), 'Incomplete Nginx syntax')
    index=0
    def block(nested=False, depth=0):
        nonlocal index
        require(depth <= 32, 'Nginx nesting exceeds bound')
        result=[]
        words=[]
        while index < len(tokens):
            token,punctuation=tokens[index]
            index+=1
            if not punctuation:
                words.append(token)
                continue
            if token == '}':
                require(nested and not words, 'Unexpected Nginx block end')
                return result
            require(words, 'Empty Nginx directive')
            children=block(True,depth+1) if token == '{' else None
            result.append((tuple(words),children))
            words=[]
        require(not nested and not words, 'Unfinished Nginx directive')
        return result
    return block()


def profile(raw, hostname):
    require(isinstance(hostname,str) and re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?',hostname), 'Invalid recovery hostname')
    tree=parse(raw)
    def walk(nodes):
        for item in nodes:
            yield item
            if item[1] is not None:yield from walk(item[1])
    servers=[]
    for words,children in walk(tree):
        if words != ('server',) or children is None:continue
        names=[w for w,c in children if w[0]=='server_name']
        ssl=[w for w,c in children if w[0]=='listen' and len(w)>1 and 'ssl' in w and re.search(r'(?:^|:)443$',w[1])]
        if ssl and any(hostname in name[1:] for name in names):servers.append(children)
    require(len(servers)==1, 'Exactly one matching HTTPS virtual host required')
    server=servers[0]
    require(all(w[0] not in ('return','rewrite','if','error_page') for w,c in server),
            'Virtual host has unsupported routing overrides')
    require(sum(w == ('include',str(SWITCH)) for w,c in server)==1, 'Managed console upstream include missing')
    definitions=[w for w,c in walk(tree) if len(w)>1 and w[:2]==('set','$noisefence_console')]
    require(len(definitions)==1 and definitions[0] in (('set','$noisefence_console','127.0.0.1:18080'),('set','$noisefence_console','127.0.0.1:18081')),
            'Ambiguous console upstream variable')
    locations={}
    for words,children in server:
        if words[0] != 'location':continue
        require(words not in locations, 'Duplicate Nginx location')
        locations[words]=children
    expected={('location','^~','/api/v1/replication/'):'http://127.0.0.1:18080',
        ('location','^~','/api/v1/cluster/'):'http://$noisefence_console',
        ('location','=','/api/v1/login'):'http://$noisefence_console',
        ('location','/'):'http://$noisefence_console'}
    if ('location','=','/healthz') in locations:
        expected[('location','=','/healthz')]='http://127.0.0.1:18080'
    if ('location','=','/') in locations:
        expected[('location','=','/')]='http://$noisefence_console'
    for location,destination in expected.items():
        require(location in locations and locations[location] is not None, 'Required standby route missing')
        contents=locations[location]
        passes=[w for w,c in contents if w[0]=='proxy_pass']
        require(passes==[('proxy_pass',destination)], 'Unexpected standby proxy destination')
        if location[2:] != ('/',) and location != ('location','/'):
            require(all(w[0] not in ('return','rewrite','try_files','if','include','error_page') for w,c in walk(contents)),
                    'API route has unsupported redirects or overrides')
    # More-specific locations could divert authenticated management requests or bodies.
    for location in locations:
        if location in expected or location in (('location','=','/healthz'),('location','^~','/.well-known/acme-challenge/')):
            continue
        require(False, 'Additional location requires explicit routing review')
    return {'hostname':hostname,'console_target':definitions[0][2],'replication_target':'127.0.0.1:18080',
            'configuration_sha256':hashlib.sha256(raw.encode()).hexdigest()}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, target):
        return None


def console_health():
    client=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
    with client.open('http://127.0.0.1:18081/healthz',timeout=5) as response:
        body=response.read(8193)
        require(response.status==200 and len(body)<=8192, 'Recovery console health unavailable')
        health=json.loads(body)
        require(health.get('status')=='ok' and health.get('smtp_ready') is False,
                'Recovery console is unhealthy or unexpectedly permits SMTP')


def inspect(hostname):
    raw=execute(['/usr/sbin/nginx','-T'],timeout=15).decode()
    return profile(raw,hostname)


def probe(hostname):
    # Certificate validation stays enabled; requests never leave loopback and do
    # not carry credentials. The worker has no management routes (404 vs 401).
    deadline=time.monotonic()+10
    while True:
        retry=False
        for method,path in (('GET','/api/v1/me'),('POST','/api/v1/cluster/v3/sync')):
            remaining=deadline-time.monotonic()
            require(remaining>0, 'Management routing did not settle before the probe deadline')
            status=execute(['/usr/bin/curl','--silent','--show-error','--noproxy','*','--proto','=https',
                '--max-time',str(min(5,remaining)),'--max-redirs','0','--request',method,
                '--resolve',hostname+':443:127.0.0.1','--output','/dev/null',
                '--write-out','%{http_code}','https://'+hostname+path],timeout=min(6,remaining+1)).decode()
            if status=='401':continue
            # systemctl reload returns after signalling the Nginx master; an old
            # worker may still handle a request using the former upstream.
            require(status in ('404','502','503','504') and time.monotonic()<deadline,
                    'Management routing probe '+method+' '+path+' returned HTTP '+status)
            retry=True
            break
        if not retry:return
        time.sleep(min(.2,max(0,deadline-time.monotonic())))


def switch(root, operation, hostname, reentry_binding=None):
    require(identity(operation), 'Canonical recovery operation required')
    root=Path(root)
    protected(root,True)
    info=protected(SWITCH)
    with private_read(SWITCH,1024) as source:current=source.read()
    require(current in (BEFORE,AFTER), 'Unexpected console switch contents')
    console_health()
    routing=inspect(hostname)
    expected_target='127.0.0.1:18080' if current==BEFORE else '127.0.0.1:18081'
    require(routing['console_target']==expected_target, 'Console switch differs from inspected routing')
    path=root/(operation+'-proxy.json')
    def require_reentry():
        require(reentry_binding is not None, 'Already switched proxy has no matching recovery receipt')
        proof=root/'reentry.json';protected(proof)
        with private_read(proof,8192) as source:record=json.load(source)
        require(record.get('protocol')=='noisefence-reentry-1' and record.get('operation')==operation
                and record.get('phase')=='replaced' and record.get('authorization')==reentry_binding
                and identity(record.get('retired_operation')), 'Proxy re-entry authority differs')
    if path.exists():
        protected(path)
        with private_read(path,8192) as source:saved=json.load(source)
        require(saved.get('operation')==operation and saved.get('hostname')==hostname
                and saved.get('status') in ('planned','rolled_back','rollback_failed','verified'),
                'Another or invalid proxy transition owns this receipt')
        require(saved.get('original_target','before') in ('before','after'), 'Invalid original proxy target')
        if saved.get('original_target')=='after':require_reentry()
        if saved['status']=='verified':
            require(current==AFTER, 'Completed proxy transition was changed externally')
            probe(hostname)
            return result(operation)
    else:
        if current==AFTER:require_reentry()
        saved={'operation':operation,'hostname':hostname,'status':'planned',
               'original_target':'before' if current==BEFORE else 'after'}
        atomic(path,canonical(saved))
    try:
        atomic(SWITCH,AFTER,uid=info.st_uid,gid=info.st_gid,mode=info.st_mode&0o777)
        execute(['/usr/sbin/nginx','-t'],timeout=15)
        execute(['/usr/bin/systemctl','reload','nginx'],timeout=30)
        probe(hostname)
        console_health()
    except BaseException:
        # Revert only our exact candidate, never a concurrent administrator edit.
        with private_read(SWITCH,1024) as source:latest=source.read()
        require(latest==AFTER, 'Proxy changed externally; retained worker fences require inspection')
        original=AFTER if saved.get('original_target')=='after' else BEFORE
        atomic(SWITCH,original,uid=info.st_uid,gid=info.st_gid,mode=info.st_mode&0o777)
        try:
            execute(['/usr/sbin/nginx','-t'],timeout=15)
            execute(['/usr/bin/systemctl','reload','nginx'],timeout=30)
            saved['status']='rolled_back'
        except BaseException:
            saved['status']='rollback_failed'
            atomic(path,canonical(saved))
            raise
        atomic(path,canonical(saved))
        raise
    saved['status']='verified'
    atomic(path,canonical(saved))
    return result(operation)


def result(operation):
    return {'operation':operation,'status':'proxy_switched','replication_target_unchanged':True,
            'services_started':False,'worker_start_authorized':False}
