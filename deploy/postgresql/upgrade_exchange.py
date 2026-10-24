#!/usr/bin/env python3
"""Pinned SSH exchange for verifying and completing an already-started MX pair.

No release selection, activation decision, startup, download or rollback is
accepted remotely. Existing root receipts remain the authority for every action.
"""
import argparse
import concurrent.futures
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import struct
import subprocess
import sys
import time
import uuid

import upgrade_activation as activation
import upgrade_reservation as reservation
from migration_protocol import Channel, atomic, canonical, identity, pairs, require, sha

PROTOCOL = 'noisefence-upgrade-exchange-1'
AUTHORIZATION = Path('/etc/noisefence-upgrade/exchange.json')
COMMAND = 'noisefence-upgrade-exchange'
MAX_FRAME = 256*1024
ACTIONS = ('status', 'check', 'verify', 'finish')
TRANSPORT_SECONDS = 120


def binding(value):
    require(isinstance(value, dict) and value.get('protocol') == PROTOCOL
            and identity(value.get('operation')) and sha(value.get('proposal_sha256')),
            'Invalid exchange identity')
    return {k:value[k] for k in ('protocol','operation','proposal_sha256')}


def node_name(value):
    return isinstance(value, str) and re.fullmatch('[a-z0-9_-]{1,40}', value) is not None


def authorization(value):
    binding(value)
    require(set(value) == {'protocol','operation','proposal_sha256','node','expires_at'}
            and node_name(value['node']) and type(value['expires_at']) is int
            and time.time() < value['expires_at'] <= time.time()+86400,
            'Invalid or expired exchange authorization')
    return value


def configuration(value):
    binding(value)
    require(set(value) == {'protocol','operation','proposal_sha256','expires_at','coordinator','ssh_key','known_hosts','nodes'}
            and type(value['expires_at']) is int and time.time() < value['expires_at'] <= time.time()+86400
            and isinstance(value['nodes'], dict) and len(value['nodes']) == 2
            and value['coordinator'] in value['nodes'], 'Invalid exchange controller configuration')
    for node, target in value['nodes'].items():
        require(node_name(node) and isinstance(target, dict) and set(target) == {'host','port','user'}, 'Invalid SSH peer')
        require(isinstance(target['host'], str) and '%' not in target['host'] and str(ipaddress.ip_address(target['host'])) == target['host']
                and type(target['port']) is int and 1 <= target['port'] <= 65535
                and isinstance(target['user'], str) and re.fullmatch('[a-z_][a-z0-9_-]{0,31}', target['user']),
                'Expected a canonical numeric SSH address and account')
    for key in ('ssh_key','known_hosts'):
        path = value[key]
        require(isinstance(path, str) and re.fullmatch('/[A-Za-z0-9_./-]+', path)
                and '..' not in Path(path).parts, 'Invalid SSH credential path')
        info = reservation.protected(Path(path))
        require(key != 'ssh_key' or not info.st_mode & 0o077, 'SSH key must be private to root')
        with reservation.private_read(Path(path), 65536) as source:
            require(source.read(1), 'Empty SSH credential file')
    return value


def send(channel, value):
    raw = canonical(value)
    require(0 < len(raw) <= MAX_FRAME, 'Exchange frame exceeds bounds')
    channel.write(struct.pack('!I', len(raw))); channel.write(raw)


def receive(channel):
    size = struct.unpack('!I', channel.read(4))[0]
    require(0 < size <= MAX_FRAME, 'Exchange frame exceeds bounds')
    value = json.loads(channel.read(size), object_pairs_hook=pairs,
                       parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Non-finite JSON')))
    require(isinstance(value, dict), 'Expected an exchange object')
    return value


def checked_report(value, cfg, node):
    activation.checked_report(value)
    require(value['operation'] == cfg['operation'] and value['node'] == node
            and activation.checked_proposal(value['proposal'], value['operation']) == cfg['proposal_sha256'],
            'Foreign activation report')
    return value


def handle(cfg, request):
    authorization(cfg)
    require(isinstance(request, dict) and set(request) == {'protocol','operation','proposal_sha256','node','nonce','action','peer'}
            and binding(request) == binding(cfg) and request['node'] == cfg['node']
            and identity(request['nonce']) and request['action'] in ACTIONS
            and ((request['peer'] is None) == (request['action'] == 'status')), 'Unauthorized exchange request')
    with reservation.operation_lock():
        operation = activation.Activation(cfg['operation'])
        own = checked_report(operation.report(), cfg, cfg['node'])
        action = request['action']; peer = request['peer']
        if action != 'status':
            require(own['decision'] is not None and own['decision']['outcome'] == 'activate'
                    and own['phase'] in ('started','verified','finishing','complete'),
                    'Only an already-started committed pair can complete remotely')
            peer_node = next(d['own']['selection']['node']['node'] for d in own['proposal']
                             if d['own']['selection']['node']['node'] != cfg['node'])
            if action == 'verify':
                activation.checked_ready(peer, cfg['operation'], own['proposal'], peer_node, int(time.time()))
            else:
                checked_report(peer, cfg, peer_node)
            result = getattr(operation, action)(peer)
        else: result = own
        if action == 'check':
            activation.checked_ready(result, cfg['operation'], own['proposal'], cfg['node'], int(time.time()))
        else: checked_report(result, cfg, cfg['node'])
    return {k:request[k] for k in ('protocol','operation','proposal_sha256','node','nonce','action')} | {'result':result}


def ssh_command(cfg, node):
    target = cfg['nodes'][node]
    options = ['BatchMode=yes','StrictHostKeyChecking=yes','IdentitiesOnly=yes','IdentityAgent=none',
        'PasswordAuthentication=no','KbdInteractiveAuthentication=no','PreferredAuthentications=publickey',
        'ClearAllForwardings=yes','ForwardAgent=no','ForwardX11=no','PermitLocalCommand=no',
        'ProxyCommand=none','ProxyJump=none','ControlMaster=no','ControlPath=none',
        'GlobalKnownHostsFile=/dev/null','UpdateHostKeys=no','ConnectTimeout=10',
        'ServerAliveInterval=5','ServerAliveCountMax=2','HostKeyAlias=noisefence-upgrade-'+node,
        'UserKnownHostsFile='+cfg['known_hosts']]
    args = ['/usr/bin/ssh','-F','/dev/null','-T']
    for option in options: args += ['-o',option]
    return args + ['-i',cfg['ssh_key'],'-p',str(target['port']),target['user']+'@'+target['host'],COMMAND]


def call(cfg, node, action, peer=None):
    require(action in ACTIONS and node in cfg['nodes'] and time.time() < cfg['expires_at'], 'Exchange not authorized')
    request = binding(cfg) | {'node':node,'nonce':str(uuid.uuid4()),'action':action,'peer':peer}
    process = subprocess.Popen(ssh_command(cfg,node), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, start_new_session=True, env={'PATH':'/usr/bin:/bin','LANG':'C'})
    try:
        channel = Channel(process.stdout.fileno(),process.stdin.fileno(),time.monotonic()+TRANSPORT_SECONDS)
        send(channel,request); process.stdin.close()
        result = receive(channel)
        require(set(result) == (set(request)-{'peer'})|{'result'}
                and all(result[k] == request[k] for k in request if k != 'peer'), 'Foreign or replayed exchange response')
        if action == 'check':
            require(peer is not None, 'Runtime check requires its counterpart')
            activation.checked_ready(result['result'],cfg['operation'],peer['proposal'],node,int(time.time()))
        else: checked_report(result['result'],cfg,node)
        # Reject trailing output and hung agents; successful JSON alone is not completion.
        try: channel.read(1)
        except EOFError: pass
        else: raise ValueError('Unexpected exchange output')
        require(process.wait(timeout=5) == 0, 'SSH exchange failed')
        return result['result']
    finally:
        if process.poll() is None:
            try: os.killpg(process.pid,signal.SIGKILL)
            except ProcessLookupError: pass
        process.wait(timeout=5)
        process.stdout.close()
        if not process.stdin.closed: process.stdin.close()


def complete(cfg, invoke, record):
    """Finish from fresh proofs, or resume a previously authorized completion."""
    nodes = list(cfg['nodes']); other = {nodes[0]:nodes[1],nodes[1]:nodes[0]}
    def parallel(action, peers=None):
        def run(node):
            value = invoke(node,action,None if peers is None else peers[other[node]])
            record(action+'-'+node,value)
            return value
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            futures = {node:pool.submit(run,node) for node in nodes}
            values = {node:future.result() for node,future in futures.items()}
        return values
    reports = parallel('status')
    for node, value in reports.items():
        checked_report(value,cfg,node)
        require(value['decision'] is not None and value['decision']['outcome']=='activate'
                and value['phase'] in ('started','verified','finishing','complete'), 'Pair has not started its committed release')
    require(reports[nodes[0]]['decision'] == reports[nodes[1]]['decision'], 'Pair decisions differ')
    roles = {d['own']['selection']['node']['node']:d['own']['selection']['role'] for d in reports[nodes[0]]['proposal']}
    require(roles[cfg['coordinator']]=='coordinator' and set(roles)==set(nodes), 'Unexpected pair roles')
    # A persisted completion certificate permits a delayed peer to catch up.
    finishing = next((node for node in nodes if reports[node]['phase'] in ('finishing','complete')), None)
    if finishing is None:
        proofs = parallel('check',reports)
        reports = parallel('verify',proofs)
        order = [cfg['coordinator'],other[cfg['coordinator']]]
    else: order = [finishing,other[finishing]]
    for node in order:
        reports[node] = invoke(node,'finish',reports[other[node]])
        checked_report(reports[node],cfg,node)
        require(reports[node]['phase']=='complete', 'Node did not finish its operation')
        record('finish-'+node,reports[node])
    return reports


def serve():
    require(os.environ.get('SSH_ORIGINAL_COMMAND') == COMMAND, 'Use the restricted exchange authorization')
    def expired(*_): raise TimeoutError('Exchange deadline exceeded')
    signal.signal(signal.SIGALRM,expired); signal.alarm(120)
    try:
        cfg = authorization(reservation.read_json(AUTHORIZATION))
        channel = Channel(sys.stdin.fileno(),sys.stdout.fileno(),time.monotonic()+TRANSPORT_SECONDS)
        send(channel,handle(cfg,receive(channel)))
    finally: signal.alarm(0)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action',required=True)
    sub.add_parser('serve')
    finish = sub.add_parser('complete');finish.add_argument('--config',type=Path,required=True)
    args = parser.parse_args();require(os.geteuid()==0 and sys.platform=='linux','Root on Linux is required');os.umask(0o077)
    if args.action=='serve': serve(); return
    cfg = configuration(reservation.read_json(args.config))
    reservation.STATE.mkdir(mode=0o700,exist_ok=True);reservation.protected(reservation.STATE,True)
    root = reservation.STATE/'exchange'
    root.mkdir(mode=0o700,exist_ok=True);reservation.protected(root,True)
    attempt = root/str(uuid.uuid4());attempt.mkdir(mode=0o700)
    atomic(attempt/'configuration.json',canonical(cfg))
    def record(name,value): atomic(attempt/(name+'.json'),canonical(value))
    result = complete(cfg,lambda node,action,peer:call(cfg,node,action,peer),record)
    print(json.dumps({'operation':cfg['operation'],'status':'complete','nodes':list(result),'evidence':str(attempt)}))


if __name__=='__main__':
    try: main()
    except Exception as error:
        print('Upgrade exchange stopped: '+type(error).__name__+'; inspect local receipts and retry the same operation.',file=sys.stderr)
        sys.exit(1)
