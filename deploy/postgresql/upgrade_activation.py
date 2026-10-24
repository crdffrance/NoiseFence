#!/usr/bin/env python3
"""Durable two-node activation after held release promotion.

Root reports travel through authenticated operator channels. No remote shell,
archive download, model change or database restore is performed by this helper.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import pwd
import sqlite3
import sys
import time
import urllib.request

import upgrade_promotion as promotion
import upgrade_reservation as reservation
import upgrade_validation as validation
from migration_protocol import atomic, canonical, identity, pairs, require, sha

PROTOCOL = 'noisefence-upgrade-activation-1'
REPORT = 'noisefence-upgrade-activation-report-1'
DECISION = 'noisefence-upgrade-decision-1'
READY = 'noisefence-upgrade-ready-1'
PHASES = ('armed', 'decided', 'starting', 'started', 'verified', 'finishing', 'complete', 'aborting', 'aborted', 'cancelling', 'cancelled')
DROPIN = '99-noisefence-upgrade-activation.conf'
NORMAL = 'noisefence.service'


def proposal(state):
    require(state['phase'] == 'promoted' and state['peer'] is not None, 'Both releases must be promoted')
    left, right = state['descriptor'], state['peer']
    require(promotion.paired(left, right) == state['pair_sha256']
            and all(d['validated_at'] is not None for d in [left, right])
            and all(left['original'][k] == right['original'][k] for k in ('version', 'commit')),
            'Prepared release pair is incompatible')
    return sorted([left, right], key=lambda d: d['own']['selection']['node']['node'])


def checked_proposal(value, operation):
    require(isinstance(value, list) and len(value) == 2, 'Activation requires exactly two prepared nodes')
    digest = promotion.paired(*value)
    require(value == sorted(value, key=lambda d: d['own']['selection']['node']['node'])
            and all(d['operation'] == operation and d['validated_at'] is not None for d in value)
            and all(value[0]['original'][k] == value[1]['original'][k] for k in ('version', 'commit')),
            'Invalid activation proposal')
    return digest


def checked_decision(value, operation, proposed):
    digest = checked_proposal(proposed, operation)
    nodes = [d['own']['selection']['node']['node'] for d in proposed]
    require(isinstance(value, dict) and set(value) == {'protocol','operation','proposal_sha256','outcome','decided_at','votes'}
            and value['protocol'] == DECISION and value['operation'] == operation and value['proposal_sha256'] == digest
            and value['outcome'] in ('activate','abort') and type(value['decided_at']) is int and value['decided_at'] > 0
            and value['votes'] == (nodes if value['outcome'] == 'activate' else []), 'Invalid durable pair decision')
    if value['outcome'] == 'activate':
        require(value['decided_at'] < min(d['own']['expires_at'] for d in proposed), 'Decision followed authorization expiry')
    return value


def checked_report(value):
    require(isinstance(value, dict) and set(value) == {'protocol','operation','node','proposal','phase','decision','started_at','verified_at','peer_completion'}
            and value['protocol'] == REPORT and identity(value['operation']) and value['phase'] in PHASES,
            'Invalid activation report')
    checked_proposal(value['proposal'], value['operation'])
    require(value['node'] in [d['own']['selection']['node']['node'] for d in value['proposal']], 'Unknown activation node')
    if value['decision'] is None:
        require(value['phase'] == 'armed', 'Activation decision missing')
    else:
        checked_decision(value['decision'], value['operation'], value['proposal'])
    if value['phase'] in ('starting','started','verified','finishing','complete'):
        require(value['decision'] is not None and value['decision']['outcome']=='activate'
                and value['started_at'] is not None, 'Normal startup requires an activation decision')
    if value['phase'] in ('verified','finishing','complete'):
        require(value['verified_at'] is not None, 'Peer runtime verification is missing')
    if value['phase'] in ('aborting','aborted','cancelling','cancelled'):
        require(value['decision'] is not None and value['decision']['outcome']=='abort'
                and value['started_at'] is None and value['verified_at'] is None, 'Abort cannot follow normal startup')
    completed = value['phase'] in ('finishing','complete','cancelling','cancelled')
    certificate = value['peer_completion']
    if completed:
        require(isinstance(certificate,dict) and set(certificate)=={'node','verified_at','outcome'}
                and certificate['node'] in [d['own']['selection']['node']['node'] for d in value['proposal']]
                and certificate['node'] != value['node'] and certificate['outcome']==value['decision']['outcome'],
                'Missing counterpart completion certificate')
        require((type(certificate['verified_at']) is int and certificate['verified_at']>0)
                if certificate['outcome']=='activate' else certificate['verified_at'] is None,
                'Invalid counterpart verification time')
    else:require(certificate is None,'Unexpected counterpart completion certificate')
    for key in ['started_at','verified_at']:
        require(value[key] is None or (type(value[key]) is int and value[key] > 0), 'Invalid activation timestamp')
    if value['started_at'] is not None:
        require(value['decision'] is not None and value['started_at'] >= value['decision']['decided_at'], 'Startup predates its decision')
    if value['verified_at'] is not None:
        require(value['started_at'] is not None and value['verified_at'] >= value['started_at'], 'Verification predates startup')
    if completed and certificate['verified_at'] is not None:
        require(certificate['verified_at'] >= value['decision']['decided_at'], 'Counterpart verification predates activation')
    return value


def checked_ready(value, operation, proposed, node, now):
    require(isinstance(value, dict) and set(value) == {'protocol','operation','node','proposal_sha256','checked_at',
                'process','binary_sha256','last_sync','heartbeat','pending_replicas','unprotected','policy','since','policy_window'}
            and value['protocol'] == READY and value['operation'] == operation and value['node'] == node
            and value['proposal_sha256'] == checked_proposal(proposed, operation)
            and type(value['checked_at']) is int and 0 <= now-value['checked_at'] <= 30,
            'Stale or foreign runtime proof')
    process = value['process']
    require(isinstance(process, dict) and set(process) == {'pid','boot','ticks','started_at'}
            and identity(process['boot']) and all(type(process[k]) is int and process[k] > 0 for k in ['pid','ticks','started_at']),
            'Invalid running process identity')
    own = next(d for d in proposed if d['own']['selection']['node']['node'] == node)
    require(value['binary_sha256'] == own['own']['candidate']['binary_sha256'] and value['policy'] == own['own']['policy']
            and type(value['since']) is int and value['since'] >= process['started_at']
            and all(type(value[k]) is int and value['since'] < value[k] <= value['checked_at'] for k in ['last_sync','heartbeat'])
            and type(value['policy_window']) is int and 15 <= value['policy_window'] <= 605
            and value['checked_at']-value['heartbeat'] <= 15
            and value['checked_at']-value['last_sync'] <= value['policy_window']
            and type(value['pending_replicas']) is int and value['pending_replicas'] == 0
            and type(value['unprotected']) is int and value['unprotected'] == 0,
            'Runtime proof does not establish fresh policy and replica readiness')
    return value


def process_identity():
    raw = reservation.execute(['/usr/bin/systemctl','show',NORMAL,'--property=MainPID','--value']).strip()
    require(raw.isdigit() and int(raw) > 0, 'Normal daemon is not running')
    pid = int(raw); proc = Path('/proc')/str(pid)
    fields = (proc/'stat').read_text().rpartition(')')[2].split()
    require(len(fields) >= 20, 'Invalid process stat')
    ticks = int(fields[19]); boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    born = next(int(line.split()[1]) for line in Path('/proc/stat').read_text().splitlines() if line.startswith('btime '))
    uid = next(line.split()[1:] for line in (proc/'status').read_text().splitlines() if line.startswith('Uid:'))
    require(uid == [str(pwd.getpwnam('noisefence').pw_uid)]*4, 'Daemon must run under the application account')
    return {'pid':pid,'boot':boot,'ticks':ticks,'started_at':born+ticks//os.sysconf('SC_CLK_TCK')}, (proc/'exe').resolve(strict=True)


def policy_window(config):
    seconds = config['cluster'].get('poll_seconds',10)
    require(type(seconds) is int and 2 <= seconds <= 300,'Invalid configured policy polling interval')
    return max(15,2*seconds+5)


def runtime_counters():
    db = sqlite3.connect((reservation.DATA/'state.sqlite3').as_uri()+'?mode=ro', uri=True, timeout=2)
    until = time.monotonic()+2; db.set_progress_handler(lambda:int(time.monotonic()>until),1000)
    try:
        db.execute('PRAGMA query_only=ON');db.execute('BEGIN')
        values = dict(db.execute("SELECT key,CASE WHEN length(value)<=20 THEN value END FROM cluster_state WHERE key IN ('last_sync','ha_last_success','ha_required')"))
        require(values.get('ha_required') == '1', 'Two durable copies are not required')
        row = db.execute('SELECT COALESCE(SUM(acked=0),0),COALESCE(SUM(acked<generation),0),'
            "COALESCE(SUM(typeof(generation)!='integer' OR typeof(acked)!='integer' OR generation<1 OR acked<0 OR acked>generation),0) FROM ha_local").fetchone()
        require(row[2] == 0, 'Invalid replica generations')
        return {'last_sync':int(values['last_sync']), 'heartbeat':int(values['ha_last_success']),
                'unprotected':row[0], 'pending_replicas':row[1]}
    finally:
        db.close()


class Activation:
    def __init__(self, operation):
        require(identity(operation), 'Canonical operation UUID required')
        self.operation = operation
        self.path = reservation.STATE/(operation+'-activation.json')
        self.marker = reservation.STATE/'activation.json'
        self.jobs = reservation.STATE/'activation-jobs.json'
        self.promoted = promotion.Promotion(operation)
        self.hold = reservation.Reservation(operation)

    def state(self):
        value = reservation.read_json(self.path)
        require(isinstance(value,dict) and set(value) == {'protocol','operation','node','proposal','phase','decision',
            'started_at','verified_at','verification','peer_vote','peer_finish'}
            and value['protocol'] == PROTOCOL and value['operation'] == self.operation, 'Invalid activation receipt')
        checked_report(self.projection(value))
        if value['phase'] not in ('armed','decided'):
            abort = value['phase'] in ('aborting','aborted','cancelling','cancelled')
            require(value['decision']['outcome'] == ('abort' if abort else 'activate'), 'Decision and activation phase conflict')
        if value['phase'] in ('starting','started','verified','finishing','complete'):
            require(value['started_at'] is not None and value['peer_vote'] is not None, 'Peer commit missing before startup')
        if value['phase'] in ('verified','finishing','complete'):
            require(type(value['verified_at']) is int and isinstance(value['verification'],dict), 'Runtime verification missing')
        if value['phase'] in ('finishing','complete','cancelling','cancelled'):
            require(isinstance(value['peer_finish'],dict), 'Peer completion missing')
        peer_node = self.peer(value)['own']['selection']['node']['node']
        if value['peer_vote'] is not None:
            self.match_peer(value,value['peer_vote'])
            require(value['peer_vote']['decision'] == value['decision']
                    and value['peer_vote']['phase'] in ('decided','starting','started','verified','finishing','complete'),
                    'Stored peer commit differs')
        if value['verification'] is not None:
            require(type(value['verified_at']) is int and set(value['verification']) == {'own','peer'}, 'Invalid verification receipt')
            checked_ready(value['verification']['own'],self.operation,value['proposal'],value['node'],value['verified_at'])
            checked_ready(value['verification']['peer'],self.operation,value['proposal'],peer_node,value['verified_at'])
        if value['peer_finish'] is not None:
            self.match_peer(value,value['peer_finish'])
            require(value['peer_finish']['decision'] == value['decision']
                    and value['peer_finish']['phase'] in (('aborted','cancelling','cancelled') if value['decision']['outcome']=='abort'
                        else ('verified','finishing','complete')), 'Stored peer completion differs')
            if value['decision']['outcome']=='activate':self.check_completion(value,value['peer_finish'])
        if value['phase'] in ('armed','decided','aborting','aborted','cancelling','cancelled'):
            require(all(value[k] is None for k in ['started_at','peer_vote','verified_at','verification']), 'Unexpected startup evidence')
        if value['phase'] not in ('finishing','complete','cancelling','cancelled'):
            require(value['peer_finish'] is None, 'Unexpected peer completion')
        return value

    @staticmethod
    def projection(state):
        peer = state['peer_finish']
        certificate = {k:peer[k] for k in ['node','verified_at']} | {'outcome':peer['decision']['outcome']} if peer is not None else None
        return {k:state[k] for k in ['operation','node','proposal','phase','decision','started_at','verified_at']} | {'protocol':REPORT,'peer_completion':certificate}

    def report(self):
        state = self.state()
        # Recover the rename-before-directory-fsync window before publishing a
        # receipt another host may use as an irrevocable promise or decision.
        reservation.sync_directory(self.path.parent)
        return self.projection(state)

    def save(self, state, phase, **changes):
        result = {**state, **changes, 'phase':phase};atomic(self.path,canonical(result));return result

    def own(self, state):
        return next(d for d in state['proposal'] if d['own']['selection']['node']['node'] == state['node'])

    def peer(self, state):
        return next(d for d in state['proposal'] if d['own']['selection']['node']['node'] != state['node'])

    def owner(self, install=False):
        expected = {'protocol':PROTOCOL,'operation':self.operation}
        if reservation.exists(self.marker):
            require(reservation.read_json(self.marker) == expected, 'Another activation owns the reservation')
        else:
            require(install, 'Activation marker missing')
            atomic(self.marker,canonical(expected))
        self.hold.owner()
        return expected

    def match_peer(self, state, report):
        checked_report(report)
        require(report['operation'] == self.operation and report['proposal'] == state['proposal']
                and report['node'] == self.peer(state)['own']['selection']['node']['node'], 'Unexpected activation counterpart')

    @staticmethod
    def check_completion(state, peer):
        if peer['phase'] in ('finishing','complete'):
            certificate=peer['peer_completion']
            require(certificate['node']==state['node']
                    and state['started_at'] <= certificate['verified_at'] <= state['verified_at'],
                    'Peer completion does not match retained local verification')

    def initialize(self, state, phase='armed', decision=None):
        proposed = proposal(state)
        node = state['descriptor']['own']['selection']['node']['node']
        value = {'protocol':PROTOCOL,'operation':self.operation,'node':node,'proposal':proposed,'decision':decision,
                 'started_at':None,'verified_at':None,'verification':None,'peer_vote':None,'peer_finish':None}
        self.save(value,phase);self.owner(install=True)
        return self.report()

    def arm(self, peer):
        state = self.promoted.state();self.promoted.owner()
        proposed = proposal(state)
        if state['descriptor']['own']['selection']['role'] == 'coordinator':
            peer = promotion.checked_report(peer)
            require(peer['phase'] == 'promoted' and peer['descriptor'] == state['peer']
                    and peer['pair_sha256'] == state['pair_sha256'], 'Both promoted receipts are required')
        else:
            peer = checked_report(peer)
            require(peer['phase'] == 'armed' and peer['decision'] is None and peer['proposal'] == proposed
                    and peer['node'] == state['peer']['own']['selection']['node']['node'],
                    'Arm the coordinator before the worker so an abort authority always exists')
        current, expected = self.promoted.frozen(state)
        require(current == expected, 'Candidate pointer is not installed')
        if reservation.exists(self.path):
            value = self.state()
            require(value['phase'] == 'armed' and value['proposal'] == proposal(state), 'Activation already advanced')
            self.owner(install=True);return self.report()
        require(not reservation.exists(self.marker) and not reservation.exists(self.jobs), 'Unowned activation artifacts')
        require(int(time.time()) < min(d['own']['expires_at'] for d in proposal(state)), 'Preparation expired')
        return self.initialize(state)

    def decide(self, outcome, peer=None):
        state = self.state();self.owner(install=True)
        require(self.own(state)['own']['selection']['role'] == 'coordinator', 'Only the selected coordinator decides')
        if state['decision'] is not None:
            require(state['decision']['outcome'] == outcome, 'The durable decision cannot be replaced')
            return self.report()
        require(state['phase'] == 'armed', 'Activation is not armed')
        if outcome == 'activate':
            self.match_peer(state,peer)
            require(peer['phase'] == 'armed', 'Both nodes must promise to retain the promoted pair')
            current, expected = self.promoted.frozen(self.promoted.state())
            require(current == expected, 'Promoted installation changed')
        now = int(time.time())
        decision = checked_decision({'protocol':DECISION,'operation':self.operation,
            'proposal_sha256':checked_proposal(state['proposal'],self.operation),'outcome':outcome,'decided_at':now,
            'votes':[d['own']['selection']['node']['node'] for d in state['proposal']] if outcome == 'activate' else []},self.operation,state['proposal'])
        self.save(state,'decided',decision=decision)
        return self.report()

    def accept(self, coordinator):
        checked_report(coordinator)
        require(coordinator['decision'] is not None and coordinator['operation'] == self.operation,
                'Coordinator has not decided this operation')
        leader = next(d for d in coordinator['proposal'] if d['own']['selection']['role'] == 'coordinator')
        require(coordinator['node'] == leader['own']['selection']['node']['node'], 'Decision did not come from the coordinator')
        if not reservation.exists(self.path):
            # Aborting after one vote must also release a peer that never armed.
            require(coordinator['decision']['outcome'] == 'abort', 'Activation requires an existing local promise')
            local = self.promoted.state()
            # The peer may already have restored, but it must retain this exact pair.
            require(local['phase'] in ('promoted','restoring','restored') and local['peer'] is not None, 'Unarmed peer lost its preparation')
            current, expected = self.promoted.frozen(local)
            proposed = proposal({**local,'phase':'promoted'})
            require(proposed == coordinator['proposal'], 'Abort proposal differs')
            self.initialize({**local,'phase':'promoted'},phase='decided',decision=coordinator['decision'])
        state = self.state();self.owner(install=True);self.match_peer(state,coordinator)
        require(self.peer(state)['own']['selection']['role'] == 'coordinator', 'Decision did not come from the coordinator')
        if state['decision'] is not None:
            require(state['decision'] == coordinator['decision'], 'The durable decision cannot be replaced')
            return self.report()
        require(state['phase'] == 'armed', 'Local activation already advanced')
        current, expected = self.promoted.frozen(self.promoted.state())
        require(current == expected, 'Promoted installation changed before decision')
        self.save(state,'decided',decision=coordinator['decision']);return self.report()

    def job_conditions(self, install=False, remove=False, missing_ok=False):
        raw = ('[Unit]\nConditionPathExists=!'+str(self.jobs)+'\n').encode()
        for unit in reservation.FENCED:
            directory = reservation.UNITS/(unit+'.d');path = directory/DROPIN
            if reservation.exists(path):
                reservation.protected(path)
                require(unit != NORMAL and path.read_bytes() == raw, 'Unexpected activation job condition')
                if remove:reservation.remove(path)
            elif install and unit != NORMAL:
                directory.mkdir(mode=0o755,exist_ok=True);reservation.protected(directory,True)
                atomic(path,raw,mode=0o644)
            elif not remove and not missing_ok and unit != NORMAL:
                raise ValueError('Activation job fence missing')
        if install or remove:
            reservation.execute(['/usr/bin/systemctl','daemon-reload'])

    def installation(self, state, jobs=False, policy=True):
        own = self.own(state);old = own['installation'];new = own['own']['candidate']
        expected = {**old,'current_link':new['directory'],'release_directory':new['directory'],
                    **{k:new[k] for k in ['binary_sha256','manifest_sha256','build_sha256']}}
        require(reservation.installation() == expected, 'Activated installation differs from its prepared manifest')
        if jobs:self.job_conditions(missing_ok=state['phase']=='finishing')
        require(promotion.service_fingerprint(ignored_dropin=DROPIN if jobs else None) == own['service_sha256'],
                'Installed service definitions changed')
        if policy:require(validation.policy_epoch() == own['own']['policy'], 'Installed policy changed during activation')

    def start(self, peer):
        state = self.state();self.owner();self.match_peer(state,peer)
        require(state['decision'] is not None and state['decision']['outcome'] == 'activate'
                and peer['decision'] == state['decision'] and peer['phase'] in ('decided','starting','started','verified','finishing','complete'),
                'Both durable activation decisions are required before startup')
        require(state['phase'] in ('decided','starting','started'), 'Startup already finalized')
        if state['phase'] == 'decided':
            self.installation(state)
            require(self.hold.status()['writers_stopped'] and reservation.exists(reservation.HOLD), 'Normal writers escaped the hold')
            require(not any(reservation.exists(reservation.UNITS/(u+'.d')/DROPIN) for u in reservation.FENCED), 'Stale activation job conditions')
            state = self.save(state,'starting',started_at=int(time.time()),peer_vote=peer)
        expected = self.owner()
        if reservation.exists(self.jobs):require(reservation.read_json(self.jobs) == expected,'Another job hold is present')
        else:atomic(self.jobs,canonical(expected))
        self.job_conditions(install=True);self.installation(state,jobs=True)
        require(not reservation.exists(self.promoted.validation.marker)
                and reservation.unit_state(validation.SERVICE) in ('inactive','failed','unknown'), 'Validation is still running')
        if reservation.exists(reservation.HOLD):reservation.remove(reservation.HOLD)
        # Retry also synchronizes a removal that may have preceded a crash.
        reservation.sync_directory(reservation.STATE)
        active = reservation.unit_state(NORMAL)
        if active != 'active':
            if active == 'failed':reservation.execute(['/usr/bin/systemctl','reset-failed',NORMAL])
            reservation.execute(['/usr/bin/systemctl','start',NORMAL])
        require(reservation.unit_state(NORMAL) == 'active','Candidate did not start; recover the committed release')
        self.save(state,'started');return self.report()

    def check(self, peer):
        state = self.state();self.owner();self.match_peer(state,peer)
        require(state['phase'] in ('started','verified') and peer['phase'] in ('started','verified','finishing','complete')
                and peer['decision'] == state['decision'] and peer['started_at'] is not None,
                'Both committed normal daemons must have started')
        self.installation(state,jobs=True)
        process, executable = process_identity();own = self.own(state)
        require(executable == Path(own['own']['candidate']['directory'])/'noisefence'
                and reservation.file_digest(executable,512*1024**2) == own['own']['candidate']['binary_sha256'], 'Unexpected running executable')
        with urllib.request.build_opener(urllib.request.ProxyHandler({}),validation.NoRedirect()).open(validation.health_url(),timeout=3) as response:
            raw = response.read(4097);require(len(raw)<=4096 and response.status==200,'Invalid runtime health response')
            health = json.loads(raw,object_pairs_hook=pairs)
        require(health.get('status') == 'ok' and health.get('smtp_ready') is True,'Normal SMTP is not ready')
        counters = runtime_counters();now = int(time.time())
        since = max(state['started_at'],peer['started_at'],process['started_at'])
        import tomllib
        with reservation.private_read(reservation.CONFIG,1024*1024) as source:config=tomllib.loads(source.read().decode())
        window = policy_window(config)
        require(0 <= now-counters['heartbeat'] <= 15 and 0 <= now-counters['last_sync'] <= window,
                'Fresh replica and authenticated policy exchange required')
        require(process_identity() == (process,executable),'Daemon changed while observing readiness')
        proof = {'protocol':READY,'operation':self.operation,'node':state['node'],
            'proposal_sha256':checked_proposal(state['proposal'],self.operation),'checked_at':now,'process':process,
            'binary_sha256':own['own']['candidate']['binary_sha256'],'policy':validation.policy_epoch(),'since':since,'policy_window':window,**counters}
        return checked_ready(proof,self.operation,state['proposal'],state['node'],now)

    def verify(self, peer_proof):
        state = self.state();self.owner()
        peer_node = self.peer(state)['own']['selection']['node']['node']
        peer_proof = checked_ready(peer_proof,self.operation,state['proposal'],peer_node,int(time.time()))
        # /proc btime and start ticks are rounded to whole seconds. The
        # process estimate can precede its durable decision by one second; use
        # the later bound without representing that estimate as protocol time.
        started_at=max(state['decision']['decided_at'],peer_proof['process']['started_at'])
        peer = {**self.report(),'node':peer_node,'phase':'started','started_at':started_at,'verified_at':None,'peer_completion':None}
        own = self.check(peer)
        require(own['since'] >= peer_proof['process']['started_at'], 'Peer restarted after the observed exchange')
        verified_at = int(time.time())
        # Local observation can consume the remainder of the counterpart's
        # freshness window. Never persist a receipt our own reader will reject.
        checked_ready(own,self.operation,state['proposal'],state['node'],verified_at)
        checked_ready(peer_proof,self.operation,state['proposal'],peer_node,verified_at)
        self.save(state,'verified',verified_at=verified_at,verification={'own':own,'peer':peer_proof})
        return self.report()

    def finish(self, peer):
        state = self.state();self.match_peer(state,peer)
        require(state['phase'] in ('verified','finishing','complete') and peer['phase'] in ('verified','finishing','complete')
                and peer['decision'] == state['decision'], 'Both runtime verifications are required')
        if state['phase'] == 'complete':return self.cleanup(state)
        self.owner()
        held=self.hold.state();promoted=self.promoted.state();self.promoted.owner()
        own=self.own(state)
        require(held['phase'] in (('held','upgraded') if state['phase']=='finishing' else ('held',))
                and held['installation']==own['installation']
                and promoted['phase'] in (('promoted','activated') if state['phase']=='finishing' else ('promoted',))
                and promoted['descriptor']==own and promoted['peer']==self.peer(state)
                and promoted['pair_sha256']==checked_proposal(state['proposal'],self.operation),
                'Reservation or promotion no longer matches this activation')
        # Validate before removing any protective service condition. An absent
        # marker is recoverable only after a finishing intent was persisted.
        if reservation.exists(self.jobs):
            require(reservation.read_json(self.jobs) == self.owner(),'Unexpected job hold')
        else:require(state['phase']=='finishing','Activation job hold missing')
        if state['phase'] == 'verified':
            completed_peer = peer['phase'] in ('finishing','complete')
            if completed_peer:
                self.check_completion(state,peer)
            else:
                now = int(time.time())
                require(all(type(t) is int and 0 <= now-t <= 30 for t in [state['verified_at'],peer['verified_at']]), 'Pair verification expired; verify again')
            current, executable = process_identity()
            require(executable == Path(self.own(state)['own']['candidate']['directory'])/'noisefence', 'Unexpected running executable')
            require(completed_peer or current == state['verification']['own']['process'],'Normal daemon restarted after verification')
            # A peer's durable completion already authorizes this pair. Permit
            # delayed catch-up without trying to undo normal policy advancement.
            state = self.save(state,'finishing',peer_finish=peer)
        # A direct retry can recover an intent renamed before directory fsync.
        # Make that intent durable before releasing any auxiliary job fence.
        reservation.sync_directory(self.path.parent)
        self.job_conditions(missing_ok=True)
        # A crash may have removed only some owned drop-ins, before reload.
        # Reconcile that authorized deletion before requiring a clean fingerprint.
        reservation.execute(['/usr/bin/systemctl','daemon-reload'])
        self.installation(state,jobs=True,policy=False)
        self.job_conditions(remove=True)
        if reservation.exists(self.jobs):reservation.remove(self.jobs)
        for unit in reservation.RESUMABLE:
            if unit != NORMAL and held['units'][unit] == 'active':
                if reservation.unit_state(unit) == 'failed':reservation.execute(['/usr/bin/systemctl','reset-failed',unit])
                reservation.execute(['/usr/bin/systemctl','start',unit])
                require(reservation.unit_state(unit) == 'active','Original timer did not resume')
        self.hold.save(held,'upgraded')
        self.promoted.save(promoted,'activated')
        state = self.save(state,'complete')
        return self.cleanup(state)

    def abort(self):
        state = self.state();self.owner()
        require(state['decision'] is not None and state['decision']['outcome']=='abort'
                and state['phase'] in ('decided','aborting','aborted'),'Committed activation cannot use pre-commit restoration')
        self.save(state,'aborting')
        self.promoted.restore(activation_abort=True)
        self.save(self.state(),'aborted');return self.report()

    def cancel(self, peer):
        state=self.state();self.match_peer(state,peer)
        require(state['phase'] in ('aborted','cancelling','cancelled') and peer['phase'] in ('aborted','cancelling','cancelled')
                and peer['decision']==state['decision'],'Both aborted pointers must be restored')
        if state['phase']=='cancelled':return self.cleanup(state)
        self.owner()
        if state['phase']=='aborted':state=self.save(state,'cancelling',peer_finish=peer)
        own=self.promoted.state()
        report={'protocol':promotion.REPORT,'operation':self.operation,'phase':'restored',
                'descriptor':self.peer(state),'pair_sha256':own['pair_sha256']}
        self.promoted.release(report,activation_abort=True)
        self.hold.cancel(activation_abort=True)
        state=self.save(state,'cancelled');return self.cleanup(state)

    def cleanup(self,state):
        require(state['phase'] in ('complete','cancelled'),'Activation is not terminal')
        # The host reservation is removed LAST. A lost cleanup reply cannot let
        # another supported operation adopt a partly cleaned activation.
        if not reservation.exists(reservation.ACTIVE):
            require(not reservation.exists(self.marker),'Unowned terminal activation marker')
            return self.report()
        self.hold.owner()
        require(not reservation.exists(reservation.HOLD) and not reservation.exists(self.jobs),'Terminal operation retains a hold')
        if reservation.exists(self.promoted.marker):self.promoted.owner();reservation.remove(self.promoted.marker)
        if reservation.exists(self.marker):self.owner();reservation.remove(self.marker)
        reservation.remove(reservation.ACTIVE)
        return self.report()


def allow_abort(operation, cancellation=False):
    state=Activation(operation).state()
    require(state['decision'] is not None and state['decision']['outcome']=='abort'
            and state['phase'] in (('cancelling',) if cancellation else ('aborting','aborted','cancelling')),
            'Only the durable abort decision permits restoration')
    Activation(operation).owner()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=['arm','decide','accept','start','check','verify','finish','abort','cancel','status'])
    parser.add_argument('--operation',required=True);parser.add_argument('--peer-report',type=Path)
    parser.add_argument('--outcome',choices=['activate','abort'])
    args=parser.parse_args();require(os.geteuid()==0,'Root is required');os.umask(0o077)
    needs=args.action in ('arm','accept','start','check','verify','finish','cancel') or (args.action=='decide' and args.outcome=='activate')
    require((args.peer_report is not None)==needs and (args.outcome is not None)==(args.action=='decide'),'Unexpected action arguments')
    with reservation.operation_lock():
        operation=Activation(args.operation)
        peer=reservation.read_json(args.peer_report) if args.peer_report else None
        result=(operation.report() if args.action=='status' else operation.decide(args.outcome,peer) if args.action=='decide'
                else getattr(operation,args.action)(peer) if needs else getattr(operation,args.action)())
    print(json.dumps(result))


if __name__=='__main__':
    try:main()
    except Exception as error:
        print('Paired activation stopped: '+type(error).__name__+': '+str(error)[:300],file=sys.stderr);sys.exit(1)
