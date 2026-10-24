#!/usr/bin/env python3
"""Supervise a temporary candidate on an already reserved native MX.

No release switch, policy change or SMTP activation. The paired controller must
obtain each root descriptor through its verified SSH channel before starting.
"""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import sys
import time
import urllib.request

import upgrade_reservation as reservation
from migration_protocol import atomic, canonical, checked_selection, identity, pairs, require
from release_version import valid as valid_version

PROTOCOL = 'noisefence-upgrade-validation-1'
DESCRIPTOR = 'noisefence-upgrade-validation-descriptor-1'
SERVICE = 'noisefence-validation.service'
PLAN = Path('/etc/noisefence/maintenance-validation.json')
LINK = Path('/opt/noisefence/validation')
UNIT = Path('/etc/systemd/system') / SERVICE
TEMPLATE = Path(__file__).with_name('upgrade_validation.service')
HASH = re.compile('[a-f0-9]{64}')


def epoch(value):
    return (isinstance(value, dict) and set(value) == {'sequence', 'revision', 'digest'}
            and all(type(value[k]) is int and 0 <= value[k] <= 2**63-1 for k in ('sequence', 'revision'))
            and isinstance(value['digest'], str) and HASH.fullmatch(value['digest']))


def checked_descriptor(value):
    require(isinstance(value, dict) and set(value) == {'protocol', 'operation', 'expires_at', 'selection', 'policy', 'candidate', 'config_sha256', 'service_sha256', 'replica_peer'}
            and value['protocol'] == DESCRIPTOR and identity(value['operation'])
            and type(value['expires_at']) is int and epoch(value['policy'])
            and all(isinstance(value[k], str) and HASH.fullmatch(value[k]) for k in ('config_sha256', 'service_sha256')),
            'Invalid validation descriptor')
    checked_selection(value['selection'])
    require(isinstance(value['replica_peer'], str) and re.fullmatch('[a-z0-9_-]{1,40}', value['replica_peer']),
            'Invalid descriptor peer identity')
    candidate = value['candidate']
    require(isinstance(candidate, dict) and set(candidate) == {'directory', 'binary_sha256', 'manifest_sha256', 'build_sha256', 'version', 'commit', 'platform'}
            and isinstance(candidate['directory'], str) and Path(candidate['directory']).is_absolute()
            and all(isinstance(candidate[k], str) and HASH.fullmatch(candidate[k]) for k in ('binary_sha256', 'manifest_sha256', 'build_sha256'))
            and valid_version(candidate['version'])
            and isinstance(candidate['commit'], str) and re.fullmatch('[a-f0-9]{40}', candidate['commit'])
            and candidate['platform'] in ('linux-amd64', 'linux-arm64'), 'Invalid candidate identity')
    return value


def policy_epoch():
    path = reservation.DATA / 'state.sqlite3'
    with sqlite3.connect(path.as_uri()+'?mode=ro', uri=True, timeout=2) as db:
        db.execute('PRAGMA query_only=ON')
        row = db.execute("SELECT CASE WHEN length(value)<=4194304 THEN value END FROM cluster_state WHERE key='activation_participant'").fetchone()
    require(row and row[0], 'Installed participant policy missing or oversized')
    local = json.loads(row[0], object_pairs_hook=pairs)
    installed = local.get('installed_epoch'); authority = local.get('authority', {})
    current = authority.get('current', {}); rollout = authority.get('rollout', {})
    require(epoch(installed) and isinstance(rollout, dict) and rollout.get('phase') in ('released', 'aborted')
            and installed == {'sequence': authority.get('current_sequence'), 'revision': current.get('revision'), 'digest': current.get('digest')},
            'Resolve pending local policy before candidate validation')
    return installed


def candidate(path):
    files, manifest = reservation.release_inventory(path)
    build = reservation.read_json(path/'build.json')
    require(build.get('project') == 'NoiseFence' and build.get('storage_schema') == 7,
            'Candidate requires the selected-management storage contract')
    return {'directory': str(path), 'binary_sha256': files['noisefence'],
            'manifest_sha256': hashlib.sha256(manifest).hexdigest(), 'build_sha256': files['build.json'],
            'version': build.get('version'), 'commit': build.get('commit'), 'platform': build.get('platform')}


def held(operation):
    hold = reservation.Reservation(operation)
    hold.owner(); status = hold.status(); recorded = hold.state()
    require(status['phase'] == 'held' and all(status[key] for key in ('reserved', 'service_hold', 'writers_stopped')),
            'Both normal writers and services must remain held')
    require(reservation.installation() == recorded['installation'], 'Reserved installation changed')
    return hold


def describe(operation, directory, expires_at):
    require(type(expires_at) is int and int(time.time()) < expires_at <= int(time.time())+3600,
            'Validation authorization expired or exceeds one hour')
    held(operation)
    selected = reservation.read_selection(reservation.DATA)
    require(selected is not None, 'Selected PostgreSQL management is required')
    import tomllib
    with reservation.private_read(reservation.CONFIG, 1024*1024) as source:
        raw = source.read()
    config = tomllib.loads(raw.decode())
    return checked_descriptor({'protocol': DESCRIPTOR, 'operation': operation, 'expires_at': expires_at,
        'selection': selected, 'policy': policy_epoch(), 'candidate': candidate(directory),
        'config_sha256': hashlib.sha256(raw).hexdigest(), 'service_sha256': hashlib.sha256(unit_template()).hexdigest(), 'replica_peer': config['replication']['peer_id']})


def authorize(own, peer):
    checked_descriptor(own); checked_descriptor(peer)
    left, right = own['selection'], peer['selection']
    require(own['operation'] == peer['operation'] and own['expires_at'] == peer['expires_at']
            and left['database'] == right['database'] and own['policy'] == peer['policy']
            and left['role'] != right['role'] and left['node']['node'] != right['node']['node']
            and own['replica_peer'] == right['node']['node'] and peer['replica_peer'] == left['node']['node']
            and own['candidate']['version'] == peer['candidate']['version']
            and own['candidate']['commit'] == peer['candidate']['commit'], 'Peer descriptor does not name the same reserved pair and candidate version')
    return {'protocol': 'noisefence-maintenance-validation-1', 'operation': own['operation'],
            'selection': left, 'policy': own['policy'],
            'peer': {'identity': right['node'], 'binary_sha256': peer['candidate']['binary_sha256']},
            'config_sha256': own['config_sha256'], 'binary_sha256': own['candidate']['binary_sha256'],
            'expires_at': own['expires_at']}


def unit_template():
    reservation.protected(TEMPLATE)
    with reservation.private_read(TEMPLATE, 16384) as source:
        raw = source.read()
    # Preserve mandatory-access profiles applied to the normal native service.
    # Never quietly weaken an installed profile for a validation process.
    for key in ('AppArmorProfile', 'SELinuxContext'):
        value = reservation.execute(['/usr/bin/systemctl', 'show', 'noisefence.service', '--property='+key, '--value']).decode().strip()
        require(not value or (len(value) <= 512 and re.fullmatch('[A-Za-z0-9_:/.,+@-]+', value)),
                'Unsupported native mandatory-access profile')
        if value:
            raw += (key+'='+value+'\n').encode()
    return raw


def service_files(install=False, missing_ok=False):
    if reservation.exists(UNIT):
        reservation.protected(UNIT)
        require(UNIT.read_bytes() == unit_template(), 'Unexpected validation service definition')
    elif install:
        atomic(UNIT, unit_template(), mode=0o644)
    else:
        require(missing_ok and reservation.unit_state(SERVICE) in ('inactive', 'failed', 'unknown'),
                'Validation service definition missing')
    # An unreviewed drop-in can change User/ExecStart or disable limits.
    dropins = reservation.execute(['/usr/bin/systemctl', 'show', SERVICE, '--property=DropInPaths', '--value']).strip()
    require(not dropins, 'Validation service has unreviewed drop-ins')


def link_to(directory):
    reservation.protected(LINK.parent, True)
    if reservation.exists(LINK):
        info = LINK.lstat()
        require(stat.S_ISLNK(info.st_mode) and info.st_uid == 0 and os.readlink(LINK) == directory,
                'Unexpected candidate pointer')
        return
    temporary = LINK.with_name(LINK.name+'.next')
    if reservation.exists(temporary):
        info = temporary.lstat()
        require(stat.S_ISLNK(info.st_mode) and info.st_uid == 0 and os.readlink(temporary) == directory,
                'Unexpected temporary candidate pointer')
    else:
        temporary.symlink_to(directory)
    os.replace(temporary, LINK); reservation.sync_directory(LINK.parent)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def health_url():
    import tomllib
    with reservation.private_read(reservation.CONFIG, 1024*1024) as source:
        config = tomllib.loads(source.read().decode())
    host, _, port = config['web']['listen'].rpartition(':'); host = host.strip('[]')
    require(ipaddress.ip_address(host).is_loopback and port.isdecimal() and 0 < int(port) < 65536,
            'Validation health must use the configured loopback listener')
    return f'http://{host if ":" not in host else "["+host+"]"}:{port}/healthz'


class Validation:
    def __init__(self, operation):
        require(identity(operation), 'Canonical operation UUID required')
        self.operation = operation
        self.path = reservation.STATE / (operation+'-validation.json')
        self.marker = reservation.STATE / 'validation.json'

    def state(self):
        value = reservation.read_json(self.path)
        require(isinstance(value, dict) and set(value) == {'protocol', 'operation', 'phase', 'own', 'peer', 'plan'}
                and value['protocol'] == PROTOCOL and value['operation'] == self.operation
                and value['phase'] in ('prepared', 'started', 'stopping', 'stopped')
                and value['plan'] == authorize(value['own'], value['peer'])
                and value['own']['operation'] == self.operation, 'Invalid candidate validation receipt')
        return value

    def save(self, state, phase):
        result = {**state, 'phase': phase}; atomic(self.path, canonical(result)); return result

    def owner(self):
        require(reservation.read_json(self.marker) == {'protocol': PROTOCOL, 'operation': self.operation},
                'Another operation owns candidate validation')

    def start(self, directory, peer, expires_at):
        reservation.require_no_activation(self.operation)
        require(not reservation.exists(reservation.STATE / 'promotion.json')
                and not reservation.exists(reservation.STATE / (self.operation+'-promotion.json')),
                'Prepared promotion owns this operation; restore the pair before resuming')
        own = describe(self.operation, directory, expires_at)
        plan = authorize(own, peer)
        if reservation.exists(self.marker):
            self.owner()
        if reservation.exists(self.path):
            state = self.state()
            require(state['phase'] in ('prepared', 'started') and state['own'] == own and state['peer'] == peer,
                    'Validation already finished or authorization changed')
        else:
            require(not reservation.exists(self.marker) and not reservation.exists(PLAN)
                    and not reservation.exists(LINK) and reservation.unit_state(SERVICE) in ('inactive', 'failed', 'unknown'),
                    'Unowned candidate validation requires recovery')
            state = self.save({'protocol': PROTOCOL, 'operation': self.operation, 'own': own, 'peer': peer, 'plan': plan}, 'prepared')
        # Receipt and marker precede service setup/start. Cancellation cannot
        # remove the normal hold after a disconnect at any later step.
        atomic(self.marker, canonical({'protocol': PROTOCOL, 'operation': self.operation}))
        require(hashlib.sha256(unit_template()).hexdigest() == own['service_sha256'], 'Validation service authorization changed')
        service_files(install=True)
        reservation.protected(PLAN.parent, True)
        if reservation.exists(PLAN):
            require(reservation.read_json(PLAN) == plan, 'Unexpected candidate authorization')
        else:
            atomic(PLAN, canonical(plan), mode=0o644)
        link_to(own['candidate']['directory'])
        reservation.execute(['/usr/bin/systemctl', 'daemon-reload'])
        service_files()  # Recheck the effective drop-in inventory after reload.
        held(self.operation)
        require(int(time.time()) < expires_at, 'Validation authorization expired during preparation')
        if reservation.unit_state(SERVICE) == 'failed':
            reservation.execute(['/usr/bin/systemctl', 'reset-failed', SERVICE])
        reservation.execute(['/usr/bin/systemctl', 'start', SERVICE])
        require(reservation.unit_state(SERVICE) == 'active', 'Candidate process failed to start; preserve both holds')
        self.save(state, 'started')
        return self.status()

    def status(self):
        state = self.state()
        if state['phase'] == 'stopped':
            return {'operation': self.operation, 'phase': 'stopped', 'validation_ready': False}
        self.owner(); held(self.operation)
        ready = False; observation = None
        try:
            require(state['phase'] == 'started' and reservation.read_json(PLAN) == state['plan'],
                    'Validation has not started or its authorization was revoked')
            require(int(time.time()) < state['plan']['expires_at'], 'Authorization expired')
            service_files()
            require(hashlib.sha256(unit_template()).hexdigest() == state['own']['service_sha256'], 'Validation service authorization changed')
            pid = int(reservation.execute(['/usr/bin/systemctl', 'show', SERVICE, '--property=MainPID', '--value']).strip())
            require(pid > 0 and reservation.unit_state(SERVICE) == 'active', 'Candidate is not active')
            binary = Path(f'/proc/{pid}/exe').resolve(strict=True)
            require(binary == Path(state['own']['candidate']['directory'])/'noisefence'
                    and reservation.file_digest(binary, 2*1024**3) == state['plan']['binary_sha256'], 'Running candidate differs')
            with urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect()).open(health_url(), timeout=3) as response:
                raw = response.read(8193); require(len(raw) <= 8192, 'Oversized validation response')
                observation = json.loads(raw, object_pairs_hook=pairs)
            require(observation.get('status') == 'maintenance_validation'
                    and observation.get('operation') == self.operation
                    and observation.get('node') == state['own']['selection']['node']['node']
                    and observation.get('binary_sha256') == state['plan']['binary_sha256']
                    and observation.get('version') == state['own']['candidate']['version']
                    and observation.get('expires_at') == state['plan']['expires_at']
                    and type(observation.get('checked_at')) is int
                    and int(time.time())-5 <= observation['checked_at'] <= int(time.time())
                    and all(observation.get(key) is False for key in ('smtp_ready', 'delivery_enabled', 'administration_enabled')),
                    'Unexpected maintenance readiness receipt')
            ready = observation.get('validation_ready') is True
        except (OSError, ValueError, KeyError, json.JSONDecodeError):
            observation = None
        return {'operation': self.operation, 'phase': state['phase'], 'validation_ready': ready,
                'normal_services_held': True, 'node': state['own']['selection']['node']['node'],
                'binary_sha256': state['plan']['binary_sha256'], 'expires_at': state['plan']['expires_at'],
                'observation': observation}

    def stop(self):
        state = self.state()
        if state['phase'] == 'stopped':
            require(not reservation.exists(PLAN) and not reservation.exists(LINK), 'Candidate artifacts remain after stop')
            if reservation.exists(self.marker):
                self.owner(); reservation.remove(self.marker)
            return {'operation': self.operation, 'phase': 'stopped', 'validation_ready': False}
        self.owner(); reservation.Reservation(self.operation).owner()
        state = self.save(state, 'stopping')
        # Revoke authorization before stopping. Reboot/restart cannot reload it.
        if reservation.exists(PLAN):
            require(reservation.read_json(PLAN) == state['plan'], 'Unexpected candidate authorization')
            reservation.remove(PLAN)
        service_files(missing_ok=True)
        if reservation.unit_state(SERVICE) != 'unknown':
            reservation.execute(['/usr/bin/systemctl', 'stop', SERVICE])
        require(reservation.unit_state(SERVICE) in ('inactive', 'failed', 'unknown'), 'Candidate did not stop; preserve holds')
        if reservation.exists(LINK):
            info = LINK.lstat()
            require(stat.S_ISLNK(info.st_mode) and info.st_uid == 0
                    and os.readlink(LINK) == state['own']['candidate']['directory'], 'Candidate pointer changed')
            reservation.remove(LINK)
        self.save(state, 'stopped'); reservation.remove(self.marker)
        return {'operation': self.operation, 'phase': 'stopped', 'validation_ready': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['describe', 'start', 'status', 'stop'])
    parser.add_argument('--operation', required=True)
    parser.add_argument('--candidate', type=Path)
    parser.add_argument('--peer-report', type=Path)
    parser.add_argument('--expires-at', type=int)
    args = parser.parse_args()
    require(os.geteuid() == 0, 'Root is required'); os.umask(0o077)
    with reservation.operation_lock():
        if args.action in ('describe', 'start'):
            require(args.candidate is not None and args.expires_at is not None, 'Candidate directory and explicit expiry required')
            require(args.candidate.is_absolute(), 'Absolute candidate directory required')
        if args.action == 'describe': result = describe(args.operation, args.candidate, args.expires_at)
        elif args.action == 'start':
            require(args.peer_report is not None, 'Root-reviewed peer report required')
            result = Validation(args.operation).start(args.candidate, reservation.read_json(args.peer_report), args.expires_at)
        else: result = getattr(Validation(args.operation), args.action)()
    print(json.dumps(result))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print('Candidate validation stopped: '+type(error).__name__+': '+str(error)[:300], file=sys.stderr)
        sys.exit(1)
