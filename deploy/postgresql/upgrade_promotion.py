#!/usr/bin/env python3
"""Prepare and switch a validated pair under durable, stopped-service holds.

This pre-commit primitive never starts normal services or authorizes activation.
Reports must be exchanged through authenticated operator channels. Root is the
trust boundary; receipt digests are bindings, not signatures or publisher proof.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

import upgrade_reservation as reservation
import upgrade_validation as validation
from migration_protocol import atomic, canonical, identity, require, sha

PROTOCOL = 'noisefence-upgrade-promotion-1'
PREPARED = 'noisefence-upgrade-prepared-1'
REPORT = 'noisefence-upgrade-promotion-report-1'
PHASES = ('prepared', 'promoting', 'promoted', 'restoring', 'restored', 'released', 'activated')


def fingerprint(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def service_fingerprint(ignored_dropin=None):
    """Bind the installed definitions of every writer, including optional jobs."""
    result = {}
    for unit in reservation.FENCED:
        raw = reservation.execute(['/usr/bin/systemctl', 'show',
            '--property=LoadState,FragmentPath,DropInPaths,NeedDaemonReload', unit])
        require(len(raw) <= 32768, 'Oversized installed service description')
        fields = {}
        for line in raw.decode().splitlines():
            key, separator, value = line.partition('=')
            require(separator and key not in fields, 'Invalid installed service description')
            fields[key] = value
        require(set(fields) == {'LoadState', 'FragmentPath', 'DropInPaths', 'NeedDaemonReload'}
                and fields['NeedDaemonReload'] == 'no', 'Reload and review installed service definitions')
        if fields['LoadState'] == 'not-found':
            require(not fields['FragmentPath'] and not fields['DropInPaths'], 'Unexpected missing unit files')
            result[unit] = None
            continue
        require(fields['LoadState'] == 'loaded' and fields['FragmentPath'], 'Unknown installed service state')
        if ignored_dropin is not None:
            fields['DropInPaths'] = ' '.join(p for p in fields['DropInPaths'].split(' ') if p and Path(p).name != ignored_dropin)
        paths = [fields['FragmentPath'], *fields['DropInPaths'].split(' ')]
        files = {}
        for name in filter(None, paths):
            path = Path(name)
            require(re.fullmatch('/[A-Za-z0-9_./@:-]+', name) and '..' not in path.parts,
                    'Unsupported installed service path')
            physical = path.resolve(strict=True)
            files[name] = {'physical': str(physical), 'sha256': reservation.file_digest(physical, 1024*1024)}
        result[unit] = {'properties': fields, 'files': files}
    return fingerprint(result)


def _checked_prepared(value, protocol, authorize, check_original):
    require(isinstance(value, dict) and set(value) == {'protocol', 'operation', 'own', 'peer',
                'original', 'installation', 'service_sha256', 'prepared_at', 'validated_at'}
            and value['protocol'] == protocol and identity(value['operation'])
            and sha(value['service_sha256']) and type(value['prepared_at']) is int,
            'Invalid prepared release descriptor')
    own, peer = value['own'], value['peer']
    authorize(own, peer)
    require(own['operation'] == value['operation']
            and value['prepared_at'] > 0
            and (value['validated_at'] is None or (type(value['validated_at']) is int
                and 0 < value['validated_at'] <= value['prepared_at'] < own['expires_at'])), 'Invalid preparation lifetime')
    # Reuse the candidate schema for the retained, independently verified release.
    check_original(own, value['original'])
    installed = value['installation']; old = value['original']
    require(isinstance(installed, dict) and set(installed) == {'node', 'role', 'config_sha256',
                'current_link', 'release_directory', 'manifest_sha256', 'binary_sha256', 'build_sha256', 'selection_sha256'}
            and installed['node'] == own['selection']['node']['node'] and installed['role'] == own['selection']['role']
            and installed['config_sha256'] == own['config_sha256']
            and installed['selection_sha256'] == fingerprint(own['selection'])
            and isinstance(installed['current_link'], str) and installed['current_link']
            and installed['release_directory'] == old['directory']
            and all(installed[k] == old[k] for k in ('manifest_sha256', 'binary_sha256', 'build_sha256'))
            and (value['validated_at'] is None or (old['directory'] != own['candidate']['directory']
                and old['platform'] == own['candidate']['platform'])), 'Prepared installation differs from its release or authority')
    return value


def checked_prepared(value):
    return _checked_prepared(value, PREPARED, validation.authorize,
                             lambda own, original: validation.checked_descriptor({**own, 'candidate': original}))


def _paired(own, peer, check):
    check(own); check(peer)
    require(own['own'] == peer['peer'] and own['peer'] == peer['own'],
            'Prepared peer does not describe the same candidate pair')
    # Architecture-specific release hashes may differ. The entire descriptors
    # are ordered by immutable node identity, not controller arrival order.
    return fingerprint(sorted([own, peer], key=lambda d: d['own']['selection']['node']['node']))


def paired(own, peer):
    return _paired(own, peer, checked_prepared)


def _checked_report(value, protocol, check):
    require(isinstance(value, dict) and set(value) == {'protocol', 'operation', 'phase', 'descriptor', 'pair_sha256'}
            and value['protocol'] == protocol and identity(value['operation']) and value['phase'] in PHASES,
            'Invalid peer promotion report')
    check(value['descriptor'])
    require(value['operation'] == value['descriptor']['operation']
            and (value['pair_sha256'] is None or sha(value['pair_sha256'])), 'Invalid peer pair binding')
    require(value['pair_sha256'] is not None or value['phase'] in ('prepared', 'restoring', 'restored'),
            'Peer promotion report missing its pair binding')
    return value


def checked_report(value):
    return _checked_report(value, REPORT, checked_prepared)


def switch_current(target, operation):
    """Atomic pointer replacement with a recoverable, operation-specific intent."""
    parent = reservation.CURRENT.parent
    reservation.protected(parent, True)
    temporary = parent / ('.noisefence-upgrade-'+operation)
    if reservation.exists(temporary):
        info = temporary.lstat()
        require(stat.S_ISLNK(info.st_mode) and info.st_uid == 0 and os.readlink(temporary) == target,
                'Unexpected pending release pointer; preserve the hold')
    else:
        temporary.symlink_to(target)
    os.replace(temporary, reservation.CURRENT)
    reservation.sync_directory(parent)


class Promotion:
    protocol = PROTOCOL
    prepared_protocol = PREPARED
    report_protocol = REPORT
    checked_prepared = staticmethod(checked_prepared)
    checked_report = staticmethod(checked_report)
    paired = staticmethod(paired)

    def validator(self):
        return validation.Validation(self.operation)

    def require_target(self, descriptor):
        validation.require_forward_upgrade(descriptor['original'], descriptor['own']['candidate'])

    def verify_context(self, state):
        # Ordinary upgrades have no historical rollback authorization.
        pass

    def __init__(self, operation):
        require(identity(operation), 'Canonical operation UUID required')
        self.operation = operation
        self.path = reservation.STATE / (operation+'-promotion.json')
        self.marker = reservation.STATE / 'promotion.json'
        self.hold = reservation.Reservation(operation)
        self.validation = self.validator()

    def state(self):
        state = reservation.read_json(self.path)
        require(isinstance(state, dict) and set(state) == {'protocol', 'operation', 'phase', 'descriptor', 'peer', 'pair_sha256'}
                and state['protocol'] == self.protocol and state['operation'] == self.operation
                and state['phase'] in PHASES, 'Invalid promotion receipt')
        self.checked_prepared(state['descriptor'])
        require(state['descriptor']['operation'] == self.operation, 'Promotion operation differs')
        require(state['phase'] not in ('prepared', 'promoting', 'promoted') or state['descriptor']['validated_at'] is not None,
                'Unvalidated restoration cannot authorize promotion')
        if state['peer'] is None:
            require(state['pair_sha256'] is None and state['phase'] in ('prepared', 'restoring', 'restored'),
                    'Incomplete prepared pair receipt')
        else:
            require(state['pair_sha256'] == self.paired(state['descriptor'], state['peer']), 'Promotion pair binding differs')
        return state

    def save(self, state, phase):
        state = {**state, 'phase': phase}
        atomic(self.path, canonical(state))
        return state

    def report(self):
        state = self.state()
        reservation.sync_directory(self.path.parent)
        return {'protocol': self.report_protocol, 'operation': self.operation, 'phase': state['phase'],
                'descriptor': state['descriptor'], 'pair_sha256': state['pair_sha256']}

    def owner(self, allow_missing=False):
        expected = {'protocol': self.protocol, 'operation': self.operation}
        if reservation.exists(self.marker):
            require(reservation.read_json(self.marker) == expected, 'Another promotion owns the hold')
        else:
            require(allow_missing, 'Promotion marker missing; preserve the hold')
        return expected

    def frozen(self, state):
        """Every pointer mutation requires a held, unchanged authority and policy."""
        self.verify_context(state)
        self.hold.owner()
        status = self.hold.status()
        require(status['phase'] == 'held' and all(status[k] for k in ('reserved', 'service_hold', 'writers_stopped')),
                'Normal services must remain durably stopped')
        descriptor = state['descriptor']
        require(self.hold.state()['installation'] == descriptor['installation']
                and validation.policy_epoch() == descriptor['own']['policy']
                and service_fingerprint() == descriptor['service_sha256'], 'Reserved policy or installed service changed')
        current = reservation.installation()
        old = descriptor['installation']
        new = descriptor['own']['candidate']
        expected = {**old, 'current_link': new['directory'], 'release_directory': new['directory'],
                    **{k: new[k] for k in ('manifest_sha256', 'binary_sha256', 'build_sha256')}}
        require(current in (old, expected), 'Current installation is neither authorized release; preserve the hold')
        return current, expected

    def prepare(self):
        reservation.require_no_activation(self.operation)
        validation.held(self.operation)
        self.owner(allow_missing=True)
        saved = reservation.exists(self.path)
        if saved:
            state = self.state()
            require(state['phase'] == 'prepared', 'Promotion preparation already advanced')
            self.frozen(state)
        else:
            require(not reservation.exists(self.marker), 'Orphaned promotion marker')
            report = self.validation.status()
            require(report.get('validation_ready') is True, 'Live candidate pair validation is required')
            candidate = self.validation.state()
            own = candidate['own']
            installed = self.hold.state()['installation']
            now = int(time.time())
            descriptor = self.checked_prepared({'protocol': self.prepared_protocol, 'operation': self.operation,
                'own': own, 'peer': candidate['peer'], 'installation': installed,
                'original': validation.candidate(Path(installed['release_directory'])),
                'service_sha256': service_fingerprint(), 'prepared_at': now, 'validated_at': now})
            self.require_target(descriptor)
            require(validation.candidate(Path(own['candidate']['directory'])) == own['candidate'],
                    'Validated candidate files changed')
            state = {'protocol': self.protocol, 'operation': self.operation, 'descriptor': descriptor, 'peer': None, 'pair_sha256': None}
            self.verify_context(state)
            # The reservation cancellation guard also reads this receipt, so a
            # crash between these two durable writes cannot release normal jobs.
            state = self.save(state, 'prepared')
        atomic(self.marker, canonical(self.owner(allow_missing=True)))
        return self.report()

    def promote(self, peer_report):
        reservation.require_no_activation(self.operation)
        state = self.state(); self.owner()
        peer = self.checked_report(peer_report)
        require(state['phase'] in ('prepared', 'promoting', 'promoted')
                and peer['phase'] in ('prepared', 'promoting', 'promoted'), 'Pair is no longer preparing promotion')
        binding = self.paired(state['descriptor'], peer['descriptor'])
        require(all(state['descriptor']['original'][k] == peer['descriptor']['original'][k] for k in ('version', 'commit')),
                'Promotion requires the same original version and source commit')
        for descriptor in (state['descriptor'], peer['descriptor']):
            self.require_target(descriptor)
        require(state['descriptor']['validated_at'] is not None and peer['descriptor']['validated_at'] is not None,
                'Both candidates must have completed live validation')
        require(peer['pair_sha256'] in (None, binding) and state['peer'] in (None, peer['descriptor']),
                'Previously authorized peer changed')
        self.frozen(state)
        require(int(time.time()) < state['descriptor']['own']['expires_at'],
                'Preparation expired; restore the retained pair instead')
        if state['phase'] == 'prepared':
            state = self.save({**state, 'peer': peer['descriptor'], 'pair_sha256': binding}, 'promoting')
        self.validation.stop()
        require(not reservation.exists(self.validation.marker)
                and reservation.unit_state(validation.SERVICE) in ('inactive', 'failed', 'unknown'),
                'Stop the candidate before changing the normal pointer')
        current, expected = self.frozen(state)
        require(validation.candidate(Path(state['descriptor']['own']['candidate']['directory'])) == state['descriptor']['own']['candidate'],
                'Candidate inventory changed after validation')
        if current != expected:
            switch_current(expected['current_link'], self.operation)
        require(reservation.installation() == expected, 'Promoted installation differs; preserve the hold')
        # A previous process may have renamed successfully but died before the
        # parent fsync. Re-observing the desired target is not durability proof.
        reservation.sync_directory(reservation.CURRENT.parent)
        self.save(state, 'promoted')
        return self.report()

    def abandon(self, peer_report):
        reservation.require_no_activation(self.operation)
        """Allow safe pair cancellation if this peer never completed validation."""
        peer = self.checked_report(peer_report)
        self.owner(allow_missing=True)
        if reservation.exists(self.path):
            state = self.state()
            require(state['phase'] in ('restoring', 'restored') and state['peer'] == peer['descriptor'],
                    'Existing preparation must use its recorded restoration path')
        else:
            require(not reservation.exists(self.marker), 'Orphaned promotion marker')
            validation.held(self.operation)
            own = peer['descriptor']['peer']
            installed = self.hold.state()['installation']
            # No ready assertion is fabricated. This descriptor can only restore
            # the unchanged retained installation and release its service hold.
            descriptor = self.checked_prepared({'protocol': self.prepared_protocol, 'operation': self.operation,
                'own': own, 'peer': peer['descriptor']['own'], 'installation': installed,
                'original': validation.candidate(Path(installed['release_directory'])),
                'service_sha256': service_fingerprint(), 'prepared_at': int(time.time()), 'validated_at': None})
            binding = self.paired(descriptor, peer['descriptor'])
            require(peer['pair_sha256'] is None, 'Peer already bound another prepared descriptor')
            state = self.save({'protocol': self.protocol, 'operation': self.operation, 'descriptor': descriptor,
                               'peer': peer['descriptor'], 'pair_sha256': binding}, 'restoring')
        atomic(self.marker, canonical(self.owner(allow_missing=True)))
        return self.restore()

    def stop_validation(self):
        if reservation.exists(self.validation.path):
            self.validation.stop()
        else:
            require(not any(reservation.exists(p) for p in (self.validation.marker, validation.PLAN, validation.LINK)),
                    'Unowned candidate validation requires recovery')
        require(reservation.unit_state(validation.SERVICE) in ('inactive', 'failed', 'unknown'), 'Validation still running')

    def restore(self, *, activation_abort=False):
        reservation.require_no_activation(self.operation, abort=activation_abort)
        state = self.state(); self.owner()
        require(state['phase'] != 'released', 'Promotion already released')
        self.frozen(state)
        state = self.save(state, 'restoring')
        self.stop_validation()
        current, _ = self.frozen(state)
        old = state['descriptor']['installation']
        require(validation.candidate(Path(old['release_directory'])) == state['descriptor']['original'],
                'Retained release changed; preserve the hold')
        # Recover an interrupted promotion's uncommitted symlink before writing
        # the opposite intent. Never remove an unknown path or inode.
        temporary = reservation.CURRENT.parent / ('.noisefence-upgrade-'+self.operation)
        if reservation.exists(temporary):
            info = temporary.lstat()
            require(stat.S_ISLNK(info.st_mode) and info.st_uid == 0
                    and os.readlink(temporary) in (old['current_link'], state['descriptor']['own']['candidate']['directory']),
                    'Unexpected pending pointer during restoration')
            reservation.remove(temporary)
        if current != old:
            switch_current(old['current_link'], self.operation)
        require(reservation.installation() == old, 'Retained installation differs; preserve the hold')
        reservation.sync_directory(reservation.CURRENT.parent)
        self.save(state, 'restored')
        return self.report()

    def release(self, peer_report, *, activation_abort=False):
        reservation.require_no_activation(self.operation, abort=activation_abort)
        state = self.state(); self.owner(allow_missing=state['phase'] == 'released')
        peer = self.checked_report(peer_report)
        require(state['phase'] in ('restored', 'released') and peer['phase'] in ('restored', 'released'),
                'Both original installations must be restored before cancellation')
        binding = self.paired(state['descriptor'], peer['descriptor'])
        require(state['peer'] in (None, peer['descriptor']) and peer['pair_sha256'] in (None, binding), 'Restored peer changed')
        # A lost reply after release/cancel returns the historical receipt only;
        # it never removes a newer operation's hold or starts services itself.
        if state['phase'] == 'released' and not reservation.exists(self.marker):
            return self.report()
        current, _ = self.frozen(state)
        require(current == state['descriptor']['installation'], 'Original release not restored')
        self.save({**state, 'peer': peer['descriptor'], 'pair_sha256': binding}, 'released')
        reservation.remove(self.marker)
        return self.report()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['prepare', 'promote', 'restore', 'abandon', 'release', 'status'])
    parser.add_argument('--operation', required=True)
    parser.add_argument('--peer-report', type=Path)
    args = parser.parse_args()
    require(os.geteuid() == 0, 'Root is required'); os.umask(0o077)
    require((args.peer_report is not None) == (args.action in ('promote', 'abandon', 'release')), 'Unexpected or missing peer report')
    with reservation.operation_lock():
        operation = Promotion(args.operation)
        if args.peer_report is not None:
            peer = reservation.read_json(args.peer_report)
            result = getattr(operation, args.action)(peer)
        else:
            result = operation.report() if args.action == 'status' else getattr(operation, args.action)()
    print(json.dumps(result))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print('Paired promotion stopped: '+type(error).__name__+': '+str(error)[:300], file=sys.stderr)
        sys.exit(1)
