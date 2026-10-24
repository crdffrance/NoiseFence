#!/usr/bin/env python3
"""Validate a retained release under a new hold, without authorizing rollback.

Only the exact original release of a completed paired upgrade is eligible. Root
operators exchange descriptors through an authenticated channel. A successful
maintenance probe cannot change the selected release or resume normal services.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import time
import tomllib

import rollback_check
import upgrade_reservation as reservation
import upgrade_validation as validation
from migration_protocol import atomic, canonical, identity, require, sha

PROTOCOL = 'noisefence-retained-validation-1'
DESCRIPTOR = 'noisefence-retained-validation-descriptor-1'
CONTEXT = 'noisefence-retained-validation-context-1'
HISTORY_KEYS = {'previous_operation', 'previous_proposal_sha256', 'previous_decision_sha256',
                'peer_completion_sha256', 'reservation_sha256', 'current'}


def context_path(operation):
    require(identity(operation), 'Canonical operation UUID required')
    return reservation.STATE/(operation+'-rollback-context.json')


def stable_inspection(value):
    return {key:item for key,item in value.items() if key != 'observed_at'}


def checked_descriptor(value):
    require(isinstance(value, dict) and value.get('protocol') == DESCRIPTOR
            and isinstance(value.get('history'), dict) and set(value['history']) == HISTORY_KEYS,
            'Invalid retained-release descriptor')
    ordinary = {key:item for key,item in value.items() if key != 'history'}
    ordinary['protocol'] = validation.DESCRIPTOR
    validation.checked_descriptor(ordinary)
    history = value['history']
    require(identity(history['previous_operation']) and history['previous_operation'] != value['operation']
            and all(sha(history[key]) for key in HISTORY_KEYS-{'previous_operation', 'current'}),
            'Invalid completed-upgrade binding')
    validation.checked_descriptor({**ordinary, 'candidate':history['current']})
    validation.require_forward_upgrade(value['candidate'], history['current'])
    require(value['candidate']['platform'] == history['current']['platform']
            and value['candidate']['directory'] != history['current']['directory'],
            'Retained release must match the installed architecture and a distinct path')
    return ordinary


def authorize(own, peer):
    left, right = checked_descriptor(own), checked_descriptor(peer)
    require(all(own['history'][key] == peer['history'][key] for key in
                ('previous_operation', 'previous_proposal_sha256', 'previous_decision_sha256')),
            'Retained pair does not refer to the same completed upgrade')
    require(all(own['history']['current'][key] == peer['history']['current'][key]
                for key in ('version', 'commit')),
            'Installed pair differs between retained-release descriptors')
    return validation.authorize(left, right)


def describe(operation, previous_operation, peer_completion, expires_at):
    require(type(expires_at) is int and int(time.time()) < expires_at <= int(time.time())+3600,
            'Validation authorization expired or exceeds one hour')
    path = context_path(operation)
    if reservation.exists(path):
        context = reservation.read_json(path)
        require(isinstance(context, dict) and set(context) == {'protocol', 'operation', 'previous_operation', 'peer_completion', 'inspection'}
                and context['protocol'] == CONTEXT and context['operation'] == operation
                and context['previous_operation'] == previous_operation and context['peer_completion'] == peer_completion,
                'Retained-release context changed')
        # Re-reading the archives and prior receipts catches changed state on
        # every retry, even if the first start lost its response.
        inspection = rollback_check.inspect_history(operation, previous_operation, peer_completion)
        require(stable_inspection(inspection) == context['inspection'],
                'Retained release, authority, policy or historical proof changed')
    else:
        inspection = rollback_check.inspect(operation, previous_operation, peer_completion)
    with reservation.private_read(reservation.CONFIG, 1024*1024) as source:
        raw = source.read()
    config = tomllib.loads(raw.decode())
    require(hashlib.sha256(raw).hexdigest() == inspection['config_sha256'],
            'Configuration changed while describing retained validation')
    result = {'protocol':DESCRIPTOR, 'operation':operation, 'expires_at':expires_at,
              'selection':inspection['selection'], 'policy':inspection['policy'],
              'candidate':inspection['retained'], 'config_sha256':inspection['config_sha256'],
              'service_sha256':hashlib.sha256(validation.unit_template()).hexdigest(),
              'replica_peer':config['replication']['peer_id'],
              'history':{key:inspection[key] for key in HISTORY_KEYS}}
    checked_descriptor(result)
    return result


class RetainedValidation(validation.Validation):
    protocol = PROTOCOL

    def describe(self, directory, expires_at):
        context = reservation.read_json(context_path(self.operation))
        result = describe(self.operation, context['previous_operation'], context['peer_completion'], expires_at)
        require(str(directory) == result['candidate']['directory'],
                'Only the original release of the completed upgrade may be validated')
        return result

    def authorize(self, own, peer):
        return authorize(own, peer)

    def prepare(self, previous_operation, peer_completion, peer_descriptor, expires_at):
        # Check both descriptors before writing even a local context. The public
        # upgrade supervisor remains forward-only and cannot adopt this receipt.
        own = describe(self.operation, previous_operation, peer_completion, expires_at)
        authorize(own, peer_descriptor)
        path = context_path(self.operation)
        if not reservation.exists(path):
            inspection = rollback_check.inspect(self.operation, previous_operation, peer_completion)
            require(own == describe(self.operation, previous_operation, peer_completion, expires_at),
                    'Retained authorization changed during preparation')
            context = {'protocol':CONTEXT, 'operation':self.operation, 'previous_operation':previous_operation,
                       'peer_completion':peer_completion, 'inspection':stable_inspection(inspection)}
            raw = canonical(context)
            require(len(raw) <= 65536, 'Retained validation context exceeds receipt limit')
            atomic(path, raw)
        return self.start(Path(own['candidate']['directory']), peer_descriptor, expires_at)

    def status(self):
        return {**super().status(), 'purpose':'retained_release_validation',
                'activation_authorized':False, 'rollback_qualified':False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['describe', 'start', 'status', 'stop'])
    parser.add_argument('--operation', required=True)
    parser.add_argument('--previous-operation')
    parser.add_argument('--peer-completion', type=Path)
    parser.add_argument('--peer-report', type=Path)
    parser.add_argument('--expires-at', type=int)
    args = parser.parse_args()
    require(os.geteuid() == 0, 'Root is required'); os.umask(0o077)
    with reservation.operation_lock():
        if args.action in ('describe', 'start'):
            require(args.previous_operation is not None and args.peer_completion is not None
                    and args.expires_at is not None, 'Completed upgrade, peer completion and expiry required')
            peer = reservation.read_json(args.peer_completion)
        operation = RetainedValidation(args.operation)
        if args.action == 'describe':
            result = describe(args.operation, args.previous_operation, peer, args.expires_at)
        elif args.action == 'start':
            require(args.peer_report is not None, 'Root-reviewed retained peer descriptor required')
            result = operation.prepare(args.previous_operation, peer, reservation.read_json(args.peer_report), args.expires_at)
        else:
            result = getattr(operation, args.action)()
        print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print('Retained validation stopped: '+type(error).__name__+': '+str(error)[:300], file=sys.stderr)
        sys.exit(1)
