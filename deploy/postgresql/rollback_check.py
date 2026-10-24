#!/usr/bin/env python3
"""Inspect a retained pair after completed activation; never authorize rollback."""
import argparse
import json
import os
from pathlib import Path
import sys
import time

import upgrade_activation as activation
import upgrade_promotion as promotion
import upgrade_reservation as reservation
import upgrade_validation as validation
from migration_protocol import identity, require

PROTOCOL = 'noisefence-paired-rollback-check-1'


def inspect(operation, previous_operation, peer):
    """Root-trusted historical reports bind identities, not runtime compatibility.

    The caller holds the native operation lock. A new reservation must already
    have stopped normal writers. This function does not write a receipt or run
    any program from either release.
    """
    require(identity(operation) and identity(previous_operation) and operation != previous_operation,
            'A new operation distinct from the completed upgrade is required')
    held = validation.held(operation)
    for name in ('validation.json', 'promotion.json', 'activation.json', 'activation-jobs.json',
                 operation+'-validation.json', operation+'-promotion.json', operation+'-activation.json'):
        require(not reservation.exists(reservation.STATE/name),
                'Resolve the existing candidate or activation operation first')
    require(not reservation.exists(validation.PLAN) and not reservation.exists(validation.LINK)
            and reservation.unit_state(validation.SERVICE) in ('inactive', 'failed', 'unknown'),
            'Stop and reconcile candidate validation before rollback inspection')

    previous = activation.Activation(previous_operation)
    state = previous.state()
    previous.match_peer(state, peer)
    require(state['phase'] == 'complete' and peer['phase'] == 'complete'
            and state['decision']['outcome'] == 'activate' and peer['decision'] == state['decision'],
            'Both nodes must have completed the same activation; unfinished decisions require forward recovery')
    previous.check_completion(state, peer)
    own = previous.own(state)
    old_hold, old_promotion = previous.hold.state(), previous.promoted.state()
    require(old_hold['phase'] == 'upgraded' and old_hold['installation'] == own['installation']
            and old_promotion['phase'] == 'activated' and old_promotion['descriptor'] == own
            and old_promotion['peer'] == previous.peer(state)
            and old_promotion['pair_sha256'] == activation.checked_proposal(state['proposal'], previous_operation),
            'Completed activation no longer matches its reservation and promotion receipts')

    installed = held.state()['installation']
    current = validation.candidate(Path(installed['release_directory']))
    require(current == own['own']['candidate'], 'Installed release differs from the completed activation')
    target = validation.candidate(Path(own['original']['directory']))
    require(target == own['original'], 'Retained release differs from the completed activation')
    validation.require_forward_upgrade(target, current)
    selected = reservation.read_selection(reservation.DATA)
    require(selected == own['own']['selection']
            and installed['selection_sha256'] == promotion.fingerprint(selected)
            and installed['node'] == state['node'] and installed['role'] == selected['role']
            and installed['config_sha256'] == own['own']['config_sha256'],
            'Authority or configuration changed since the completed activation')
    policy = validation.policy_epoch()
    # Policy may have advanced since the prior activation. Record the current
    # epoch; never restore the old database or use the old runtime proof as a
    # substitute for fresh validation of that state by the retained binary.
    require(validation.epoch(policy), 'Invalid current policy epoch')
    return {
        'protocol': PROTOCOL, 'operation': operation, 'previous_operation': previous_operation,
        'node': state['node'], 'observed_at': int(time.time()),
        'previous_proposal_sha256': activation.checked_proposal(state['proposal'], previous_operation),
        'previous_decision_sha256': promotion.fingerprint(state['decision']),
        'peer_completion_sha256': promotion.fingerprint(peer),
        'reservation_sha256': promotion.fingerprint(held.state()),
        'selection': selected, 'policy': policy, 'config_sha256': installed['config_sha256'],
        'current': current, 'retained': target,
        'status': 'identity_checked_rollback_unqualified', 'activation_authorized': False,
        'remaining_gates': ['retained_binary_validation_of_current_state',
                            'exact_pair_rollback_rehearsal', 'explicit_paired_rollback_protocol'],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--operation', required=True)
    parser.add_argument('--previous-operation', required=True)
    parser.add_argument('--peer-completion', required=True, type=Path)
    args = parser.parse_args()
    try:
        require(os.geteuid() == 0, 'Run the native inspector as root')
        os.umask(0o077)
        with reservation.operation_lock():
            peer = reservation.read_json(args.peer_completion)
            result = inspect(args.operation, args.previous_operation, peer)
        print(json.dumps(result, sort_keys=True, indent=2))
        return 0
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
