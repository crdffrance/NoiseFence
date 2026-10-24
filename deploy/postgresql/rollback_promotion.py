#!/usr/bin/env python3
"""Prepare an exact retained pair under fresh holds; never start normal services.

This protocol is separate from forward promotion. Only the original release of
an authenticated completed paired upgrade may be prepared, after it validates
the current selected authority and policy. This is not rollback activation.
"""
import argparse
import json
import os
from pathlib import Path
import sys

import rollback_check
import rollback_validation as retained
import upgrade_promotion as promotion
import upgrade_reservation as reservation
import upgrade_validation as validation
from migration_protocol import require

PROTOCOL = 'noisefence-retained-promotion-1'
PREPARED = 'noisefence-retained-prepared-1'
REPORT = 'noisefence-retained-promotion-report-1'


def check_original(own, original):
    ordinary = retained.checked_descriptor(own)
    validation.checked_descriptor({**ordinary, 'candidate': original})
    require(original == own['history']['current'],
            'Retained promotion must start from the completed upgrade release')


def checked_prepared(value):
    return promotion._checked_prepared(value, PREPARED, retained.authorize, check_original)


def paired(own, peer):
    return promotion._paired(own, peer, checked_prepared)


def checked_report(value):
    return promotion._checked_report(value, REPORT, checked_prepared)


class RetainedPromotion(promotion.Promotion):
    protocol = PROTOCOL
    prepared_protocol = PREPARED
    report_protocol = REPORT
    checked_prepared = staticmethod(checked_prepared)
    checked_report = staticmethod(checked_report)
    paired = staticmethod(paired)

    def validator(self):
        return retained.RetainedValidation(self.operation)

    def require_target(self, descriptor):
        checked_prepared(descriptor)
        check_original(descriptor['own'], descriptor['original'])

    def verify_context(self, state):
        context = reservation.read_json(retained.context_path(self.operation))
        require(isinstance(context, dict)
                and set(context) == {'protocol', 'operation', 'previous_operation', 'peer_completion', 'inspection'}
                and context['protocol'] == retained.CONTEXT and context['operation'] == self.operation,
                'Missing or foreign retained validation context')
        inspection = rollback_check.inspect_bound_history(
            self.hold, context['previous_operation'], context['peer_completion'])
        require(retained.stable_inspection(inspection) == context['inspection'],
                'Completed history, retained files, authority or policy changed')
        own = state['descriptor']['own']
        require(own['history'] == {key:inspection[key] for key in retained.HISTORY_KEYS}
                and own['candidate'] == inspection['retained']
                and state['descriptor']['original'] == inspection['current']
                and own['selection'] == inspection['selection']
                and own['policy'] == inspection['policy']
                and own['config_sha256'] == inspection['config_sha256'],
                'Retained descriptor differs from the freshly bound history')

    def abandon(self, peer_report):
        # Both operators must have established their own history before one can
        # adopt a counterpart's uncommitted preparation for safe cancellation.
        peer = checked_report(peer_report)
        original = self.hold.state()['installation']
        state = {'descriptor': {'own':peer['descriptor']['peer'],
                                'original':validation.candidate(Path(original['release_directory']))}}
        self.verify_context(state)
        return super().abandon(peer_report)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['prepare', 'promote', 'restore', 'abandon', 'release', 'status'])
    parser.add_argument('--operation', required=True)
    parser.add_argument('--peer-report', type=Path)
    args = parser.parse_args()
    require(os.geteuid() == 0, 'Root is required');os.umask(0o077)
    require((args.peer_report is not None) == (args.action in ('promote', 'abandon', 'release')),
            'Unexpected or missing retained peer report')
    with reservation.operation_lock():
        operation = RetainedPromotion(args.operation)
        if args.peer_report is not None:
            result = getattr(operation, args.action)(reservation.read_json(args.peer_report))
        else:
            result = operation.report() if args.action == 'status' else getattr(operation, args.action)()
        print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print('Retained promotion stopped: '+type(error).__name__+': '+str(error)[:300], file=sys.stderr)
        sys.exit(1)
