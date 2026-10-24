#!/usr/bin/env python3
"""Explicit paired activation of a freshly validated, exact retained release.

This protocol never rewinds databases, queue generations or policies. It requires
completed upgrade history and a new held validation on both nodes. Once committed,
recover the same decision; pre-commit restoration cannot undo accepted mail.
"""
import argparse
import json
import os
from pathlib import Path
import sys

import rollback_promotion as retained
import upgrade_activation as activation
import upgrade_reservation as reservation
from migration_protocol import require

PROTOCOL = 'noisefence-retained-activation-1'
REPORT = 'noisefence-retained-activation-report-1'
DECISION = 'noisefence-retained-decision-1'
READY = 'noisefence-retained-ready-1'


def proposal(state):
    return activation._proposal(state, retained.paired)


def checked_proposal(value, operation):
    return activation._checked_proposal(value, operation, retained.paired)


def checked_decision(value, operation, proposed):
    return activation._checked_decision(value, operation, proposed, DECISION, checked_proposal)


def checked_report(value):
    return activation._checked_report(value, REPORT, checked_proposal, checked_decision)


def checked_ready(value, operation, proposed, node, now):
    return activation._checked_ready(value, operation, proposed, node, now, READY, checked_proposal)


class RetainedActivation(activation.Activation):
    protocol = PROTOCOL
    report_protocol = REPORT
    decision_protocol = DECISION
    ready_protocol = READY
    promotion_type = retained.RetainedPromotion
    promotion_report = staticmethod(retained.checked_report)
    proposal = staticmethod(proposal)
    checked_proposal = staticmethod(checked_proposal)
    checked_decision = staticmethod(checked_decision)
    checked_report = staticmethod(checked_report)
    checked_ready = staticmethod(checked_ready)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=['arm','decide','accept','start','check','verify','finish','abort','cancel','status'])
    parser.add_argument('--operation',required=True)
    parser.add_argument('--peer-report',type=Path)
    parser.add_argument('--outcome',choices=['activate','abort'])
    args=parser.parse_args()
    require(os.geteuid()==0,'Root is required');os.umask(0o077)
    needs=args.action in ('arm','accept','start','check','verify','finish','cancel') or (args.action=='decide' and args.outcome=='activate')
    require((args.peer_report is not None)==needs and (args.outcome is not None)==(args.action=='decide'),
            'Unexpected retained activation arguments')
    with reservation.operation_lock():
        operation=RetainedActivation(args.operation)
        peer=reservation.read_json(args.peer_report) if args.peer_report else None
        result=(operation.report() if args.action=='status' else operation.decide(args.outcome,peer) if args.action=='decide'
                else getattr(operation,args.action)(peer) if needs else getattr(operation,args.action)())
    print(json.dumps(result,sort_keys=True))


if __name__=='__main__':
    try:main()
    except Exception as error:
        print('Retained activation stopped: '+type(error).__name__+': '+str(error)[:300],file=sys.stderr)
        sys.exit(1)
