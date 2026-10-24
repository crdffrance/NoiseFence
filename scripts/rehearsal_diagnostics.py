#!/usr/bin/env python3
"""Print bounded, public-source references for a failed synthetic rehearsal.

Never print raw logs, exception values, command arguments or fixture state.
A diagnostic is not qualification evidence and cannot turn a failure into a pass.
"""
import argparse
import ast
import json
import os
from pathlib import Path
import re
import stat

ROOT = Path(__file__).resolve().parents[1]
LIMIT = 256 * 1024
PHASES = {'baseline', 'paired-image', 'standalone-image', 'standalone', 'paired', 'summary'}
SOURCES = (
    'tests/release_lifecycle.py', 'tests/paired_release_lifecycle.py',
    'tests/confined_paired_release.py', 'tests/render_apparmor_fixture.py',
    'tests/fixtures/paired_node.py', 'tests/fixtures/confinement_node.py',
    'tests/fixtures/validation_node.py', 'tests/fixtures/exchange_node.py',
    'scripts/release_rehearsal.py', 'deploy/postgresql/upgrade_reservation.py',
    'deploy/postgresql/upgrade_validation.py', 'deploy/postgresql/upgrade_promotion.py',
    'deploy/postgresql/upgrade_activation.py', 'deploy/postgresql/upgrade_exchange.py',
    'deploy/postgresql/migrate.py', 'deploy/postgresql/migration_agent.py',
    'deploy/postgresql/migration_protocol.py', 'deploy/postgresql/migration_snapshot.py',
)
LOGS = (
    'paired.log', 'standalone.log', 'paired/failure-command.log',
    'paired/mx1-journal.log', 'paired/mx2-journal.log',
    'paired/mx1-validation-journal.log', 'paired/mx2-validation-journal.log',
    'paired/mx1-command-error.log', 'paired/mx2-command-error.log',
    'paired/mx1-migration-errors.json', 'paired/mx2-migration-errors.json',
    'apparmor/denials.log',
)
ERRORS = ('RuntimeError', 'ValueError', 'AssertionError', 'PermissionError',
          'FileNotFoundError', 'CalledProcessError', 'TimeoutExpired')
INDICATORS = {
    'permission_denied': ('Permission denied', 'os error 13', 'apparmor="DENIED"'),
    'missing_path': ('No such file or directory', 'os error 2'),
    'no_space': ('No space left on device', 'os error 28'),
    'memory_limit': ('oom-kill', 'OOMKilled'),
    'service_apparmor_failure': ('231/APPARMOR',),
    'service_exec_failure': ('203/EXEC',),
    'connection_refused': ('Connection refused', 'os error 111'),
    'central_sync_pending': ('central management synchronization pending',),
    'central_policy_capacity_unavailable': ('Central policy capacity unavailable',),
    'central_ingestion_capacity_unavailable': ('Central ingestion capacity unavailable',),
    'replication_unavailable': ('durable replication unavailable',),
    'activation_pending': ('coordinated activation pending',),
    'database_error': ('database is locked', 'database is busy', 'error returned from database'),
}


def tail(root, relative):
    """Read only a bounded suffix from fixed regular files, without following links."""
    try:
        current = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError:
        return None
    try:
        parts = relative.split('/')
        for part in parts[:-1]:
            following = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
            os.close(current); current = following
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=current)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                return None
            os.lseek(fd, max(0, info.st_size - LIMIT), os.SEEK_SET)
            return os.read(fd, LIMIT).decode('utf-8', errors='replace')
        finally:
            os.close(fd)
    except OSError:
        return None
    finally:
        os.close(current)


def catalog():
    """Only reviewed public source locations can enter the diagnostic output."""
    locations, assertions = {}, []
    for relative in SOURCES:
        source = (ROOT/relative).read_text()
        locations[Path(relative).name] = (relative, len(source.splitlines()))
        for node in ast.walk(ast.parse(source)):
            if not isinstance(node, ast.Call):
                continue
            name = node.func.id if isinstance(node.func, ast.Name) else ''
            argument = node.args[1] if name == 'require' and len(node.args) > 1 else (
                node.args[0] if name in ERRORS and node.args else None)
            if isinstance(argument, ast.Constant) and isinstance(argument.value, str) and len(argument.value) >= 12:
                assertions.append((argument.value, {'source':relative, 'line':node.lineno}))
    return locations, assertions


DENIAL_OPERATIONS = {'open', 'file_mmap', 'file_lock', 'exec', 'signal', 'ptrace',
                     'connect', 'bind', 'create', 'listen', 'accept', 'sendmsg', 'recvmsg'}
DENIAL_RESOURCES = {
    'configuration': '/etc/noisefence/', 'application': '/opt/noisefence/',
    'data': '/var/lib/noisefence/', 'postgresql_socket': '/run/postgresql/',
    'process': '/proc/', 'temporary': '/tmp/', 'system_library': '/usr/lib/',
    'system_configuration': '/etc/',
}


def denial_categories(text):
    categories = []
    for line in text.splitlines():
        if 'apparmor="DENIED"' not in line:
            continue
        operation = re.search(r'\boperation="([^"\n]+)"', line)
        name = re.search(r'\bname="([^"\n]+)"', line)
        if not operation or operation[1] not in DENIAL_OPERATIONS:
            continue
        resource = ('intentional_canary' if name and name[1] == '/etc/noisefence-blocked-fixture.toml'
                    else next((key for key, prefix in DENIAL_RESOURCES.items()
                               if name and name[1].startswith(prefix)), 'other'))
        item = {'operation':operation[1], 'resource':resource}
        if item not in categories:
            categories.append(item)
    return categories


def describe(text, locations, assertions):
    frames = []
    # Include source line numbers, never exception values or the source line's
    # dynamic local variables. Ignore paths not in the explicit source catalog.
    for filename, line in re.findall(r'File "[^"\n]*/([^/"\n]+\.py)", line ([0-9]{1,6})', text):
        item = locations.get(filename)
        if item and 0 < int(line) <= item[1]:
            frame = {'source':item[0], 'line':int(line)}
            if frame not in frames:
                frames.append(frame)
    return {'frames':frames[-32:],
            'assertions':[location for message, location in assertions if message in text][-32:],
            'error_types':[name for name in ERRORS if re.search(r'\b'+name+r'\b', text)],
            'indicators':[name for name, markers in INDICATORS.items() if any(m in text for m in markers)],
            'denials':denial_categories(text)}


def runtime_observation(text):
    """Only fixed enums and optional booleans may leave the private fixture."""
    try:
        value = json.loads(text)
    except (TypeError, ValueError):
        return {'status':'unavailable'}
    if (not isinstance(value,dict) or set(value) != {'schema','service','health','database'}
        or value['schema'] != 'noisefence-fixture-runtime-diagnostic-1'
        or value['service'] not in ('active','inactive','failed','activating','deactivating','unavailable')
        or value['health'] not in ('ready','not_ready','invalid','unavailable')):
        return {'status':'unavailable'}
    db=value['database']
    if (not isinstance(db,dict) or set(db) != {'selected','replication_required','pending_updates','unprotected','heartbeat','policy_sync'}
        or any(db[key] is not None and type(db[key]) is not bool for key in ('selected','replication_required','pending_updates','unprotected'))
        or any(db[key] not in ('fresh','stale','invalid','missing','unavailable') for key in ('heartbeat','policy_sync'))):
        return {'status':'unavailable'}
    return value


def diagnose(directory, phase):
    if phase not in PHASES:
        raise ValueError('Unknown rehearsal phase')
    locations, assertions = catalog()
    logs = {}
    for relative in LOGS:
        text = tail(directory, relative)
        if text is not None:
            logs[relative] = describe(text, locations, assertions)
    return {'schema':'noisefence-rehearsal-failure-1', 'status':'failed', 'phase':phase,
            'raw_data_included':False, 'logs':logs,
            'runtime':{node:runtime_observation(tail(directory,'paired/'+node+'-runtime-diagnostic.json'))
                       for node in ('mx1','mx2')}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('phase', choices=sorted(PHASES))
    args = parser.parse_args()
    print(json.dumps(diagnose(args.directory, args.phase), sort_keys=True))


if __name__ == '__main__':
    main()
