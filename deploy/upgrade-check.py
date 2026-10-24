#!/usr/bin/env python3
"""Capture bounded, read-only local upgrade prerequisites. Never installs a release.

A local-format check is not authorization for a paired rollout or a rollback.
Selected management authorities always require coordinated deployment.
"""
import argparse
import contextlib
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import sqlite3
import tempfile
import time
import tomllib
import urllib.error
import urllib.request

MARKERS = ('management_selection', 'management_transport', 'runtime_history_protocol',
           'management_recovery_required', 'management_worker_release')
MAX_CONFIG = 1024 * 1024


class DeadlineExceeded(Exception):
    """The whole CLI deadline must not be swallowed as a single failed probe."""


def bounded(path, maximum):
    with Path(path).open('rb') as stream:
        value = stream.read(maximum + 1)
    if len(value) > maximum:
        raise ValueError('Input exceeds the size limit')
    return value


@contextlib.contextmanager
def snapshot(path):
    db = sqlite3.connect(path.resolve().as_uri() + '?mode=ro', uri=True, timeout=.05)
    deadline = time.monotonic() + 2
    db.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)
    try:
        db.execute('PRAGMA query_only=ON')
        db.execute('BEGIN')
        yield db
    finally:
        db.close()


def storage(path):
    # lexists distinguishes a missing database from a broken symlink.
    if not os.path.lexists(path):
        if any(os.path.lexists(str(path) + suffix) for suffix in ('-wal', '-shm', '-journal')):
            raise ValueError('Database sidecars exist without the database')
        return {'exists': False, 'format': None, 'management_markers': [], 'replication': None}
    with snapshot(path) as db:
        version = db.execute('PRAGMA user_version').fetchone()[0]
        if not 1 <= version <= 7:
            raise ValueError('Unknown or uninitialized storage format')
        clustered = db.execute("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='cluster_state')").fetchone()[0]
        markers, replication = [], None
        if clustered:
            # Only names and bounded operational counters are read. Never load policy/credential blobs.
            markers = [key for (key,) in db.execute(
                'SELECT key FROM cluster_state WHERE key IN (' + ','.join('?' * len(MARKERS)) + ')', MARKERS)]
            required = db.execute("SELECT EXISTS(SELECT 1 FROM cluster_state WHERE key='ha_required')").fetchone()[0]
            if required:
                row = db.execute('SELECT COUNT(*),COALESCE(SUM(acked=0),0),'
                                 'COALESCE(SUM(acked<generation),0),'
                                 "COALESCE(SUM(typeof(generation)!='integer' OR typeof(acked)!='integer' OR "
                                 'generation<1 OR acked<0 OR acked>generation),0) FROM ha_local').fetchone()
                if row[3]:
                    raise ValueError('Invalid replica generation counters')
                raw = db.execute("SELECT CASE WHEN length(value)<=20 THEN value END FROM cluster_state WHERE key='ha_last_success'").fetchone()
                heartbeat = int(raw[0]) if raw and raw[0] is not None else None
                replication = dict(required=True, tracked=row[0], unprotected=row[1],
                                   pending_updates=row[2], last_success=heartbeat)
        return dict(exists=True, format=version, management_markers=sorted(markers), replication=replication)


def candidate(directory):
    raw = bounded(Path(directory) / 'build.json', 1024 * 1024)
    value = json.loads(raw)
    if (not isinstance(value, dict) or value.get('project') != 'NoiseFence' or type(value.get('storage_schema')) is not int
            or not 1 <= value['storage_schema'] <= 7
            or not isinstance(value.get('version'), str)
            or not re.fullmatch(r'\d+\.\d+\.\d+(?:-[a-zA-Z0-9.-]+)?', value['version'])
            or not re.fullmatch(r'[0-9a-f]{40}', value.get('commit', ''))
            or not re.fullmatch(r'[0-9a-f]{64}', value.get('source_sha256', ''))):
        raise ValueError('Invalid candidate release metadata')
    return {key: value[key] for key in ('version', 'commit', 'source_sha256', 'storage_schema')} | {
        'build_json_sha256': hashlib.sha256(raw).hexdigest(), 'artifact_checksums_verified': False}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def readiness(listen):
    host, port = listen.rsplit(':', 1)
    address = ipaddress.ip_address(host.strip('[]'))
    if not address.is_loopback or not 1 <= int(port) <= 65535:
        raise ValueError('Health target must be numeric loopback')
    host = f'[{address}]' if address.version == 6 else str(address)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        response = opener.open(f'http://{host}:{int(port)}/healthz', timeout=3)
    except urllib.error.HTTPError as error:
        error.close()
        raise ValueError('Health endpoint returned an error') from None
    with response as response:
        raw = response.read(4097)
        if response.status != 200 or len(raw) > 4096:
            raise ValueError('Invalid health response')
    value = json.loads(raw)
    if not isinstance(value, dict) or value.get('status') != 'ok' or type(value.get('smtp_ready')) is not bool:
        raise ValueError('Invalid health response')
    return {'status': 'observed', 'smtp_ready': value['smtp_ready']}


def inspect(config, release, *, working_directory=Path('/opt/noisefence'), live=False, now=None, expect_existing=False):
    now = int(time.time()) if now is None else now
    raw = bounded(config, MAX_CONFIG)
    settings = tomllib.loads(raw.decode())
    data = Path(settings['data_dir'])
    if not data.is_absolute():
        if not working_directory.is_absolute():
            raise ValueError('Working directory must be absolute')
        data = working_directory / data
    saved = storage(data / 'state.sqlite3')
    proposed = candidate(release)
    reasons = []
    if expect_existing and not saved['exists']:
        reasons.append('existing_local_storage_missing')
    coordinated = ('management' in settings or bool(saved['management_markers'])
                   or (saved['format'] or 0) >= 7)
    if coordinated:
        reasons.append('coordinated_management_required')
    if saved['format'] and saved['format'] > proposed['storage_schema']:
        reasons.append('candidate_storage_format_too_old')
    if saved['replication'] and 'replication' not in settings:
        reasons.append('mandatory_replication_missing_from_configuration')
    report = dict(schema='noisefence-upgrade-check-1', checked_at=now,
                  config_sha256=hashlib.sha256(raw).hexdigest(), candidate=proposed, storage=saved,
                  local_install_supported=not reasons, local_install_blockers=reasons,
                  coordinated_management_required=coordinated,
                  paired='replication' in settings or bool(saved['replication']),
                  live={'status': 'not_checked'}, operational_blockers=[],
                  rollback='not_qualified', operation='read_only_snapshot')
    if live:
        try:
            report['live'] = readiness(settings['web']['listen'])
            if not report['live']['smtp_ready']:
                report['operational_blockers'].append('smtp_not_ready')
        except (KeyError, OSError, ValueError, TypeError):
            # Never include server response text, connection strings or configuration values.
            report['live'] = {'status': 'unavailable'}
            report['operational_blockers'].append('smtp_readiness_unavailable')
        replica = saved['replication']
        if report['paired']:
            if not replica:
                report['operational_blockers'].append('replication_not_initialized')
            else:
                age = now - replica['last_success'] if replica['last_success'] is not None else None
                replica['heartbeat_age_seconds'] = age
                if age is None or not 0 <= age <= 15:
                    report['operational_blockers'].append('replica_heartbeat_not_fresh')
                if replica['unprotected']:
                    report['operational_blockers'].append('replica_initial_acknowledgements_pending')
                if replica['pending_updates']:
                    report['operational_blockers'].append('replica_updates_pending')
    return report


def write_receipt(path, value):
    """Publish one private immutable receipt; never overwrite an earlier operation."""
    path = Path(path)
    fd, temporary = tempfile.mkstemp(prefix='.upgrade-check-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            os.fchmod(stream.fileno(), 0o600)
            json.dump(value, stream, sort_keys=True, indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        os.unlink(temporary)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--candidate', type=Path, required=True)
    parser.add_argument('--working-directory', type=Path, default=Path('/opt/noisefence'))
    parser.add_argument('--expect-existing-state', action='store_true', help='Refuse a missing database on an already installed gateway')
    parser.add_argument('--live', action='store_true', help='Also query numeric loopback /healthz; never sends mail')
    parser.add_argument('--output', type=Path, help='New private report path; existing files are never replaced')
    parser.add_argument('--require-local-install', action='store_true', help='Installer guard; selected management is refused')
    args = parser.parse_args()
    def expired(_signal, _frame):
        raise DeadlineExceeded('Upgrade check deadline exceeded')
    signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, 10)
    try:
        report = inspect(args.config, args.candidate, working_directory=args.working_directory, live=args.live, expect_existing=args.expect_existing_state)
        if args.output:
            write_receipt(args.output, report)
    except (DeadlineExceeded, OSError, ValueError, KeyError, TypeError, sqlite3.Error):
        parser.exit(2, 'Upgrade check unavailable: inspect configuration, release metadata and local storage. No installation was authorized.\n')
    signal.setitimer(signal.ITIMER_REAL, 0)
    if args.require_local_install and not report['local_install_supported']:
        parser.exit(1, 'Local installation refused: ' + ', '.join(report['local_install_blockers']) + '. Use the coordinated upgrade/recovery procedure; do not clear authority or replication markers.\n')
    print(json.dumps({key: report[key] for key in ('schema', 'local_install_supported', 'local_install_blockers', 'operational_blockers', 'rollback')}))
    return 1 if report['operational_blockers'] else 0


if __name__ == '__main__':
    raise SystemExit(main())
