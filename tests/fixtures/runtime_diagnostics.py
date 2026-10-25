"""Bounded, content-free observations for a disposable native fixture failure."""
import argparse
import contextlib
import json
import os
import re
from pathlib import Path
import sqlite3
import subprocess
import time
import urllib.request

DATA = Path('/var/lib/noisefence/state.sqlite3')
SERVICES = {'active', 'inactive', 'failed', 'activating', 'deactivating'}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def freshness(value, now):
    if value is None:
        return 'missing'
    try:
        timestamp = int(value)
    except (TypeError, ValueError):
        return 'invalid'
    if timestamp <= 0 or timestamp > now:
        return 'invalid'
    return 'fresh' if now-timestamp <= 30 else 'stale'


def database(path=DATA):
    result = {'selected': None, 'replication_required': None, 'pending_updates': None,
              'unprotected': None, 'heartbeat': 'unavailable', 'policy_sync': 'unavailable'}
    try:
        until = time.monotonic()+2
        with contextlib.closing(sqlite3.connect(path.as_uri()+'?mode=ro', uri=True, timeout=2)) as db:
            db.set_progress_handler(lambda: int(time.monotonic() > until), 1000)
            db.execute('PRAGMA query_only=ON');db.execute('BEGIN')
            state = dict(db.execute("SELECT key,CASE WHEN length(value)<=20 THEN value END FROM cluster_state WHERE key IN ('ha_required','ha_last_success','last_sync')"))
            selected = db.execute("SELECT EXISTS(SELECT 1 FROM cluster_state WHERE key='management_selection')").fetchone()[0]
            pending = db.execute('SELECT EXISTS(SELECT 1 FROM ha_local WHERE acked<generation)').fetchone()[0]
            unprotected = db.execute('SELECT EXISTS(SELECT 1 FROM ha_local WHERE acked=0)').fetchone()[0]
        now = int(time.time())
        return {'selected': bool(selected), 'replication_required': state.get('ha_required') == '1',
                'pending_updates': bool(pending), 'unprotected': bool(unprotected),
                'heartbeat': freshness(state.get('ha_last_success'), now),
                'policy_sync': freshness(state.get('last_sync'), now)}
    except (OSError, sqlite3.Error):
        return result


def health(node):
    url = 'http://127.0.0.1:'+('18080' if node == 'mx1' else '18081')+'/healthz'
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        with opener.open(url, timeout=2) as response:
            raw = response.read(4097)
            if response.status != 200 or len(raw) > 4096:
                return 'invalid'
            value = json.loads(raw)
        if not isinstance(value, dict) or value.get('status') != 'ok' or type(value.get('smtp_ready')) is not bool:
            return 'invalid'
        return 'ready' if value['smtp_ready'] else 'not_ready'
    except (OSError, ValueError):
        return 'unavailable'


def observe(node):
    if node not in ('mx1', 'mx2'):
        raise ValueError('Unknown fixture node')
    service = 'unavailable'
    try:
        result = subprocess.run(['systemctl', 'show', 'noisefence.service', '--property=ActiveState', '--value'],
                                capture_output=True, timeout=3, check=True)
        text = result.stdout.decode().strip()
        if text in SERVICES:
            service = text
    except (OSError, subprocess.SubprocessError, UnicodeError):
        pass
    return {'schema': 'noisefence-fixture-runtime-diagnostic-1', 'service': service,
            'health': health(node), 'database': database()}



MANAGEMENT_INDICATORS = {
    'binding_unavailable': ('Central database binding is unavailable or does not match',),
    'permission_denied': ('Permission denied', 'os error 13'),
    'connection_refused': ('Connection refused', 'os error 111'),
    'missing_socket_or_path': ('No such file or directory', 'os error 2'),
    'pool_timeout': ('Timeout occurred while waiting', 'Timeout occurred while creating',
                     'Timeout occurred while recycling', 'deadline has elapsed'),
    'authentication_failed': ('authentication failed',),
    'pool_closed': ('Pool has been closed',),
}


def management_result(result):
    # Read only an existing CLI's aggregate health output. Never publish its
    # stderr: database/driver errors can contain names or submitted values.
    if len(result.stdout) + len(result.stderr) > 16384:
        return {'status': 'invalid', 'indicators': []}
    if result.returncode == 0:
        try:
            value = json.loads(result.stdout)
            valid = (isinstance(value, dict)
                     and set(value) == {'backend', 'checked_at', 'workers', 'stale_workers'}
                     and value['backend'] == 'postgresql'
                     and all(type(value[key]) is int for key in ('checked_at', 'workers', 'stale_workers'))
                     and value['checked_at'] > 0 and 0 <= value['stale_workers'] <= value['workers'])
        except (ValueError, UnicodeError):
            valid = False
        return {'status': 'query_ok' if valid else 'invalid', 'indicators': []}
    text = result.stderr.decode(errors='replace')
    return {'status': 'failed', 'indicators': [category for category, markers in MANAGEMENT_INDICATORS.items()
                                              if any(marker in text for marker in markers)]}


def management():
    # The same archived executable, user, read-only command and config on each
    # side of the AppArmor boundary. No archive editing, schema migration,
    # models, listener, relay or service state changes.
    profile = os.environ.get('NOISEFENCE_TEST_APPARMOR_PROFILE', '')
    if profile and not re.fullmatch(r'noisefence-test-[a-f0-9]{12}', profile):
        raise ValueError('Invalid fixture profile')
    result = {'schema': 'noisefence-fixture-management-diagnostic-1'}
    for mode in ('unconfined', 'confined'):
        if mode == 'confined' and not profile:
            result[mode] = {'status': 'not_configured', 'indicators': []}
            continue
        arguments = ['runuser', '-u', 'noisefence', '--']
        if mode == 'confined':
            arguments += ['/usr/bin/aa-exec', '-p', profile, '--']
        arguments += ['/opt/noisefence/noisefence', '--config', '/etc/noisefence/config.toml',
                      'management-health']
        try:
            completed = subprocess.run(arguments, capture_output=True, timeout=8,
                env={'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C'})
            result[mode] = management_result(completed)
        except subprocess.TimeoutExpired:
            result[mode] = {'status': 'command_timeout', 'indicators': []}
        except (OSError, UnicodeError):
            result[mode] = {'status': 'unavailable', 'indicators': []}
    return result


def main():
    if not (os.geteuid() == 0 and Path('/.dockerenv').is_file()
            and os.environ.get('NOISEFENCE_DISPOSABLE_PAIRED_TEST') == '1'
            and Path('/run/systemd/container').read_text().strip() == 'docker'):
        raise ValueError('Disposable native fixture required')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--node', choices=('mx1', 'mx2'), required=True)
    parser.add_argument('--management', action='store_true')
    args = parser.parse_args()
    if args.management and args.node != 'mx1':
        parser.error('Management database diagnostic is coordinator-only')
    print(json.dumps(management() if args.management else observe(args.node), sort_keys=True))


if __name__ == '__main__':
    main()
