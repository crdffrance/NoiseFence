"""Bounded, content-free observations for a disposable native fixture failure."""
import argparse
import contextlib
import json
import os
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


def main():
    if not (os.geteuid() == 0 and Path('/.dockerenv').is_file()
            and os.environ.get('NOISEFENCE_DISPOSABLE_PAIRED_TEST') == '1'
            and Path('/run/systemd/container').read_text().strip() == 'docker'):
        raise ValueError('Disposable native fixture required')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--node', choices=('mx1', 'mx2'), required=True)
    print(json.dumps(observe(parser.parse_args().node), sort_keys=True))


if __name__ == '__main__':
    main()
