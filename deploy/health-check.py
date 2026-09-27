#!/usr/bin/env python3
"""Read-only operational checks; emits no message content or credentials."""
import argparse
import contextlib
import smtplib
import tempfile
import datetime
import json
import os
from pathlib import Path
import shutil
import socket
import sqlite3
import subprocess
import time
import tomllib
import urllib.request


HISTORY_SECONDS = 48 * 3600
HISTORY_LIMIT = 2881


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def web_readiness(listen):
    host, port = listen.rsplit(':', 1)
    if host not in ('127.0.0.1', 'localhost', '[::1]'):
        raise ValueError('health checker expects a loopback web backend')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with opener.open(f'http://{host}:{int(port)}/healthz', timeout=3) as reply:
        body = reply.read(4097)
        if reply.status != 200 or len(body) > 4096:
            raise ValueError('invalid health response')
    payload = json.loads(body)
    if payload.get('status') != 'ok' or payload.get('smtp_ready') is not True:
        raise ValueError('HTTP backend responds but SMTP is not ready')
    return {'status': 'ok', 'smtp_ready': True}


def smtp_probe(listen):
    # Never submit RCPT or DATA. Check admission without generating a message.
    host, port = listen.rsplit(':', 1)
    host = host.strip('[]')
    if host in ('0.0.0.0', '::'):
        host = '127.0.0.1' if host == '0.0.0.0' else '::1'
    with smtplib.SMTP(host, int(port), timeout=3) as client:
        for label, reply in [('EHLO', client.ehlo('health.invalid')),
                             ('MAIL', client.mail('')),
                             ('RSET', client.rset())]:
            if reply[0] != 250:
                raise ValueError(f'SMTP {label} returned {reply[0]}')
        return {'admission': 'ok', 'starttls_advertised': client.has_extn('starttls')}


@contextlib.contextmanager
def readonly_db(path):
    db = sqlite3.connect(path.resolve().as_uri() + '?mode=ro', uri=True, timeout=1)
    deadline = time.monotonic() + 2
    db.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)
    try:
        yield db
    finally:
        db.close()


def replication_status(db, config, now=None):
    state = dict(db.execute("SELECT key,value FROM cluster_state WHERE key IN "
                            "('ha_required','ha_last_success','role','last_sync')"))
    # Timestamp after reading state: a heartbeat can advance during other checks.
    now = int(time.time()) if now is None else now
    result, warnings = {}, []
    if 'ha_required' in state:
        row = db.execute('SELECT COUNT(*),COALESCE(SUM(acked=0),0),'
                         'COALESCE(SUM(acked<generation),0) FROM ha_local').fetchone()
        age = now - int(state.get('ha_last_success', 0))
        result.update(required=True, tracked=row[0], unprotected=row[1],
                      pending_updates=row[2], heartbeat_age_seconds=age)
        if not 0 <= age <= 15:
            warnings.append('replica heartbeat is missing, stale or future-dated')
        # A fresh transaction can be in flight at sampling time. Record counters;
        # persistent backlog is checked against the previous sample below.
    cluster = config.get('cluster', {})
    stale = cluster.get('max_stale_seconds', 60)
    if state.get('role') == 'worker':
        age = now - int(state.get('last_sync', 0))
        result['policy_age_seconds'] = age
        if not 0 <= age <= stale:
            warnings.append('worker policy synchronization is stale')
    elif state.get('role') == 'coordinator':
        ages = [now - (row[0] or 0) for row in db.execute(
            'SELECT last_seen FROM cluster_nodes WHERE enabled=1')]
        result['workers'] = len(ages)
        result['stale_workers'] = sum(not 0 <= age <= stale for age in ages)
        if result['stale_workers']:
            warnings.append('one or more enabled workers stopped synchronizing')
    return result, warnings


def memory_sample(root=Path('/sys/fs/cgroup')):
    result = subprocess.run(['systemctl', 'show', 'noisefence.service',
                             '--property=ControlGroup', '--value'],
                            capture_output=True, text=True, timeout=3, check=True)
    group = (root / result.stdout.strip().lstrip('/')).resolve()
    if not group.is_relative_to(root.resolve()) or group == root.resolve():
        raise ValueError('invalid service cgroup')
    def number(name):
        raw = (group / name).read_text().strip()
        return None if raw == 'max' else int(raw)
    events = dict(line.split() for line in (group / 'memory.events').read_text().splitlines())
    return {'current_bytes': number('memory.current'), 'high_bytes': number('memory.high'),
            'max_bytes': number('memory.max'), 'swap_bytes': number('memory.swap.current'),
            'events': {key: int(events.get(key, 0)) for key in ('high', 'max', 'oom', 'oom_kill')},
            'cgroup_id': group.stat().st_ino,
            'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip()}


def sample_warnings(current, previous):
    warnings = []
    memory = current.get('memory', {})
    old = previous.get('memory', {})
    if memory.get('high_bytes') and memory['current_bytes'] >= memory['high_bytes']:
        warnings.append('gateway memory is at or above MemoryHigh')
    if (memory and old and memory.get('boot_id') == old.get('boot_id')
            and memory.get('cgroup_id') == old.get('cgroup_id')):
        for key, count in memory.get('events', {}).items():
            if count > old.get('events', {}).get(key, count):
                warnings.append(f'new memory {key} events')
    if 30 <= current['checked_at'] - previous.get('checked_at', 0) <= 180:
        for key in ('unprotected', 'pending_updates'):
            if current.get('replication', {}).get(key, 0) and previous.get('replication', {}).get(key, 0):
                warnings.append(f'replication {key} present in consecutive samples')
    return warnings


def load_history(path, now):
    if not path.exists():
        return []
    if path.stat().st_size > 8 * 1024 * 1024:
        raise ValueError('health history exceeds size limit')
    history = json.loads(path.read_text())
    if not isinstance(history, list) or any(not isinstance(item, dict) or
            not isinstance(item.get('checked_at'), int) for item in history):
        raise ValueError('invalid health history')
    return [item for item in history if now - HISTORY_SECONDS <= item['checked_at'] <= now][-HISTORY_LIMIT:]


def write_json(path, value):
    # Private atomic output, also when an older report already exists.
    fd, pending = tempfile.mkstemp(prefix=path.name + '.', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(value, stream, indent=2)
            stream.write('\n')
        os.replace(pending, path)
    finally:
        if os.path.exists(pending):
            os.unlink(pending)


def check(config_file, output):
    config = tomllib.loads(Path(config_file).read_text())
    now = int(time.time())
    issues = []
    details = {}

    def issue(name, operation):
        try:
            details[name] = operation()
        except Exception as error:
            issues.append({'check': name, 'error': str(error)[:250]})

    def service(name):
        result = subprocess.run(['systemctl', 'is-active', name], capture_output=True,
                                text=True, timeout=5)
        if result.returncode:
            raise ValueError(result.stdout.strip() or 'service unavailable')
        return 'active'

    for name in ['noisefence.service', 'nginx.service', 'certbot.timer']:
        issue(name, lambda name=name: service(name))

    def version(path):
        with socket.socket(socket.AF_UNIX) as stream:
            stream.settimeout(3)
            stream.connect(path)
            stream.sendall(b'zVERSION\0')
            reply = stream.recv(1024).decode('ascii').strip('\0\n')
        if not reply.startswith('ClamAV '):
            raise ValueError('unexpected scanner response')
        return reply

    if config.get('antivirus'):
        issue('clamav-daemon.service', lambda: service('clamav-daemon.service'))
        issue('clamav-freshclam.service', lambda: service('clamav-freshclam.service'))

        def official():
            reply = version(config['antivirus']['socket'])
            stamp = datetime.datetime.strptime(reply.split('/', 2)[2], '%a %b %d %H:%M:%S %Y')
            age = now - int(stamp.replace(tzinfo=datetime.timezone.utc).timestamp())
            if age < -300 or age > 48 * 3600:
                raise ValueError('official daily database is older than 48 hours or future-dated')
            return {'version': reply, 'age_seconds': age}

        issue('official_database', official)

    if config.get('signatures'):
        for name in ['noisefence-signature-scanner.service', 'noisefence-signatures.timer']:
            issue(name, lambda name=name: service(name))
        issue('advisory_scanner', lambda: version(config['signatures']['socket']))

        def signatures():
            marker = Path('/var/lib/clamav-unofficial-sigs/configs/last-ss-update.txt')
            age = now - int(marker.read_text().strip())
            if age < -300 or age > 48 * 3600:
                raise ValueError('last successful signature check is older than 48 hours')
            return {'last_check_age_seconds': age}

        issue('signature_updates', signatures)

    data = Path(config['data_dir'])

    def queue():
        with readonly_db(data / 'state.sqlite3') as db:
            rows = db.execute("SELECT m.is_dsn,COUNT(*),MIN(m.created) FROM deliveries d "
                              "JOIN messages m ON m.id=d.message_id "
                              "WHERE d.status IN ('pending','sending') GROUP BY m.is_dsn").fetchall()
        result = {}
        for is_dsn, count, created in rows:
            kind = 'dsn' if is_dsn else 'mail'
            oldest = max(0, now - created) if created is not None else 0
            result[kind] = {'pending': count, 'oldest_age_seconds': oldest}
            if count > 1000 or oldest > 1800:
                issues.append({'check': 'queue_' + kind,
                               'error': f'{count} pending deliveries; oldest {oldest}s'})
        return result

    issue('queue', queue)

    def disk():
        free = shutil.disk_usage(data).free
        if free < max(config['smtp']['minimum_free_bytes'] * 2, 2 * 1024**3):
            raise ValueError('available disk space below operational reserve')
        return {'available_bytes': free}

    issue('disk', disk)

    def certificate():
        result = subprocess.run(['openssl', 'x509', '-in', config['smtp']['tls_cert'],
                                 '-noout', '-checkend', '604800'], capture_output=True, timeout=5)
        if result.returncode:
            raise ValueError('TLS certificate expires in less than seven days or cannot be read')
        return 'valid_more_than_seven_days'

    issue('certificate', certificate)

    issue('web', lambda: web_readiness(config['web']['listen']))
    issue('smtp', lambda: smtp_probe(config['smtp']['listen']))
    issue('memory', memory_sample)

    if config.get('cluster') or config.get('replication'):
        def replication():
            with readonly_db(data / 'state.sqlite3') as db:
                result, warnings = replication_status(db, config)
            issues.extend({'check': 'replication', 'error': value} for value in warnings)
            return result
        issue('replication', replication)

    history_path = Path(output).with_name('operational-health-history.json') if output else None
    history = []
    if history_path:
        try:
            history = load_history(history_path, now)
        except (OSError, ValueError) as error:
            issues.append({'check': 'history', 'error': str(error)[:250]})
    sample = {'checked_at': now, **{key: details[key] for key in
              ('memory', 'replication', 'queue', 'web', 'smtp') if key in details}}
    issues.extend({'check': 'trend', 'error': value} for value in
                  sample_warnings(sample, history[-1] if history else {}))

    if config.get('llm', {}).get('monthly_budget_micro_eur', 0):
        def llm():
            remaining = config['llm']['pricing_checked_at'] + 30 * 86400 - now
            if remaining < 3 * 86400:
                raise ValueError('LLM pricing must be reviewed within three days or is expired')
            with readonly_db(data / 'llm-budget.sqlite3') as db:
                row = db.execute("SELECT accounted,requests FROM llm_months WHERE month=strftime('%Y-%m','now')").fetchone() or (0, 0)
            cap = config['llm']['monthly_budget_micro_eur']
            if row[0] >= cap * 9 // 10:
                raise ValueError('LLM local budget has reached 90 percent')
            return {'accounted_micro_eur': row[0], 'requests': row[1], 'monthly_budget_micro_eur': cap}

        issue('llm_budget', llm)

    report = {'checked_at': now, 'status': 'attention' if issues else 'ok',
              'checks': details, 'issues': issues}
    if output:
        write_json(Path(output), report)
        sample['status'] = report['status']
        write_json(history_path, (history + [sample])[-HISTORY_LIMIT:])
    print(json.dumps(report, ensure_ascii=False))
    return bool(issues)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', default='/etc/noisefence/config.toml')
    parser.add_argument('--output')
    args = parser.parse_args()
    raise SystemExit(check(args.config, args.output))
