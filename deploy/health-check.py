#!/usr/bin/env python3
"""Read-only operational checks; emits no message content or credentials."""
import argparse
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
        with sqlite3.connect(f'file:{data / "state.sqlite3"}?mode=ro', uri=True, timeout=3) as db:
            pending = db.execute("SELECT COUNT(*),MIN(m.created) FROM deliveries d JOIN messages m ON m.id=d.message_id WHERE d.status IN ('pending','sending')").fetchone()
        oldest = now - pending[1] if pending[1] is not None else 0
        if pending[0] > 1000 or oldest > 1800:
            raise ValueError(f'queue requires attention: {pending[0]} deliveries, oldest {oldest}s')
        return {'pending': pending[0], 'oldest_age_seconds': oldest}

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

    def http():
        host, port = config['web']['listen'].rsplit(':', 1)
        if host not in ('127.0.0.1', 'localhost', '[::1]'):
            raise ValueError('health checker expects a loopback web backend')
        with urllib.request.urlopen(f'http://{host}:{port}/healthz', timeout=3) as reply:
            if reply.status != 200:
                raise ValueError('web health endpoint unavailable')
        return 'ok'

    issue('web', http)

    if config.get('llm', {}).get('monthly_budget_micro_eur', 0):
        def llm():
            remaining = config['llm']['pricing_checked_at'] + 30 * 86400 - now
            if remaining < 3 * 86400:
                raise ValueError('LLM pricing must be reviewed within three days or is expired')
            with sqlite3.connect(f'file:{data / "llm-budget.sqlite3"}?mode=ro', uri=True, timeout=3) as db:
                row = db.execute("SELECT accounted,requests FROM llm_months WHERE month=strftime('%Y-%m','now')").fetchone() or (0, 0)
            cap = config['llm']['monthly_budget_micro_eur']
            if row[0] >= cap * 9 // 10:
                raise ValueError('LLM local budget has reached 90 percent')
            return {'accounted_micro_eur': row[0], 'requests': row[1], 'monthly_budget_micro_eur': cap}

        issue('llm_budget', llm)

    report = {'checked_at': now, 'status': 'attention' if issues else 'ok',
              'checks': details, 'issues': issues}
    if output:
        path = Path(output)
        pending = path.with_suffix('.pending.json')
        with pending.open('w') as file:
            os.fchmod(file.fileno(), 0o600)
            json.dump(report, file, indent=2)
            file.write('\n')
        pending.replace(path)
    print(json.dumps(report, ensure_ascii=False))
    return bool(issues)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', default='/etc/noisefence/config.toml')
    parser.add_argument('--output')
    args = parser.parse_args()
    raise SystemExit(check(args.config, args.output))
