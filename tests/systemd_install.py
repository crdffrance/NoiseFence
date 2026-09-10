#!/usr/bin/env python3
"""Exercise the real installer, daemon, queue and OCR pool on a disposable VM.

Refuses every existing NoiseFence installation/account. Baseline and candidate
use the supplied native binary: this tests deployment transitions, not binary
compatibility between released versions. No production host or mailbox is used.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import shutil
import smtplib
import socket
import sqlite3
import struct
import subprocess
import tempfile
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
BASE = Path('/opt/noisefence')
CONFIG = Path('/etc/noisefence/config.toml')
DATA = Path('/var/lib/noisefence')
UNITS = Path('/etc/systemd/system')
SERVICE = 'noisefence.service'
WORKERS = [f'noisefence-vision@{i}.service' for i in (1, 2)]
SOCKETS = [f'noisefence-vision@{i}.socket' for i in (1, 2)]
UNIT_FILES = ['noisefence.service', 'noisefence-vision.service', 'noisefence-vision.socket',
              'noisefence-vision@.service', 'noisefence-vision@.socket']
spec = importlib.util.spec_from_file_location('install_vision_fixture', ROOT / 'tests/vision_worker.py')
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)


def run(*args, check=True, timeout=45):
    result = subprocess.run([str(a) for a in args], capture_output=True, text=True, timeout=timeout)
    if check and result.returncode:
        raise AssertionError(f'{args}: exit {result.returncode}\n{result.stdout}\n{result.stderr}')
    return result


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def checksums(bundle):
    (bundle / 'SHA256SUMS').write_text(''.join(
        f'{digest(p)}  {p.relative_to(bundle)}\n' for p in sorted(bundle.rglob('*'))
        if p.is_file() and p.name != 'SHA256SUMS'))


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def active(unit):
    return run('systemctl', 'is-active', '--quiet', unit, check=False).returncode == 0


def ready(port):
    deadline = time.monotonic() + 15
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    while time.monotonic() < deadline:
        if active(SERVICE):
            try:
                with opener.open(f'http://127.0.0.1:{port}/healthz', timeout=.5) as response:
                    if json.load(response) == {'status': 'ok'}:
                        return
            except (OSError, ValueError):
                pass
        time.sleep(.1)
    raise AssertionError('Native daemon did not become healthy')


def pids():
    return [int(run('systemctl', 'show', '-p', 'MainPID', '--value', s).stdout) for s in WORKERS]


def assert_ocr(request, payload, backend):
    raw = json.dumps(request).encode()
    for i in (1, 2):
        with socket.socket(socket.AF_UNIX) as sock:
            sock.settimeout(8)
            sock.connect(f'/run/noisefence-vision-{i}/worker.sock')
            sock.sendall(struct.pack('!I', len(raw)) + raw)
            length = struct.unpack('!I', fixtures.worker.read_exact(sock, 4))[0]
            assert 0 < length <= fixtures.worker.MAX_RESPONSE
            reply = json.loads(fixtures.worker.read_exact(sock, length))
        assert reply['status'] == 'complete' and reply['backend_sha256'] == backend, reply
        assert len(reply['pages']) == 1
        assert 'NOISEFENCE' in reply['pages'][0]['text']
        assert payload in [c['data'] for c in reply['pages'][0]['codes']]


def queue_snapshot():
    deadline = time.monotonic() + 5
    with sqlite3.connect((DATA / 'state.sqlite3').as_uri() + '?mode=ro', uri=True) as db:
        assert db.execute('pragma integrity_check').fetchone() == ('ok',)
        rows = db.execute('select id,scan,raw_present,is_dsn from messages order by id').fetchall()
        assert len(rows) == 1 and rows[0][2:] == (1, 0), rows
        deliveries = db.execute('select message_id,address,status from deliveries').fetchall()
        while len(deliveries) == 1 and deliveries[0][2] == 'sending' and time.monotonic() < deadline:
            time.sleep(.05)
            deliveries = db.execute('select message_id,address,status from deliveries').fetchall()
        assert len(deliveries) == 1 and deliveries[0][2] == 'pending', deliveries
        schema = db.execute('pragma user_version').fetchone()[0]
    return {'messages': rows, 'deliveries': deliveries, 'schema': schema,
            'spool_sha256': digest(DATA / 'spool' / f'{rows[0][0]}.eml')}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    parser.add_argument('--disposable-host', action='store_true', required=True)
    args = parser.parse_args()
    assert os.geteuid() == 0 and Path('/run/systemd/system').is_dir()
    assert not any(p.exists() or p.is_symlink() for p in (BASE, CONFIG.parent, DATA))
    assert not list(UNITS.glob('noisefence*')) and not list(Path('/run').glob('noisefence*'))
    assert not run('systemctl', 'list-unit-files', 'noisefence*', '--no-legend', '--no-pager').stdout.strip()
    for user in ('noisefence', 'noisefence-vision'):
        try:
            pwd.getpwnam(user)
        except KeyError:
            pass
        else:
            raise AssertionError(f'Existing account {user}; refusing this host')
    binary = args.binary.resolve(strict=True)
    version = run(binary, '--version').stdout.strip().split()[1]
    assert all(c.isalnum() or c in '.-' for c in version)
    backend = fixtures.worker.capabilities()['backend_sha256']
    # Keep this port bound but never listen: every relay attempt must fail
    # locally, even if another process allocates a port during the test.
    relay_guard = socket.socket()
    relay_guard.bind(('127.0.0.1', 0))
    relay_port = relay_guard.getsockname()[1]
    smtp_port, web_port = free_port(), free_port()
    assert len({smtp_port, web_port, relay_port}) == 3
    records = []
    owned = False
    try:
        with tempfile.TemporaryDirectory(prefix='nf-installer-') as temporary:
            stage = Path(temporary)
            clean = stage / 'clean'
            clean.mkdir()
            shutil.copy2(binary, clean / 'noisefence')
            shutil.copytree(ROOT / 'deploy', clean / 'deploy', ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
            (clean / 'web').mkdir()
            (clean / 'web/index.html').write_text('Synthetic installer verification')
            (clean / 'build.json').write_text(json.dumps({'storage_schema': 2, 'version': version}))
            config = (ROOT / 'config/development.toml').read_text().replace(
                'var/development', str(DATA)).replace('web/dist/client', '/opt/noisefence/web').replace(
                '127.0.0.1:2525', f'127.0.0.1:{smtp_port}').replace(
                '127.0.0.1:18080', f'127.0.0.1:{web_port}').replace('port = 2526', f'port = {relay_port}')
            config += ('\n[vision]\nsocket = "/run/noisefence-vision-1/worker.sock"\n'
                       'additional_sockets = ["/run/noisefence-vision-2/worker.sock"]\n'
                       f'max_parallel = 2\nbackend_sha256 = "{backend}"\n')
            initial = stage / 'initial.toml'
            initial.write_text(config)
            checksums(clean)
            owned = True
            run('sh', clean / 'deploy/install.sh', clean, initial)
            ready(web_port)
            # This is the shipped optional installer, including apt and both real instances.
            run('sh', BASE / 'current/deploy/install-vision.sh', '2', timeout=180)
            image, payload = fixtures.fixture(stage)
            request = fixtures.request(image)
            assert_ocr(request, payload, backend)
            assert not active('noisefence-vision.service')
            with smtplib.SMTP('127.0.0.1', smtp_port, timeout=15) as smtp:
                assert smtp.sendmail('sender@example.test', ['alice@example.test'],
                                     'From: sender@example.test\r\nTo: alice@example.test\r\n'
                                     'Subject: Synthetic persistent installer check\r\n\r\nQueue sentinel.\r\n') == {}
            original = queue_snapshot()
            original_config = digest(CONFIG)
            records.append({'case': 'initial_install_and_optional_two_worker_install', 'passed': True})
            run('systemctl', 'stop', SERVICE, *WORKERS)
            baseline = BASE / 'releases/fixture-baseline'
            (BASE / f'releases/{version}').rename(baseline)
            baseline_unit = baseline / 'deploy/noisefence.service'
            baseline_unit.write_text(baseline_unit.read_text() + '\n# Synthetic previous service definition\n')
            baseline_worker = baseline / 'deploy/noisefence-vision@.service'
            baseline_worker_original = baseline_worker.read_text()

            def reset_baseline():
                run('systemctl', 'stop', SERVICE, *WORKERS, check=False)
                (BASE / 'current').unlink()
                (BASE / 'current').symlink_to('releases/fixture-baseline')
                candidate_installed = BASE / f'releases/{version}'
                if candidate_installed.exists():
                    shutil.rmtree(candidate_installed)
                (baseline / 'build.json').write_text(json.dumps({'storage_schema': 2}))
                baseline_worker.write_text(baseline_worker_original)
                for name in UNIT_FILES:
                    shutil.copy2(baseline / 'deploy' / name, UNITS / name)
                run('systemctl', 'daemon-reload')
                run('systemctl', 'reset-failed', SERVICE, *WORKERS, check=False)
                run('systemctl', 'start', *SOCKETS, *WORKERS, SERVICE)
                ready(web_port)
                assert queue_snapshot() == original and digest(CONFIG) == original_config

            for case in ('upgrade', 'daemon_unit_failure', 'worker_start_failure',
                         'incompatible_storage', 'rollback_worker_failure'):
                reset_baseline()
                before = pids()
                assert all(pid > 0 for pid in before)
                candidate = stage / case
                shutil.copytree(clean, candidate)
                if case != 'upgrade':
                    fault = 'noisefence-vision@.service' if case == 'worker_start_failure' else 'noisefence.service'
                    file = candidate / 'deploy' / fault
                    file.write_text(file.read_text().replace('[Service]', '[Service]\nExecStartPre=/bin/false', 1))
                if case == 'incompatible_storage':
                    (baseline / 'build.json').write_text(json.dumps({'storage_schema': 1}))
                if case == 'rollback_worker_failure':
                    baseline_worker.write_text(baseline_worker_original.replace('[Service]', '[Service]\nExecStartPre=/bin/false', 1))
                checksums(candidate)
                result = run('sh', candidate / 'deploy/install.sh', candidate, check=False)
                expected = 0 if case == 'upgrade' else 1
                assert result.returncode == expected, (case, result.stdout, result.stderr)
                healthy = case not in ('incompatible_storage', 'rollback_worker_failure')
                if healthy:
                    ready(web_port)
                    assert all(active(s) for s in WORKERS)
                    assert not active('noisefence-vision.service'), 'Upgrade started unused legacy worker'
                    after = pids()
                    assert all(a > 0 and a != b for a, b in zip(after, before))
                    expected_release = BASE / f'releases/{version}' if case == 'upgrade' else baseline
                    assert (BASE / 'current').resolve() == expected_release
                    for name in UNIT_FILES:
                        assert (UNITS / name).read_bytes() == (expected_release / 'deploy' / name).read_bytes()
                    assert_ocr(request, payload, backend)
                else:
                    assert not active(SERVICE)
                    if case == 'incompatible_storage':
                        assert (BASE / 'current').resolve() == BASE / f'releases/{version}'
                        assert 'Automatic rollback refused' in result.stdout
                    else:
                        assert (BASE / 'current').resolve() == baseline
                        assert 'SMTP remains stopped' in result.stderr
                assert queue_snapshot() == original and digest(CONFIG) == original_config
                records.append({'case': case, 'passed': True, 'installer_exit': expected,
                                'smtp_healthy': healthy, 'queue_and_config_preserved': True})
                print(json.dumps(records[-1]), flush=True)
    except BaseException:
        if owned:
            print(run('journalctl', '-u', SERVICE, '-u', WORKERS[0], '-u', WORKERS[1],
                      '-n', '100', '--no-pager', check=False).stdout, flush=True)
        raise
    finally:
        if owned:
            run('systemctl', 'stop', SERVICE, *SOCKETS, *WORKERS, 'noisefence-vision.socket',
                'noisefence-vision.service', check=False)
            assert not any(active(s) for s in (SERVICE, *SOCKETS, *WORKERS))
            run('systemctl', 'disable', SERVICE, *SOCKETS, check=False)
            for name in UNIT_FILES:
                (UNITS / name).unlink(missing_ok=True)
            run('systemctl', 'daemon-reload')
            run('systemctl', 'reset-failed', SERVICE, *WORKERS, check=False)
            for path in (BASE, CONFIG.parent, DATA):
                if path.exists():
                    shutil.rmtree(path)
            for user in ('noisefence-vision', 'noisefence'):
                run('userdel', user, check=False)
                run('groupdel', user, check=False)
                try:
                    pwd.getpwnam(user)
                except KeyError:
                    pass
                else:
                    raise AssertionError(f'Test account {user} remains')
            for name in ('noisefence-vision', 'noisefence-vision-1', 'noisefence-vision-2'):
                path = Path('/run') / name
                if path.exists():
                    path.rmdir()  # Only empty runtime directories owned by this test.
            assert not any(path.exists() for path in (BASE, CONFIG.parent, DATA))
        relay_guard.close()
    print(json.dumps({'cases': records, 'binary_sha256': digest(binary), 'backend_sha256': backend,
                      'cleaned_up': True, 'external_messages': 0,
                      'scope': 'Real installer/systemd/native daemon/SQLite/OCR; same native binary in both fixture releases; no cross-version ABI or antispam quality claim.'}), flush=True)


if __name__ == '__main__':
    main()
