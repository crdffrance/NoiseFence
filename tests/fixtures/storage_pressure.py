"""Exercise real ENOSPC only inside the disposable native lifecycle fixture.

A 64 MiB synthetic tmpfs tests admission and buffered DATA failure, not power-loss
persistence, paired failover or full-disk disaster recovery on production storage.
"""
import errno
import hashlib
import json
import os
from pathlib import Path
import smtplib
import socket
import sqlite3

ROOT = Path('/var/lib/noisefence')
FILLER = ROOT/'synthetic-enospc-fill'
SNAPSHOT = Path('/root/accepted.json')


def inventory():
    with sqlite3.connect('file:/var/lib/noisefence/state.sqlite3?mode=ro', uri=True) as db:
        rows = [list(row) for row in db.execute('select id from messages order by id')]
    return {'rows': rows, 'digests': {
        row[0]: hashlib.sha256((ROOT/'spool'/(row[0]+'.eml')).read_bytes()).hexdigest()
        for row in rows}}


def fill():
    descriptor = os.open(FILLER, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    written = 0
    try:
        for size in [1048576, 4096]:
            chunk = b'X'*size
            while written <= 80*1048576:
                try:
                    written += os.write(descriptor, chunk)
                except OSError as error:
                    if error.errno != errno.ENOSPC:
                        raise
                    break
            else:
                raise AssertionError('Synthetic filesystem exceeded its configured bound')
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    assert os.statvfs(ROOT).f_bavail == 0
    return written


def connect():
    client = smtplib.SMTP('127.0.0.1', 2525, timeout=10)
    client.ehlo('sender.example.test')
    return client


def main():
    # Refuse ordinary hosts before opening a writable file or an SMTP connection.
    assert os.geteuid() == 0 and os.environ.get('container') == 'docker'
    assert socket.gethostname() == 'test-lifecycle'
    mounts = [line.split() for line in Path('/proc/mounts').read_text().splitlines()]
    assert any(row[1:3] == [str(ROOT), 'tmpfs'] for row in mounts)
    space = os.statvfs(ROOT)
    assert space.f_blocks*space.f_frsize == 64*1048576
    expected = json.loads(SNAPSHOT.read_text())
    assert len(expected['rows']) == 1 and inventory() == expected
    checks = []
    try:
        fill_bytes = fill()
        with connect() as client:
            upfront = client.mail('sender@example.test')
            assert upfront[0] == 452, upfront[0]
        checks.append('disk_full_before_mail_temporarily_rejected')
    finally:
        FILLER.unlink(missing_ok=True)
    assert inventory() == expected
    raw = (b'From: sender@example.test\r\nTo: alice@example.test\r\n'
           b'Subject: Synthetic storage pressure\r\n\r\nNo external delivery.\r\n')
    with connect() as client:
        assert client.mail('sender@example.test')[0] == 250
        assert client.rcpt('alice@example.test')[0] == 250
        assert client.docmd('DATA')[0] == 354
        try:
            fill()
            client.send(raw+b'.\r\n')
            late = client.getreply()
            assert late[0] == 452, late[0]
            checks.append('disk_full_after_data_temporarily_rejected')
        finally:
            FILLER.unlink(missing_ok=True)
    assert inventory() == expected  # Neither rejected transaction was accepted.
    with connect() as client:
        assert not client.sendmail('sender@example.test', ['alice@example.test'], raw)
    recovered = inventory()
    assert len(recovered['rows']) == 2 and all(
        recovered['digests'].get(key) == value for key, value in expected['digests'].items())
    checks.append('disk_full_recovery_preserves_accepted_messages')
    # The later service-removal check must preserve both actual acceptances.
    SNAPSHOT.write_text(json.dumps(recovered))
    print(json.dumps({'status': 'passed', 'checks': checks, 'fill_bytes': fill_bytes,
                      'before_mail_reply': upfront[0], 'after_data_reply': late[0],
                      'accepted_messages': len(recovered['rows']), 'filesystem': '64MiB tmpfs',
                      'power_loss_tested': False, 'production_affected': False}))


if __name__ == '__main__':
    main()
