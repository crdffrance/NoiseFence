#!/usr/bin/env python3
"""Certbot deploy hook for NoiseFence (Debian 12+, Python 3.11+)."""
import grp
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import uuid


def command(*args, data=None):
    return subprocess.run(args, input=data, check=True, capture_output=True).stdout


def validate_bundle(directory, hostname):
    cert = str(directory / 'fullchain.pem')
    key = str(directory / 'key.pem')
    command('openssl', 'x509', '-in', cert, '-noout', '-checkend', '86400')
    command('openssl', 'verify', '-purpose', 'sslserver', '-verify_hostname', hostname,
            '-untrusted', cert, cert)
    certificate_key = command('openssl', 'x509', '-in', cert, '-pubkey', '-noout')
    certificate_der = command('openssl', 'pkey', '-pubin', '-outform', 'DER',
                              data=certificate_key)
    private_der = command('openssl', 'pkey', '-in', key, '-pubout', '-outform', 'DER')
    if certificate_der != private_der:
        raise ValueError('TLS certificate and private key do not match')


def sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def switch_link(base, target):
    pending = base / ('.current-' + uuid.uuid4().hex)
    pending.symlink_to(target)
    try:
        os.replace(pending, base / 'current')
        sync_directory(base)
    finally:
        pending.unlink(missing_ok=True)


def deploy(lineage, hostname, base, uid, gid, restart):
    base.mkdir(parents=True, exist_ok=True)
    versions = base / 'versions'
    versions.mkdir(exist_ok=True)
    for path in (base, versions):
        os.chown(path, uid, gid)
        path.chmod(0o750)
    current = base / 'current'
    if current.exists() and not current.is_symlink():
        raise ValueError('Refusing to replace a non-symlink TLS current path')
    previous = os.readlink(current) if current.is_symlink() else None
    staging = Path(tempfile.mkdtemp(prefix='.pending-', dir=versions))
    try:
        os.chown(staging, uid, gid)
        staging.chmod(0o750)
        for source, name in [('fullchain.pem', 'fullchain.pem'), ('privkey.pem', 'key.pem')]:
            path = staging / name
            with path.open('xb') as destination:
                os.fchmod(destination.fileno(), 0o640)
                os.fchown(destination.fileno(), uid, gid)
                destination.write((lineage / source).read_bytes())
                destination.flush()
                os.fsync(destination.fileno())
        validate_bundle(staging, hostname)
        fingerprint = hashlib.sha256((staging / 'fullchain.pem').read_bytes()).hexdigest()
        target = versions / fingerprint
        if target.exists():
            for name in ('fullchain.pem', 'key.pem'):
                if (target / name).read_bytes() != (staging / name).read_bytes():
                    raise ValueError('Conflicting existing certificate bundle')
        else:
            sync_directory(staging)
            os.rename(staging, target)
            sync_directory(versions)
        switch_link(base, 'versions/' + fingerprint)
        try:
            restart()
        except Exception:
            if previous is not None:
                switch_link(base, previous)
                restart()
            else:
                current.unlink()
                sync_directory(base)
            raise
    finally:
        if staging.exists():
            shutil.rmtree(staging)


def main():
    import tomllib
    if os.geteuid() != 0:
        raise SystemExit('Run this hook as root')
    config = tomllib.loads(Path('/etc/noisefence/config.toml').read_text())
    hostname = config['hostname']
    lineage = Path(os.environ['RENEWED_LINEAGE'])
    if lineage != Path('/etc/letsencrypt/live') / hostname:
        print('Skipping a certificate not used by NoiseFence')
        return
    base = Path('/etc/noisefence/tls')
    if (config['smtp'].get('tls_cert') != str(base / 'current/fullchain.pem')
            or config['smtp'].get('tls_key') != str(base / 'current/key.pem')):
        raise SystemExit('Configure the NoiseFence TLS paths documented in docs/operations.md')
    deploy(lineage, hostname, base, 0, grp.getgrnam('noisefence').gr_gid,
           lambda: subprocess.run(['systemctl', 'try-restart', 'noisefence.service'], check=True))
    print('NoiseFence TLS certificate installed; active service restarted')


if __name__ == '__main__':
    main()
