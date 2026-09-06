#!/bin/sh
set -eu
install -d -o clamav -g clamav -m 0755 /run/clamav
if [ "${NOISEFENCE_TEST_UNOFFICIAL:-0}" = 1 ]; then
    python3 /opt/noisefence-deploy/fetch-unofficial-sigs.py /opt/unofficial-sigs
    install -d /etc/clamav-unofficial-sigs
    install -m 0755 /opt/unofficial-sigs/clamav-unofficial-sigs.sh /usr/local/sbin/clamav-unofficial-sigs
    install -m 0644 /opt/unofficial-sigs/config/master.conf /etc/clamav-unofficial-sigs/master.conf
    install -m 0644 /opt/unofficial-sigs/config/os/os.debian.conf /etc/clamav-unofficial-sigs/os.conf
    install -m 0644 /opt/noisefence-deploy/unofficial-sigs.user.conf /etc/clamav-unofficial-sigs/user.conf
    # Initial fixture setup has no daemon to reload; production retains reloads.
    printf '\nreload_dbs="no"\n' >> /etc/clamav-unofficial-sigs/user.conf
    install -d -o clamav -g clamav /var/lib/noisefence-signatures /var/lib/clamav-unofficial-sigs /var/log/clamav-unofficial-sigs
    install -d -o clamav -g clamav -m 0700 /var/lib/clamav-unofficial-sigs/gpg-key
    install -o clamav -g clamav -m 0600 /opt/unofficial-sigs/sanesecurity-publickey.gpg /var/lib/clamav-unofficial-sigs/gpg-key/publickey.gpg
    # No daemon is running yet. The updater verifies signatures before installation.
    su -s /bin/bash -c '/usr/local/sbin/clamav-unofficial-sigs' clamav
    python3 - <<'PY'
import hashlib, pathlib, subprocess
work = pathlib.Path('/var/lib/clamav-unofficial-sigs')
installed = pathlib.Path('/var/lib/noisefence-signatures')
count = 0
for name in ('sanesecurity.ftm', 'sigwhitelist.ign2', 'phish.ndb', 'junk.ndb'):
    sources = list(work.glob('*/' + name))
    assert len(sources) == 1, 'Missing signature source: ' + name
    source = sources[0]
    assert source.stat().st_size > 0
    assert (installed / name).read_bytes() == source.read_bytes(), 'Installed source differs'
    checked = subprocess.run(['gpg', '--batch', '--no-default-keyring', '--homedir', str(work / 'gpg-key'), '--keyring', str(work / 'gpg-key/ss-keyring.gpg'), '--status-fd', '1', '--verify', str(source) + '.sig', str(source)], capture_output=True, text=True, check=True)
    assert '[GNUPG:] VALIDSIG 4E025A1CBA90A0653F38D2D8D691DED931EA4D9E ' in checked.stdout
    count += 1
print('Verified and installed Sanesecurity test databases:', count, flush=True)
PY
    install -d -o clamav -g clamav -m 0755 /run/noisefence-signatures
    install -m 0644 /opt/noisefence-deploy/noisefence-signatures.conf /etc/clamav/noisefence-signatures.conf
    clamd --foreground=true --config-file=/etc/clamav/noisefence-signatures.conf &
    advisory_pid=$!
fi
# Official downloads only; do not bypass CDN throttling if FreshClam refuses.
freshclam --stdout
clamd --foreground=true &
daemon_pid=$!
trap 'kill "$daemon_pid" ${advisory_pid:-} 2>/dev/null || true' EXIT INT TERM
python3 - <<'PY'
import socket, time
for attempt in range(60):
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
            stream.settimeout(1)
            stream.connect('/run/clamav/clamd.ctl')
            stream.sendall(b'zVERSION\0')
            reply = stream.recv(512)
            if reply.startswith(b'ClamAV '):
                print(reply.rstrip(b'\0').decode(), flush=True)
                break
    except OSError:
        pass
    time.sleep(1)
else:
    raise SystemExit('ClamAV did not become ready in 60 seconds')
PY
if [ "${NOISEFENCE_TEST_UNOFFICIAL:-0}" = 1 ]; then
    clamdscan --config-file=/etc/clamav/noisefence-signatures.conf --stream --no-summary /etc/hostname
fi
NOISEFENCE_TEST_CLAMD=/run/clamav/clamd.ctl cargo test --locked --test antivirus live_clamav -- --ignored --nocapture
