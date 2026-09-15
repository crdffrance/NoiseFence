#!/bin/sh
# Initial installation only. Existing comparison profiles are never overwritten.
set -eu
test "$(id -u)" = 0 || { echo 'Run as root.' >&2; exit 1; }
root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
resolver=${1:-127.0.0.53}
test ! -e /etc/noisefence-rspamd || { echo 'A profile already exists. Follow the documented upgrade procedure.' >&2; exit 1; }
if systemctl is-active --quiet rspamd.service; then
    echo 'The vendor Rspamd service is active. Refusing to replace an existing mail integration.' >&2
    exit 1
fi
id _rspamd >/dev/null
command -v python3 >/dev/null
"$root/rspamd-profile.sh" /etc/noisefence-rspamd "$resolver"
install -d -m 0700 -o _rspamd -g _rspamd /var/lib/noisefence-rspamd /run/noisefence-rspamd
rspamadm --var=LOCAL_CONFDIR=/etc/noisefence-rspamd --var=DBDIR=/var/lib/noisefence-rspamd configtest -c /etc/noisefence-rspamd/rspamd.conf
install -m 0644 "$root/noisefence-rspamd.service" /etc/systemd/system/noisefence-rspamd.service
systemctl daemon-reload
systemctl enable --now noisefence-rspamd.service
systemctl is-active --quiet noisefence-rspamd.service
printf '\nLocal scanner installed. Add the [rspamd] configuration with enabled=false first.\nProfile: '
cat /etc/noisefence-rspamd/profile-id
