#!/bin/sh
# Production starts this launcher as root only to retain the privileged-port
# capability while changing identity. No SMTP/MIME code runs before this exec.
set -eu
if [ "$(id -u)" = 0 ]; then
    exec /usr/bin/setpriv --reuid=10001 --regid=10001 --clear-groups \
        --inh-caps=-all,+net_bind_service \
        --ambient-caps=-all,+net_bind_service \
        --bounding-set=-all,+net_bind_service --no-new-privs \
        /usr/local/bin/noisefence --config /etc/noisefence/config.toml "$@"
fi
exec /usr/local/bin/noisefence --config /etc/noisefence/config.toml "$@"
