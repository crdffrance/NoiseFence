#!/bin/sh
# Install a verified NoiseFence archive on a systemd Linux host.
set -eu
umask 027
if [ "$(id -u)" != 0 ]; then echo 'Run this installer as root.' >&2; exit 1; fi
bundle=$(realpath "${1:?Usage: install.sh EXTRACTED_RELEASE [INITIAL_CONFIG]}")
initial_config=${2:-}
cd "$bundle"
sha256sum --check --quiet SHA256SUMS
python3 -c "import sqlite3, tomllib"
version=$(./noisefence --version | awk '{print $2}')
case "$version" in ''|*[!0-9A-Za-z.-]*) echo 'Invalid version' >&2; exit 1;; esac
base=/opt/noisefence
destination="$base/releases/$version"
if ! id noisefence >/dev/null 2>&1; then
    useradd --system --user-group --home-dir /var/lib/noisefence --shell /usr/sbin/nologin noisefence
fi
install -d -m 0755 "$base" "$base/releases"
install -d -m 0700 -o noisefence -g noisefence /var/lib/noisefence
install -d -m 0750 -o root -g noisefence /etc/noisefence
if [ ! -f /etc/noisefence/config.toml ]; then
    if [ -z "$initial_config" ]; then echo 'Supply the initial configuration.' >&2; exit 1; fi
    install -m 0640 -o root -g noisefence "$initial_config" /etc/noisefence/config.toml
fi
./noisefence --config /etc/noisefence/config.toml check-config
if [ -e "$destination" ]; then
    cmp SHA256SUMS "$destination/SHA256SUMS" || { echo 'Refusing to overwrite a different build of the same version.' >&2; exit 1; }
else
    install -d -m 0755 "$destination"
    cp -a . "$destination/"
    chown -R root:root "$destination"
fi
# Private extraction directories can be 0700 even for a public release archive.
# Make the installed bundle readable/traversable by the service account while
# preserving executable files and excluding group/other write access.
chmod -R u=rwX,go=rX "$destination"
for entry in noisefence web; do
    if [ -e "$base/$entry" ] && [ ! -L "$base/$entry" ]; then
        echo "Refusing to replace non-symlink $base/$entry; migrate it first." >&2; exit 1
    fi
done
previous=$(readlink "$base/current" || true)
ln -sfn "releases/$version" "$base/current.next"
mv -Tf "$base/current.next" "$base/current"
ln -sfn current/noisefence "$base/noisefence"
ln -sfn current/web "$base/web"
install -m 0644 deploy/noisefence.service /etc/systemd/system/noisefence.service
vision_installed=false
vision_was_active=false
vision_pool_instances=
if [ -f /etc/systemd/system/noisefence-vision.service ]; then
    # Pool installations also ship the legacy unit without starting it. Do not
    # allocate an unused extra OCR process during every gateway upgrade.
    vision_installed=true
    if systemctl is-active --quiet noisefence-vision.service; then vision_was_active=true; fi
    install -m 0644 deploy/noisefence-vision.service /etc/systemd/system/
    install -m 0644 deploy/noisefence-vision.socket /etc/systemd/system/
fi
if [ -f /etc/systemd/system/noisefence-vision@.service ]; then
    install -m 0644 deploy/noisefence-vision@.service /etc/systemd/system/
    install -m 0644 deploy/noisefence-vision@.socket /etc/systemd/system/
    for instance in 1 2 3 4; do
        if systemctl is-active --quiet "noisefence-vision@$instance.service"; then
            vision_pool_instances="$vision_pool_instances $instance"
        fi
    done
fi
systemctl daemon-reload
systemctl enable noisefence.service
if ! (if "$vision_was_active"; then systemctl restart noisefence-vision.service || exit 1; fi
      for instance in $vision_pool_instances; do
          systemctl restart "noisefence-vision@$instance.service" || exit 1
      done
      systemctl restart noisefence.service); then
    systemctl stop noisefence.service || { echo 'Could not stop candidate; automatic rollback refused.' >&2; exit 1; }
    if [ -n "$previous" ] && [ -f "$base/$previous/deploy/noisefence.service" ] \
       && python3 deploy/can-rollback.py --config /etc/noisefence/config.toml --previous "$base/$previous" \
       && "$base/$previous/noisefence" --config /etc/noisefence/config.toml check-config; then
        ln -sfn "$previous" "$base/current.next"
        mv -Tf "$base/current.next" "$base/current"
        # A candidate unit can itself be the reason startup failed. Restore the
        # daemon definition as well as its executable and optional workers.
        install -m 0644 "$base/current/deploy/noisefence.service" /etc/systemd/system/
        rollback_workers_ok=true
        if "$vision_installed" && [ -f "$base/current/deploy/noisefence-vision.service" ]; then
            install -m 0644 "$base/current/deploy/noisefence-vision.service" /etc/systemd/system/
            install -m 0644 "$base/current/deploy/noisefence-vision.socket" /etc/systemd/system/
        fi
        if [ -f "$base/current/deploy/noisefence-vision@.service" ]; then
            install -m 0644 "$base/current/deploy/noisefence-vision@.service" /etc/systemd/system/
            install -m 0644 "$base/current/deploy/noisefence-vision@.socket" /etc/systemd/system/
        fi
        systemctl daemon-reload
        if "$vision_was_active" && [ -f "$base/current/deploy/noisefence-vision.service" ]; then
            systemctl reset-failed noisefence-vision.service || true
            systemctl restart noisefence-vision.service || rollback_workers_ok=false
        fi
        if [ -f "$base/current/deploy/noisefence-vision@.service" ]; then
            for instance in $vision_pool_instances; do
                systemctl reset-failed "noisefence-vision@$instance.service" || true
                systemctl restart "noisefence-vision@$instance.service" || rollback_workers_ok=false
            done
        else
            # A prior release without pooling may still accept a legacy config.
            # Stop unused pool instances rather than leave candidate workers live.
            for instance in $vision_pool_instances; do
                systemctl stop "noisefence-vision@$instance.socket" "noisefence-vision@$instance.service" || rollback_workers_ok=false
            done
        fi
        if "$rollback_workers_ok"; then
            systemctl reset-failed noisefence.service || true
            if systemctl restart noisefence.service; then
                echo 'Previous service definition, release and workers restored.' >&2
            else
                echo 'Previous SMTP service could not restart; manual recovery required.' >&2
            fi
        else
            echo 'Previous OCR workers could not restart; SMTP remains stopped for manual recovery.' >&2
        fi
    fi
    echo 'Startup failed; inspect journalctl -u noisefence.' >&2
    exit 1
fi
systemctl is-active noisefence.service
echo "NoiseFence $version installed. Existing configuration was preserved."
