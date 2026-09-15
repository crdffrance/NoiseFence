#!/bin/sh
# Generate a separate, versioned comparison profile. Never edit a vendor config.
set -eu
target=${1:?Usage: rspamd-profile.sh NEW_PROFILE_DIRECTORY [LOOPBACK_DNS]}
resolver=${2:-127.0.0.53}
case "$target" in /*) ;; *) echo 'Use an absolute profile directory.' >&2; exit 1;; esac
case "$target" in *[!a-zA-Z0-9_./-]*) echo 'Unsupported profile path.' >&2; exit 1;; esac
case "$resolver" in 127.0.0.1|127.0.0.53|127.0.0.54) ;; *) echo 'Use a local caching DNS resolver.' >&2; exit 1;; esac
test ! -e "$target" || { echo 'Refusing to overwrite an existing profile.' >&2; exit 1; }
version=$(rspamd --version | head -n 1 | awk '{print $4}')
test "${version%%-*}" = 4.1.5 || { echo 'This profile was audited for Rspamd 4.1.5; review changes before upgrading.' >&2; exit 1; }
vendor=/etc/rspamd
if [ -f /usr/share/rspamd/config/rspamd.conf ]; then vendor=/usr/share/rspamd/config; fi
test -f "$vendor/rspamd.conf"
test -d /usr/share/rspamd/plugins
umask 022
mkdir -p "$target/local.d" "$target/override.d"
cat > "$target/rspamd.conf" <<EOF
# An explicit top-level config omits classifiers and ancillary workers entirely.
lua = "\$RULESDIR/rspamd.lua";
.include "$vendor/metrics.conf"
.include "$vendor/actions.conf"
.include "$vendor/groups.conf"
.include "$vendor/composites.conf"
.include "$vendor/modules.conf"
modules { path = "\$PLUGINSDIR"; }
options {
  .include "$vendor/options.inc"
  .include(priority=10) "\$LOCAL_CONFDIR/override.d/options.inc"
}
lang_detection { .include "$vendor/lang_detection.inc" }
logging { .include "\$LOCAL_CONFDIR/override.d/logging.inc" }
worker "normal" { .include "\$LOCAL_CONFDIR/override.d/worker-normal.inc" }
EOF
# Disabling every non-allowlisted module also covers plugins without a shipped
# module configuration. New providers cannot silently become active.
for file in "$vendor"/modules.d/*.conf /usr/share/rspamd/plugins/*.lua; do
    name=$(basename "$file"); name=${name%.*}
    case "$name" in
        arc|chartable|dkim|dmarc|forged_recipients|hfilter|maillist|mid|mime_types|phishing|regexp|spf) ;;
        *) printf 'enabled = false;\n' > "$target/override.d/$name.conf";;
    esac
done
cat > "$target/override.d/worker-normal.inc" <<'EOF'
enabled = true;
bind_socket = "127.0.0.1:11333";
count = 1;
max_tasks = 8;
allow_file_and_shm_inputs = false;
timeout = 6s;
task_timeout = 5s;
EOF
for worker in controller proxy fuzzy hs_helper; do
    printf 'enabled = false;\ncount = -1;\n' > "$target/override.d/worker-$worker.inc"
done
cat > "$target/override.d/options.inc" <<EOF
filters = "chartable,dkim,regexp";
explicit_modules = [];
max_message = 8388608;
max_map_size = 8M;
max_lua_http_response = 128k;
max_urls = 1024;
max_lua_urls = 256;
max_recipients = 100;
dns_max_requests = 32;
dns { nameserver = ["$resolver"]; timeout = 1s; retransmits = 1; sockets = 8; }
task_timeout = 5s;
soft_reject_on_timeout = true;
history_rows = 0;
pidfile = "/run/noisefence-rspamd/rspamd.pid";
EOF
cat > "$target/override.d/logging.inc" <<'EOF'
type = "console";
level = "warning";
log_re_cache = false;
EOF
cat > "$target/override.d/classifier-bayes.conf" <<'EOF'
enabled = false;
autolearn = false;
EOF
# Use packaged maps only. No remote phishing feeds or report submission.
cat > "$target/override.d/phishing.conf" <<EOF
openphish_enabled = false;
phishtank_enabled = false;
generic_service_enabled = false;
exceptions { REDIRECTOR_FALSE = ["$vendor/maps.d/redirectors.inc"]; }
EOF
printf 'file = ["%s/maps.d/mime_types.inc"];\n' "$vendor" > "$target/override.d/mime_types.conf"
printf 'source { url = ["%s/maps.d/mid.inc"]; }\n' "$vendor" > "$target/override.d/mid.conf"
cat > "$target/override.d/dmarc.conf" <<'EOF'
reporting { enabled = false; }
EOF
cat > "$target/override.d/arc.conf" <<'EOF'
sign_inbound = false;
sign_authenticated = false;
sign_local = false;
EOF
# Retain IP/HELO/From checks, without resolving URLs from message content.
printf 'url_enabled = false;\n' > "$target/override.d/hfilter.conf"
printf 'max_size = 8388608;\n' > "$target/override.d/regexp.conf"
# Hash installed executable, vendor rules/modules/maps and all profile settings.
# Paths participate in the identity; different package layouts are distinct.
{
    command -v rspamd | xargs sha256sum
    find "$vendor" /usr/share/rspamd "$target" -type f ! -name inputs.sha256 ! -name profile-id -exec sha256sum {} \;
} | LC_ALL=C sort > "$target/inputs.sha256"
identity=$(sha256sum "$target/inputs.sha256" | awk '{print $1}')
printf 'rspamd-%s:%s\n' "$version" "$identity" > "$target/profile-id"
printf 'Created %s\nProfile: ' "$target"
cat "$target/profile-id"
