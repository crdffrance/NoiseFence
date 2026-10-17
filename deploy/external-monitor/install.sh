#!/bin/sh
set -eu
[ "$(id -u)" = 0 ] || { echo "Run as root on an independent monitoring host." >&2; exit 1; }
[ "$#" = 1 ] || { echo "Usage: install.sh /path/to/monitor.json" >&2; exit 1; }
source_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
python3 - "$source_dir" "$1" <<'CHECK'
import importlib.util,sys
from pathlib import Path
spec=importlib.util.spec_from_file_location('probe',Path(sys.argv[1])/'probe.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
module.load_config(sys.argv[2])
CHECK
install -d -m 0755 /usr/local/libexec/noisefence-external
install -m 0644 "$source_dir/probe.py" /usr/local/libexec/noisefence-external/probe.py
install -m 0644 "$1" /etc/noisefence-external.json
install -m 0644 "$source_dir/noisefence-external.service" "$source_dir/noisefence-external.timer" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now noisefence-external.timer
systemctl start noisefence-external.service
