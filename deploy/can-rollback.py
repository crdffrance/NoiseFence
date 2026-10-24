#!/usr/bin/env python3
"""Read-only schema compatibility check; run only after stopping the candidate."""
import argparse
import contextlib
import json
import os
from pathlib import Path
import sqlite3
import tomllib


def compatible(config: Path, previous: Path) -> bool:
    settings = tomllib.loads(config.read_text())
    # A local schema number cannot certify central data compatibility. A
    # reconciled restore/export needs a separate, explicit operator procedure.
    if 'management' in settings:
        return False
    database = Path(settings['data_dir']) / 'state.sqlite3'
    if not database.is_absolute():
        database = Path('/opt/noisefence') / database
    manifest = json.loads((previous / 'build.json').read_text())
    supported = manifest.get('storage_schema', 1)
    if type(supported) is not int or not 1 <= supported <= 7:
        return False
    if not os.path.lexists(database):
        # An installed predecessor is not proof that missing state is fresh.
        return False
    with contextlib.closing(sqlite3.connect(database.resolve().as_uri() + '?mode=ro', uri=True, timeout=.05)) as db:
        db.execute('PRAGMA query_only=ON')
        db.execute('BEGIN')
        version = db.execute('PRAGMA user_version').fetchone()[0]
        if not 1 <= version < 7:
            return False
        if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='cluster_state'").fetchone():
            if db.execute("SELECT 1 FROM cluster_state WHERE key IN ('management_selection','management_transport','runtime_history_protocol','management_recovery_required','management_worker_release') LIMIT 1").fetchone():
                return False
            if 'replication' not in settings and db.execute("SELECT 1 FROM cluster_state WHERE key='ha_required' LIMIT 1").fetchone():
                return False
    return version <= supported


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--previous', type=Path, required=True)
    args = parser.parse_args()
    try:
        allowed = compatible(args.config, args.previous)
    except (OSError, ValueError, KeyError, TypeError, sqlite3.Error):
        allowed = False
    if not allowed:
        print('Automatic rollback refused: incompatible or unknown storage schema. Keep the compatible release and inspect the service logs.')
    raise SystemExit(0 if allowed else 1)


if __name__ == '__main__':
    main()
