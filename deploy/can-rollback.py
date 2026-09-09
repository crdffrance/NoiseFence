#!/usr/bin/env python3
"""Read-only schema compatibility check; run only after stopping the candidate."""
import argparse
import json
from pathlib import Path
import sqlite3
import tomllib


def compatible(config: Path, previous: Path) -> bool:
    settings = tomllib.loads(config.read_text())
    database = Path(settings['data_dir']) / 'state.sqlite3'
    if not database.is_absolute():
        database = Path('/opt/noisefence') / database
    manifest = json.loads((previous / 'build.json').read_text())
    supported = manifest.get('storage_schema', 1)
    if type(supported) is not int or supported < 1:
        return False
    if not database.exists():
        return True
    with sqlite3.connect(database.resolve().as_uri() + '?mode=ro', uri=True) as db:
        version = db.execute('PRAGMA user_version').fetchone()[0]
    return version <= supported


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--previous', type=Path, required=True)
    args = parser.parse_args()
    try:
        allowed = compatible(args.config, args.previous)
    except (OSError, ValueError, KeyError, sqlite3.Error):
        allowed = False
    if not allowed:
        print('Automatic rollback refused: incompatible or unknown storage schema. Keep the compatible release and inspect the service logs.')
    raise SystemExit(0 if allowed else 1)


if __name__ == '__main__':
    main()
