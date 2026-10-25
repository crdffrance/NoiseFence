"""Private installation material for identity/memory recovery, never policy export.

No provider calls, decryption, key creation or credential renewal. PostgreSQL
archives still require a separate isolated database restore and native checks.
"""
import contextlib
import hashlib
import json
import os
import re
import sqlite3
import stat

PROTOCOL = 'noisefence-identity-recovery-1'
KEY_FILES = ('directory-vault/key', 'contact-memory/key', 'contact-memory/key-id')


def sha(value):
    if not isinstance(value, str) or not re.fullmatch('[a-f0-9]{64}', value):
        raise ValueError('Invalid identity recovery key identifier')
    return value


def read(root, relative, maximum, private=False):
    path = root / relative
    owner = root.stat().st_uid
    for parent in path.parents:
        if parent == root:
            break
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or (private and (info.st_uid != owner or info.st_mode & 0o077)):
            raise ValueError('Unsafe identity recovery directory')
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > maximum
                or (private and (info.st_uid != owner or info.st_mode & 0o077))):
            raise ValueError('Unsafe identity recovery file')
        value = stream.read(maximum + 1)
        if len(value) > maximum:
            raise ValueError('Oversized identity recovery file')
        return value


def files(root, private=True):
    """Only published keys and bounded content-addressed prepared catalogs."""
    result = {}
    for name in KEY_FILES:
        path = root / name
        if path.exists() or path.is_symlink():
            read(root, name, 64, private=private)
            result['data/' + name] = path
    prepared = root / 'identity/prepared'
    if prepared.exists() or prepared.is_symlink():
        for folder in (root / 'identity', prepared):
            info = folder.lstat()
            if not stat.S_ISDIR(info.st_mode) or (private and (info.st_uid != root.stat().st_uid or info.st_mode & 0o077)):
                raise ValueError('Unsafe identity recovery directory')
        count = total = 0
        for path in prepared.iterdir():
            count += 1
            if count > 32 or not re.fullmatch(r'[a-f0-9]{64}\.json', path.name):
                raise ValueError('Unstable or invalid prepared identity catalog')
            name = str(path.relative_to(root))
            value = read(root, name, 64 * 1024**2, private=private)
            total += len(value)
            if total > 128 * 1024**2 or hashlib.sha256(value).hexdigest() != path.stem:
                raise ValueError('Prepared identity catalog mismatch')
            result['data/' + name] = path
    return result


def postgres_keys(snapshot, target):
    """Read only public IDs, including revoked records; never fetch ciphertext."""
    def query(sql):
        output = snapshot.run(*snapshot.postgres_command(target, 'psql'), '-X', '-A', '-t',
                              '-v', 'ON_ERROR_STOP=1', '-c', sql, timeout=15).stdout
        if len(output) > 2048:
            raise ValueError('Oversized directory recovery identity')
        return output.strip()
    exists = query("SELECT to_regclass('noisefence.identity_connections') IS NOT NULL")
    if exists == 'f':
        return []
    if exists != 't':
        raise ValueError('Unknown directory component state')
    values = query("SELECT COALESCE(json_agg(key_id),'[]'::json) FROM (SELECT DISTINCT record#>>'{metadata,key_id}' AS key_id FROM noisefence.identity_connections LIMIT 17) AS keys")
    keys = json.loads(values)
    if not isinstance(keys, list) or len(keys) > 16:
        raise ValueError('Invalid directory recovery identity')
    return sorted({sha(value) for value in keys})


def inspect(root, config, connection_keys=None, expected=None, private=False):
    ids = {}
    for directory in ('directory-vault', 'contact-memory'):
        folder = root / directory
        if folder.exists() or folder.is_symlink():
            try:
                key = read(root, directory + '/key', 32, private)
            except FileNotFoundError as error:
                raise ValueError('Identity recovery key missing') from error
            if len(key) != 32:
                raise ValueError('Identity recovery key must contain 32 bytes')
            ids[directory] = hashlib.sha256(key).hexdigest()
            if directory == 'contact-memory':
                try:
                    marker = read(root, directory + '/key-id', 64, private).decode('ascii')
                except (FileNotFoundError, UnicodeError) as error:
                    raise ValueError('Contact memory recovery marker missing or invalid') from error
                if marker != ids[directory]:
                    raise ValueError('Contact memory recovery key mismatch')
    policies = [config]
    local_keys = []
    database = root / 'state.sqlite3'
    if database.is_file():
        with contextlib.closing(sqlite3.connect(database.resolve().as_uri() + '?mode=ro', uri=True)) as db:
            tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            # A selected central store must never use an old local shadow.
            if connection_keys is None and config.get('management') is None and 'identity_connections' in tables:
                rows = db.execute("SELECT DISTINCT json_extract(record,'$.metadata.key_id') FROM identity_connections LIMIT 17").fetchall()
                if len(rows) > 16:
                    raise ValueError('Invalid directory recovery identity')
                local_keys = sorted({sha(r[0]) for r in rows})
            installed = False
            if 'cluster_state' in tables:
                row = db.execute("SELECT CASE WHEN length(value)<=4194304 THEN value END FROM cluster_state WHERE key='activation_participant'").fetchone()
                if row:
                    if row[0] is None:
                        raise ValueError('Oversized installed policy')
                    policies = [json.loads(row[0]).get('installed', {}).get('settings', config)]
                    installed = True
            if not installed and config.get('management') is None and 'console_revisions' in tables:
                row = db.execute('SELECT CASE WHEN length(settings)<=4194304 THEN settings END FROM console_revisions ORDER BY id DESC LIMIT 1').fetchone()
                if row:
                    if row[0] is None:
                        raise ValueError('Oversized installed policy')
                    policies = [json.loads(row[0])]
    keys = local_keys if connection_keys is None else sorted({sha(k) for k in connection_keys})
    if any(k != ids.get('directory-vault') for k in keys):
        raise ValueError('Directory vault recovery key missing or mismatched')
    for policy in policies:
        memory = policy.get('contact_learning') or {}
        if memory.get('key_id') is not None:
            if sha(memory['key_id']) != ids.get('contact-memory'):
                raise ValueError('Installed contact memory recovery key missing or mismatched')
    report = {'protocol': PROTOCOL, 'keys': ids, 'connection_key_ids': keys}
    if expected is not None:
        if (not isinstance(expected, dict) or set(expected) != set(report)
                or expected.get('protocol') != PROTOCOL or expected.get('keys') != ids
                or not isinstance(expected.get('connection_key_ids'), list)
                or len(expected['connection_key_ids']) > 16):
            raise ValueError('Identity recovery receipt mismatch')
        recorded = [sha(k) for k in expected['connection_key_ids']]
        if any(k != ids.get('directory-vault') for k in recorded) or (connection_keys is None and config.get('management') is None and recorded != keys):
            raise ValueError('Directory recovery receipt mismatch')
    return report
