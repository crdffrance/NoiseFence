"""Export only frozen metadata and the exact installed runtime's data artifacts."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import sqlite3
import stat
import tomllib
from migration_protocol import MAX_FILE, MAX_TOTAL, atomic, canonical, pairs, private_read, require, sha


def name_ok(name):
    return (isinstance(name, str) and len(name) <= 240
            and re.fullmatch('[A-Za-z0-9_./-]+', name) is not None
            and not name.startswith('/') and all(p and not p.startswith('.') for p in name.split('/')))


def checked_manifest(manifest):
    require(isinstance(manifest, dict) and 2 <= len(manifest) <= 256, 'Invalid migration file manifest')
    total = 0
    for name, info in manifest.items():
        require(name_ok(name) and isinstance(info, dict) and set(info) == {'bytes', 'sha256'}
                and type(info['bytes']) is int and 0 <= info['bytes'] <= MAX_FILE and sha(info['sha256']),
                'Invalid migration file entry')
        total += info['bytes']
    require(total <= MAX_TOTAL and {'state.sqlite3', 'config.toml'} <= set(manifest), 'Migration export exceeds bounds')
    for name in manifest:
        parts = PurePosixPath(name).parts
        require(name in ('state.sqlite3', 'config.toml', 'mfa.key')
                or (len(parts) == 3 and parts[:2] == ('cluster', 'credentials')
                    and re.fullmatch(r'[a-f0-9]{64}\.json', parts[2]))
                or (len(parts) >= 4 and parts[:2] == ('cluster', 'models') and sha(parts[2])),
                'Unapproved migration export member')
    return total


def describe(path, limit):
    with private_read(path, limit) as source:
        info = os.fstat(source.fileno())
        digest = hashlib.sha256()
        for block in iter(lambda: source.read(65536), b''):
            digest.update(block)
        return {'bytes': info.st_size, 'sha256': digest.hexdigest()}


def source_files(data, config_path, ready):
    """Called while the native source session owns its locks/write reservation."""
    data = Path(data)
    export = Path(ready['export_path'])
    with private_read(config_path, 1024 * 1024) as source:
        config = tomllib.loads(source.read().decode())
    require(Path(config['data_dir']) == data, 'Configuration data directory differs')
    node = ready['receipt']['journal']['identity']['node']
    require(config.get('cluster', {}).get('node_id') == node, 'Configuration node differs')
    paths = {'state.sqlite3': export, 'config.toml': Path(config_path)}
    manifest = {'state.sqlite3': {'bytes': ready['receipt']['bytes'], 'sha256': ready['receipt']['sha256']}}
    manifest['config.toml'] = describe(config_path, 1024 * 1024)
    with sqlite3.connect(export.as_uri() + '?mode=ro', uri=True, timeout=2) as db:
        row = db.execute("SELECT CASE WHEN length(value)<=4194304 THEN value END FROM cluster_state WHERE key='activation_participant'").fetchone()
        require(row is not None and row[0] is not None, 'Missing or oversized installed participant')
        installed = json.loads(row[0], object_pairs_hook=pairs)['installed']
    files = installed.get('files')
    require(isinstance(files, dict) and len(files) <= 250, 'Invalid installed file manifest')
    # Rust serializes BTreeMap keys in order; Artifact fields are sha256, size.
    digest = hashlib.sha256(canonical(files)).hexdigest()
    for name, item in files.items():
        require(name_ok(name) and isinstance(item, dict) and set(item) == {'sha256', 'size'}
                and sha(item['sha256']) and type(item['size']) is int and 0 <= item['size'] <= MAX_FILE,
                'Invalid installed artifact')
        target = 'cluster/models/' + digest + '/' + name
        paths[target] = data / target
        manifest[target] = {'bytes': item['size'], 'sha256': item['sha256']}
    generation = installed.get('credential_generation')
    require(sha(generation), 'Installed credentials have no immutable generation')
    target = 'cluster/credentials/' + generation + '.json'
    paths[target] = data / target
    manifest[target] = describe(paths[target], 4096)
    if config['cluster']['role'] == 'coordinator':
        paths['mfa.key'] = data / 'mfa.key'
        manifest['mfa.key'] = describe(paths['mfa.key'], 32)
        require(manifest['mfa.key']['bytes'] == 32, 'Original MFA key is invalid')
    checked_manifest(manifest)
    return paths, manifest


def receive_export(channel, directory, manifest, ready):
    directory = Path(directory)
    require(directory.is_absolute() and directory.resolve() == directory and not directory.exists(),
            'Export destination must be a new physical directory')
    checked_manifest(manifest)
    expected = {'bytes': ready['receipt']['bytes'], 'sha256': ready['receipt']['sha256']}
    require(manifest['state.sqlite3'] == expected, 'Manifest differs from original source receipt')
    directory.mkdir(mode=0o700)
    # Keep a failed private import for diagnosis; never expose it as complete.
    for name in sorted(manifest):
        target = directory / name
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        channel.receive_file(target, manifest[name])
    completion = channel.receive()
    require(completion == {'status': 'exported', 'manifest_sha256': hashlib.sha256(canonical(manifest)).hexdigest()},
            'Export completion was not acknowledged')
    atomic(directory / 'export-receipt.json', canonical({'receipt': ready, 'manifest': manifest}))


def remap_config(directory):
    """Change only the copied configuration's top-level data_dir, preserving TOML."""
    directory = Path(directory)
    path = directory / 'config.toml'
    with private_read(path, 1024 * 1024) as source:
        raw = source.read().decode()
    original = tomllib.loads(raw)
    lines = raw.splitlines(keepends=True)
    changed = False
    for index, line in enumerate(lines):
        if line.lstrip().startswith('['):
            break
        if re.match(r'^\s*data_dir\s*=', line):
            require(not changed, 'Duplicate top-level data_dir')
            lines[index] = 'data_dir = ' + json.dumps(str(directory), ensure_ascii=False) + '\n'
            changed = True
    require(changed, 'Missing top-level configuration data_dir')
    updated = ''.join(lines)
    expected = dict(original)
    expected['data_dir'] = str(directory)
    require(tomllib.loads(updated) == expected, 'Configuration remapping changed unrelated values')
    atomic(path, updated.encode())


def management_config(raw, desired):
    """Append installation backend only; preserve every existing TOML value."""
    original = tomllib.loads(raw.decode())
    if 'management' in original:
        require(original['management'] == desired, 'Existing management configuration differs')
        return raw
    require(desired.get('backend') in ('coordinator', 'postgresql'), 'Unsupported management backend')
    text = '\n\n[management]\nbackend = ' + json.dumps(desired['backend']) + '\n'
    if desired['backend'] == 'coordinator':
        require(set(desired) == {'backend'}, 'Unexpected worker management settings')
    else:
        require(set(desired) == {'backend', 'connection'}, 'Unexpected management settings')
        connection = desired['connection']
        require(set(connection) == {'host', 'port', 'database', 'username', 'max_connections'},
                'This migration requires the bounded Unix peer PostgreSQL profile')
        require(isinstance(connection['host'], str) and connection['host'].startswith('/')
                and re.fullmatch('/[A-Za-z0-9_./-]+', connection['host'])
                and '..' not in Path(connection['host']).parts, 'Invalid PostgreSQL Unix socket')
        for key in ('database', 'username'):
            require(isinstance(connection[key], str) and re.fullmatch('[A-Za-z0-9_]{1,63}', connection[key]),
                    'Invalid PostgreSQL identity')
        require(type(connection['port']) is int and 1 <= connection['port'] <= 65535
                and type(connection['max_connections']) is int and 1 <= connection['max_connections'] <= 6,
                'Invalid PostgreSQL connection limits')
        text += '[management.connection]\n'
        text += ''.join(key + ' = ' + json.dumps(value) + '\n' for key, value in connection.items())
    updated = raw + text.encode()
    expected = dict(original)
    expected['management'] = desired
    require(tomllib.loads(updated.decode()) == expected, 'Backend configuration changed unrelated settings')
    return updated
