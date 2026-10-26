"""Online metadata archives for selected PostgreSQL/coordinator installations.

SQLite backup APIs read their WAL; raw queues and replica bodies are excluded.
Frozen activation identity is checked before/after every archive. This is console
and configuration recovery material, never permission to restore a live queue.
"""
import contextlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import tarfile
import tempfile
import tomllib


def checkpoint_tools():
    path = Path(__file__).resolve().parent.parent / 'ha/standby.py'
    if not path.is_file():
        path = Path('/opt/noisefence/current/deploy/ha/standby.py')
    spec = importlib.util.spec_from_file_location('nf_metadata_checkpoint', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def authority(path, cfg, immutable=False):
    tools = checkpoint_tools()
    role = cfg.get('cluster', {}).get('role')
    if role == 'coordinator':
        state = tools.selected_state(path, immutable=immutable)
    elif role == 'worker':
        uri = tools.snapshot_uri(path) if immutable else path.as_uri() + '?mode=ro'
        with contextlib.closing(sqlite3.connect(uri, uri=True, timeout=2)) as db:
            if db.execute('PRAGMA user_version').fetchone()[0] != 7:
                raise ValueError('Online metadata requires storage format seven')
            rows = dict(db.execute("SELECT key,CASE WHEN length(value)<=4194304 THEN value END FROM cluster_state WHERE key IN ('management_selection','activation_participant','management_recovery_required')"))
        if 'management_recovery_required' in rows or any(v is None for v in rows.values()):
            raise ValueError('Unfinished recovery or oversized activation state')
        selection = json.loads(rows['management_selection'])
        local = json.loads(rows['activation_participant'])
        epoch, bundle, journal = local['installed_epoch'], local['installed'], local['authority']
        rollout = journal.get('rollout') or {}
        if (selection.get('protocol') != 'noisefence-management-selection-1'
                or selection.get('role') != 'worker' or local.get('version') != 1
                or local.get('node') != selection['node']['node']
                or local['node'] == journal.get('owner')
                or local['node'] not in rollout.get('participants', {})
                or rollout.get('phase') not in ('released', 'aborted')
                or journal.get('current_sequence') != epoch['sequence']
                or journal.get('current') != bundle
                or bundle.get('revision') != epoch['revision']
                or bundle.get('digest') != epoch['digest']
                or type(journal.get('sequence')) is not int
                or journal['sequence'] < epoch['sequence']):
            raise ValueError('Worker metadata requires a stable installed policy')
        state = {'selection': selection, 'epoch': epoch, 'bundle': bundle,
                 'policy_sequence': journal['sequence'], 'phase': rollout['phase']}
    else:
        raise ValueError('Online metadata requires a selected coordinator or worker')
    if cfg['cluster']['node_id'] != state['selection']['node']['node']:
        raise ValueError('Configuration differs from selected metadata authority')
    return state


def export(snapshot, config=Path('/etc/noisefence')):
    data, root = snapshot.DATA, snapshot.ROOT
    cfg_bytes = (config / 'config.toml').read_bytes()
    cfg = tomllib.loads(cfg_bytes.decode())
    snapshot.verify_management_selection(data / 'state.sqlite3', cfg)
    tools = checkpoint_tools()
    tools.DATA = data
    before = authority(data / 'state.sqlite3', cfg)
    pg = snapshot.postgres_target(cfg)
    central = tools.postgres_state(snapshot, pg) if pg is not None else None
    if central is not None:
        tools.match_central(before, central)
    if 'recovery' in before:
        raise ValueError('Use the dedicated recovered-console checkpoint exporter')
    identity = snapshot.identity_tools()
    connection_keys = identity.postgres_keys(snapshot, pg) if pg is not None else None
    identity_before = identity.inspect(data, cfg, connection_keys, private=True)
    files = tools.selected_artifacts(data, before)
    identity_files = identity.files(data)
    files.update(identity_files)
    files['data/state.sqlite3'] = data / 'state.sqlite3'
    # Include base-configuration model paths as well as the installed bundle.
    # Never retain mail, history cache, research samples or temporary operations.
    forbidden = {'spool', 'incoming', 'replicas', 'research-archive', 'calibration'}
    for selected in tools.data_paths(cfg):
        if selected == data or selected.relative_to(data).parts[0] in forbidden:
            continue
        for path in selected.rglob('*') if selected.is_dir() else [selected]:
            if path.is_file() and not path.name.endswith(('-wal', '-shm', '-journal')):
                files['data/' + str(path.relative_to(data))] = path
    for name in ('mfa.key', 'llm-budget.sqlite3', 'protection/reputation.sqlite3',
                 'protection/crdf.key', 'protection/virustotal.key'):
        if (data / name).is_file():
            files['data/' + name] = data / name
    for path in config.rglob('*'):
        if path.is_file():
            files['config/' + str(path.relative_to(config))] = path
    for name, path in files.items():
        base = data if name.startswith('data/') else config
        if (path.is_symlink() or not path.resolve().is_relative_to(base.resolve())
                or any(parent.is_symlink() for parent in path.parents if parent != base and base in parent.parents)):
            raise ValueError('Metadata source symlink refused')
    size = sum(p.stat().st_size for p in files.values()) + (snapshot.postgres_bytes(pg) if pg is not None else 0)
    if size > 4 * 1024**3 or shutil.disk_usage(root).free < size * 2 + 2 * 1024**3:
        raise RuntimeError('Insufficient online metadata reserve')
    with tempfile.TemporaryDirectory(prefix='metadata-', dir=root) as tmp:
        dest = Path(tmp)
        for name, source in sorted(files.items()):
            target = dest / name
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            if source.name.endswith('.sqlite3'):
                subprocess.run(['/opt/noisefence/current/noisefence', 'ha-snapshot', str(source), str(target)],
                               check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=40)
            else:
                original = tools.digest(source)
                shutil.copyfile(source, target)
                if tools.digest(target) != original or tools.digest(source) != original:
                    raise ValueError('Metadata source changed; retry')
                with target.open('rb') as f:
                    os.fsync(f.fileno())
            target.chmod(0o600)
        if pg is not None:
            snapshot.dump_postgres(pg, dest / 'data/management.postgresql.dump', 60)
        if ((config / 'config.toml').read_bytes() != cfg_bytes
                or authority(dest / 'data/state.sqlite3', cfg, immutable=True) != before
                or authority(data / 'state.sqlite3', cfg) != before
                or (pg is not None and tools.postgres_state(snapshot, pg) != central)):
            raise ValueError('Policy changed during metadata backup; retry')
        tools.selected_artifacts(dest / 'data', before)
        expected = before['selection'].get('mfa_key_sha256')
        if expected and tools.digest(dest / 'data/mfa.key') != expected:
            raise ValueError('Metadata MFA key mismatch')
        identity_after = identity.inspect(dest / 'data', cfg, connection_keys, expected=identity_before)
        if set(identity.files(data)) != set(identity_files):
            raise ValueError('Identity recovery files changed during metadata backup; retry')
        identity.files(dest / 'data', private=False)
        if pg is not None and identity.postgres_keys(snapshot, pg) != connection_keys:
            raise ValueError('Directory keys changed during metadata backup; retry')
        metadata = snapshot.manifest(dest, 'metadata')
        metadata['identity_recovery'] = identity_after
        if sum(f['bytes'] for f in metadata['files'].values()) > 4 * 1024**3:
            raise ValueError('Online metadata archive exceeds size limit')
        metadata.update(online=True, pause_and_copy_seconds=0,
                        recovery_scope='metadata_only_not_a_queue_restore')
        (dest / 'manifest.json').write_text(json.dumps(metadata, sort_keys=True) + '\n')
        import sys
        with tarfile.open(fileobj=sys.stdout.buffer, mode='w|') as archive:
            for path in sorted(dest.iterdir()):
                archive.add(path, arcname=path.name, recursive=True)
