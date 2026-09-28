#!/usr/bin/python3
"""Restore a pinned checkpoint into a NEW, operation-specific local PostgreSQL DB.

Never overwrites an existing database, changes the active application configuration,
or starts application services. Restore SQL and its authority receipt commit together.
"""
import argparse
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import resource
import shutil
import signal
import stat
import subprocess
import tempfile
import time

from migration_protocol import atomic, canonical, identity, private_read, require, sha
from recovery_install import protected

STATE = Path('/var/lib/noisefence-recovery-database')
PG = Path('/usr/lib/postgresql/17/bin')
LIMIT = 8 * 1024**3


def command(plan, tool, admin=False, database=None):
    user = 'postgres' if admin else plan['username']
    return ['/usr/sbin/runuser', '-u', user, '--', '/usr/bin/env', '-i', 'PATH=/usr/bin:/bin',
            'LC_ALL=C', 'PGCONNECT_TIMEOUT=5', str(PG / tool), '--no-password',
            '--host='+plan['host'], '--port='+str(plan['port']), '--username='+user,
            '--dbname='+(database or plan['database'])]


def run(args, folder, *, stdin=None, stdout=None, timeout=900, byte_limit=LIMIT):
    # Children share a process group so timeout kills runuser and PostgreSQL tools.
    def limits():
        resource.setrlimit(resource.RLIMIT_FSIZE, (byte_limit, byte_limit))
    with (folder / 'restore-tool.log').open('ab') as log:
        process = subprocess.Popen(args, stdin=stdin or subprocess.DEVNULL,
            stdout=stdout or log, stderr=log, start_new_session=True, preexec_fn=limits)
        try:
            process.wait(timeout=timeout)
        except BaseException:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
            raise
        require(process.returncode == 0, 'PostgreSQL recovery tool failed; inspect the private local tool log')


def query(plan, sql, folder, *, admin=False, database=None):
    with tempfile.TemporaryFile() as output:
        run([*command(plan, 'psql', admin, database), '-X', '-A', '-t', '-v', 'ON_ERROR_STOP=1', '-c', sql],
            folder, stdout=output, timeout=30, byte_limit=65536)
        output.seek(0)
        raw = output.read(65537)
        require(len(raw) <= 65536, 'Oversized PostgreSQL recovery result')
        return raw.decode().strip()


def receipt_sql(plan):
    # Every interpolated value is a validated UUID/hash, never an arbitrary SQL name.
    operation = plan['operation']
    binding = plan['binding']
    receipt = canonical({'operation': operation, 'dump_sha256': plan['dump_sha256'], 'binding': binding}).decode()
    return ("\nDO $nf$ BEGIN IF NOT EXISTS (SELECT 1 FROM noisefence.migration_state WHERE id=1 "
        "AND activated_at IS NOT NULL AND source_digest='" + binding['source_digest'] + "' "
        "AND report->>'instance'='" + binding['instance'] + "') THEN RAISE EXCEPTION 'Restored authority mismatch'; END IF; "
        "IF EXISTS (SELECT 1 FROM noisefence.migration_state WHERE id=1 AND "
        "jsonb_typeof(COALESCE(report->'database_restore_receipts','{}'::jsonb)) <> 'object') "
        "THEN RAISE EXCEPTION 'Invalid restore receipt journal'; END IF; END $nf$;\n"
        "UPDATE noisefence.migration_state SET report=report || jsonb_build_object('database_restore_receipts', "
        "COALESCE(report->'database_restore_receipts','{}'::jsonb) || jsonb_build_object('" + operation + "','" + receipt + "'::jsonb)) WHERE id=1;\n")


def object_count(plan, folder):
    value = query(plan, "SELECT (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname<>'information_schema') + (SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname<>'information_schema')", folder)
    require(value.isdecimal(), 'Invalid restore target inventory')
    return int(value)


def verified_receipt(plan, folder):
    if object_count(plan, folder) == 0:
        return False
    raw = query(plan, "SELECT report->'database_restore_receipts'->'"+plan['operation']+"' FROM noisefence.migration_state WHERE id=1 AND activated_at IS NOT NULL AND source_digest='"+plan['binding']['source_digest']+"' AND report->>'instance'='"+plan['binding']['instance']+"'", folder)
    require(raw and json.loads(raw) == {'operation':plan['operation'], 'dump_sha256':plan['dump_sha256'], 'binding':plan['binding']},
            'Nonempty target has no matching atomic restore receipt; do not overwrite it')
    return True


def restore(authorization):
    require(not protected(authorization).st_mode & 0o077, 'Restore authorization must be private')
    with private_read(authorization, 65536) as source:
        plan = json.load(source)
    require(set(plan) == {'protocol','operation','binding','dump','dump_sha256','host','port','username','database','expires_at'},
            'Invalid database recovery authorization')
    require(plan['protocol'] == 'noisefence-recovery-database-1' and identity(plan['operation'])
            and set(plan['binding']) == {'instance','source_digest'} and identity(plan['binding']['instance'])
            and sha(plan['binding']['source_digest']) and sha(plan['dump_sha256']), 'Invalid restore identity')
    require(plan['database'] == 'nf_recovery_'+plan['operation'].replace('-','')
            and isinstance(plan['username'], str) and re.fullmatch('[a-z_][a-z0-9_]{0,30}', plan['username'])
            and plan['username'] != 'postgres' and pwd.getpwnam(plan['username']).pw_uid != 0,
            'Recovery requires a dedicated new database and non-root application role')
    require(isinstance(plan['host'], str) and re.fullmatch('/[A-Za-z0-9_./-]+', plan['host'])
            and '..' not in Path(plan['host']).parts and type(plan['port']) is int and 1 <= plan['port'] <= 65535,
            'Restore requires explicit local Unix PostgreSQL connection')
    require(type(plan['expires_at']) is int and time.time() < plan['expires_at'] <= time.time()+3600,
            'Restore authorization expired or too long-lived')
    with private_read(plan['dump'], 2 * 1024**3) as source:
        info = os.fstat(source.fileno())
        require(not info.st_mode & 0o077 and info.st_uid in (0,pwd.getpwnam(plan['username']).pw_uid)
                and source.read(5) == b'PGDMP', 'Private custom-format PostgreSQL dump required')
        source.seek(0)
        require(hashlib.file_digest(source,'sha256').hexdigest() == plan['dump_sha256'], 'Checkpoint dump checksum differs')
    STATE.mkdir(mode=0o700, exist_ok=True)
    protected(STATE, True)
    folder = STATE / plan['operation']
    folder.mkdir(mode=0o700, exist_ok=True)
    protected(folder, True)
    fingerprint = hashlib.sha256(canonical({k:v for k,v in plan.items() if k != 'expires_at'})).hexdigest()
    state_path = folder / 'state.json'
    saved = None
    if state_path.exists():
        protected(state_path)
        with private_read(state_path, 65536) as source:
            saved = json.load(source)
        require(saved['authorization'] == fingerprint, 'Database recovery authorization changed')
    database = plan['database']
    row = query(plan, "SELECT json_build_object('oid',oid,'owner',pg_get_userbyid(datdba)) FROM pg_database WHERE datname='"+database+"'", folder, admin=True, database='postgres')
    if not saved:
        require(not row, 'Recovery target already exists without an allocation receipt')
        # Never use -C, --clean or a configurable existing database name.
        role = query(plan, "SELECT count(*) FROM pg_roles r WHERE rolname='"+plan['username']+"' AND rolcanlogin AND NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolreplication AND NOT rolbypassrls AND NOT EXISTS(SELECT 1 FROM pg_auth_members a WHERE a.member=r.oid)", folder, admin=True, database='postgres')
        require(role == '1', 'Restore owner must be an existing unprivileged PostgreSQL role')
        query(plan, 'CREATE DATABASE "'+database+'" WITH TEMPLATE template0 OWNER "'+plan['username']+'"', folder, admin=True, database='postgres')
        row = query(plan, "SELECT json_build_object('oid',oid,'owner',pg_get_userbyid(datdba)) FROM pg_database WHERE datname='"+database+"'", folder, admin=True, database='postgres')
        saved = {'authorization':fingerprint, 'database':json.loads(row), 'restored':False}
        atomic(state_path, canonical(saved))
    require(row and json.loads(row) == saved['database'] and saved['database']['owner'] == plan['username'],
            'Restore target was removed, replaced or reassigned')
    if not verified_receipt(plan, folder):
        require(not saved['restored'], 'Previously restored database lost its receipt')
        reserve = shutil.disk_usage(folder).free - 2 * 1024**3
        require(reserve >= 64 * 1024**2, 'Insufficient restore staging disk reserve')
        ceiling = min(LIMIT, reserve)
        # Open/verify the dump again and pass the descriptor, so a replaced path
        # cannot select different SQL between verification and pg_restore.
        with private_read(plan['dump'], 2 * 1024**3) as dump:
            require(hashlib.file_digest(dump,'sha256').hexdigest() == plan['dump_sha256'], 'Checkpoint changed before restore')
            dump.seek(0)
            with tempfile.TemporaryFile(dir=folder) as sql:
                args = ['/usr/sbin/runuser','-u',plan['username'],'--','/usr/bin/env','-i','PATH=/usr/bin:/bin','LC_ALL=C',
                        str(PG/'pg_restore'),'--no-owner','--no-privileges','--exit-on-error','--file=-']
                run(args, folder, stdin=dump, stdout=sql, byte_limit=ceiling)
                sql.write(receipt_sql(plan).encode())
                require(sql.tell() <= ceiling, 'Restore SQL exceeds disk budget')
                sql.flush()
                # Check the actual PostgreSQL filesystem too; it need not share
                # the SQL staging filesystem. Keep headroom for heap/index rebuilds.
                pg_data = Path(query(plan, 'SHOW data_directory', folder, admin=True, database='postgres'))
                require(pg_data.is_absolute() and pg_data.is_dir(), 'Invalid PostgreSQL data directory')
                require(shutil.disk_usage(pg_data).free >= 4 * sql.tell() + 2 * 1024**3,
                        'Insufficient PostgreSQL filesystem reserve for restore')
                sql.seek(0)
                run([*command(plan,'psql'),'-X','-v','ON_ERROR_STOP=1','--single-transaction','--file=-'], folder, stdin=sql, byte_limit=ceiling)
        require(verified_receipt(plan, folder), 'Atomic database restore receipt missing')
        saved['restored'] = True
        atomic(state_path, canonical(saved))
    elif not saved['restored']:
        # A committed transaction with a lost client reply is safe to acknowledge.
        saved['restored'] = True
        atomic(state_path, canonical(saved))
    return {'operation':plan['operation'],'database':database,'binding':plan['binding'],
            'status':'restored_not_activated','services_started':False,'source_database_changed':False}


if __name__ == '__main__':
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--authorization', type=Path, required=True)
    args = parser.parse_args()
    require(os.geteuid() == 0, 'Root required')
    with open('/run/noisefence-upgrade.lock','a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        print(json.dumps(restore(args.authorization)))
