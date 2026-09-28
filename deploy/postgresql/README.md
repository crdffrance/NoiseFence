# Temporary PostgreSQL hosting on an MX

This directory contains installation settings for PostgreSQL 17 on Debian 13
when a dedicated database host is not yet available. They are intended for an
8 GiB gateway with at least 3 GiB of available RAM and sufficient free disk.
They are **not a NoiseFence database migration or a production backend switch**.

Install `postgresql-17` from the Debian repositories after reviewing an APT
simulation. On a new, unused `17/main` cluster, install `mx-staging.conf` as
`/etc/postgresql/17/main/conf.d/noisefence-resources.conf`, owned by root with
mode 0644. Install `mx-staging.service.conf` as
`/etc/systemd/system/postgresql@17-main.service.d/noisefence-resources.conf`.
Run `systemctl daemon-reload`, then restart `postgresql@17-main` only. On a
new, unused cluster, enable page checksums while it is stopped using
`runuser -u postgres -- /usr/lib/postgresql/17/bin/pg_checksums --enable -D /var/lib/postgresql/17/main`
and verify `SHOW data_checksums` after starting it. Do not
restart NoiseFence for this preparation step. Existing clusters require a
separate review of their databases and connection requirements first.

The profile disables TCP listening and retains local Unix socket access. Debian's
peer authentication must remain enabled; do not add `trust` authentication.
It uses 128 MiB shared buffers, 20 connections, bounded parallelism, and a 1 GiB
systemd memory ceiling. The database may be killed rather than consume memory
needed by the mail gateway. Applications must tolerate that outage; a memory
limit is not a guarantee that every query or workload will fit.
Systemd restarts failures after ten seconds, with at most three starts in five
minutes. A deliberate administrative stop does not trigger a restart.

Verify the effective settings with `SHOW listen_addresses`,
`SHOW max_connections`, `SHOW shared_buffers`, `SHOW fsync` and
`SHOW synchronous_commit`. Check `pg_isready`, the unit's memory limits, the
absence of TCP port 5432 listeners, and continued NoiseFence service health.
`max_wal_size` is a checkpoint target, **not a hard disk quota**. Monitor disk
usage and leave room for WAL, backups and the durable SMTP queues.

Before the actual switch, create or verify the dedicated application role,
initialize and verify the schema, run the complete offline import and parity
checks, test database loss, and configure verified backups and restoration.
Those steps are still migration work; installing these files does not complete
them. No application data or database credentials belong in this directory.

For a new, empty installation using the existing Unix account `noisefence`, the
local peer-authenticated role and database can be prepared with:

```sh
runuser -u postgres -- createuser --no-superuser --no-createdb --no-createrole --connection-limit=12 noisefence
runuser -u postgres -- createdb --owner=noisefence --encoding=UTF8 --template=template0 noisefence
runuser -u noisefence -- psql -X -d noisefence -c 'SELECT current_user, current_database();'
```

Inspect existing roles/databases before running these creation commands. Do not
drop an existing database to make them succeed. The role owns only the dedicated
application database; it has no superuser, role-creation, database-creation or
replication privileges. Plan connection pools and maintenance jobs within the
12-connection role limit. No database password or TCP access is needed for this
local deployment. Do not apply `src/central/schema.sql` manually: schema creation
must use the application's checksummed migration path.

## Backups and restoration validation

The hardening snapshot exporter includes `data/management.postgresql.dump` when
format-seven storage selects PostgreSQL. The currently supported profile is
PostgreSQL 17 on a local Unix socket using peer authentication. Remote database
connections and password-based configurations fail explicitly before the mail
service is stopped; they require a separately implemented backup profile.

The exporter adds database size to its free-space reserve, freezes the local
writers with the snapshot procedure (including the calibration timer and worker
lock), and runs a full custom-format
`pg_dump` as the configured Unix/database owner. Connection settings are explicit
and inherited PostgreSQL environment variables are cleared. The dump shares the
archive manifest and encrypted restic storage with the SQLite queue metadata,
configuration, model artifacts and original MFA key. A process-group deadline
terminates a stalled dump and removes its partial output. No dump is written to
stdout except as part of the existing protected backup stream.

The offline archive checker verifies the dump header and checksum, requires a
PostgreSQL dump for a selected coordinator, and checks the original MFA key
against its selection receipt. It reports `requires_postgresql_restore` rather
than claiming that file checks alone prove database recovery. The central
backup verifier propagates this status. Never automatically execute SQL from an
untrusted archive against the production database.

The synthetic `central_restore` test uses `pg_dump` and `pg_restore` in the
explicitly selected disposable PostgreSQL container. It compares every
management table and sequence and tests the restored runtime database binding.
It does not prove recovery of a particular production backup, restore the SMTP
queue, or authorize starting a restored coordinator alongside the original.
An isolated drill using the actual encrypted backup, original key and matching
spool/artifacts remains required before production cutover. Check each restored
SQLite `PRAGMA user_version` against the importer requirements: archive integrity
and a recent timestamp do not prove that it contains the current storage format
or coordinated policy journal. Renew outdated backups rather than altering their
format number to bypass importer checks. External role
creation and connection privileges are installation state, not part of a
single-database dump.

See PostgreSQL's [pg_dump documentation](https://www.postgresql.org/docs/17/app-pgdump.html)
and [pg_restore documentation](https://www.postgresql.org/docs/17/app-pgrestore.html).

For an ARM development host, see [Linux cross-compilation](BUILD-LINUX.md) to
build the x86-64 binary with a native compiler instead of CPU emulation. This
build step does not replace the migration or recovery validation gates.
