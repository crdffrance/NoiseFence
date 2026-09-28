# Isolated PostgreSQL checkpoint restoration

`recovery_database.py` restores a pinned custom-format checkpoint into a **new**
local PostgreSQL 17 database. It does not change the active NoiseFence configuration,
reconcile management history, authorize a console, remove fences or start services.
Use it as the database stage of coordinated recovery, not as a standalone promotion.

Install it with the same-release `recovery_install.py`, `migration_agent.py`,
`migration_protocol.py` and `migration_snapshot.py` in a root-owned directory.
Python 3.11 or newer, PostgreSQL 17 tools, local Unix peer authentication and the
existing unprivileged NoiseFence OS/database account are required. The database
role must have no elevated attributes or role memberships. The helper uses the
local `postgres` administrator only to allocate a new database and inspect its
identity/storage; dump SQL executes under the application role.

A private root-owned authorization, with protected physical ancestors, contains:

| Field | Value |
| --- | --- |
| `protocol` | `noisefence-recovery-database-1` |
| `operation` | Canonical recovery UUID |
| `binding` | Exact checkpoint `instance` UUID and `source_digest` SHA-256 |
| `dump` | Absolute physical path of the private custom-format dump |
| `dump_sha256` | SHA-256 pinned from the verified checkpoint manifest |
| `host`, `port` | Explicit local Unix socket directory and PostgreSQL port |
| `username` | Existing unprivileged application OS/database account |
| `database` | `nf_recovery_` followed by the operation UUID without hyphens |
| `expires_at` | Unix expiry, no more than one hour in the future |

```sh
python3 /usr/local/libexec/noisefence-management/recovery_database.py \
  --authorization /etc/noisefence-recovery/database.json
```

The helper rejects an existing target without its own allocation receipt. It never
uses `--clean`, restores over a configured production database, or changes database
ownership to adopt an unknown target. Allocation records pin the database OID and
owner; subsequent replacement/reassignment causes refusal. A crash between database
creation and recording that identity requires separate inspection; automatic retries
do not adopt the unrecorded database.

The verified dump is read through its held file descriptor. SQL is staged privately,
with bounded output and process deadlines, then executed in one PostgreSQL transaction
with `ON_ERROR_STOP`. The final SQL verifies the restored management binding and
records the operation/dump binding inside `migration_state.report`. Thus a wrong
binding or SQL failure rolls back both restored objects and the receipt. A committed
transaction whose reply was lost can be recognized on retry without reapplying SQL.
A nonempty database without a matching receipt is refused, never cleaned. Every
retry checks the current binding as well as the receipt.

Staging retains at least 2 GiB free, caps generated SQL at 8 GiB, and checks the actual
PostgreSQL data filesystem for four times the generated SQL size plus 2 GiB before
restoration. This is capacity headroom, not a filesystem quota. Keep normal database
storage monitoring enabled. Private diagnostic logs and allocation receipts remain
under `/var/lib/noisefence-recovery-database/<operation>`; temporary generated SQL is
removed when the process closes it. An interrupted transaction can leave an empty
allocated target for the same-operation retry.

After `restored_not_activated`, the supervisor must bind the private console
configuration to this database, restore/fence the coordinator queue, attach the real
surviving worker queue, perform native access/history/policy recovery, install keys,
authorize services and verify health/routing. Those later checks remain mandatory.

`tests_python/recovery_database_linux.py` is an explicit **disposable container
fixture**. It creates synthetic databases and verifies exact sample rows, preservation
of an existing target, transaction rollback on a wrong binding, retry after a lost
reply, and refusal of missing receipts or changed authority. It is not a production
migration command or a complete application-recovery test.
