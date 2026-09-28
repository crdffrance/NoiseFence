# Guarded management migration supervisor

These operators' tools coordinate the native Rust import commands described in
[`docs/postgresql-development.md`](../../docs/postgresql-development.md). They
are not an automatic installer. Production use still requires a rehearsal of the
installed release, backup restoration, runtime health and failure recovery.

## Invariants

- The controller runs on the PostgreSQL coordinator. Original metadata moves
  directly from the worker to that host over pinned SSH. Mail bodies and research
  corpora are not exported. Private configurations, credentials and the original
  MFA key remain on the participating servers.
- Each original source stays frozen under the native daemon/calibration locks
  and SQLite write reservation until the PostgreSQL activation receipt commits.
- Every source acknowledges its exact export hash, journal sequence and proposed
  database selection. The native activation transaction checks actual receipts.
- A service fence survives disconnection and reboot. A selected format-seven
  source cannot be downgraded to the SQLite management backend. Recovery after a
  partial selection proceeds forward against the same database binding.
- Installation configuration changes only the management backend. The controller
  does not modify filtering, recipient policies, observation mode or SMTP queues.

## Components and installation boundary

Install `migrate.py`, `migration_agent.py`, `migration_protocol.py` and
`migration_snapshot.py` together in a root-owned, non-writable directory at
`/usr/local/libexec/noisefence-management`. Python 3.11 or newer is required.
The agent reads only `/etc/noisefence-migration/agent.json`; it accepts no command
arguments. Use a dedicated, expiring SSH authorization restricted to this agent,
with forwarding and interactive sessions disabled. Do not copy a personal or
existing deployment private key between servers. Pin the worker host key using
an independently verified value. Installation of this restricted authorization
and the outer systemd runtime limit is a separate deployment step.

Rehearse the whole operation with representative backups and a measured memory
budget. Snapshot extraction, native imports and isolated runtime checks consume
memory beyond the PostgreSQL pool itself. A server-only rehearsal was killed by
a 1 GiB cgroup limit and completed with a 2 GiB limit; this is workload evidence,
not a universal sizing guarantee. Leave capacity for the live mail gateway and
PostgreSQL, inspect systemd's result and peak memory, and verify temporary database
and file cleanup after interruption. A SIGKILL can prevent a script's cleanup
handler from running. Never delete a production source or clear its service fence
as part of test cleanup.

Before activation, verify the installed gateway's AppArmor profile, not only the
recovery-console profile. The coordinator needs the local PostgreSQL socket rule
`/run/postgresql/.s.PGSQL.[0-9]* rw,` supplied by the current hardening profile.
Validate and reload any profile update while retaining enforcement and a protected
copy of the previous profile. Do not disable confinement to make migration work.
After selection, the simple `deploy-control.py activate` path refuses management
installations; use coordinated migration or recovery instead of switching one
gateway's release pointer independently.

The coordinator configuration has these exact fields:

- `run_id`: persistent UUID for this operation.
- `coordinator`, `user`: node ID and installation account.
- `root`: root-private state directory; `runtime`: installation-owner private
  directory for native sockets and verified metadata copies.
- `binary`, `binary_sha256`: root-owned physical release executable and checksum.
- `database`: Unix peer connection (`host`, `port`, `database`, `username`,
  `max_connections`, limited to six). The username must match `user`.
- `ssh_key`, `known_hosts`: dedicated root-private key and pinned host-key file.
- `nodes`: complete node map, with `{"ssh": null}` for the coordinator and
  `{"ssh": "debian@HOST"}` for each worker.
- `lease_seconds`: absolute operation deadline, 30–1800 seconds.

Each agent configuration contains `run_id`, `node_id`, `role`, `user`, `data`,
`config`, `root`, `runtime`, `release_directory`, `binary_sha256`, `current_link`,
`management`, `expires_at`, `lease_seconds` and `health_url`. The last field must
be a numeric loopback HTTP `/healthz` URL. The release directory is a physical,
root-owned directory containing the approved `noisefence` executable.
`management` is the exact intended backend configuration. Authorization expires
within 24 hours; extending `expires_at` does not change the pinned migration
identity. Other installation fields must remain unchanged during recovery.

Both root state and owner runtime directories contain sensitive material.
Retain them privately until restoration and recovery have been verified; do not
publish them as logs or source artifacts. Remove verified import copies and
revoke the temporary SSH authorization after successful recovery verification.

## Execution and recovery

Run the controller as root on the PostgreSQL coordinator, under an outer process
supervisor that terminates the entire process group at its absolute deadline:

```sh
/usr/local/libexec/noisefence-management/migrate.py --config /private/controller.json
```

The controller first opens every agent, then fences writers, freezes originals,
verifies exported checksums, stages PostgreSQL, verifies data parity and checks
installation artifacts. It persists proposals before selecting originals.
Only a committed active PostgreSQL receipt permits publishing configurations and
starting services. Previously active background timers resume after both SMTP
readiness checks pass.

Re-run the same controller configuration after an interrupted connection. An
active database finishes configuration/service recovery without reimport. An
inactive database reopens original sessions with the same journal generations;
selected sources additionally require their persisted exact selection. If a
completed staging receipt survived a lost controller save, the controller checks
its database and source parity before adopting it. A missing, partial or failed
staging receipt requires operator inspection; it is never permission to import
again into an ambiguous destination.

Before any source has been selected, explicit cancellation is available:

```sh
/usr/local/libexec/noisefence-management/migrate.py --config /private/controller.json \
  --cancel-before-selection
```

Cancellation verifies all original selection markers and the known database
receipt before restoring the unchanged legacy services. After any original is
selected, cancellation is refused. Never manually remove the service fence to
force the old runtime to start.

A successful health endpoint is necessary but not sufficient: complete real
SMTP acceptance/replication, management API, PostgreSQL outage, restart and
backup-restoration checks before declaring the migration complete.

## Installed lifecycle rehearsal

A synthetic two-node Debian 13 rehearsal exercised the installed controller and
agents through real systemd units and a dedicated restricted SSH key. The native
migration executable was the Linux v4 staging build; later recovery-library changes
still require a fresh release build and validation before production deployment.

The run covered source fencing, metadata export, PostgreSQL import and parity,
selection of both original queues, destination activation, configuration publication
and service restart. An interruption after activation resumed against the same
binding without reimport. Both gateways then became SMTP-ready. Only previously
active timers resumed.

The rehearsal identified two systemd lifecycle cases now handled by the agent:

- A successfully stopped unit may be unloaded. `reset-failed` is called only for
  an actual failed unit, so an unloaded inactive unit does not prevent restart.
- `is-active` reports `inactive` for missing units too. The agent now reads both
  `LoadState` and `ActiveState`, skips absent optional jobs, and rejects masked or
  invalid units rather than assuming they are safe to manage.

Two messages were accepted before migration, two after migration and one during a
brief PostgreSQL outage. After database recovery and restart of both gateway
services, all five appeared in the authenticated console, metadata outboxes were
empty, and all ten original/replica body files matched by SHA-256. Login failed
closed during the database outage (the tested staging build returned HTTP 500);
no stale SQLite authentication fallback occurred.

These results use synthetic mail, a loopback HTTP test transport, and an unavailable
local relay destination. They do not prove production TLS, successful upstream
mail delivery, provider behavior, or the final versioned binary. The production
cutover must repeat the relevant checks against the approved release.

To generate fresh enrolled synthetic source directories for an isolated rehearsal:

```sh
NOISEFENCE_REHEARSAL_OUTPUT=/absolute/new/private/fixture \
  cargo test --test management_rehearsal_fixture -- --ignored
```

The output path must not already exist. The fixture contains disposable account
and node credentials, two format-six databases and bound immutable credential
caches. Keep it private. Its configuration uses `/var/lib/noisefence` and
`/etc/noisefence` inside the test installations; it must not be copied over an
existing installation. No production messages or credentials are required.
