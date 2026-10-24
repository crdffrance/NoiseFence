# Paired upgrade preparation and recovery boundaries

An upgrade changes running binaries. It is different from applying a Web policy
revision, selecting a PostgreSQL authority or restoring a failed coordinator.
Keep these operations separate. Preserve observation, the installed model and
thresholds, suspended providers, original queue identities and the mandatory
second durable copy throughout an upgrade.

The current development tree provides read-only local prerequisite reports,
durable native reservations, bounded candidate validation, held pair promotion
and an operator-driven paired activation protocol.
It also guards simple installation paths. It does **not** provide a qualified unattended
paired updater or certify arbitrary release pairs for rollback. The disposable
fixture below exercises a coordinated stop/start with exact published archives;
it is not a production controller. A passing prerequisite report is not an
authorization to deploy. The full installed-system matrix remains a release gate.

## Installation paths

| Installation state | Simple `deploy/install.sh` / restricted activation | Recovery boundary |
| --- | --- | --- |
| Fresh or legacy local management | Local storage checks apply; validate the exact release and configuration separately | Retain the verified prior archive and current state |
| Two-copy replication with local management | Preserve `[replication]`, verify both peers and use a reviewed rolling procedure | Local format compatibility alone does not establish cluster/policy compatibility |
| Configured, selected or partially selected PostgreSQL management | Refused before the candidate is invoked or the release pointer changes | Require a coordinated, rehearsed procedure for the selected authority |
| Missing, broken or unknown existing state | Refused when the observed database cannot be interpreted safely | Inspect the original state; never create a replacement database to make the check pass |

The guards recognize `[management]` even if its table is empty, format 7 and
persisted selection, transport, runtime-history, recovery or worker-release
markers. Removing configuration does not undo an authority selection. An orphaned
SQLite WAL, shared-memory or journal file is not a fresh installation. When an
installed `current` pointer exists, the installer also refuses a missing local
database instead of treating it as a fresh installation. Automatic rollback
requires existing readable state. Simple installation and rollback refuse removal
of a recorded two-copy requirement.

The native installer verifies the archive's internal checksums before its local
preflight. It runs that preflight before creating accounts, copying configuration,
executing the candidate or changing installed links. The report command itself
only reads candidate metadata; it does not verify the archive's checksums or
execute the candidate. Authenticate the release origin and verify both the outer
archive checksum and internal `SHA256SUMS` independently.

## Capture local prerequisites on each MX

Use the candidate's verified `deploy/upgrade-check.py`, Python 3.11 or newer, and a
new private receipt filename for each observation. The data path is resolved like
the native service, relative to `/opt/noisefence` when it is not absolute. Supply
`--working-directory` if a custom service uses a different directory.

```sh
sudo install -d -m 0700 /var/lib/noisefence-upgrades
sudo python3 /path/to/verified-candidate/deploy/upgrade-check.py \
  --config /etc/noisefence/config.toml \
  --candidate /path/to/verified-candidate \
  --live --expect-existing-state \
  --output /var/lib/noisefence-upgrades/OPERATION-mx1-before.json
```

Replace `OPERATION` with a new operation identifier and use the other node's ID
for its report. Omit `--expect-existing-state` only when examining a fresh
installation that has no queue yet. The helper reads a committed, query-only
SQLite snapshot including current WAL transactions. It never calls the application store opener or runs a
migration. It reads marker names and aggregate replication counters, not messages,
credentials or policy blobs. Reports contain a configuration digest, candidate
version/commit/digest, observed local format and operational facts. Keep them
private even though message content and secret values are excluded.

With `--live`, the helper queries only the configured numeric loopback API address.
It disables HTTP proxies and redirects, bounds the response to 4 KiB and requires
an actual JSON boolean `smtp_ready`. The CLI has a ten-second total deadline;
individual socket operations are limited to three seconds. Replica readiness
includes initial acknowledgements, outstanding generations and a heartbeat no
older than 15 seconds. Future heartbeat timestamps are rejected as unhealthy.
This is an availability snapshot: a heartbeat does not prove a particular
message has two durable copies. SMTP still requires its own body/manifest receipts.

Receipts are published atomically with mode 0600 and synchronized to disk. Existing
receipt paths are never replaced. Repeated checks need new filenames. A failed
write makes the command fail; inspect a possible receipt after an interrupted
write before retrying. Do not delete older evidence to reuse a filename.

Interpret the fields separately:

- `local_install_supported` describes only the local authority/schema guards.
  It does not establish binary authenticity, protocol compatibility, sufficient
  memory/disk, a successful backup or a safe rolling upgrade.
- `local_install_blockers` explain a refusal such as
  `coordinated_management_required` or a removed replication configuration.
- `live.status: not_checked` means no HTTP check was requested. `unavailable`
  is distinct from a valid response reporting `smtp_ready: false`.
- `operational_blockers` list stale or missing heartbeat, pending replica
  acknowledgements or unavailable/negative SMTP readiness.
- `rollback: not_qualified` is intentional. This report does not authorize a
  rollback, including when all reported operational checks pass.

Exit 0 means the requested observation completed without operational blockers.
It can still describe a management installation requiring coordination. Add
`--require-local-install` to make local installation blockers return exit 1;
`deploy/install.sh` always uses this flag. Operational blockers also return 1.
Invalid input, unreadable state, expired deadline or failed receipt publication
return 2. Neither a failed probe nor missing data counts as success.

## Selected management requires matching builds

The published 0.31.8 and 0.31.9 PostgreSQL policy transport accepts only a worker
reporting the coordinator's exact application version. The legacy
`compatible_build` policy window does not extend that central transport contract.
An actual two-node archive rehearsal reproduced `Invalid central policy poll`
when one node ran each version. A recently healthy process can still report ready
before its next policy poll, so a health snapshot alone is insufficient.

Do not advertise a rolling mixed-version upgrade for this pair. A coordinated
maintenance procedure must stop both daemons before changing either installed
binary, start the complete matching pair, and verify a **new authenticated policy
exchange** after that transition. SMTP senders retry during the outage. This does
not make any other release pair compatible or protect against concurrent policy,
recovery or deployment operations. Those reservations remain required.

A [durable native reservation](maintenance-reservations.md) now implements the
stopped-service hold and unchanged-installation cancellation primitive. The
[validation host helper](maintenance-validation.md#supervised-host-procedure) can
start a bounded candidate under that hold. The [pre-commit promotion helper](maintenance-promotion.md)
binds both prepared releases and can switch or restore their pointers without
starting normal services. The [activation protocol](maintenance-activation.md)
then records mutual promises and a durable coordinator decision, starts the pair
and verifies fresh runtime state. The [staging helper](release-staging.md)
authenticates and extracts a release before reservation without executing it.
The [restricted SSH completion helper](maintenance-exchange.md) exchanges final
proofs for an already-started pair. Its real ARM64 native lifecycle includes
recovery after a lost completion response and expired temporary proofs. The first
attested-release round trip, earlier remote lifecycle stages, final archives on
both architectures and rollback after ordinary startup remain qualification gates.

## Reviewed maintenance sequence

1. Record both node identities, coordinator/worker roles, installed release
   manifests, the proposed archive hashes and the complete management authority.
   Confirm the exact old/new pair and the actual management transport have been
   rehearsed. Selected PostgreSQL policy transport can require matching builds
   even when the legacy policy window permits older bundles. Do not infer
   compatibility from matching local schema numbers or a semver comparison.
2. Obtain a consistent backup and prove it can be restored into an isolated
   destination. A PostgreSQL selection needs its bound database, original MFA
   key, immutable models/credentials and local journals. A metadata-only backup
   does not restore accepted message bodies. Keep the live queues and replicas.
3. Reserve a single operator-controlled maintenance window. Prevent concurrent
   policy/model changes, backend migration, promotion, recovery and a second
   deploy operation. These report files are not a distributed lock or lease.
4. Capture fresh reports from both MX servers. Resolve unavailable readiness,
   stale heartbeat, unprotected messages and pending updates before proceeding.
   Verify queue age, free space, memory headroom, checkpoint age and the tested
   recovery procedure separately; the helper does not measure them all.
5. Use the procedure rehearsed for this authority and exact version pair. For
   published 0.31.8/0.31.9 selected management, stop both daemons before switching
   either binary. A selected deployment must not use the simple pointer-switch
   installer or rerun a backend migration merely to upgrade a binary.
6. Verify the actual running builds, authority binding, SMTP readiness, peer
   identity, replica receipts and a successful authenticated policy exchange
   newer than the transition. A cached last-seen timestamp is not enough. If a
   start fails, retain the operation state and use the rehearsed recovery plan;
   do not clear a fence or declare an unchanged second node upgraded.
7. Capture new receipts and verify every accepted synthetic test message and
   recipient state. Close the operation only after both nodes run the expected
   release and outstanding replica updates converge.

While either mandatory peer is unavailable, new SMTP traffic can receive `451`.
This is deliberate deferral; the sending server retries. Never remove a two-copy
requirement, discard accepted bodies, reset a database or change filtering mode
just to make an upgrade appear uninterrupted.

## Rollback and failure recovery

The local `can-rollback.py` check runs only after the candidate has been stopped.
It checks the retained release's supported local format and refuses management
selection/transport/recovery markers, unknown state and removed replication.
This limited guard does not prove management, policy, model or cluster protocol
compatibility. The native installer uses it for a failed local service start;
that behavior is not a qualified paired rollback strategy. `systemctl is-active`
alone also does not establish SMTP readiness.

For a selected authority, preserve all current selection and recovery receipts.
Use the [management recovery gates](postgresql-development.md) and
[HA recovery procedure](high-availability.md) appropriate to the failure.
The [migration supervisor](../deploy/postgresql/MIGRATION-SUPERVISOR.md)
coordinates backend selection; it is not a general binary-upgrade controller.
Do not lower `user_version`, erase markers, restore a stale database over accepted
mail, run duplicate coordinators or silently fall back to legacy SQLite.

## Required installed-system rehearsal

Qualify the exact archive pair on two isolated Linux nodes before claiming a
paired upgrade or rollback works. Use synthetic accounts and messages, blocked
external relay and no production state. Record:

- both archive hashes, architecture, runtime builds and authority bindings;
- accepted messages before and after each restart, original/replica body hashes
  and recipient progress, including any uncertain delivery held for inspection;
- normal coordinator/worker sequencing and a lost controller connection;
- failed candidate startup, stale/absent heartbeat, full replica storage and
  refusal to proceed to the second node;
- an explicitly compatible rollback preserving current accepted messages,
  or forward recovery when a migration makes rollback incompatible;
- final readiness, queue reconciliation and immutable operation receipts.

The single-node [release lifecycle fixture](installation.md#rehearse-an-upgrade-without-production-data)
proves install/reinstall/remove preservation only for its tested archives. It does
not satisfy this paired test matrix or a selected PostgreSQL restoration gate.


## Run the disposable archive-pair fixture

Use Python 3.11+, Docker on a dedicated test host or disposable VM, Rust and two
previously authenticated release archives with their `.sha256` sidecars. The
systemd fixture uses privileged containers; do not run it on a production MX.
It binds no host ports or host directories. Its two root filesystems have distinct
machine identities and share only a loopback network namespace without an
external route. Test SSH credentials are ephemeral and valid only in that
namespace. A local PostgreSQL 17 instance is initialized from synthetic state.

From the repository root, with a **new** fixture and output directory:

```sh
# Match the image platform to both release archives. Use linux/amd64 on x86-64.
docker build --platform linux/arm64 -f tests/fixtures/paired.Dockerfile \
  -t noisefence-paired:qualification .

NOISEFENCE_REHEARSAL_OUTPUT=/absolute/private/paired-fixture \
NOISEFENCE_REHEARSAL_BASE_BUILD=0.31.8 \
NOISEFENCE_REHEARSAL_SHARED_LOOPBACK=1 \
  cargo test --locked --test management_rehearsal_fixture -- --ignored

python3 tests/paired_release_lifecycle.py \
  --old-archive /absolute/releases/noisefence-0.31.8-linux-arm64.tar.gz \
  --new-archive /absolute/releases/noisefence-0.31.9-linux-arm64.tar.gz \
  --image noisefence-paired:qualification --platform linux/arm64 \
  --fixture /absolute/private/paired-fixture \
  --output /absolute/private/paired-result
```

The generator records a synthetic baseline for the requested compatible old
build. This is only test preparation: each real archive still has to parse and
validate that state. Never supply a production data directory or credentials.
The runner checks archive names, outer and inner checksums, platform, build
identity, bounded safe member paths and image identity before using them.

The fixture starts both old binaries, accepts synthetic mail on each node and
uses the real management migration supervisor to select a synthetic PostgreSQL
authority. That migration creates the laboratory baseline; it is **not repeated**
for either binary transition. It exercises a missing replica, an injected failed
candidate start, coordinated upgrade and coordinated rollback. It requires fresh
policy synchronization, unchanged authority/configuration/installed policy,
original recipient state, matching original and replica body hashes, and
converged durable metadata acknowledgements. The final report records the exact
archives, image, architecture and accepted IDs. Private journals and diagnostic
logs remain in the output directory. No external mail is delivered.

With `--validation-candidate`, the final activation uses a dedicated temporary SSH
authorization on both disposable nodes. Host keys are pinned from the local test
control plane. A test-only wrapper discards the coordinator response after actual
durable completion. The fixture accepts additional synthetic mail, waits beyond
the 30-second proof window, resumes the peer and repeats completion. It records
the same retained decision, verification timestamps, restored timers and two-copy
message invariants. The SSH exchange receipts are saved privately in
`exchange-receipts.json`; private keys never leave the containers.

`paired-lifecycle-report.json` has status `passed` only after the assertions and
container cleanup succeed. `failed.json` or `cleanup_failed` is a failure, even
when earlier events were positive. Inspect `cleanup.json` and the bounded logs;
do not reuse an output directory or silently discard failure evidence. Removal
is attempted for both test containers even after an earlier diagnostic fails.

The base fixture also exercises durable root reservations and unchanged
cancellation after the initiating helper exits. Its optional
`--validation-candidate DIRECTORY` mode adds a separately compiled candidate,
real supervised startup on both nodes, disabled mail/admin paths, peer loss,
native authorization expiry and unchanged application data. See the
[validation contract](maintenance-validation.md) for its metadata format and limits.

This fixture does **not** qualify an unattended updater, complete paired
controller-disconnect recovery, full-disk behavior, PostgreSQL disaster recovery,
production models, external delivery, throughput or detection quality. A passing
ARM64 run does not cover AMD64. A passing published archive pair does not qualify
an unreleased candidate unless that optional mode was actually run; even then,
it covers maintenance validation rather than normal candidate activation. Keep
these distinct from the broader release gates.

See [candidate runtime validation](maintenance-validation.md) for the explicit
temporary mode that loads a reserved candidate without starting normal mail or
administrative services. Its probe readiness is separate from normal SMTP and
replica durability; the complete production supervisor remains a release gate.
