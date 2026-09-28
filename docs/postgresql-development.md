# PostgreSQL management migration: development status

This document records the incremental implementation and its historical test
boundaries. Statements below about unfinished work describe the stage at which
that section was written; they are not the current deployment procedure.

For version 0.29.0 installation, use the [PostgreSQL operator guide](../deploy/postgresql/README.md)
and [guarded migration supervisor](../deploy/postgresql/MIGRATION-SUPERVISOR.md).
Never switch an existing installation by editing its database settings alone.

The intended split keeps message bodies, delivery leases, recipient progress and
mandatory two-copy acknowledgements on each MX. PostgreSQL will own console
accounts, permissions, policies, searchable history and learning annotations.
Message acceptance must never wait for a central database transaction.

## Installation selection and startup safeguards

The development daemon accepts an installation-only `management` section.
The coordinator uses `backend = "postgresql"` with connection settings in
`management.connection`; MX workers use `backend = "coordinator"`. These settings
remain outside web policies and shared bundles, while full installation
configuration roundtrips preserve them. Do not enable them on existing servers:
the supported importer and activation command are not complete.

Local format seven records the database instance, import digest, spool identity,
installed policy epoch and coordinator MFA key fingerprint. Selecting a backend
requires this durable receipt. Legacy opening, mismatched identities, missing
markers and replacement MFA keys are rejected. Coordinator account recovery can
open the bound repository without a local MFA key; starting the console cannot.
Worker account operations must run on the coordinator; local queue operations
remain separate.

Both PostgreSQL pools verify the activated import receipt and schema checksum
when opening or reusing connections, with a two-second deadline. A wrong or
unactivated database is rejected. Runtime initialization reads the verified
local policy cache without contacting PostgreSQL or reviving obsolete SQLite
console revisions. Unit tests exercise console construction during an outage;
this does not replace full daemon, SMTP, restore and failover testing. Recovery
commands and coordinated production activation still require completion.

Selected workers also bind every v3 exchange to the database instance and
import digest through `X-NoiseFence-Management-Authority`. The coordinator
requires an exact, single header before parsing the request body and returns
the same binding. Workers verify it before acknowledging metadata or SMTP logs,
executing queue commands, installing detector history, or applying policy replies.
A missing, duplicated or mismatched identity leaves work pending. A missing local
transport marker after format-seven selection fails instead of selecting the
legacy protocol. This binding supplements certificate and node authentication;
it does not replace them. Older unselected test embeddings use no identity header
and cannot talk to a selected coordinator without explicit enrollment.

## Implemented foundations

- Lazy connection pools with separate interactive and ingestion capacity.
  Unix sockets are supported; remote connections require certificate-verified
  TLS. The plaintext exception accepts numeric loopback addresses only.
  Reused connections receive a liveness probe within a two-second recycling
  deadline, so sockets closed during an outage are not knowingly reused.
- Private, size-limited password files. Credentials are not passed in a DSN,
  command argument or web setting. PostgreSQL errors expose SQLSTATE rather than
  server details that could contain private submitted values.
- Explicit, transactional schema initialization with a checksum and migration
  lock. Schema changes do not run inside SMTP acceptance.
- A transactional SQLite metadata journal. Changes coalesce by message ID;
  monotonically increasing generations prevent stale acknowledgements from
  deleting more recent work. Deletion tombstones survive restart.
- Bounded metadata snapshots and atomic PostgreSQL ingestion. Accepted envelope
  identities and recipient sets cannot be rewritten by a later projection.
  Registered node epochs prevent another spool from taking over an identity.
  Duplicate or reordered updates are safe. Tombstones prevent resurrection.
- PostgreSQL account repositories connected to HTTP authentication, account
  administration, password changes, invitations and MFA in central-mode tests.
  Password verification is revalidated at commit, failed-factor attempts remain
  durable, and recovery codes are single-use. A missing or mismatched external
  MFA key prevents central-mode startup.
- Privileged installation-owner account creation, disablement, password reset
  and MFA reset share the selected repository. Recovery revokes sessions and
  increments the account version; concurrent requests cannot disable the last
  active administrator. MFA reset clears pending factors, recovery codes and
  attempt counters. These paths are tested with a programmatically bound store;
  installation-only CLI selection is implemented; the verified import and
  production cutover procedure remains unfinished.
- Central history, search, feedback and dashboard counts. PostgreSQL search uses
  literal phrase/prefix queries and an accent-insensitive dictionary. Counts,
  results and recipient details use one authorized read snapshot. Both backends
  share the same recorded-assessment presentation code.
- Complete retained SMTP transcripts use a separate durable journal, with
  per-log generations and deletion tombstones. Metadata is acknowledged before
  its transcripts are sent. Diagnostics preserve recipient authorization and
  the existing limits of fifty attempts per recipient and one hundred per
  request; central ingestion does not reduce history to the cluster summary.
- Quarantine and retry commands are authorized centrally, then executed in the
  owning MX's local SQLite transaction. A payload digest and durable receipt
  prevent a replay from repeating a queue mutation. Dispatch rechecks sessions,
  grants and account versions. Execution receipts survive database outages and
  local restarts until PostgreSQL acknowledges them.
- Central policy revisions and the coordinated commit barrier share one
  PostgreSQL transaction. Both storage backends use the same state transitions.
  Staging requires fresh participant reports; committing rechecks the approving
  session, account version and delegated mailbox scope. Recovery creates a higher
  revision behind admission fences, never rewinds an installed policy in place.
  The controller routes staging, commit, release, abort and recovery through this
  repository in central mode. Local participant journals retain verified runtime
  state; an expired policy cache closes admission on the coordinator as well as
  workers. Stale local console revisions are not read as central configuration.
- Authenticated v3 worker channels for policy, metadata, complete SMTP logs and
  queue commands. Node keys and spool epochs are checked against PostgreSQL;
  payload transactions recheck credentials after authentication. A rotated or
  revoked key cannot fall back to a local SQLite identity. Node administration
  supports renaming, rotation and revocation of explicitly enrolled spools.
- Independent policy and history/command background loops. Delayed metadata does
  not stop policy renewal. Request and response sizes and network deadlines are
  bounded; local acknowledgements must match the exact submitted generations.
  Workers selected for central management refuse legacy protocol fallback.

These repositories are selectable programmatically for integration tests;
production configuration and cutover are not enabled yet. Remaining operational
administration paths still need an authority audit. Policy membership reconciliation,
import of existing activation epochs and startup authority checks remain open.
CLI policy reads reject newer local formats and persisted central-authority
markers instead of reading old SQLite console revisions. The research worker
also refuses stale local configuration before writing a heartbeat or claiming a
job; it will not create a missing SQLite database. The automatic binary rollback
check refuses central configuration, central markers and storage format seven
or later, even if the older build advertises a sufficiently high schema number.
A schema number alone does not establish central-data compatibility.

The installer still needs to select the new transport under a durable backend
fence. Do not set internal SQLite transport flags manually. New-node enrollment,
membership changes and old-journal reconciliation remain migration work.

An ingestion batch contains at most twelve events and three MiB. Each SQL
statement has a three-second server timeout, lock waits are limited to 500 ms,
and ingestion has a fifteen-second overall deadline. A failed batch remains
in the local journal. No SQLite writer is held during PostgreSQL calls.

## Offline import primitives

Before making migration exports from real MXs, initialize each original spool's
management journal while its daemon and calibration worker are stopped:

```sh
noisefence --config /etc/noisefence/config.toml management-initialize-source
```

Run as the installation owner. The command verifies the existing format-six
spool's node and role, acquires both local process locks, and durably initializes
its journal. It never creates a replacement database, chooses PostgreSQL or
changes the storage format. Repeating it preserves the same node epoch. Export
only after this step: initializing a clone instead would create an identity that
the live source does not possess. This command releases its locks on exit; it is
not a remote export holder and does not stop or restart systemd services.

`SourceLocks` acquires the daemon and calibration worker locks without waiting;
active processes cause an explicit failure. It runs as the installation owner,
rejects symlink/unsafe lock paths, and checks that source directories and lock
files have not been replaced. The installer must retain these guards on every
live source host throughout capture, copy and cutover. A local guard does not
stop systemd services or lock a remote MX.

`PreparedImport` combines account, recipient-ID, learning, policy and reconciled
spool snapshots. It checks their source epochs and hashes their canonical
contents together with the schema identity. `Central::stage_import` requires a
fresh initialized destination, claims an inactive migration receipt and copies
accounts, owner metadata, public recipient IDs, full SMTP logs, learning data
and finally the policy authority. Before recording copy completion, it compares
the destination against the frozen source projections under PostgreSQL table
locks. It records progress without activating the backend. The returned database binding cannot pass runtime connection checks
while `activated_at` is NULL.

A copy failure leaves the original SQLite sources authoritative and retains the
inactive destination for diagnosis. Existing receipts and partial data are never
automatically overwritten or deleted. This implementation requires a fresh
staging destination for a new attempt; it does not yet resume a partial import.
A successful copy is recorded as `copied_not_activated`, not as proof that final
source/artifact checks, backup/restore or production activation have passed.
The local operator command is available:

```sh
noisefence management-stage --plan /private/import.toml
```

It reads this standalone manifest (the normal service configuration is unused):

```toml
[database]
host = "/run/postgresql"
database = "noisefence_staging"
username = "noisefence"
max_connections = 4

[[sources]]
node_id = "mx1"
role = "coordinator"
data_dir = "/private/offline/mx1"

[[sources]]
node_id = "mx2"
role = "worker"
data_dir = "/private/offline/mx2"
```

Run as the source-directory owner. Use absolute physical paths without symlinks;
the database must already exist and be unused. The command initializes the
checksummed schema, but never creates a PostgreSQL database or role. Network
connections require verified TLS and a private `password_file`; the Unix-socket
example uses peer authentication.

All local process locks must be acquired before source journal initialization.
The command checks format-six node identities, requires the existing coordinator
MFA key, and captures sources under SQLite write reservations. Combined input is
limited to 200,000 message/transcript rows and 512 MiB of scan/transcript fields;
individual snapshots have additional limits. Process locks remain held through
the copy. Output is a JSON receipt with the database binding and reconciliation
counts, without message bodies or secrets.

This command does **not** stop services, lock remote hosts, install format-seven
selection, activate the destination, change service configuration or restart an
MX. Source journals may be initialized even if a later copy fails. On copied
spools, newly created epochs identify those copies, not the live servers. An
inactive receipt from such a rehearsal cannot authorize live cutover. Ordinary
operator writes after capture are not excluded by process locks: activation must
reacquire source locks and verify a fresh complete snapshot. Coordinated remote
lock/export, final parity checks and activation remain release gates.

For an export whose original journal was already prepared and frozen, use
`management-stage --preserve-source-generations --plan /private/import.toml`.
This preserves the original spool epoch and event generations. It refuses missing
journals or missing owner entries instead of creating or reseeding them. It does
not acquire remote locks or establish that an export still matches its original.
Never use the default reseeding mode for the final import of frozen remote
exports: the imported generations must match the originals exactly.

Before proceeding, recheck the frozen management sources against the returned
binding:

```sh
noisefence management-verify-sources --plan /private/import.toml \
  --instance RECEIPT_INSTANCE --source-digest RECEIPT_SOURCE_DIGEST
```

This command reacquires local process locks, reads existing source identities
and journals without reseeding them, and compares a new canonical capture with
the import digest. It refuses missing owner journal entries, changed accounts,
metadata, learning records or policy data, a different destination receipt,
an incomplete import, or an already activated destination. It also compares the
destination account and learning tables, source identities, owner records,
recipient data and public IDs, full SMTP transcripts and tombstones, policy
journal and membership. Exact counts reject extra rows. Runtime-only tables must
be empty, and recipient/revision/audit sequences must not trail restored IDs.
An unknown or missing management table fails verification instead of silently
escaping coverage. Generated timestamps are not compared to source timestamps;
they describe the import itself.

Success reports `sources_match_inactive_import` only after both source freshness
and destination parity pass. Repeated verification does not advance journal
generations. This is a point-in-time management-data check; it does not prove
unchanged model/credential artifacts, backup recovery or permission to activate. The final cutover must retain locks and database reservations until
selection is committed; a separate verification command releases its guards
when it exits.

The native `import::frozen::with_source` primitive prepares the original
journal under the daemon/calibration locks, then retains a SQLite write
reservation while producing an owner-only metadata export. The export receipt
records the original identity, event sequence, byte size and SHA-256. Copying
uses a separate read-only SQLite connection and a 120-second deadline. The
export is removed when the callback finishes; an interrupted process may leave
its private `management-export-*` directory for operator cleanup.

Its selection method rechecks immutable installation artifacts and the MFA
binding before committing format seven, while keeping process locks until the
callback returns. Failure after that commit never restores legacy selection.
Tests cover concurrent writer exclusion, identical exported event generations,
cleanup before selection, and durable selection after a lost acknowledgement.
The `management-freeze-source` command exposes this primitive through one
owner-only Unix socket. It is not a complete remote cutover controller: coordinated
transfer, PostgreSQL activation, configuration publication and service recovery
still need orchestration. Never restart an old daemon after a partial commit.

### Bounded source sessions and partial selection recovery

After stopping the MX and its background writers, a migration supervisor can run
this command as the installation owner:

```sh
noisefence --config /etc/noisefence/config.toml management-freeze-source \
  --export-parent /var/lib/noisefence-migration \
  --socket /var/lib/noisefence-migration/source.sock --lease-seconds 900
```

The export parent and socket parent must already exist as physical directories
owned by that user, with mode 0700. The socket uses mode 0600. An existing socket
or other file is never overwritten. The command accepts one connection; it
neither listens on TCP nor changes service configuration. The supervisor must
also enforce an outer process timeout for stalled filesystem operations, record
which services it stopped, and keep them stopped after a partial selection.

The control protocol is `noisefence-source-session-1`. Each frame is a four-byte
big-endian length followed by UTF-8 JSON, limited to 5 MiB. The initial response
contains a random `session`, `state: frozen`, the private `export_path`, the
`receipt` (journal identity/sequence, SHA-256 and bytes), and any
`existing_selection`. Subsequent requests contain `protocol`, `session`, a
strictly increasing `sequence` starting at one, and `command`. Unknown fields,
replayed sequences, a different session, oversized frames and disconnections
terminate the session. The absolute lease is 1–1800 seconds and is not renewed
by requests; at most 64 commands are accepted.

Commands are:

- `{"action":"check"}`: confirm the original source guards are still held.
- `{"action":"select","authority":JOURNAL,"selection":SELECTION,"export_sha256":HASH,"source_sequence":NUMBER}`:
  acknowledge this exact export, recheck installation artifacts, and durably
  select the proposed authority. The response includes the actual selection.
- `{"action":"release"}`: finish after a successful selection acknowledgement.
- `{"action":"abort"}`: finish only if no local selection has been committed.

The final PostgreSQL activation transaction must call `select` on every frozen
source, check every acknowledgement, and commit the database receipt before the
supervisor publishes configurations and starts services. A socket response is
not proof that PostgreSQL is active. Temporary source exports are removed when
the session ends. Keep the coordinator's verified import copies and receipts
until recovery and backup verification complete.

If a source was selected before a connection or activation failure, restart its
session with `--resume-selection /private/original-selection.json`. This bounded
receipt file must describe the exact selection already stored in that source.
The command does not reseed its journal or revert format seven. It exports the
current selected snapshot, rechecks the same immutable installation on `select`,
and refuses `abort` even before the new session has acknowledged selection.
Other sources may still be at format six; keep all of them stopped and reopen
them with `management-freeze-source --preserve-source-generations`. This option
requires the already initialized, complete journal and preserves its epoch and
sequence. Omitting it would reseed the unselected source and invalidate the
existing import binding. Missing owner entries fail instead of being repaired
after import. Re-run
`management-verify-sources` and `management-prepare-selections` against the same
inactive database binding using fresh frozen exports. These verification commands
accept a mixture of legacy and selected sources only when every selected source
names that exact database authority. Canonical management data must still match
its original import digest; selection markers alone do not alter that digest.
Fresh staging of already selected sources remains forbidden. An already active
database requires inspection of its committed receipt rather than a second
activation attempt.

### Final activation barrier and receipt inspection

A supervisor holding every original source session can invoke the activation
command against its verified import copies:

```sh
noisefence management-activate --plan /private/import.toml \
  --instance RECEIPT_INSTANCE --source-digest RECEIPT_SOURCE_DIGEST \
  --commit-socket /private/migration/commit.sock
```

The supervisor creates this Unix socket in an owner-only physical directory;
both the directory and socket belong to the installation user, with no group or
other permissions. The command performs source and installation preflight,
connects with a five-second deadline, then holds the PostgreSQL activation
transaction while checking destination parity. Only after those checks does it
send a framed `noisefence-import-commit-1` request containing a random `request`,
`database` binding, policy `authority`, and exact proposed `selections`.

The supervisor must forward each proposal to the corresponding still-frozen
original session, including that session's export hash and sequence. It responds
with the same `protocol`, `request`, `database`, and the actual acknowledged
`selections`. Frames use the same bounded encoding as source sessions; the
bridge has an absolute 90-second I/O deadline. Missing, duplicate or different
selection receipts prevent the PostgreSQL commit. The command reports
`status: activated` only after the database transaction commits. It does not
publish service configuration, restart an MX, or release the original sessions;
those remain supervisor responsibilities. The activation command itself holds
locks on the import copies, while the supervisor holds the original MX sessions.
Do not supply a static receipt file in place of that live barrier.

After any ambiguous result, inspect the committed receipt without retrying an
activation blindly:

```sh
noisefence management-status --plan /private/import.toml \
  --instance RECEIPT_INSTANCE --source-digest RECEIPT_SOURCE_DIGEST
```

This read-only command checks the schema hash and database identity and returns
`phase`, `activated_at`, and the recorded selections. Database unavailability,
another identity, an unknown phase or an inconsistent receipt are errors, never
an inferred inactive state. `active` confirms the stored activation receipt;
it does not prove service health or that configuration publication finished.
`copied_not_activated` requires completing the same guarded attempt. The CLI
integration test exercises a durable source selection followed by a lost
acknowledgement, an inactive destination, a resumed selected source, and final
activation of that same database binding. The remote service/transfer supervisor
and its deployment recovery checks remain separate release gates.

Installation preflight additionally requires an absolute `config` path in each
`[[sources]]` entry. Each configuration must identify that source's data
directory, node and role. Initial preflight requires the legacy backend; recovery
also accepts the exact previously committed selection described above. Then run:

```sh
noisefence management-prepare-selections --plan /private/import.toml \
  --instance RECEIPT_INSTANCE --source-digest RECEIPT_SOURCE_DIGEST
```

Every source must have a released, installed participant policy matching the
frozen coordinator epoch. The command verifies the content-addressed model files
and the policy-bound credential generation, and binds the coordinator selection
to its existing private MFA key. Missing credentials cannot fall back to mutable
key files or environment variables. Configuration input is bounded to 1 MiB;
parse failures do not echo its contents. No secret values enter the output.

The JSON result is `installation_checked_not_activated` with proposed local
selections. This command does not install them, edit configuration or activate
PostgreSQL. It also reruns source/destination parity. The check does not load the
full inference engine, contact providers, validate SMTP TLS handshakes or prove
backup restoration. Files can still change after the process exits: the final
coordinated cutover must revalidate these inputs while retaining source locks.




`SpoolSnapshot::capture` reads the entire retained owner history, including rows
already acknowledged by a previous consumer. It reseeds the owner's metadata and
SMTP transcript journals in a caller-owned offline transaction. A nested
savepoint rolls back the reseed on any error. Existing deletion tombstones stay
intact, and later runtime changes receive higher generations so an old import
receipt cannot erase newer work.

Capture validates rows before copying large fields, with a combined limit of
100,000 events and 256 MiB of serialized metadata per spool. It exports all
retained SMTP attempts, not only the five-attempt cluster summary. Diagnostics
pass through the existing redaction boundary. Bodies and attachments remain on
their MX. Coordinator mirror records and their retained logs are returned
separately with their owner and synchronization provenance; remote body
availability is preserved separately from local body presence. They must be
reconciled against every owning spool before activation. Capture does not
silently discard mirrors or assign their local log IDs to an owning worker.

`ReconciledSpools::verify` verifies distinct source identities and immutable
accepted envelopes across the captured spools. It keeps the owner's current
analysis and delivery state when an asynchronous mirror is older. Every retained
mirror transcript must exist at the owner after the same diagnostic redaction,
including multiplicity when traces repeat. Only proven duplicates are removed
from the import stream. An absent owner, a retained mirror conflicting with an
owner tombstone, a changed envelope, or a missing transcript stops migration
with an explicit reconciliation error. No source identity is invented and no
missing owner record is silently recreated. Such conflicts still require an
operator reconciliation procedure before activation.

Tests cover previously acknowledged rows, all retained transcripts, tombstones,
mirror provenance, malformed and oversized input, rollback and stale receipts.
The PostgreSQL roundtrip test checks 13 synthetic messages, 26 stable public
recipient IDs and 182 complete SMTP attempts, including replay after reconnect.
This validates the capture/copy components; the offline installer still needs
to orchestrate locks, reconciliation across the actual offline snapshots, parity
receipts and final activation.


The account snapshot/import primitive copies users, grants, sessions, sealed MFA
credentials, recovery hashes, attempt counters and invitations. It preserves
account versions, session MFA verification flags, factor replay counters and
invitation creator versions. It requires the original MFA key to decrypt-check
all factors before copying; no replacement key is generated. The caller supplies
one consistent SQLite read transaction. Snapshots stay in memory and have no
public serialization or debug representation.

The source is checked for broken foreign keys, invalid boolean values and
resource limits (1,000 accounts, 100,000 total rows, 256 KiB per row, 16 MiB
total). PostgreSQL must have no enrolled sources or existing account data. All
seven destination tables are locked, copied and compared field by field inside
one transaction. A failure, timeout or parity mismatch rolls back the entire
copy. Text ordering explicitly uses the C collation to match SQLite ordering.
Repeating an import cannot overwrite an occupied destination.

The learning-history primitive copies operational feedback and categories,
independent labels, sample membership and ranks, sample purpose/cohort, curated
reference provenance, explicit training exclusions, adaptive labels, research
jobs and export exposure. Legacy samples without an explicit purpose remain
regression samples. Deleted sample exposure and campaign exposure survive the
copy. It preserves the original exposure tracking start and initializes the new
PostgreSQL publication generation to zero. It does not import a stale worker
heartbeat as evidence of a running worker. The original referenced model files
still need to be copied and digest-verified by the complete installer.

Learning imports require existing message identities and accounts, empty learning
tables, no central policy authority and no activated migration. They refuse an
active central research worker and an already-advanced export generation. The
11 tables are copied and compared in one transaction, including after a late
failure; limits are 100,000 total rows, 1 MiB per row and 64 MiB overall with a
60-second deadline. Research job statuses are preserved; the worker's existing
restart handling interrupts abandoned running jobs when it starts later.

The recipient identity primitive preserves the old coordinator's public numeric
delivery IDs, including its worker-message projections. After importing metadata
from all MXs, and **before importing SMTP transcripts or activating policy**, it
checks every old message/recipient/destination against PostgreSQL and restores
those numeric IDs atomically. New worker recipients absent from the old console
receive non-colliding IDs above the reserved range. Repeating this step is stable.
A late failure rolls back the mapping; sequence advancement never rewinds and
can leave harmless gaps. The operation is bounded to 100,000 recipients and 64
MiB, with a 30-second deadline. Message UUIDs are not rewritten.

The policy import primitive preserves the complete terminal activation journal,
including its current sequence, higher aborted-rollout sequence and model/key
bindings. It copies the retained policy revisions, audit IDs and registered
worker credentials, versions and enabled state. It requires the captured MX
spool epochs to match the imported sources, verifies the coordinator's durable
local identity, refuses to re-enable revoked sources and refuses unresolved
legacy queue commands or a rollout still in progress. Enabled membership must
match the journal's participants. Destination audit, node and policy tables must
be empty; all copies, source revocations, the policy head and the journal commit
in one transaction after field-by-field comparison.

Revision zero is materialized as a clearly identified bootstrap record if it
was never present in the SQLite revision history. A missing nonzero installed
revision, a conflicting policy or a newer source revision causes an error.
The imported head uses zero for an unknown legacy activation timestamp; it does
not assert a fresh activation or peer heartbeat. Existing diagnostic node status
is retained, but no fresh policy-peer acknowledgements are invented. Audit and
revision sequences advance without rewinding. Policy import runs last and is
bounded to 100,000 projected rows, 4 MiB per row, 64 MiB overall and 60 seconds.

These primitives do not stop services, import message data, write a cutover
receipt, select the production backend or provide a rollback.
The complete installer must hold daemon and research-worker locks across the
whole snapshot, import, verification and activation sequence. Do not run a
partial import as a production migration.

## Evaluation metadata

Central mode routes human risk/type annotations, frozen score-blind samples,
member pages, cohort summaries, observation dates, qualification readiness and
private dataset exports through PostgreSQL. Eligibility calculations and export
projections are shared with SQLite. Readiness remains a data inventory, not an
accuracy certificate or permission to activate a model.

Exports omit message content and mailbox identities. Raw scans are read through
bounded portal batches; exports are limited to 50,000 messages and 128 MiB of
projected JSON. Exposure accounting commits before file creation. A failed file
write remains consumed, and concurrent exporters cannot both report the same
campaign as unseen. Reserved evaluation membership and independent quality
labels are excluded from the training-feedback view. Operational feedback edits
invalidate adaptive annotations without deleting independent evaluation truth.

Central mode also routes adaptive labels and tenant-scoped adaptive exports,
and research job enqueue/list/cancel/candidate lookups through PostgreSQL.
Adaptive exports use the same row projection and protected-campaign matching as
SQLite. Conflicting labels, inaccessible labels and messages spanning multiple
tenant domains are excluded. Research queue limits and duplicate checks are
serialized; fitting is permitted only for development samples. Preparing an
evaluation job does not activate a model, and candidate selection still verifies
the immutable local file against its recorded digest.

Lexical/semantic feedback exports, the legacy corpus format and tenant-scoped
native Bayes exports now route to PostgreSQL in central mode. Both backends
share eligibility and serialization code. Full-population exports use a stable
read snapshot and bounded portal batches; a bounded channel hands file writes
to a blocking worker. No fixed recent-message subset replaces the full eligible
population. Only a completed database snapshot can publish the final file;
invalid late rows or database errors remove the partial file and preserve an
existing export. Files are private. The legacy SQLite corpus exporter now uses
the same atomic publication routine.

Native Bayes exports retain their 50,000-message limit and use a 128 MiB projected
JSON cap in the PostgreSQL repository. Counts and exported rows are tested against
SQLite, including conflicting categories, protocol omissions, revoked accounts,
protected campaigns and supplementary-check failures.

The Python research worker now has a central adapter using the private Rust
`quality-worker-session` stdio protocol. The Rust child owns a dedicated database
connection and a session advisory lock; the connection is never recycled into
the pool. Periodic heartbeats detect lost ownership even during Python training.
Another runner cannot claim work while the owning session is connected. After a
connection loss, abandoned jobs become interrupted; their old session cannot
publish a late result. Claiming rechecks administrator, sample purpose and
candidate eligibility. Final publication rechecks the administrator and always
records observation-only results.

Protocol requests and responses have size/deadline limits and accept only typed
operations, never arbitrary SQL. The Python path has no SQLite fallback. Tests
cover the Rust protocol against PostgreSQL and the Python adapter against an
actual child process. Production management configuration and cutover are still
unavailable, so the installed CLI cannot bind this central repository yet. The
complete native/Python/PostgreSQL training pipeline through production bootstrap
remains a release gate, as do remaining periodic training consumers and historical
metadata import.

The complete retained-population audit exporter also reads PostgreSQL. Its
projection and counters are shared with SQLite; it includes unlabelled,
conflicting and unusable records instead of filtering them out of evaluation.
Votes are rechecked against current grants in the same snapshot and Bcc
recipients do not multiply messages. Bounded streaming retains the 50,000-row /
512 MiB limits. Publishing is private and atomic, and refuses to replace an
existing snapshot, including a racing file creator. Tests compare both backends,
including invalid typed scan data and ignored votes from revoked users.

## SMTP detector history

Sender history, behavioral history, fuzzy memory and campaign corroboration use
a separate private SQLite cache in central mode. PostgreSQL supplies authorized
administrator annotations and the minimum detector features through background
refreshes. The cache contains no message text, subjects, mailbox addresses,
passwords or console permissions. It cannot authorize a console request.

Refreshes are attempted every fifteen seconds by the management transport loop.
A snapshot expires after sixty seconds, is limited to 50,000 records and 64 MiB,
and is installed atomically without holding the local SMTP queue writer. Existing
readers retain a consistent snapshot. Credential rotation, node revocation and
spool epochs are checked for remote refreshes. Cached training labels respect
account revocation at the next successful refresh, or expire with the snapshot.

A fresh cache remains usable during a PostgreSQL outage. A missing, expired or
invalid cache makes these historical signals unavailable; it does not revive
the old local annotations. The durable backend selection also rejects unknown
protocol versions. Corrupt disposable caches can be rebuilt, and an expired
cache can recover after a database restore resets its generation sequence.
Production bootstrap and rollback must manage this selection explicitly.

Projection preserves the recent unlabelled messages used to bound campaign
lookups; it does not expand the campaign window to older labelled messages.
Integration tests compare sender/behavior and fuzzy-memory results with SQLite,
exercise expiry, database disconnection, disabled annotators and cache recovery,
and verify authenticated HTTP refreshes. This cache does not yet establish
complete daemon cold-start behavior during a PostgreSQL outage.

## Reliability reports

The recipient-scoped reliability report reads PostgreSQL in central mode. It
uses the same observation accumulator, label precedence, confidence intervals,
symbol diagnostics and frozen-score comparisons as SQLite. A single read
snapshot checks the active account and recipient grants before selecting any
message or annotation. Multiple deliveries do not multiply observations.

Portal batches bound retrieval memory; the report retains the existing limits
of 5,000 messages, 32 MiB and two seconds of processing. Exceeding a limit marks
the report partial and disables distribution-change alerts. Invalid recorded
scans remain explicit. The report is advisory and never activates a model.
An unavailable central database returns an error rather than a report from old
local accounts or annotations.

## Configuration history, previews and model retention

Configuration revision lists and individual revisions, including revision zero,
read the central policy repository. Old SQLite configuration history is not a
fallback. Administrator-requested policy simulations use bounded PostgreSQL
snapshots for the exact requested recipient, preserving request order and marking
unavailable messages explicitly. These previews retain the fifty-message and
16 MiB limits and never rerun detectors or alter delivery. Archive status uses
the current central node registry and reported worker status, while the console's
own archive status comes from its local archive.

Model files remain immutable local artifacts. In central mode, retaining or
removing a set checks the active administrator session, including MFA, in
PostgreSQL. An authorized `model_set_retain_started` or `model_set_remove_started`
audit event commits before filesystem work. A corresponding `_completed` or
`_failed` event records its outcome. Both events share an object identifier made
from the operation UUID and model-set digest. No database transaction or local
SMTP writer is held while copying files. Revoking a session prevents a new
operation; it does not erase the result of an already-authorized request.

Filesystem changes and PostgreSQL commits are not one atomic transaction. An
outcome-log failure returns an error and keeps the original intent; a crash can
likewise leave a started event without a terminal event. Inspect the named set
before retrying such an operation. Retention of an identical intact set is
idempotent. Removing an already-absent set returns an error. These catalog
operations do not install models or change the active policy.

Integration tests exercise central permissions, revoked administrators, database
outages, real file operations and an injected failure of the completion audit.
HTTP tests verify revision history, recipient simulations and archive status
without consulting stale local administration data.

## Retention and activation incidents

Central housekeeping runs in the management synchronization loop, independently
of SMTP delivery and policy renewal. A sweep has a ten-second overall deadline
and limited batches: up to 500 expired sessions, invitations, annotations or
exposure records per table, 100 unreferenced finished jobs and one expired sample.
That sample can contain at most 50,000 members. Expired invitation records remain
available for thirty days after expiration. Ordinary audit history is retained
for thirty days. Completed catalog audit pairs expire together; unresolved
catalog intents remain available for reconciliation.

Running and queued jobs, candidates referenced by other jobs, and models named
by retained policy revisions are preserved. Removing old evaluation labels or
samples reserves their messages against future training; these minimal
reservations disappear when the messages are deleted. Message deletion itself
still follows the owning MX's durable tombstone, and housekeeping does not erase
node identities, policy epochs or delivery replay fences. A failed sweep rolls
back all its changes. Failed housekeeping is logged and retried later.

Activation incidents use central storage and contain only a bounded code,
timestamp and rollout epoch. A write or clear must match the current authority
identity and rollout epoch. A new rollout discards an old incident. The console
exposes incidents only to administrators or the authorized owner of a personal
change. A membership mismatch remains inspectable and reports the policy as not
ready; viewing that status does not grant permission to advance or recover it.
PostgreSQL outages can prevent incident persistence and are additionally logged.
Incident and status queries project only the required metadata; they do not
deserialize model bundles to display progress. Policy mutations still validate
the complete journal. Tests run on the standard test-thread stack and cover
stale incident writes, owner mismatch, scoped visibility after grant revocation,
incident clearing and membership-change diagnostics.

## Integration tests

Use a disposable PostgreSQL 17 instance listening on `127.0.0.1:15432`, with
database `noisefence_test` and role `postgres`. Never point these tests at a
production database. Each test creates its own `nf_test_*` database with
synthetic accounts, messages and sessions, then removes it. Tests temporarily
lock tables and disconnect their own database connections to exercise recovery.
The test role needs permission to create and drop these disposable databases.

Store the test password in an absolute-path regular file with mode `0600`, then
run:

```sh
NOISEFENCE_TEST_PG_CONTAINER=noisefence-pg-migration-test \
NOISEFENCE_TEST_PG_PASSWORD_FILE=/absolute/private/test-password \
  cargo test --locked --test central_postgres --test central_console \
    --test central_search --test central_logs --test central_commands \
    --test central_policies --test central_transport --test central_quality --test central_adaptive --test central_research --test central_learning --test central_research_worker --test central_runtime_history --test central_reliability --test central_catalog --test central_preview --test central_retention --test central_operator --test central_import --test central_import_quality --test central_import_delivery_ids --test central_import_policy --test central_binding --test central_import_spool --test central_staged_import --test central_restore --test central_transport_binding --test central_offline_cli --test import_session -- --ignored
cargo test --locked --test central_outbox
cargo test --locked --lib central::settings::tests
cargo test --locked --test cluster --test replication
```

The PostgreSQL tests are intentionally ignored in ordinary `cargo test` runs. The
dedicated `postgres` CI job provisions a disposable service and explicitly runs
it. Tests cover retries after lost acknowledgements, ownership fencing, stale
updates, atomic rollback, durable deletion, a blocked database followed by
recovery, recipient isolation, disabled accounts, concurrent password changes,
MFA enrollment invalidating old sessions and recovery-code replay. HTTP tests
exercise the actual console routes; search tests compare full result payloads
against SQLite, including pagination and BCC visibility. Central-mode login must
not fall back to old local accounts while PostgreSQL is unavailable.

Transcript tests compare complete diagnostics against SQLite and exercise
retention, stale updates and attempted recipient reassignment. Command tests
exercise the HTTP routes, revoked permissions before dispatch, repeated delivery
of the same command, an unavailable PostgreSQL backend, restart, and late
execution receipts after command-history retention.

Policy tests inject a database failure between revision insertion and head
update, exercise revoked approvals, stale epochs, missing participant readiness,
partial activation recovery and database outage. An additional controller test
uses two real runtime participants, verifies that central release alone cannot
open a local fence, and checks that an expired coordinator cache remains closed.
A complete daemon restart through a database outage remains a separate release
gate; the controller cache test does not establish it.

Transport tests use actual loopback HTTP endpoints and PostgreSQL. They exercise
lost replies after committed ingestion, transcript retries, command receipts
after restart, credential rotation, revocation through the Web administration
route, and refusal to use stale SQLite node keys. Another test runs both real
cluster loops through two coordinated policy activations while the history
endpoint is unavailable, then verifies that retained metadata catches up.

Search configuration follows PostgreSQL's
[unaccent dictionary](https://www.postgresql.org/docs/17/unaccent.html) and
[text search controls](https://www.postgresql.org/docs/17/textsearch-controls.html).
Only already-retained subjects, envelope senders and rule IDs enter the search
index; message bodies, recipients and detector explanations are not indexed.

## Replication resynchronization after selection

The stopped-queue resynchronization command accepts an explicit installation
configuration for selected format-seven storage:

```sh
sudo -u noisefence noisefence ha-resync /var/lib/noisefence \
  --management-config /etc/noisefence/config.toml
```

Stop the daemon and calibration worker first. The configuration must identify
that same queue and its recorded management authority. Process locks are acquired
before opening selected storage. This operation only advances local replica
generations and clears their acknowledgements; it does not start SMTP, contact
PostgreSQL or the peer, delete bodies, or replay completed deliveries. Its audit
entry is local operational history. The next normal replication pass rebuilds
the peer's acknowledgements. The storage format and management binding remain
unchanged. Omitting the configuration continues to refuse selected storage rather
than falling back to obsolete SQLite management data.

This is replica resynchronization, not disaster promotion. Recovery of a selected
coordinator, including its central accounts and policy authority, still requires
the coordinated PostgreSQL recovery procedure and remains a release gate.

### Recovering selected queue bodies

`ha-restore` accepts an explicit matching installation configuration for a
selected coordinator. Run against stopped, staged snapshots as their installation
owner, after fencing the original owner:

```sh
noisefence ha-restore --source /srv/recovery/peer \
  --target /srv/recovery/coordinator --owner mx1 \
  --fence-receipt /srv/recovery/fence.json \
  --management-config /srv/recovery/coordinator.toml
```

The configuration must name the target data directory and its recorded backend.
Both source and target require daemon and calibration locks. The source must be
the configured worker peer, selected against the same database instance, import
digest and baseline policy epoch. Different authorities, running writers and
implicit fallback to legacy SQLite are refused before queue mutations.

This operation uses local journals and bodies only, without connecting to
PostgreSQL. It preserves the selection, verifies body checksums, requires new
replication acknowledgements, keeps delivered recipients finished and holds
uncertain SMTP outcomes. Repeating a completed recovery does not replay deliveries.

The result explicitly reports `central_management_recovery_required: true`.
A durable local marker blocks both normal and recovery-console startup, including
a final check after acquiring the daemon lock. This primitive does not restore
central accounts, access revocations, outbox epochs or policy authority. Do not
manually delete the marker or switch to the old backend. The coordinated central
recovery finalizer remains a release gate; this command alone is not a complete
promotion procedure.

Do not confuse temporary database unavailability with disaster recovery:

| Situation | Required response |
| --- | --- |
| PostgreSQL is temporarily unreachable and the original spool is intact | Restore database connectivity. Do not run queue restoration or replace the management backend. |
| The coordinator spool must be rebuilt from a fenced peer snapshot | Restore into a stopped staging directory with the matching installation configuration. Keep the recovered service stopped until central recovery is complete. |
| A queue restoration was interrupted | Keep the original owner fenced. Inspect the recorded operation and repeat the same restoration against the same snapshots; do not remove the recovery marker. |
| Startup reports `Complete coordinated management recovery` | Queue recovery has not established fresh account, policy and management state. Starting the old binary or deleting the marker is not a supported recovery. |

The startup guard is checked both when opening selected storage and after taking
the daemon lock. This also prevents a process that opened storage before an
offline restoration from starting afterwards with stale management assumptions.
The guard treats the presence of the recovery marker as authoritative even if its
value is malformed. Diagnostic and repair commands can still open the local queue;
that access does not authorize SMTP or console startup.

### Central access recovery primitive

`Central::recover_access` is an internal building block for the coordinated
recovery procedure. It requires an active, exactly bound database and a canonical
operation UUID. The caller must fence all writers and durably save the operation
and recovery credentials before calling it; stopping a staged local spool does
not prove that writers on the original coordinator have stopped.

One PostgreSQL transaction disables existing accounts, increments their versions,
deletes old sessions, revokes invitations and creates a fresh recovery administrator.
Existing MFA records and recipient grants remain attached to disabled accounts for
later review. The transaction also records its operation and credential fingerprint
outside the expiring audit history. A failed transaction leaves access unchanged;
a retry of the same committed operation does not revoke newly issued sessions.
Reusing an operation with different credentials or colliding with an existing
account is refused.

`Central::recover_access_saved` adds durable credential preparation to this operation.
Its destination must be in an existing physical directory owned by the caller with
no group or other permissions. It publishes a complete mode-0600 file without
replacing any existing file, synchronizes it before database changes, and reuses the
same account and password hash after a database failure or lost reply. The file is
bound to the database instance, import digest and recovery operation. Symlinks,
malformed files, mismatching operations and permissive access modes are refused.
The result reports the file path and account name, never the password or its hash.
Keep this file private; it contains the credentials needed by the operator.

These primitives have no Web route and do not clear the local recovery marker.
They still need integration with the fenced recovery supervisor,
policy/outbox reconciliation and the console activation procedure.
It must not be used against the live original database from a staged recovery copy.

### Attaching stopped worker queues in place

After persistently fencing the original services and background jobs, prepare the
restored coordinator's private console configuration and queue-recovery receipt.
The recovery plan must name each surviving worker's **actual installed source
configuration and data directory**, not a disposable replacement queue. Then run:

```sh
noisefence management-recovery-attach-workers --plan /private/recovery/prepare.json
```

This offline command holds daemon and calibration locks on all configured sources.
It checks the selected database and node epochs, the fresh fencing attestations,
the complete participant set, unanimous completed policy and the coordinator's
existing recovery operation before making changes. Each worker receives a pending
recovery marker and an operation/selection receipt in one durable SQLite transaction.
Messages, bodies, delivery states, source epochs, management outboxes and their
sequence numbers remain unchanged. A busy source or inconsistent existing marker
causes refusal. Retrying the same operation preserves existing receipts; a failure
partway through multiple workers leaves the already attached workers fenced and
can be retried with the same plan.

No PostgreSQL connection is required for attachment. This command neither stops
remote services nor proves that a configured path belongs to the live systemd
worker. The supervisor must verify those installation paths and maintain persistent
service fences throughout recovery. Subsequent management preparation must use
these same worker roots so that replay generations and transcript allocators advance
in the original queues. Never copy a staged worker database over its real queue to
transfer those cursors. Worker startup remains blocked after attachment; releasing
it after console activation is a separate guarded deployment step.

### Coordinating offline recovery phases

[Selected recovery preparation](../deploy/postgresql/RECOVERY-PREPARATION.md)
combines verified checkpoint staging, a new PostgreSQL restore, native queue recovery,
worker attachment, management preparation, key installation and native authorization.
Its phase journal supports retries and keeps services persistently stopped. The
runtime/proxy handoff and complete installed promotion rehearsal remain required;
`authorized_services_stopped` is not a completed promotion.

### Restoring the checkpoint database

The isolated PostgreSQL restoration helper is documented in
[Checkpoint database restoration](../deploy/postgresql/RECOVERY-DATABASE.md).
It allocates a new operation-specific database and commits restored objects together
with a binding/dump receipt. Existing targets without its allocation receipt are
refused. This stage does not select a backend or start services; native management
recovery and the complete promotion supervisor remain required.

### Installing worker keys with root privileges

The privileged helper and its root-owned authorization contract are described in
[Recovery credential installation](../deploy/postgresql/RECOVERY-INSTALLER.md).
It derives destinations from the protected installed configuration, confirms the
systemd startup command and actual queue selection, and holds daemon/calibration
locks while installing credentials and the coordinator URL. It leaves a persistent
service fence in place. Its isolated Linux/systemd fixture uses a harmless stand-in
process; complete protocol-2 promotion and native service health remain separate
deployment gates.

### Authorizing attached workers after console recovery

After console authorization, install the verified replacement token and set each
worker's actual configuration to the restored console origin. While all services
remain persistently fenced, run:

```sh
noisefence management-recovery-release-workers --plan /private/recovery/prepare.json
```

The command retains every source lock and verifies console authorization, current
policy authority and membership, installed credentials, empty metadata outboxes,
and exact history inventories. PostgreSQL records authorization before each local
SQLite transaction installs its release receipt and removes its pending marker.
A local publication failure keeps that worker fenced; retry the same plan and
configuration to finish. The restored console retains its permanent SMTP fence.
The command never starts services or changes configuration, credentials, or routing.
The supervisor must validate console health and maintain persistent service fences
until it deliberately starts the workers.

This development primitive binds cold startup to the authorized origin, credential
path and token. Never remove or edit recovery receipts to bypass these checks.
A subsequent recovery uses a fresh operation UUID. Queue recovery archives an
authorized console's previous fence, replay and activation in the same transaction
that installs its new pending fence. Worker attachment similarly archives the prior
attachment, release, optional key renewal and replay receipt before installing the
new pending attachment. Incomplete prior operations must be resumed; a completed
operation or an archived operation cannot be reused to start another recovery.
The archive retains at most 256 completed operations per source and refuses further
changes when full. A transaction failure preserves all previous receipts. These
steps do not reset node epochs, queue contents, delivery states, outbox generations
or transcript allocators. A new replay reserves generations above existing local
and restored central counters. Protocol-2 promotion is not yet an end-to-end
supported deployment procedure.

After a later administrator-authorized central token rotation, install the new
private token at the worker's existing credential path. Stop and persistently fence
all sources, refresh the fencing attestations in the original recovery plan, and run:

```sh
noisefence management-recovery-renew-worker-keys --plan /private/recovery/prepare.json
```

This command validates the recovered console authorization, exact source membership,
original release receipts, unchanged worker routes and paths, and current enabled
worker identities and token hashes in PostgreSQL. It never rotates a central key,
re-enables a worker, changes its destination, or starts a service. It records an
idempotent central authorization before atomically publishing each local renewal.
An interrupted local publication remains blocked with the newly installed key;
retry with the same configuration and keys. Once renewed, the old key fails the
local startup guard. Every retry checks the current central authorization again,
so an earlier receipt cannot authorize a subsequently revoked key. The receipt
journal retains up to 256 distinct renewal batches and refuses further changes
when full. This offline procedure requires the coordinator and actual worker
sources to be accessible under their source locks; remote orchestration remains
a deployment integration gate.

### Preparing the restored management state as one operation

`Central::prepare_recovered_management` coordinates the offline recovery steps for
all selected source copies. It holds every daemon and calibration lock continuously
through access revocation, history replay, and policy reconciliation. It verifies
source identities and database binding, the complete enabled membership, the shared
completed policy, immutable provider credentials, and the original MFA key before
revoking access. A missing or busy source fails before credential publication.

Recovery credentials are persisted privately before account changes. The coordinator
receives a durable provider-budget hold before replay; this hold survives a failed
attempt and requires a separate review of restored allocations. Retrying the same
operation reuses its credentials and receipts without revoking new sessions.

After policy reconciliation, preparation replaces every enabled worker's central
authentication token. It first persists distinct replacement tokens in the private
companion file `<credentials_file>.workers.json`, bound to the operation, selected
database and exact node epochs. The PostgreSQL transaction revokes old tokens,
increments node versions, clears restored heartbeat information and records an
idempotent receipt. It neither enrolls unknown nodes nor re-enables disabled nodes.
A retry preserves the replacement tokens and any subsequent heartbeat; a later
revocation or token change causes refusal rather than being overwritten.

The report includes the companion file path, never the tokens. Keep both credential
files at their recorded paths until recovery is complete. The companion JSON stores
each node's `epoch` and `token` under `workers`; it must remain private. Existing
worker credential files are not overwritten by preparation. The supervisor must
install each replacement on the matching fenced worker and verify installation
before releasing that worker. Until then the report states
`worker_installation_required: true`, and restored services remain blocked.

After installing the replacement tokens at the worker credential paths named by
the source configurations, rerun preparation with:

```sh
noisefence management-recovery-prepare --plan /private/recovery/prepare.json \
  --verify-worker-installation
```

This checks each configured local key file against the saved replacement and the
currently enabled PostgreSQL node identity. It retains all source locks, checks
private file permissions and size, rejects symbolic links, and rereads files under
the central authority lock. A successful verification writes one durable receipt
and audit event. Repeated verification rereads the files and checks current central
credentials even when that receipt already exists; it does not overwrite changed
keys or undo a revocation. A database error rolls back both the new receipt and its
audit event.

The result reports `worker_credentials_verified: true` with scope
`configured_local_files` and sets `worker_installation_required: false` for that
invocation. It verifies the paths in the supplied configurations, not deployment
to a different remote host or a running worker's in-memory token. The supervisor
must install and verify the actual worker configuration before starting it. This
flag does not install keys, change routes, clear recovery markers, or start services;
the overall status remains `prepared_not_activated`.

The caller must first fence **all original writers** and select the restored
PostgreSQL database. Locks on local copies do not establish a remote fence. The
method returns a preparation report, not an activation authorization: it retains
every recovery marker, starts no console or SMTP service, and does not redirect
workers. The promotion supervisor and final activation checks must still integrate
this operation, including worker credential installation and remaining history conflicts.

The native command is available for the offline supervisor:

```sh
noisefence management-recovery-prepare --plan /private/recovery/prepare.json
```

The JSON plan must be an owner-private regular file (0600), at most 64 KiB.
Run the command as the owner of the staged source directories. For example:

```json
{
  "protocol": "noisefence-management-recovery-plan-1",
  "operation": "<existing queue recovery operation UUID>",
  "database": {
    "instance": "<selected management instance UUID>",
    "source_digest": "<selected source digest>"
  },
  "source_configs": ["/private/recovery/mx1.toml", "/private/recovery/mx2.toml"],
  "credentials_file": "/private/recovery/secrets/administrator.json",
  "fences": [
    {
      "source": {"node": "mx1", "epoch": "<original source epoch UUID>"},
      "method": "provider-poweroff",
      "reference": "<verified provider operation reference>",
      "created": 0,
      "fenced": true
    },
    {
      "source": {"node": "mx2", "epoch": "<original source epoch UUID>"},
      "method": "systemd-persistent-condition",
      "reference": "<verified persistent service fence reference>",
      "created": 0,
      "fenced": true
    }
  ]
}
```

Replace every placeholder, including `created` with the actual verification time
in Unix seconds. Each fence must be no older than one hour and cover all original
writers, including background jobs. A stopped or unreachable service is insufficient
without a persistent fence. The command checks the attestation's freshness and
exact source epochs under the source locks; it cannot independently verify the
provider's power state or establish a remote service fence.

The coordinator configuration must explicitly name the **restored** PostgreSQL
endpoint. Never point it at the live original database. Every source configuration
must refer to its stopped recovery copy and retain its selected management backend.
The credential file's parent must already be an owner-private physical directory.
No passwords are accepted inline in the plan or printed in the preparation report.

Preparation has a 30-minute deadline. Its successful report has status
`prepared_not_activated` and includes a SHA-256 of the fencing attestation plan.
After an interruption, retain the same operation and saved credential file; refresh
expired fencing attestations only after independently rechecking the fences. A
successful preparation without an activation flag does not authorize console promotion or release a source's
startup fence. The Python promotion supervisor still requires protocol-2 integration.

### Authorizing the recovered console

Once worker keys are installed, the native command can authorize the private console:

```sh
noisefence management-recovery-prepare --plan /private/recovery/prepare.json \
  --activate-console
```

This flag implies `--verify-worker-installation`. It repeats the coordinated checks
with all source locks retained, validates the queue-recovery receipt and private
coordinator configuration, and requires the provider-budget hold. The coordinator
must listen for Web requests on loopback, have its SMTP listener set to loopback
port zero, and have no replication listener configured. The original MFA key,
installed policy and immutable provider credentials must still validate.

Authorization records the database and source identity, canonical installation
configuration digest, verified history inventory digests, policy recovery receipt
and worker-key installation receipt. PostgreSQL commits its receipt and audit event
first; the coordinator then publishes the exact receipt in SQLite with full durable
synchronization. A failure between these commits leaves startup blocked. An exact
retry completes local publication without creating a second authorization or audit
event. Conflicting local or central receipts are refused.

The result is `console_authorized_not_started`. Start **only** `serve-console` using
the same coordinator configuration. It checks the local receipt before opening the
store, then checks the matching PostgreSQL receipt and sealed MFA records under the
daemon lock before opening the Web socket. A missing central receipt, unavailable
authority, changed installation configuration, or mismatched local receipt prevents
startup. Web policy updates remain separate from this installation configuration.

The `management_recovery_required` marker is retained. The additional permanent
console-activation marker also prevents `serve` from starting SMTP on this recovery
copy, even if the pending marker is accidentally removed. Other sources remain
fenced; neither this command nor `serve-console` installs worker keys, changes the
proxy, redirects workers, resumes workers, or establishes remote fencing. The Python
promotion supervisor must still integrate those deployment operations before this
path can replace production promotion.

### Preparing history replay after recovery

Access recovery also revokes unfinished queue commands. A delayed worker execution
receipt remains recordable as a separate outcome; recovery does not falsely claim
that a command already executed by a worker was undone.

The same transaction records each source's identity, greatest known generation,
and greatest SMTP transcript ID, including tombstones. `recovery_replay_bounds`
reads these immutable values on retries, rather than following cursors that advance
during replay. A receipt without the transcript bound is refused; the bound must
never be inferred as zero from an older receipt.

With all writers fenced and daemon/calibration locks held, the supervisor can call
`recovery::outbox::requeue` against each matching selected source. It atomically
requeues retained owned metadata, SMTP traces and pending tombstones above both the
local journal and the recorded central floor. Mirrored history is excluded. Delivery
statuses, bodies, policy state, source identity and replication acknowledgements are
unchanged. Generation overflow or incomplete local history aborts the transaction.

In that same transaction, preparation advances the local transcript AUTOINCREMENT
allocator beyond all IDs known to the restored PostgreSQL snapshot, local history,
and pending log outbox. It preserves any higher local allocator on retries. This
prevents a new SMTP attempt from reusing an old or deleted transcript ID after
restoring an older SQLite snapshot. Invalid or exhausted allocators fail atomically;
this reservation does not repair collisions already present in the restored data.

The source records a durable operation receipt so replay preparation can resume
without erasing newer local changes or recreating acknowledged batches. Its scheduled
counts describe that original preparation, not the current remaining backlog. This
does not reconstruct history absent from all surviving copies or reconcile conflicting
log identities. Source parity, central ingestion, policy reconciliation and guarded
startup still have to complete before the recovery marker can be cleared.

### Verifying a recovered source against PostgreSQL

`Central::replay_recovered_source` acquires the local daemon and calibration locks,
checks the selected database and recorded recovery operation, prepares the outboxes,
and drains both metadata and SMTP traces through the existing bounded transport.
The offline supervisor must fence the original authority and all other writers
before invoking it. Local process locks alone do not fence a remote authority.

Each batch must be present at its exact source generation before local acknowledgement;
a superseding destination version is not silently accepted as successful recovery.
After draining, the method compares owned message IDs and transcript identities with
PostgreSQL, including when a retry starts with empty outboxes. Missing destination
records therefore fail verification even if local acknowledgements survived. This
is an inventory check, not a field-by-field content comparison or policy validation.

The operation has a 15-minute deadline and bounded batch and inventory counts.
Partial progress can resume with the same recovery operation. Delivered messages
remain delivered, mirrored records are excluded, and the startup recovery marker
remains set. An integration test exercises a locked source, multiple transcript
batches, an empty-outbox retry and destination record loss after acknowledgement.

Conflicting log identities, missing history and stale extra destination records
still require reconciliation. This primitive does not promote a console, clear
its recovery marker or authorize service startup.

### Reconciling installed policy after a database restore

`Central::reconcile_recovered_policy` handles the steady-state recovery case where
all selected MX copies contain the same completed authority journal and installed
policy. It holds each local daemon/calibration lock, verifies the recovery operation,
database and source identities, coordinator MFA key, model checksums and immutable
credential generation, and requires the complete enrolled participant set.

After access recovery, a PostgreSQL transaction checks that the saved and current
source sets still match. It can advance an older restored authority to the unanimous
installed journal. It refuses newer or conflicting destination journals, conflicting
revision contents, unfinished rollouts and missing or inconsistent policy heads.
A missing current revision is recorded with the recovery administrator as its actor;
its original approval history cannot be reconstructed from the installed bundle.

The transaction stores a durable operation receipt, advances the revision allocator,
clears obsolete proposal approvals and peer heartbeats, and records the recovery in
the audit log. Retrying the same operation verifies the destination again without
repeating those mutations. The activation timestamp is zero, identifying recovered
installation evidence rather than a new activation or peer heartbeat.

This does not distribute a policy to disagreeing nodes, rotate worker transport
credentials, reconcile provider budgets, clear startup markers or promote a console.
The supervisor must fence all original writers before calling it. Divergent or
partially committed rollouts require the coordinated recovery path before this
steady-state reconciliation can proceed.

## Remaining release gates

Before production activation, complete all management API, CLI and learning
repository routes; finish startup freshness integration and the fenced transport
cutover; and import and reconcile existing management records. No fallback to
stale SQLite authentication or management
writes is allowed after cutover.

Import checks must preserve account hashes, the external MFA encryption key,
recipient ownership, message IDs, diagnostic delivery IDs, annotations and
protected evaluation cohorts. Validate counts and content digests, API parity,
resource limits, PostgreSQL outage behavior, backups and restoration before
cutover.

After PostgreSQL accepts management writes, changing a binary symlink is not a
database rollback. Rollback requires fencing writers and reconciling those
writes into the restored backend. The final deployment procedure must include
this operation and its tests.

## Final destination activation primitive

`Central::activate_import` now provides the explicit destination commit for the
future offline cutover coordinator. It checks the source digest, complete node
set (including disabled workers), spool epochs, policy baseline, database identity,
schema and full imported row parity. It serializes activators and holds PostgreSQL
table locks while the caller durably installs every local selection. PostgreSQL
becomes active only after all matching selection receipts are returned; those
receipts are retained in the migration report. An already active receipt cannot
run source commits again.

This is a library primitive, not a supported production cutover command. Its
caller must retain source process locks and SQLite write reservations from capture
through local commits, validate installed artifacts and MFA material, and coordinate
configuration changes. A failed partial local commit leaves PostgreSQL inactive;
keep services stopped and recover the same authority. A lost destination commit
reply requires reading its existing receipt before recovery. Cross-process and
remote recovery orchestration remains a release gate.

The disposable PostgreSQL integration test uses two actual SQLite spools and
checks rejected source omissions, destination divergence, interruption after the
first durable local commit, missing final receipts, successful activation and
rejected reactivation. Runtime-bound connections remain unavailable before the
complete final commit. This does not establish production migration readiness.


The import and live management projection preserve legacy local delivery notices
identified as `dsn-<positive integer>`, including their public recipient IDs and
SMTP transcripts. This identifier is reserved for notifications marked `is_dsn`
with an empty envelope sender. Ordinary mail cannot use it. Runtime history also
preserves the notification flag, so legacy notices do not block cache updates.
UUID message identifiers remain unchanged; no migration renumbering is performed.


Parity comparison accounts for PostgreSQL's JSON representation of integral
floating-point columns (`50` versus `50.0`). This is exact numeric equivalence,
not approximate comparison: no epsilon, string conversion or integer-to-float
rounding is used. Adjacent large integer identifiers, fractional changes, missing
fields and array-order changes still fail verification. Mismatch diagnostics name
only the projected table and columns, never message contents or SQL arguments.
