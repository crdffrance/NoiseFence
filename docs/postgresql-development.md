# PostgreSQL management migration: development status

The PostgreSQL backend is under development. The released daemon still uses
SQLite. Do not change production database settings or remove the SQLite file:
there is no supported production cutover command yet.

The intended split keeps message bodies, delivery leases, recipient progress and
mandatory two-copy acknowledgements on each MX. PostgreSQL will own console
accounts, permissions, policies, searchable history and learning annotations.
Message acceptance must never wait for a central database transaction.

## Implemented foundations

- Lazy connection pools with separate interactive and ingestion capacity.
  Unix sockets are supported; remote connections require certificate-verified
  TLS. The plaintext exception accepts numeric loopback addresses only.
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
production configuration and cutover are not enabled yet. Quality workflows,
model catalog administration and other administrative operations still need
their central routing. Policy membership reconciliation, incident presentation,
import of existing activation epochs and startup authority checks remain open.
The installer still needs to select the new transport under a durable backend
fence. Do not set internal SQLite transport flags manually. New-node enrollment,
membership changes and old-journal reconciliation remain migration work.

An ingestion batch contains at most twelve events and three MiB. Each SQL
statement has a three-second server timeout, lock waits are limited to 500 ms,
and ingestion has a fifteen-second overall deadline. A failed batch remains
in the local journal. No SQLite writer is held during PostgreSQL calls.

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
remains a release gate, as do the complete-population audit exporter, remaining
periodic training consumers and historical metadata import.

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
NOISEFENCE_TEST_PG_PASSWORD_FILE=/absolute/private/test-password \
  cargo test --locked --test central_postgres --test central_console \
    --test central_search --test central_logs --test central_commands \
    --test central_policies --test central_transport --test central_quality --test central_adaptive --test central_research --test central_learning --test central_research_worker -- --ignored
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
