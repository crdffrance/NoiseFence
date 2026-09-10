# Isolated Office analysis connector

`src/sandbox.rs` provides a working, opt-in CAPEv2 REST connector with its own
durable SQLite queue. The gateway hashes and transports attachment bytes; it
does not launch Office, interpret VBA, unpack documents, or execute attachments.
The separately operated CAPE installation supplies the actual analysis VM.

**Validation boundary:** automated tests exercise a local fake CAPEv2 HTTP
service and real SQLite persistence. No CAPE deployment, Windows/Office VM,
hypervisor confinement, snapshot reset, macro execution, malicious sample, or
production mail path has been exercised here. `provenance.isolation_verified`
is always false. Synthetic API tests do not establish detection effectiveness.

## Integration API (no additional dependencies)

`Config.sandbox: Option<sandbox::Settings>` is validated at startup.
The [durable SMTP pipeline](sandbox-pipeline.md) selects documents and records
intent with accepted mail; `sandbox_service` owns the client lifecycle and
periodic retention. The console exposes a recipient-authorized projection.
Existing reqwest, rusqlite, Tokio, serde, sha2, hex, uuid, libc and anyhow are used;
there is no Cargo feature or dependency change, and no shared-store migration.

```rust,ignore
// All Client methods below except new/enabled are async.
let client = sandbox::Client::new(settings)?; // local store only; no network
let job = client.enqueue_created_at(
    &original_message_sha256,
    decoded_attachment_bytes,
    sandbox::OfficeKind::Docm,
    sandbox::Disposition::ResearchOnly,
    primary_outbox_created_secs * 1000, // frozen original time, never retry time
).await?;

// Run periodically in an independent application worker, never in SMTP DATA.
let processed_count = client.tick().await?;
let current: Option<sandbox::Summary> = client.get(&job.job_id).await?;
let page: Vec<sandbox::Summary> = client.list(0, 100).await?;
// After persisting the terminal summary to the owner's audit/retention system:
client.remove(&job.job_id).await?;
```

Exact public methods:

| Method | Contract |
| --- | --- |
| `Settings::validate(&self) -> Result<()>` | Pure validation; no credentials read or network access. |
| `Settings::policy_sha256(&self) -> String` | Versioned settings identity excluding credential paths and local state location. |
| `Client::new(Settings) -> Result<Client>` | Opens a private spool and exclusive worker lock; clone this client for sharing. Disabled settings create no files. |
| `Client::enabled(&self) -> bool` | Whether this client can enqueue or contact CAPE. |
| `Client::policy_sha256(&self) -> Option<String>` | Actual opened client's policy; disabled clients return None. Check against the frozen outbox backend policy before enqueue or tick. |
| `enqueue_created_at(&self, message_sha256: &str, attachment: &[u8], kind: OfficeKind, disposition: Disposition, created_at_ms: i64) -> Result<Summary>` | Preferred outbox API: local persistence using original durable creation time; rejects expired/future intents. |
| `enqueue(&self, message_sha256: &str, attachment: &[u8], kind: OfficeKind, disposition: Disposition) -> Result<Summary>` | Legacy local enqueue. After retention first runs, recovers existing live tuples but refuses new tuples without an original creation timestamp. |
| `get(&self, job_id: &str) -> Result<Option<Summary>>` | Stored status/result; never raw bytes. |
| `list(&self, offset: usize, limit: usize) -> Result<Vec<Summary>>` | Up to 100 local summaries, insertion order; page on restart. |
| `tick(&self) -> Result<usize>` | One bounded background pass; returns number of jobs attempted. Concurrent ticks return zero while a pass runs. |
| `remove(&self, job_id: &str) -> Result<()>` | Removes a local terminal row only if no remote capacity reservation remains; does not delete CAPE artifacts. |
| `prune_before(&self, cutoff_ms: i64) -> Result<usize>` | Scrubs up to 100 expired rows, including unresolved jobs, retaining minimal remote reservation tombstones. Reused active client only; busy is an explicit error. |
| `Client::prune_local(state_dir: &Path, cutoff_ms: i64) -> Result<usize>` | Same bounded purge while backend is disabled/not opened; uses only the local path, with no HTTP client or credentials. An active Client's lock refuses it; an absent store is a no-op. |
| `tombstones(&self, offset: usize, limit: usize) -> Result<Vec<RemoteReservation>>` | Up to 100 minimal unresolved remote reservations; never samples, results or digests. |
| `acknowledge_remote_stopped(&self, job_id: &str) -> Result<()>` | Operator-only acknowledgement for a terminal job or retention tombstone whose remote slot is held. Call only after verifying **all** associated CAPE tasks are stopped/absent. Does not itself cancel remote work or release mail. |

`OfficeKind` has `Doc`, `Docx`, `Docm`, `Xls`, `Xlsx`, `Xlsm`, `Xlsb`, `Ppt`,
`Pptx`, `Pptm`; `from_extension(&str) -> Option<OfficeKind>` accepts these
extensions, case-insensitively. This dispatch is a package selection hint, not
document validation or a macro detector. Select parts with the existing MIME
parser under its own message/part limits; pass decoded bytes, not the full mail.
The connector does not receive subjects, recipients, original filenames or
message bodies. It computes the attachment SHA-256 itself. The caller supplies
the SHA-256 of the original RFC822 message and must preserve that original.

`Summary` exposes `version`, `job_id`, `message_sha256`, `attachment_sha256`,
`attachment_bytes`, `kind`, `disposition`, `status`, `outcome`, `detail`, `cape_malscore`,
`remote_task_id`, `remote_slot_held`, `remote_fanout`, timestamps in Unix milliseconds,
`requests`, bounded `findings`, `findings_total`, `findings_truncated`, and
`provenance`. `Summary::default()` is disabled; `Summary::validate()` verifies
the metadata shape. Diagnostic consumers should display these enum statuses
and bounded metadata, never derive a clean verdict from availability failures.

`Disposition::{ResearchOnly, Quarantine}` is recorded per job. ResearchOnly is
the default and has no delivery effect. `requires_quarantine()` remains true
for Quarantine jobs even after a no-findings report: this API **never authorizes
automatic release**. Quarantine is an integration intent, not a claim that the
connector has stored or held the message.

## SMTP and quarantine integration

Persist the original message/quarantine record with an intended sandbox action
first. Then call `enqueue`, persist the returned job ID against that record,
and let SMTP finish according to the configured quarantine or research policy.
No HTTP request or VM wait belongs on the SMTP path. Local enqueue completion
means SQLite committed the job and attachment bytes, not that analysis passed.
Queue-full, busy or disk failure must remain explicit/inconclusive. In quarantine
mode, keep the original held when enqueue fails; retry from the durable intent.

Enqueue deduplicates `(message SHA-256, attachment SHA-256, OfficeKind,
Disposition)` within this policy-bound store. This makes a crash between enqueue
and persisting the job ID recoverable by repeating enqueue. A cancelled enqueue
may still commit; repeating the tuple recovers the same ID. Identical attachment
bytes across unrelated messages get separate jobs. Same-message identical parts
share a job. The caller owns recipient/tenant authorization and links one result
to every relevant part; SHA-256 values and job IDs are not authorization tokens.

For the primary outbox, use `enqueue_created_at` with the original immutable
creation time in Unix milliseconds. That time becomes `Summary.created_at_ms`;
the analysis deadline is additionally capped at original creation plus 30 days.
Do not replace the timestamp with the current retry time. Live tuple
deduplication remains unchanged across a crash/restart, including terminal rows
until expiry. The pipeline must check `client.policy_sha256()` against its frozen
backend binding, and treat `get(None)` after expiry as inconclusive without
re-enqueueing. Confucius's pipeline has accepted this contract.

Start a loop after client construction, using a Tokio interval at
`settings.poll_interval_ms` and `MissedTickBehavior::Skip`, and await `tick()`.
Run independent clients only for independent stores; one client/store should
serve all local callers. The optional sandbox should remain disabled in offline
engine evaluation; offline evaluations should not spawn this network worker.
Persist per-job summaries in the gateway's existing evidence format if desired.
For multiple attachments, retain all job IDs and require the message digest to
match on every completion. No partial result releases a message.

The connector and quarantine database are separate durable stores. The ordering
above and idempotent enqueue form the reconciliation protocol; there is no
cross-database transaction. Preserve recovery mappings through handoff; at the
retention deadline expire the primary intent and scrub its result/mapping without
resubmission. A local retention deadline never permits quarantine release or
indicates that remote analysis stopped.

## Explicit local/on-prem configuration

Absence of `Config.sandbox` disables integration. `Settings::default()` also
sets `enabled = false`; neither default silently uploads anything. An example
for an operator-controlled service behind a loopback tunnel is:

```toml
[sandbox]
enabled = true
state_dir = "/var/lib/noisefence/sandbox"
endpoint = "http://127.0.0.1:8000/apiv2/"
token_file = "/etc/noisefence/cape.token"
instance_id = "cape-onprem-01"
environment_id = "office-snapshot-2026-09"
machine = "office-vm"
expected_version = "2.5"
request_timeout_ms = 3000
analysis_timeout_secs = 120
job_timeout_secs = 1800
poll_interval_ms = 15000
max_parallel = 1
max_attachment_bytes = 16777216
max_total_bytes = 134217728
max_jobs = 1000
max_response_bytes = 8388608
max_findings = 64
use_lite_report = false
```

For direct on-prem HTTPS use a literal RFC1918/IPv6 ULA address whose TLS
certificate contains that IP as a subject alternative name; set `ca_certificate`
to a PEM trust root if needed. Normal TLS verification remains enabled. Existing
application startup must install the Rustls ring provider, as it does for other
reqwest clients. Token files contain only the Django REST token; the connector
adds the `Token` authorization scheme. Restrict token and CA files to trusted
operators. Token contents are not part of settings Debug/serialization or the
state fingerprint, so credentials can rotate without migrating the queue.

URLs must end exactly in `/apiv2/`, with no userinfo, query or fragment. Public IPs,
DNS names, link-local addresses and non-loopback cleartext HTTP are rejected.
HTTP redirects and environment proxies are disabled, as are automatic HTTP
retries. Attachment-supplied URLs are never fetched. Restrict routing/firewall
rules to the intended on-prem service: a private IP or a loopback tunnel is a
destination restriction, not proof of the endpoint's ownership or location.

## CAPEv2 API and VM preparation

The implementation uses the current Django `/apiv2/` interface. CAPE's primary
[REST API guide](https://capev2.readthedocs.io/en/latest/usage/api.html) marks its
older `api.py` examples as deprecated and documents token authentication.
Routes and response shapes were checked against upstream
[apiv2 URLs](https://github.com/kevoreilly/CAPEv2/blob/master/web/apiv2/urls.py) and
[apiv2 views](https://github.com/kevoreilly/CAPEv2/blob/master/web/apiv2/views.py)
on 2026-09-10. Verify these contracts against the operator's pinned CAPE release.

| Operation | Wire contract |
| --- | --- |
| Submit | `POST /apiv2/tasks/create/file/`, multipart `file`, fixed `sample.<extension>`, explicit Office `package`, single `machine`, `platform=windows`, `timeout`, `route=drop`, unique `custom=noisefence:<job UUID>`. Accept exactly one positive `data.task_ids` integer. |
| Poll | `GET /apiv2/tasks/view/<id>/`; require `data.id`, `custom`, `category=file`, selected `package`, and `sample.sha256` to match. Read `data.status`; retain no raw task details. |
| Recover lost POST reply | `GET /apiv2/tasks/search/sha256/<sha256>/`; accept exactly one matching `custom`, ID, package, category and original sample digest. A hash alone is insufficient. |
| Report | `GET /apiv2/tasks/get/report/<id>/json/`; when explicitly configured, use `litereport/`. Require report `info.id`, `info.custom`, category, package, engine version and `target.file.sha256` binding. Never request an artifact archive. |

Enable CAPE `filecreate`, `taskview`, `tasksearch` (including SHA-256), and
`taskreport` API permissions for a dedicated operator account. The account also
needs report-download permission. Ensure that CAPE exposes the submitted
`custom` marker and original digest; rewritten/recovered tasks fail binding.
Configure API throttling for the poll frequency and number of tasks. A reported
task uses two reads in a pass (task plus report). Transient HTTP/API errors retry
only reads at the configured interval until the absolute job deadline.

The `static` field is omitted: CAPE's
[request parser](https://github.com/kevoreilly/CAPEv2/blob/master/lib/cuckoo/common/web_utils.py)
returns it as a string, so sending `static=0` can still select static extraction.
No custom analysis options or scripts are accepted from attachments or callers.

If `use_lite_report=true`, enable CAPE's `litereport` reporter and include
`info target signatures debug malscore` in its `keys_to_copy`. See the primary
[LiteReport implementation](https://github.com/kevoreilly/CAPEv2/blob/master/modules/reporting/litereport.py).
`litereport` returns JSON; CAPE's similarly named `lite` endpoint returns an
archive of potentially sensitive artifacts and is deliberately unused.
Oversized JSON reports fail explicitly; there is no fallback archive download.

Provision CAPE on a dedicated isolated host with an instrumented Windows/Office
VM, snapshots reset between tasks, licensed Office, and macro policy appropriate
to the operator's lab. Explicit `doc`, `xls` and `ppt` packages launch their Office
applications inside that VM; the
[Word package](https://github.com/kevoreilly/CAPEv2/blob/master/analyzer/windows/modules/packages/doc.py)
shows this execution boundary. Specifying a package and one machine avoids
generic archive unpacking/fanout; the
[demultiplexer](https://github.com/kevoreilly/CAPEv2/blob/master/lib/cuckoo/common/demux.py)
treats explicit packages separately. Preserve the original bytes rather than
silently substituting decrypted or extracted files.

Enforce VM CPU/memory/disk/runtime quotas and deny access to the gateway,
production networks and host mounts from the guest. `route=drop` asks CAPE for
no guest network routing; verify the actual result-server and firewall policy
separately. Disable offsite submission, reputation/cloud enrichment, external
reporting and sample sharing in CAPE and all its plugins. The gateway cannot
enforce CAPE-side behavior or guarantee snapshot cleanup. The connector's
`analysis_timeout_secs` is the requested CAPE runtime; enforce it server-side.
Disable automatic child-task submission/resubmission in CAPE reporting plugins
as well: connector capacity accounting covers its own submitted task IDs, and
cannot bound additional analyses independently created by the backend. Enforce
the deployment's aggregate VM/task quota on CAPE itself.
No VM isolation validation was available in this development environment.

## Durable states, binding and resource limits

The private `state_dir` contains `jobs.sqlite3` and `worker.lock`; use local
storage supporting SQLite fsync/locking, not NFS. The directory must be owned by
the service user with no group/other access; files are 0600, non-symlink, singly
linked. SQLite uses FULL synchronization, rollback journals and secure deletion.
The payload and job are committed together. Attachment blobs are cleared after
the first submission attempt or terminal expiry; raw reports never enter SQLite.
Secure deletion is not encrypted storage or guaranteed erasure from SSDs,
snapshots or backups; protect the spool and its backup lifecycle accordingly.

The store records a versioned settings fingerprint. A different backend,
environment label, VM or limit configuration cannot silently adopt its old jobs:
startup rejects a policy mismatch. Drain the old client/store before changing
policy and create a fresh state directory. Credentials may rotate. Hold the
worker lock for the entire lifetime of all Client clones/background passes.

| State | Meaning |
| --- | --- |
| `disabled` | No work or network. |
| `queued` | Attachment and digest binding durably stored locally. |
| `submitting` | Durable intent and remote capacity reservation committed before POST. On restart use reconciliation, never blind resubmission. |
| `uncertain` | Submission outcome unknown, or recovery cannot identify a unique matching task. Keep the reservation and retry search until expiry. |
| `submitted` | Remote task ID recorded; CAPE may still be pending/distributed. |
| `running` | CAPE reports execution in progress. |
| `reporting` | CAPE completed execution or its report is awaiting bounded retrieval. |
| `complete` | Bound report parsed; inspect `outcome` and `detail`, including incomplete processing and truncated findings. |
| `failed` | Binding/protocol/size rejection or explicit CAPE failure; inconclusive. |
| `timed_out` | Absolute local deadline expired; inconclusive. This is not proof of remote cancellation. |

`max_parallel` limits reserved remote tasks (including pending and uncertain)
and concurrent work items in a pass. A pass may issue two sequential requests
for a reported task. No semaphore wait is added to SMTP; concurrent enqueue
capacity fails busy before copying bytes. Concurrent ticks do not overlap. If a
tick waiter is cancelled, its one bounded pass continues holding the lock until
its tasks and state commits finish; a process crash leaves durable intentions.

`max_attachment_bytes` caps each input; `max_total_bytes` caps retained attachment
blobs; `max_jobs` caps all rows, including results. Queue-full never evicts active
work. Per-request bytes are checked both through Content-Length and incremental
body reads; compressed responses are rejected. Each request has a deadline
bounded by the remaining absolute job time. `max_findings` caps returned entries.
SQLite additionally caps main-file pages to a conservative budget of
`2 * max_total_bytes + 65536 * max_jobs + 16 MiB`; rollback journaling temporarily
adds disk overhead. Use an OS filesystem quota for a hard aggregate disk limit.

An uncertain POST cannot be made exactly-once against CAPE's non-idempotent
create API. This connector makes at most one POST attempt per job. Recovery
search may find no task even though a delayed submission later appears, so it
does not recycle that capacity slot automatically. After local expiry or an
unbound task failure, inspect CAPE out of band and call
`acknowledge_remote_stopped` only after verifying all tasks for the custom marker
are stopped or absent. A multiple-task response is a contract violation and
stops further local admission while its unresolved reservation remains; the
connector cannot undo fanout already performed by a misconfigured server.
Normal bound `reported`/failure statuses release capacity. Neither local expiry
nor pruning deletes remote samples/reports; apply a separate CAPE retention policy.

## Local retention and remote reservations

Local request blobs, original-message and sample digests, deduplication digests,
findings, score, report digest and per-job provenance must be scrubbed within the
configured retention period, which cannot exceed 30 days. Call `prune_before`
periodically on the reused client, or `Client::prune_local` with the dedicated
state directory when the backend is disabled. These functions reject future or
negative cutoffs and use the later of the requested cutoff and now minus 30 days.
They scrub jobs whose original `created_at_ms` is at or before that cutoff,
regardless of completion status. `PRUNE_BATCH_SIZE` is 100; repeat bounded calls
until a call returns zero and monitor cleanup errors/backlogs. Disabling the
backend does not run cleanup by itself; `sandbox_service` continues calling the local-only function while the disabled
configuration retains its state directory. No software can guarantee erasure
while its storage is offline or cleanup is not running.

The cutoff is monotonically persisted in the same SQLite transaction as each
scrub batch. Expired rows are invisible to `get`/`list` and skipped by `tick`,
including between batches. The entire payload/summary/dedup row is removed using
SQLite secure deletion. This remains a logical local purge, not a guarantee of
erasure from snapshots/backups/SSD history; apply the same retention to those.
The store's global version/policy fingerprint and monotonic cutoff remain so a
different backend cannot adopt unresolved reservations.

For an unresolved remote reservation, the only per-job fields retained are
`RemoteReservation { job_id, remote_task_id, remote_fanout }`. The UUID reconstructs
the CAPE `custom` marker; unknown task IDs remain None. No sample/message digest,
dedup commitment, result or per-job provenance remains. These technical
correlation identifiers are still operator-only metadata; do not expose them as
public authorization credentials. Normal settled rows leave no tombstone.
Tombstones continue counting against `max_parallel`, and a fanout tombstone
continues stopping new admission. They are never polled: the digests needed to
bind a new response have been erased. Only explicit operator acknowledgement
after independent verification removes an unresolved reservation. Pruning does
not acknowledge completion, issue a CAPE delete/cancel request or release mail.

Erasing deduplication digests means an un-timestamped tuple cannot distinguish an
old replay from a new intent. Consequently, after the first purge transaction,
legacy `enqueue` only recovers existing live jobs; new jobs must use
`enqueue_created_at`. That API rejects original creation times at/before the
persisted cutoff (and times older than 30 days or in the future), including after
restart. An expired outbox must never supply a freshly invented timestamp. A
deliberately new outbox with a later original creation time may create a new job.
Manual `remove` does not establish a retention cutoff; use the purge APIs for
automated retention and finish primary recovery obligations before manual removal.

The active client's pruning takes the same lock as `tick`; busy errors leave data
untouched and require retry. Cancellation of a pruning waiter does not release
that lock before its database transaction finishes. `prune_local` uses the
process lock, reads no backend configuration or token, and creates no absent
spool. This path can clean the store with the backend disabled even if credentials
are absent or its old endpoint is no longer available. Remote CAPE artifacts and
their retention policy remain separate, operator-controlled deployment work.

## Findings and interpretation

`Outcome::{Inconclusive, NoFindings, Findings}` is advisory. `NoFindings` means
the bound report contained no signatures; it does **not** mean the document is
safe, that a macro was present, or that all triggers ran. Processing errors,
missing execution metadata, malformed reports and output truncation remain
inconclusive. No classifier threshold or SMTP score is changed by this module.

`cape_malscore` preserves CAPE's optional top-level `malscore` as backend metadata,
validated to 0–10; missing/null means unavailable. It is neither a probability nor
a gateway verdict. CAPE separately emits signature severity/weight/confidence and
may emit `malstatus`; for non-executable files its generic score need not come with
a category. See upstream [signature output](https://github.com/kevoreilly/CAPEv2/blob/master/lib/cuckoo/common/abstracts.py),
[score calculation](https://github.com/kevoreilly/CAPEv2/blob/master/lib/cuckoo/common/scoring.py)
and [report fields](https://github.com/kevoreilly/CAPEv2/blob/master/lib/cuckoo/core/plugins.py).
The connector does not copy `malstatus`, infer a malware category from an individual
signature weight, or use the aggregate score to alter `Outcome` or quarantine.
`NoFindings` describes the signature list only, even if an aggregate score exists.
Malformed scores fail inconclusively. Earlier summaries without the optional field
remain readable.

Each finding contains only the CAPE signature identifier (ASCII letters/digits,
dot, underscore or hyphen, maximum 128 bytes), severity 0–5 and confidence 0–100.
Descriptions, marks, extracted VBA, raw IOCs, filenames, screenshots, files,
network captures and command lines are discarded. Provenance contains the
operator's instance/environment IDs, policy digest, reported engine version,
optional reported commit hash and SHA-256 of canonical parsed report JSON.
That last digest identifies the parsed report, not the original HTTP byte stream.
Engine/machine metadata comes from the configured backend; it is not independent
attestation. All failure details exposed by the connector are fixed enums.

## Tests and deployment verification

Run `cargo test --offline --test sandbox` after shared modules compile. The test
file imports the owned module directly so it does not require a `lib.rs` change.
Tests create a fake HTTP service on `127.0.0.1` and temporary stores, using
synthetic text bytes; they never submit the user's attachments or contact an
existing sandbox. Coverage includes restart before/after submission, uncertain
intent recovery, status polling, digest/task/backend mismatch, queue and byte
limits, concurrency, deadlines, failures, redacted findings, retention, policy
binding and quarantine intent. A temporary standalone Cargo harness can run the
same test file while unrelated shared modules are unfinished.

Development verification on 2026-09-10: **29/29 local fake-service tests passed**
through a temporary standalone harness using the repository's dependency versions;
the focused Clippy run passed with `-D warnings`. The initial repository-wide test
invocation was blocked by unfinished shared modules being edited concurrently.
Additional adversarial cases cover unexpected multi-task fanout, foreign jobs
with the same digest, redirect refusal, chunked response overflow, stalled bodies,
compressed responses, unsafe spool permissions/symlinks, optional CAPE score
validation/persistence, backward-compatible summary decoding, and no automatic
classification from scores, individual weights or backend categories. Retention
tests cover bounded batches, disabled cleanup, future cutoff rejection, original
outbox timestamps, stale replay rejection, restart, physical SQLite-page checks
for scrubbed data, unresolved capacity/fanout tombstones and poll/prune exclusion.
These results cover
the connector contract; they are not a claim of SMTP wiring or actual VM testing.

## Separate deployment validation record (not performed)

The operator must keep a separate deployment validation record; these fake-service
test results must not be presented as that record. Identify the deployment,
CAPE commit/configuration fingerprint, VM snapshot/image, Office build and macro
policy, validation date, operator, expected observations and captured evidence.
This connector's `isolation_verified=false` remains unchanged by fake-service tests.

Before enabling real delivery effects, the operator must separately validate
the pinned CAPE API, harmless lab Office fixtures with expected macro execution,
no-macro and trigger-dependent cases, guest network denial, inability to reach
gateway/production services, forced timeout, VM reset, remote retention and
restart/ambiguous-submission reconciliation. Record that deployment evidence
separately from these fake-service tests. No production settings were changed.
