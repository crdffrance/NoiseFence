# SCIM provisioning: development profile

**Status: authenticated HTTP provisioning, durable staging, Web enrollment and
explicit inventory review are implemented in the development branch.** Use
synthetic qualification data only; do not connect a production identity provider
yet. No live Entra/Okta SCIM interoperability is claimed.
The existing [correspondent memory](contact-learning.md) works independently of
this connector and requires no directory enrollment.

The implemented Rust module is `src/identity/scim`. It prepares bounded,
source-scoped identity data for the existing directory review workflow. It has
no network client, SMTP dependency, mailbox-routing authority or console-login
provisioning. Its API deliberately separates a valid resource, a staged inventory
and a reviewed runtime catalog.

## Identity mapping

| Provisioned data | Directory meaning |
| --- | --- |
| Server-generated UUID | Stable resource ID within the enrolled source |
| `userName` | Login identifier for matching and uniqueness; never an email alias |
| `emails[].value` | Explicit mailbox assignment; domain canonicalized, local-part case preserved |
| `displayName`, formatted name or given/family names | Display identity; not proof of authentication |
| User `active` | Explicit active/inactive state; absent or null means unknown |
| Group `displayName` | Group label; an address-shaped label does not create a mailing list |
| Group `members[].value` and `type` | Source-local reference to a User or Group; references must resolve before candidate preparation |
| `externalId` | Client-provided, case-exact identifier scoped to the source; not a server-enforced unique key |

Groups have no standardized active attribute in this profile and retain unknown
activity. A reference URL or display hint never grants access, changes scope or
triggers a fetch. Provider data cannot create protected roles, sending delegations,
shared-mailbox semantics or supplier trust. Existing local protections must be
preserved through the normal collected-directory review, not overwritten by a
provisioning payload.

The initial profile accepts visible ASCII `userName` values, compared without
ASCII case distinctions. Names and explicit addresses may contain supported
international characters. Wider international login identifiers require a
qualified PRECIS implementation; arbitrary Unicode lowercasing is insufficient.
This restriction must be disclosed in provider attribute mappings.

## Implemented protocol behavior

- Case-insensitive attribute names; exact and case-variant duplicate JSON keys
  are rejected, including nested keys. Schema URIs retain their case.
- User and Group create/replace resource validation with server-generated IDs,
  creation/modification timestamps and version tokens. Input `id`, `meta` and
  read-only User `groups` cannot assign server state.
- Atomic ordered PATCH drafts. A failed operation returns no changed resource.
  Add, replace and remove support the documented writable attributes, name
  subattributes, email value/type selectors and group-member value selectors.
- Primary email changes clear other primary flags. Adding an existing member
  is idempotent. Email additions merge explicit attributes for an existing exact
  canonical address. A selected membership is changed through remove/add rather
  than silently replacing its immutable value.
- Whole-resource replacement clears omitted optional writable attributes.
  Required login/group names cannot be removed. Unknown attributes, unsupported
  paths and extensions fail explicitly; passwords, roles and entitlements are
  not accepted.
- Optional exact version preconditions and `*` existence preconditions; stale
  versions fail. A successful no-op preserves its version and modification time.
  A backward mutation clock is refused.
- One equality filter for `id`, `externalId`, `displayName`, or User `userName`
  and `active`. Unsupported expressions are errors, not ignored filters.
- One-based bounded pagination, count-zero totals and explicit rejection of
  duplicate/unsupported query parameters. Negative counts become zero and
  start indices below one become one.

General boolean filters, sorting, attribute projection, bulk requests, schema
extensions, password changes and arbitrary PATCH expressions are unsupported.
Authenticated discovery describes this restricted profile; it is not a claim of
complete SCIM conformance.

## Management console and one-time access

In **Administration → Filters → Identity protection → Directory synchronization**,
choose **Set up SCIM provisioning**. Supply a stable source ID, display name, provider
tenant identifier and explicit receiving-domain scope. Choose a lifetime of 1–90
days and a directory freshness limit. These assignments remain fixed on rotation.
Review the grant before issuing it. Existing administrator, MFA, Origin/CSRF,
configuration revision and saved-generation checks apply on the server.

The response contains a configured HTTPS base URL and one server-generated bearer
token. The console masks it initially and keeps it only in component memory. Copy
it into the intended provider; closing the view discards it. No browser storage,
policy snapshot or status response contains this token. **Rotate provisioning
token** immediately invalidates the previous token while preserving staged users
and groups. **Revoke access** stops future authorized requests. Neither operation
deletes the installed identity catalog or changes filtering.

If the issuance response is lost, the access may already exist. Reload saved access,
then rotate its current generation explicitly. The console disables replay from
the uncertain form. It cannot recover the old bearer from its encrypted verifier.
The generic saved-credential endpoint refuses caller-supplied SCIM credentials.

## HTTP profile

Base URL: `https://<configured-console-origin>/scim/<source-id>/v2` on the management
server. Worker-only routers expose no provisioning service. The source ID must be
1–100 ASCII letters, digits, underscores or hyphens and start with a letter or
digit. URLs are derived from the configured public HTTPS origin, never Host,
Forwarded or provider-supplied reference headers. Explicit loopback development
may use `http://127.0.0.1:<port>`.

Send one `Authorization: Bearer <token>` header. Console cookies cannot authorize
provisioning. The source, owner, expiry and generation are checked before reading
the body and again inside the transaction. JSON writes accept `application/scim+json`
or `application/json`, with optional UTF-8 charset. Compressed bodies are refused.
Responses use SCIM JSON, `Cache-Control: no-store` and constant error explanations.

| Endpoint | Methods |
| --- | --- |
| `/Users`, `/Groups` | GET, HEAD, POST |
| `/Users/{id}`, `/Groups/{id}` | GET, HEAD, PUT, PATCH, DELETE |
| `/ServiceProviderConfig` | GET, HEAD |
| `/ResourceTypes`, `/ResourceTypes/{User,Group}` | GET, HEAD |
| `/Schemas`, `/Schemas/{schema-URN}` | GET, HEAD |

Create returns 201 with Location and ETag; reads and updates return 200; deletion
returns 204. Exact version or `*` If-Match preconditions guard item mutations;
stale versions return 412. Item GET/HEAD supports If-None-Match and 304. ETag lists
are outside this profile. Unsupported methods return 405 with Allow. Duplicate or
unsupported query parameters, invalid UTF-8 and malformed escaping fail explicitly.
Discovery advertises PATCH, restricted equality filtering and ETags; bulk, sorting
and password changes are disabled. `.search`, `/Me`, attribute projection, general
boolean filters and schema extensions are not implemented.

Read the resource after a lost or uncertain write response before retrying.
`externalId` is not a unique idempotency key; a repeated POST can create a duplicate.
Use source-scoped matching and exact version preconditions when reconciling state.

## Transport and execution bounds

- Four concurrent provisioning tasks and a fixed global window of 1,200 admission
  attempts per minute, including unauthenticated attempts. Admission state has no
  unbounded map keyed by attacker-controlled addresses. Exhaustion returns 429
  with Retry-After. Console enrollment uses separate administrator capacity.
- Body limit 1 MiB and body-read deadline 10 seconds; query limit 4 KiB and three
  parameters. Disconnected requests retain their capacity until the work finishes.
- Each storage operation has a 10-second deadline. SQLite runs on a dedicated
  blocking connection with a 250 ms busy timeout, interrupt on expiry and a
  pre-commit deadline check. Completion is awaited after interrupt: this is not a
  hard upper bound on uninterruptible operating-system I/O. PostgreSQL also applies
  its pool, statement and lock timeouts. SMTP does not await a provisioning request,
  although both can still compete for disk or database resources.
- Reverse proxy templates admit 1 MiB only under `/scim/`; ordinary console limits
  remain narrower. Nginx disables request buffering and access logs for that path.
  Keep provisioning query strings, Authorization headers and bodies out of any
  additional operator-managed tracing or access logs.

## Bounds and candidate integrity

A request is limited to 1 MiB, 12 JSON nesting levels, 100 PATCH operations,
32 email aliases per user and 4,096 members per group. A list page has at most
100 resources. Errors contain constant explanations rather than provider values.

A candidate also enforces the existing directory caps: 20,000 people, 5,000
groups, 100,000 membership edges and a 16 MiB serialized snapshot. Source-bound
resource encoding is limited to 1 MiB plus record overhead; total staged bytes
examined during candidate preparation are capped at 64 MiB. Repository admission
enforces resource and membership limits before committing a mutation. Its 64 MiB
reservation counts the exact stored base-record bytes plus 128 bytes per membership
edge; this is an admission budget, not a bound on physical database, index or WAL
disk usage. Candidate preparation independently enforces its serialized limits.

Every stored resource is bound to the full immutable source configuration digest,
not just its visible source ID. A changed authority with the same ID cannot reuse
it. Candidate preparation rejects duplicate resource IDs, conflicting login names,
missing or wrong-kind references, self-membership, cycles and cross-source data.
Deleting a User or Group removes its outgoing and incoming membership references
and advances affected group versions in the same transaction. References to unknown
resources or to the wrong resource kind are rejected during writes. A staged cycle
can temporarily exist while provisioning is in progress, but cannot become a runtime
candidate.

A SCIM stream does not prove that the provider completed a full synchronization.
Candidate preparation therefore requires an **explicit administrator attestation**
of the staged inventory, bound to its source, enrollment generation, sequence and
content digest. The attestation time is not inferred from the last PATCH. It must
be current and no earlier than any included mutation. Before handing the candidate
to policy review, the repository rechecks the same revision in the transaction
that publishes the preparation receipt. A concurrent update invalidates the job;
its data is never silently added to the displayed candidate. An administrator
attestation is a human assertion, not independent proof that a provider exposed
all objects or had sufficient permissions.

## Review the staged inventory

In **Administration → Filters → Identity protection → Directory synchronization**:

1. Find the SCIM source under **Saved directory access** and select **Review staged
   inventory**, then **Load current inventory**. Counts and the last staged change
   are shown separately from active-directory freshness. Inspect/search people,
   groups and memberships; tables display 50 records per page. A malformed or
   cyclic graph prevents preparation. Merely loading this view attests nothing.
2. Compare the inventory with the provider's completed provisioning job. Explicitly
   confirm it contains the complete intended set, including removals. NoiseFence
   does not infer completion from the most recent PATCH, a quiet period or counts.
3. Review the confirmation, then select **Attest and prepare candidate**. The
   request binds the exact source, enrollment generation, staged sequence, content
   SHA-256 and current policy revision. The server records the attestation time
   and a durable preparation intent before writing an immutable catalog artifact.
4. Inspect the preparation receipt. Review the normal directory diff, including
   deletions, disabled identities and protected-role changes. Surviving identities
   retain administrator-owned protections and delegations. Provisioning cannot
   supply or overwrite those assignments. **Add to draft**, then use the normal
   **Review and apply** policy workflow; preparation alone is not activation.

Both selected backends check current administrator authorization and the SCIM
access generation at intent and result publication. Rotation, expiry or revocation
prevents a new ready result. A staged mutation during preparation produces a stale
failure. After a candidate is ready, later provisioning does not rewrite its
artifact: to include newer records, load and attest a new inventory. Normal policy
revision checks still protect activation. Revoking provisioning access does not
retroactively delete an already reviewed artifact or an installed directory.

The Web client records only the operation UUID in session storage, before sending
the attestation. A lost response must be resolved through the preparation receipt;
it is never automatically replayed. Reusing a completed operation ID is refused.
After a controller restart an unfinished job is shown as outcome unknown, not as
successful. Jobs share existing bounded admission (two active, one per source,
20 per hour), the six-minute lease and retention of the directory sync journal.
Receipts contain provenance, hashes and summary counts, not raw identities or
bearer tokens. Inventory views are administrator-only; no user or mailbox grant
is derived from SCIM data.

## Durable repository and provisioning access

SQLite and selected PostgreSQL use the same transaction algorithm. Each request
checks its source, enrollment generation, current owner authorization and expiry
inside the transaction, then checks authorization again before commit. PostgreSQL
requests share the management mutation lock with revocation and account changes;
SQLite uses an immediate transaction on a dedicated blocking connection, without
locking the SMTP writer mutex. Writes still share the underlying SQLite database. When PostgreSQL is selected, an outage fails the operation instead of
reading or writing a local shadow.

Resources are stored individually, with indexed source-scoped identifiers and
normalized membership references. Group updates write membership differences in
bounded batches. A rename does not rebuild the group's membership. Login uniqueness,
reference validity, counters and revision changes commit together. Concurrent writes
with the same version precondition cannot both succeed. Deletion also updates every
referencing group version atomically. Rotation preserves staged data while changing
the enrollment generation used by inventory reviews.

The repository currently admits 600 authenticated operations per source per
60-second window. Rejected resource mutations still consume that allowance while
all partial resource changes are rolled back. Infrastructure errors abort the whole
transaction. Pre-body authorization does not consume this source quota; the actual operation
charges it once. The separate transport limit also bounds anonymous requests.

The bearer component generates 256 random bits and binds each token to a new
server-generated enrollment UUID. The token has no logging/serialization interface;
only explicit issuance can disclose its value. Durable storage retains an encrypted
verifier, never the bearer. Constant-time verifier comparison, the existing vault's
source/installation binding, current administrator account version, generation and
expiry all gate access. The maximum lifetime is 90 days. Rotation and revocation
invalidate the old access; a missing vault key never creates a replacement.

The dedicated enrollment endpoint generates the bearer on the server; status
returns metadata only. The generic saved-access endpoint rejects SCIM credentials.
SCIM access cannot authorize an outbound collection schedule.

Administrative inventory reads require a current authorized session and a live
connection. They return a consistent revision and validate resource/edge accounting.
They do not attest completeness, activate a catalog or change filtering.
Attestation is a separate administrator POST with Origin/CSRF checks before its
bounded body is read. Both inventory loading and attestation use the console's
separate two-operation capacity, not SMTP analysis workers.

The new storage component has its own immutable SQL checksum. An unknown version
or changed checksum refuses operation. Offline account migration refuses existing
directory connection records, including SCIM, rather than silently dropping staged
identities or rebinding encrypted access. A populated PostgreSQL SCIM repository is
not an empty import destination. Credential migration, downgrade compatibility and
production backup/restore qualification remain release gates; follow the
[directory vault guidance](directory-credential-storage.md#migration-backup-and-restore).

## Validation and remaining integration

The shared behavioral suite runs against SQLite and a disposable real PostgreSQL
instance. It covers source isolation, indexed matching, atomic PATCH failure,
concurrent version preconditions, membership changes and pruning, restart, rotation,
revocation, owner authorization, quotas and rate accounting. Additional checks cover
missing keys, schema tampering, selected-backend outages and refusal to silently
lose credentials during account migration. These synthetic tests do not establish
live provider compatibility, high-volume latency or production recovery readiness.

Before connecting a production provider:

1. Qualify real provider mappings and retries, large directories and interrupted
   transactions with the intended provider and tenant permissions.
2. Qualify backup/restore, migration and the exact release's two-MX publication.
   Provisioning and attestation alone must not activate a catalog or change SMTP
   acceptance or scoring.

The shared HTTP suite covers administrator enrollment, one-time disclosure,
source-token isolation, discovery, conditional requests and safe public URLs on
both selected backends. Additional SQLite HTTP tests exercise authorization before
body read, concurrent revocation, timeouts and cancellation capacity. Proxy and
console fixtures use synthetic data.
The review suite exercises role/CSRF checks, explicit completeness, changed
inventories and digests, lost-response receipt recovery, frozen candidates,
rotation and inactive policy on both backends. A deterministic concurrency fixture
also changes staging between preparation and result publication. These tests do
not replace live-provider and release-lifecycle qualification.
No production provider, access token, model or threshold is changed by this work.

## References

The profile is based on the [SCIM core schema (RFC 7643)](https://www.rfc-editor.org/rfc/rfc7643.html)
and [SCIM protocol (RFC 7644)](https://www.rfc-editor.org/rfc/rfc7644.html).
Microsoft's [SCIM endpoint guidance](https://learn.microsoft.com/en-us/entra/identity/app-provisioning/use-scim-to-provision-users-and-groups)
is an interoperability reference, not evidence that this implementation has
passed a live provider test.
