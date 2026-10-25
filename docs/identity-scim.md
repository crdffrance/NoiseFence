# SCIM provisioning: development profile

**Status: protocol, durable staging and bearer-verification components implemented.**
This branch does not yet expose a SCIM HTTP endpoint or an administrator enrollment
and inventory-review workflow. Do not configure an identity provider to send
provisioning traffic yet. No live Entra/Okta SCIM interoperability is claimed.
The existing [correspondent memory](contact-learning.md) works independently of
this connector.

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

These are library behaviors, **not currently advertised HTTP capabilities**.
General boolean filters, sorting, attribute projection, bulk requests, schema
extensions, password changes and arbitrary PATCH expressions are unsupported.
The future discovery endpoints must accurately describe this restricted profile.

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
to policy review, the repository must recheck the same revision. This detects a
change since review and avoids presenting a partial provider run as a full census.
The primitive does not itself record or authorize that attestation.

## Durable repository and provisioning access

SQLite and selected PostgreSQL use the same transaction algorithm. Each request
checks its source, enrollment generation, current owner authorization and expiry
inside the transaction, then checks authorization again before commit. PostgreSQL
requests share the management mutation lock with revocation and account changes;
SQLite uses an immediate transaction on a blocking worker. SMTP does not acquire
these locks. When PostgreSQL is selected, an outage fails the operation instead of
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
transaction. This repository limit is not a substitute for the HTTP admission,
unauthenticated-request and body-reading limits still required before exposure.

The bearer component generates 256 random bits and binds each token to a new
server-generated enrollment UUID. The token has no logging/serialization interface;
only explicit issuance can disclose its value. Durable storage retains an encrypted
verifier, never the bearer. Constant-time verifier comparison, the existing vault's
source/installation binding, current administrator account version, generation and
expiry all gate access. The maximum lifetime is 90 days. Rotation and revocation
invalidate the old access; a missing vault key never creates a replacement.

These are internal components, **not an enrollment API**. The generic saved-access
endpoint rejects SCIM credentials, and SCIM access cannot authorize an outbound
collection schedule. The dedicated administrator enrollment flow must issue and
display the bearer once; provider-supplied tokens must not be accepted there.

Administrative inventory reads require a current authorized session and a live
connection. They return a consistent revision and validate resource/edge accounting.
They do not attest completeness, activate a catalog or change filtering. The
controller must still connect that revision to explicit attestation and reviewed
publication without allowing a provisioning update to invalidate the reviewed data.

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

Before enabling provisioning:

1. Add authenticated HTTPS routes and accurate service/schema discovery, capacity
   and time bounds, and safe proxy limits. Authenticate before reading a potentially
   large body. Never log a token or provisioning payload.
2. Add the authorized server-generated enrollment, one-time disclosure, rotation,
   revocation and status flows to the Web interface.
3. Provide stage counts, freshness, explicit inventory attestation, exact candidate
   diff and reviewed activation with a revision recheck. Provisioning alone must
   not activate a catalog or change SMTP acceptance or scoring.
4. Qualify real provider mappings and retries, large directories, interrupted
   transactions, backup/restore, migration and two-MX publication.

Do not enable a `ServiceProviderConfig` feature merely because its protocol
primitive passes a unit test. The entire authenticated persistence and review
path must pass its integration checks first. No production setting, model,
threshold, provider connection or access token is changed by this increment.

## References

The profile is based on the [SCIM core schema (RFC 7643)](https://www.rfc-editor.org/rfc/rfc7643.html)
and [SCIM protocol (RFC 7644)](https://www.rfc-editor.org/rfc/rfc7644.html).
Microsoft's [SCIM endpoint guidance](https://learn.microsoft.com/en-us/entra/identity/app-provisioning/use-scim-to-provision-users-and-groups)
is an interoperability reference, not evidence that this implementation has
passed a live provider test.
