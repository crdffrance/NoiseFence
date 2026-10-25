# SCIM provisioning: development profile

**Status: protocol and candidate-validation primitives only.** This branch does
not expose a SCIM HTTP endpoint, issue provisioning tokens or save SCIM resources
in the selected management database. Do not configure an identity provider to
send provisioning traffic yet. No live Entra/Okta SCIM interoperability is claimed.
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
examined during candidate preparation are capped at 64 MiB. Admission in the
future repository must enforce these quotas before durable acknowledgement.

Every stored resource is bound to the full immutable source configuration digest,
not just its visible source ID. A changed authority with the same ID cannot reuse
it. Candidate preparation rejects duplicate resource IDs, conflicting login names,
missing or wrong-kind references, self-membership, cycles and cross-source data.
User deletion has a reference-removal primitive that advances affected group
versions; the repository must commit these changes with the deletion atomically.

A SCIM stream does not prove that the provider completed a full synchronization.
Candidate preparation therefore requires an **explicit administrator attestation**
of the staged inventory, bound to its source, enrollment generation, sequence and
content digest. The attestation time is not inferred from the last PATCH. It must
be current and no earlier than any included mutation. Before handing the candidate
to policy review, the repository must recheck the same revision. This detects a
change since review and avoids presenting a partial provider run as a full census.
The primitive does not itself record or authorize that attestation.

## Required before enabling provisioning

1. Implement per-resource durable staging in both SQLite and selected PostgreSQL,
   with source-local transactions, normalized membership references, uniqueness
   checks, quotas and restart tests. Never fall back to a local shadow when
   PostgreSQL is selected. Avoid rewriting a whole directory for every PATCH.
2. Enroll expiring, source-scoped, high-entropy bearer access through an authorized
   administrator flow. Display it once, retain only a verifier, bind it to the
   installation and current owner authorization, support rotation/revocation,
   and recheck authorization inside every transaction.
3. Add authenticated HTTPS routes, service/schema discovery, request capacity and
   time bounds, per-source rate limits and safe proxy limits. Authenticate before
   reading a potentially large body. Never log a token or provisioning payload.
4. Provide Web status, stage counts, freshness, explicit inventory attestation,
   exact candidate diff and reviewed activation. Provisioning alone must not
   activate a catalog or change SMTP acceptance or scoring.
5. Qualify real provider mappings and retry semantics, concurrent updates and
   rotation, stale preconditions, interrupted transactions, source/tenant
   isolation, deletion/cycle behavior, backup/restore and two-MX publication.

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
