# Directory credential storage

This page describes **development groundwork**, not an enabled background
synchronization service. Automatic correspondent memory already works without
provider credentials; see [contact learning](contact-learning.md). The existing
Entra, Google and Okta Web collection forms still use request-only credentials.
They do not save credentials through this component.

## Boundary

The Rust connection repository supplies encrypted persistence, generation-based
rotation, revocation, expiry and administrator authorization. It is intended for
future reviewed connector configuration and scheduled collection. No HTTP route,
scheduler, OAuth refresh service or automatic snapshot activation is added by this
component. No identity provider is contacted during storage operations.

Credentials are unrelated to SMTP authentication, mailbox routing, console login
or recipient permissions. Directory records do not grant any of those rights.
Stored connections are management-only: they are not part of policy bundles,
message metadata, synchronization receipts, worker credential manifests or the
SMTP path. A public status view contains metadata and state, never ciphertext or
a plaintext credential.

## Encryption and key handling

Each installation uses a random 256-bit key at
`<data_dir>/directory-vault/key`. The parent directory must be private (`0700`)
and the key must be an owner-private, single-link, regular 32-byte file (`0600`).
The loader rejects symlinks, group/other access and malformed files. Initialization
publishes a fully written and synced key without overwriting an existing key.

Each record uses AES-256-GCM with a fresh random 96-bit nonce. Authenticated
metadata binds the ciphertext to all of the following:

- source identity, provider, tenant, scopes and freshness configuration;
- selected storage authority, encryption key ID and generation;
- previous generation, authorizing administrator and account version;
- creation time and expiry.

Changing those values without re-encryption makes decryption fail. Encryption
protects a database copy without the installation key. It does not protect against
a compromised running management process or an attacker with both the database
and key. Credentials are temporarily present in process memory; guaranteed memory
zeroization is not claimed.

Loading never creates a key. The authorized initialization path checks the selected
repository under its mutation lock. If any connection record exists, a missing key
requires restoration; it is never silently replaced. A malformed or inaccessible
key is also not replaced. The key is not recreated automatically after revoking
all connections.

## Repository and authorization

SQLite and selected PostgreSQL implement the same generation checks. PostgreSQL
unavailability fails the operation; it never falls back to a stale SQLite record.
The repository rechecks the administrator session and MFA for each administrative
operation. A saved credential also records its owner's account version. Disabling
that account, removing administrator rights or changing its version prevents reuse
of the saved connection. These checks are not a reusable scheduler grant: a future
background worker will need its own explicitly configured, revocable authorization.

At most 16 source connections can be stored. A rotation must reference the current
generation and preserve the source configuration. Competing rotations cannot both
win. Repeating the identical committed record is idempotent; a different record
cannot reuse the current generation. A stale revoke cannot revoke a later rotation.
Revocation removes the current encrypted payload and retains a tombstone so that a
retry cannot restore the revoked generation. It does not erase old database backups
or prove that a provider has revoked the underlying secret. Provider-side revocation
remains necessary when a secret is compromised.

Status values are `configured`, `expired`, `revoked`, `authorization_changed` and
`not_yet_valid`. `configured` means locally usable material, not a successful provider
login or a synchronized directory. A caller must recheck the current generation and
authorization when using credentials and before publishing a collected result; a
previously returned record is not an enduring grant.

The maximum stored lifetime is 90 days for an Entra application secret and one hour
for a Google or Okta access token. An earlier provider expiry still applies. Refresh
tokens, service-account keys, managed identities and renewable Google/Okta workload
authorization are not implemented here. Expiry does not refresh or extend itself.

## Migration, backup and restore

The optional connection component has its own version and SQL checksum. It does not
rewrite the immutable central v1 schema or change the SMTP queue format. An unknown
component version or changed checksum fails closed. Central setup creates the
component through `Central::migrate`; local setup uses an authorized transaction.
Do not hand-edit the registry to bypass a migration error.
Offline SQLite-to-PostgreSQL account import refuses existing directory connection
records, including revocation tombstones, until an explicit credential migration
is implemented. It never silently discards them. A destination with any connection
rows is not treated as empty.

Before this component is enabled by a future interface, installation and recovery
procedures must retain **both** the management database and the original vault key
in protected backups. Copying ciphertext to another authority or losing the key
makes it unusable. Restoring an old database may restore an earlier credential state;
reconcile provider revocations and authorizations before using a restored connection.
Do not distribute the key to SMTP workers to make such a restore appear successful.
A dedicated operator recovery workflow and production backup qualification remain
part of the connector rollout work.

## Validation

Synthetic tests cover encryption randomness and metadata tampering; expiry and
provider binding; key permissions, links and missing-key behavior; SQLite restart,
MFA, authorization changes and competing rotations; and real disposable PostgreSQL
persistence, revocation, selected-authority dispatch and component migration checks.
These tests do not establish live provider connectivity or email detection accuracy.
