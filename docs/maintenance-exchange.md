# Authenticated completion of a started MX pair

`deploy/postgresql/upgrade_exchange.py` automates the final proof exchange in the
[paired activation protocol](maintenance-activation.md). It supports exactly
`status`, `check`, `verify` and `finish`. Both normal daemons must already have
started under the same durable activation decision. It cannot reserve a host,
choose or download a release, change a pointer, decide activation, start a daemon,
restore a database or authorize a downgrade.

The existing native activation helper remains the authority. Every request runs
under the host operation lock and binds the exact operation, prepared pair and
node. The agent checks its root-owned authorization before reading the receipt.
Native process, policy and replica proofs retain their existing freshness limits.
An unavailable peer or missing proof stops completion; it does not release holds.

## Trust and installation

Install the complete reviewed helper directory on both native Linux hosts, with
Python 3.11 or newer and OpenSSH. Its files and ancestors must belong to root and
must not be writable by other users. Installation and SSH authorization remain
server administration tasks, not permissions granted to the Web console.

Use a dedicated temporary SSH key. On each destination, restrict that key to this
forced command, with forwarding and interactive sessions disabled:

```text
restrict,command="/usr/bin/python3 /usr/local/libexec/noisefence-management/upgrade_exchange.py serve" ssh-ed25519 REPLACE_WITH_DEDICATED_PUBLIC_KEY
```

This command must run as root. A root account with this restricted authorization
is one supported arrangement; do not enable password login or grant an
unrestricted shell to the key. The agent also requires the exact original SSH
command `noisefence-upgrade-exchange`. A different command is refused even if the
key authenticates. Do not reuse a personal or existing deployment private key.

The controller is trusted to supply counterpart reports. Reports are not
independently signed. Possession of this temporary key authorizes the permitted
completion operations for the exact prepared pair, while the native receipt and
freshness checks still apply. Protect the key, review the authorization and revoke
it after completion. Root can renew an expired authorization for the same operation;
expiry never cancels an already committed activation or removes its hold.

Pin each server's public host key using an independently verified value in a
root-protected `known_hosts` file. Its aliases must be:

```text
noisefence-upgrade-mx1 ssh-ed25519 VERIFIED_MX1_HOST_KEY
noisefence-upgrade-mx2 ssh-ed25519 VERIFIED_MX2_HOST_KEY
```

Do not automatically accept the result of `ssh-keyscan` as identity proof. The
client uses only this file, disables user/system SSH configuration, agent and
password fallback, forwarding, proxy commands and connection multiplexing. It
uses numeric IP addresses and explicit ports. A changed or unknown host key fails.

## Exact-pair authorization

After both daemons have started, review their activation reports. Use the same
operation UUID and prepared-pair SHA-256 from the existing promotion/activation
receipts. Do not substitute a release checksum for the pair digest. On each node,
create `/etc/noisefence-upgrade/exchange.json` under root-protected directories,
with mode 0600 and these exact fields (replace the example values):

```json
{
  "protocol": "noisefence-upgrade-exchange-1",
  "operation": "REVIEWED_OPERATION_UUID",
  "proposal_sha256": "REVIEWED_PREPARED_PAIR_SHA256",
  "node": "mx1",
  "expires_at": 0
}
```

Use `mx2` for the other node and an integer Unix expiry later than now but no more
than 24 hours away. Authorization does not create or replace an activation receipt.
The zero timestamp and placeholder identities above are deliberately invalid.

Prepare a root-private controller configuration with the same identity and expiry:

```json
{
  "protocol": "noisefence-upgrade-exchange-1",
  "operation": "REVIEWED_OPERATION_UUID",
  "proposal_sha256": "REVIEWED_PREPARED_PAIR_SHA256",
  "expires_at": 0,
  "coordinator": "mx1",
  "ssh_key": "/root/noisefence-upgrade/key",
  "known_hosts": "/root/noisefence-upgrade/known_hosts",
  "nodes": {
    "mx1": {"host": "192.0.2.10", "port": 22, "user": "root"},
    "mx2": {"host": "192.0.2.20", "port": 22, "user": "root"}
  }
}
```

Replace the documentation addresses with the authorized numeric addresses. The
key must be a physical root-private file; all configuration/key/host-file ancestors
must be protected by root. The controller never uses 1Password or an SSH agent.

## Completion and retry

Run on the trusted Linux controller as root:

```sh
python3 /usr/local/libexec/noisefence-management/upgrade_exchange.py complete \
  --config /root/noisefence-upgrade/controller.json
```

The controller obtains both saved states, collects fresh runtime proofs in
parallel, verifies the counterpart proofs on both nodes and finishes the
coordinator followed by its peer. The native protocol keeps auxiliary jobs held
until completion is authorized. Each authenticated response is saved privately
under a new `/var/lib/noisefence-upgrade/exchange/<attempt-UUID>/` directory before
it is forwarded. The configuration is retained there too, without private key
contents. Failed attempts remain evidence; do not publish them.

A lost reply or interrupted connection never replaces the durable decision.
Rerun the same reviewed configuration. If one node already persisted `finishing`
or `complete`, its retained counterpart certificate lets the other finish the
same operation without fabricating fresh proofs. Otherwise both nodes must pass
new checks. A changed release, operation, node, pair, process or unready replica
is refused by the existing native helpers.

Each SSH invocation handles one request, a fresh response nonce and a maximum
256 KiB frame. Connect, agent and process deadlines are bounded; excess output,
truncated frames, duplicate JSON keys, a mismatched response or unsuccessful SSH
exit are errors. Remote diagnostics and credentials are not copied into stdout.
Inspect the protected local activation receipts and service journals after a
failure. An exchange error is not permission to delete markers or switch releases.

## Validation scope

The regression tests cover exact authorization, proof/node binding, private SSH
inputs, forbidden operations, framing bounds, replayed/trailing/truncated replies,
process deadlines and completion after a lost response. The disposable
`tests/fixtures/exchange_ssh.py` fixture exercises real OpenSSH with temporary keys
and a synthetic status backend: valid pinned identity succeeds; a foreign host
key, client key, command, node or expired authorization is refused. Run it only in
the dedicated isolated Linux test container, never on an installed MX.

The native ARM64/systemd lifecycle now also runs this SSH exchange against the
actual installed activation helper, selected PostgreSQL authority, running
candidate and replica state. It discards one real coordinator completion response,
waits beyond the 30-second proof window and resumes using the durable completion
certificate. Both nodes finish the same decision, repeated completion is
idempotent, and all 24 accepted synthetic messages retain their two copies.
Previously active auxiliary timers resume and the disposable containers are removed.

The test-only SSH wrapper injects the lost response; it does not replace the native
activation backend or fabricate its proofs. Temporary private SSH keys remain
inside the laboratory. The retained local candidate is a release-profile ARM64
build, not a published final archive. Final archives, AMD64, production security
profiles and post-start downgrade compatibility remain qualification gates. This
completion helper does not yet automate the earlier reservation, candidate
validation, promotion, commit and startup stages.
