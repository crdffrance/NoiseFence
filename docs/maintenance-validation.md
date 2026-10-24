# Candidate runtime validation during maintenance

`validate-runtime --plan PATH` is an explicit, temporary daemon mode for an
already reserved pair of native MXs with selected PostgreSQL management. It loads
the actual candidate engine and frozen policy, then exposes only authenticated
validation probes and a maintenance health response. It does not start SMTP,
delivery, the normal console, retention, training, the policy activation driver,
command consumption or quota allocation.

This is a **controller building block**, not a complete paired updater. A root
supervisor must keep both normal services and every scheduled writer stopped
using [durable maintenance reservations](maintenance-reservations.md). This
command does not reserve a host, change a release pointer, release a hold or
restart the normal services. Do not use it as a replacement for `serve`.

## Authorization contract

The plan is root-authorized JSON with exactly these fields:

| Field | Required binding |
| --- | --- |
| `protocol` | `noisefence-maintenance-validation-1` |
| `operation` | Canonical UUID of the coordinated maintenance operation |
| `selection` | Exact saved local management selection, including database, node epoch, role, baseline and applicable MFA key digest |
| `policy` | Exact currently installed and settled activation epoch (`sequence`, `revision`, `digest`) |
| `peer.identity` | Exact registered peer node and spool epoch |
| `peer.binary_sha256` | SHA-256 of the peer's authorized candidate executable |
| `config_sha256` | SHA-256 of this node's exact configuration file bytes |
| `binary_sha256` | SHA-256 of this node's authorized candidate executable |
| `expires_at` | Unix seconds, later than startup and no more than one hour ahead |

There is deliberately no sample with invented identities. A supervisor must read
and reconcile these values from the reserved installations and verified candidate
archives, then write the plan atomically. Neither an email nor a browser request
can provide this authorization. The plan, configuration and executable must be
regular root-owned files with one hard link, no group/other write access, and
physical absolute paths whose ancestor directories are also protected by root.
The plan is bounded to 16 KiB and contains no credential values. The application
account needs read access to it, configuration and the selected runtime files.

The command takes the daemon lock **before** opening the writable spool. It
refuses a simultaneous daemon, missing or different management selection,
unsettled policy, unexpected peer identity, non-loopback API listener and expired
authorization. Actual loading also verifies the existing policy/artifact/model
contracts; no compatibility override is introduced. Startup can initialize local
storage/runtime bookkeeping, so this is not a byte-for-byte read-only filesystem
operation. It does not recover delivery leases or consume queued messages.

The time limit includes startup work, uses a monotonic clock as well as the wall
clock, and is rechecked after database waits and before returning HTTP responses.
Expiry, SIGTERM or interruption stops this process and leaves the external
maintenance reservation in place. There is no timeout that resumes email traffic.

A supervisor may launch the reviewed candidate as the unprivileged application
account with the explicit mode, for example:

```text
/opt/noisefence/releases/CANDIDATE/noisefence \
  --config /etc/noisefence/config.toml \
  validate-runtime --plan /etc/noisefence/maintenance-validation.json
```

Keep normal daemon and timer holds intact. The supervisor must stop the validation
process before it cancels an unchanged reservation or attempts a later qualified
activation. The reservation's `cancel` command remains limited to the unchanged
installation; a validation result does not authorize starting changed files.

## Probe and readiness semantics

The separate router binds only the configured loopback API address. Existing
verified HTTPS peer transport can reach it through the configured reverse proxy.
The explicit HTTP-loopback test exemption remains restricted to synthetic local
fixtures. Each request is bounded to 4 KiB, four concurrent requests and five
seconds; external requests never follow redirects or use an ambient HTTP proxy.

- `/api/v1/replication/v1/validation` checks the existing replica credential on
  both nodes. It verifies the operation, selected database, exact identities and
  epochs, settled policy, application version, authorized peer executable hash
  and a fresh request nonce. Production peers must report distinct machine IDs.
- `/api/v1/cluster/v3/validation` is coordinator-only. It checks the enrolled
  worker credential, exact database-binding header and the same probe bindings.
  The PostgreSQL transaction rechecks token revocation, the settled epoch and
  **exactly two enabled source identities**. It does not acknowledge activation,
  update a heartbeat, issue credit or run a remote command. A larger cluster is
  refused by this pair-specific primitive.
- `/healthz` reports `status: maintenance_validation`. `smtp_ready`,
  `delivery_enabled` and `administration_enabled` are always `false`.
  `validation_ready` requires the current local runtime check and both replica
  and policy observations less than 15 seconds old. Failed observations clear
  earlier readiness. It includes the operation, node, version, binary digest and
  expiry for the supervising process to match.
- Other application paths return maintenance-unavailable responses; browser
  sessions do not grant access to administrative actions in this mode.

The two explicitly authorized binary hashes may differ for amd64 and arm64.
Detector build fingerprints also include target/compiler/build options and are
not compared for cross-architecture equality here. Existing model and transport
compatibility checks are not relaxed.

These probes prove the candidate can load the saved runtime and authenticate its
peer under the selected policy authority. They do **not** upload message bodies,
prove a durable replica write, grant an SMTP acceptance, or exercise the normal
worker synchronization protocol. A later activation still requires fresh normal
policy exchange, actual running binary hashes, SMTP/queue checks and durable
replica receipts after both nodes start the authorized normal build.

## Validation and remaining gates

Unit tests exercise expiry, changed bindings, independent machine identity,
credential failures, disabled application routes, body/capacity bounds, freshness,
failed observations, lock contention and special-file refusal. The PostgreSQL
suite verifies exact membership, changed/pending policy and token revocation,
comparing every application table before and after read-only probes.

This does not qualify a production paired supervisor, unattended upgrade,
current-candidate archive installation on both architectures, schema-changing
rollback or detection accuracy. Keep those gates in the
[paired upgrade procedure](paired-upgrades.md) and [release checklist](releasing.md).
