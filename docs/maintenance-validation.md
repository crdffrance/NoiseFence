# Candidate runtime validation during maintenance

`validate-runtime --plan PATH` is an explicit, temporary daemon mode for an
already reserved pair of native MXs with selected PostgreSQL management. It loads
the actual candidate engine and frozen policy, then exposes only authenticated
validation probes and a maintenance health response. It does not start SMTP,
delivery, the normal console, retention, training, the policy activation driver,
command consumption or quota allocation.

This is a **controller building block**, not a complete paired updater. The root
host helper requires the local normal service and scheduled writers to remain
stopped using [durable maintenance reservations](maintenance-reservations.md). This
command does not reserve a host, change a release pointer, release a hold or
restart the normal services. Do not use it as a replacement for `serve`.

## Supervised host procedure

Install `upgrade_validation.py`, `upgrade_validation.service` and all the other
`deploy/postgresql/` helpers together in the protected directory specified by the
[reservation guide](maintenance-reservations.md). The helper uses the same host
operation lock. It supports the fixed native installation paths only.

A separate candidate directory must already be staged under
`/opt/noisefence/releases/`, with its original complete `SHA256SUMS` and
`build.json`. Authenticate the archive's origin before staging it. The helper
verifies every declared file and refuses unlisted files, writable paths and links;
manifest consistency alone does not authenticate a publisher. It never changes
`/opt/noisefence/current`.

1. Reserve **both** hosts with the same operation UUID and verify their `held`
   receipts before starting either candidate. Keep the original release installed.
2. Choose one common Unix expiry, at most one hour ahead. On each host, obtain a
   descriptor for the intended candidate:

   ```text
   sudo python3 /usr/local/libexec/noisefence-management/upgrade_validation.py \
     describe --operation OPERATION_UUID \
     --candidate /opt/noisefence/releases/CANDIDATE --expires-at UNIX_SECONDS
   ```

3. Transfer each descriptor to a private, root-owned file on the other host through
   your verified SSH channel. It must be the counterpart's actual `describe`
   output. Preserve root ownership after copying; an unprivileged file is refused.
   The pair must have matching operation, expiry, database authority, policy,
   application version and source commit, opposite roles and reciprocal peer IDs.
   Per-architecture executable hashes may differ.
4. Start each host with its counterpart's descriptor:

   ```text
   sudo python3 /usr/local/libexec/noisefence-management/upgrade_validation.py \
     start --operation OPERATION_UUID \
     --candidate /opt/noisefence/releases/CANDIDATE --expires-at UNIX_SECONDS \
     --peer-report /root/PEER-DESCRIPTOR.json
   sudo python3 /usr/local/libexec/noisefence-management/upgrade_validation.py \
     status --operation OPERATION_UUID
   ```

The root receipt and persistent validation marker are written before service
setup. The dedicated systemd service runs as `noisefence`, with bounded resources,
no capabilities, no automatic restart and a one-hour maximum lifetime. It retains
the normal service's environment-file path and mandatory AppArmor/SELinux profile
when configured. The exact resulting service definition is hashed into the host
descriptor. Unexpected drop-ins, changed definitions and changed authorizations
are refused.

`start` can initially report `validation_ready: false` while the counterpart is
starting. `status` checks the real process executable, its hash, the still-valid
root authorization and the bounded loopback health response. It never treats an
active systemd unit alone as readiness. Neither response permits normal mail or
administrative activity.

A lost connection can resume `start` with the **same** candidate, peer descriptor,
expiry and operation. A changed authorization cannot adopt that receipt. Expiry
never lifts the normal service hold. To finish or abandon validation, stop it on
both hosts:

```text
sudo python3 /usr/local/libexec/noisefence-management/upgrade_validation.py \
  stop --operation OPERATION_UUID
```

`stop` records its intent, removes the authorization, stops the service and removes
its separate candidate pointer before completing the receipt. Failed writes or
stops retain the marker and normal hold; retry the same operation after resolving
the cause. A completed stop can be retried after a lost response. A stopped or
expired grant cannot be silently renewed.

Reservation cancellation refuses an outstanding validation marker or running
validation service. Once both are stopped, the unchanged-installation `cancel`
procedure can restore the original releases, followed by normal policy/SMTP/replica
checks. A successful validation does not authorize changing the installed pointer:
archive promotion and coordinated activation/rollback still need the complete
paired controller and their own receipts.

## Authorization contract

The host helper creates root-authorized JSON with exactly these fields:

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

There is deliberately no sample with invented identities. The host helper reconciles these values from the reserved installation, candidate
manifest and counterpart descriptor before writing the plan atomically. Neither an email nor a browser request
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
failed observations, lock contention and special-file refusal. Local HTTP tests reject stale nonces, oversized responses, redirects and replies
that outlive their authorization. The PostgreSQL suite verifies exact membership, changed/pending policy and token revocation,
comparing every application table before and after read-only probes.

The optional `--validation-candidate DIRECTORY` argument of
`tests/paired_release_lifecycle.py` accepts a locally compiled Linux `release`
binary with the `semantic` feature and a matching `candidate.json`. It verifies
architecture and digest before Docker use, stages it separately from published
archives, runs both candidates through the real root helper/systemd, checks closed
SMTP and administrative routes, peer-loss readiness, native expiry, unchanged
PostgreSQL rows and preserved queued-message copies, then stops validation and
resumes the published archive lifecycle. This is a synthetic candidate fixture,
not a way to publish or install an unsigned production archive.

This does not qualify a production paired controller, unattended upgrade,
current-candidate archive installation on both architectures, schema-changing
rollback or detection accuracy. Keep those gates in the
[paired upgrade procedure](paired-upgrades.md) and [release checklist](releasing.md).

## Continue under the service hold

The [pre-commit promotion helper](maintenance-promotion.md) captures both live
validation results before stopping either candidate. It binds and switches the
release pointers while services remain held, and supports restoration before
cancellation. It does not authorize normal startup or rollback after activation.

Ordinary startup uses the separate [paired activation protocol](maintenance-activation.md),
with mutual durable decisions and fresh normal-runtime checks. Candidate-validation
readiness is never substituted for those checks.
