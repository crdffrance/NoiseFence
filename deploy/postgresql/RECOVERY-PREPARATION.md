# Coordinated offline preparation of a selected console

`recovery_prepare.py` joins checkpoint validation, isolated PostgreSQL restoration,
queue restoration, native recovery preparation and privileged worker-key installation.
It is currently the **offline half** of protocol-2 promotion, for one restored
coordinator and one surviving local worker. The offline sequence has passed a
two-node Linux/systemd rehearsal with synthetic messages, a real PostgreSQL restore,
worker-key installation and native release authorization. The runtime handoff has
also passed an installed Debian VM rehearsal with AppArmor and HTTPS. The full
checkpoint/background-job/successive-promotion lifecycle remains a release gate.
The legacy `ha/promote.py`
continues to reject protocol-2 checkpoints.

The command never replaces the surviving worker queue, changes HTTP routing, removes
persistent service fences or starts services. Its final status is
`authorized_services_stopped`; that is not a live or completed promotion.

## Authorization and installation

Run on the standby host as root, with the matching release's PostgreSQL helpers
installed together. Supply a private, root-owned authorization under root-protected
physical directories. Its exact fields are:

| Field | Value |
| --- | --- |
| `protocol` | `noisefence-selected-recovery-1` |
| `operation` | Canonical recovery UUID, matching the original-source fence |
| `checkpoint` | Physical directory of the verified immutable selected checkpoint |
| `manifest_sha256` | SHA-256 of its exact `manifest.json` bytes |
| `fence` | Verified original coordinator fencing receipt, including owner, operation, method, creation time and `fenced: true` |
| `disaster` | Boolean: provider-powered-off disaster recovery or planned final-checkpoint recovery |
| `binary`, `binary_sha256` | Physical root-protected native executable and pinned SHA-256 |
| `worker_config` | Physical root-protected configuration used by the installed worker's systemd command |
| `user` | Existing unprivileged NoiseFence account |
| `hostname`, `console_url` | Recovery hostname and approved HTTPS console origin |
| `postgres` | Local `host`, `port`, `username` matching `user`, and `max_connections` from 1 to 6 |
| `expires_at` | Unix expiry no more than one hour ahead |

A planned checkpoint must have been captured after the original source fence.
Disaster recovery requires a recent checkpoint and an explicit provider power-off
reference. A failed ping or stale heartbeat is not fencing evidence. The tool can
verify local service state but cannot independently verify a remote provider action.

```sh
python3 /usr/local/libexec/noisefence-management/recovery_prepare.py \
  --authorization /etc/noisefence-recovery/prepare.json
```

## Durable order

1. Verify the checkpoint inventory, selected identities, native build, actual worker
   configuration/systemd command and fencing evidence. Persistently fence and stop
   the local worker and known background writers.
2. Atomically publish a private copy under `/var/lib/noisefence-standby/active`, retaining
   a stage identity marker. The original checkpoint and surviving worker queue remain
   separate. Preserve the immutable policy, model and credential artifacts.
3. Restore into the new operation-specific PostgreSQL database using
   [the atomic database restore helper](RECOVERY-DATABASE.md).
4. Generate a queue-only configuration pointing to that database and copied data;
   run the native selected `ha-restore` against the real surviving worker's replicas.
   A checkpoint exported by an already restored console has no replication
   listener configuration. For this offline command only, the helper derives the
   reciprocal pair from the reviewed installed worker and its existing credential
   path. It verifies both node identities and preserves unrelated settings. The
   resulting console configuration still has replication disabled.
5. Generate and verify the private console configuration. Bind the native recovery
   plan to that console and the actual installed worker source, not a copied worker.
6. Attach the worker in place, reconcile management state, and prepare new access keys.
   Compare both the complete identity inventories and the message/recipient payloads
   and SMTP transcript contents against the stopped sources. Apply the same error
   and transcript sanitization as normal ingestion. Compare JSON numbers by exact
   value; do not round identifiers or tolerate approximate differences. A mismatch
   retains the fences and requires reconciliation rather than silent repair.
7. Use [the root installation helper](RECOVERY-INSTALLER.md) to install the worker key
   and approved console URL without removing its persistent service fence.
8. Run native console authorization and guarded worker release while source locks
   can still be acquired. Services remain stopped throughout.

A root-private phase journal records confirmed native results. If a command commits
but its caller loses the reply, retry the same authorization; the native receipt
makes that phase idempotent. Later phases do not repeat access revocation or overwrite
worker deliveries. Retries revalidate the restored database and final native release
instead of trusting the phase journal alone. Source fencing timestamps/authorization
expiry can be refreshed after verifying that the original fence still holds; the
operation, checkpoint ordering, provider reference and other identity fields remain
pinned. Keep the immutable checkpoint until the operation completes.

## Remaining runtime handoff

The [runtime supervisor](RECOVERY-RUNTIME.md) verifies the authorized console unit and its PostgreSQL
socket access, starts only the console, checks health/login, switches Web and cluster
management routes while retaining replication routes on the worker, then removes the
matching worker service fence and starts the worker. Its combined installed
AppArmor/HTTPS rehearsal has passed with synthetic data. The console's SMTP fence remains
permanent. It must also resume checkpointing from the promoted console. These actions
are deliberately not implied by `authorized_services_stopped` and are not yet wired
into the legacy promotion entry point.

### Routing helper validation

`recovery_proxy.py` implements the routing portion as a library, not a standalone
promotion command. Its caller must already hold the upgrade lock, verify the native
console authorization and systemd service identity, and keep the worker fenced.
It accepts only the standard installed standby Nginx layout. Custom locations,
ambiguous upstream definitions and API routing overrides require an explicit review.

The helper checks that the console on loopback port 18081 reports healthy with SMTP
disabled, then changes only the managed console upstream include. Replication and
worker health remain on port 18080. After `nginx -t` and reload, it probes the console
session endpoint with GET and the management exchange endpoint with POST over
certificate-verified HTTPS resolved to loopback. Both requests carry no credentials
and must receive an authentication refusal. These probes verify routing, not the
full database-backed authentication flow.

A failed first transition restores the previous include and reloads Nginx. An external
edit is never overwritten during rollback. A completed transition is verified again
without rewriting or reloading; a later probe failure does not undo an established
route. An operation receipt records completion or rollback failure. This helper
never starts services or authorizes worker startup.

The routing tests cover accepted/refused layouts, HTTP methods, graceful-reload
settling, successful retry, failure rollback, external edits and an unhealthy
console. A Debian VM rehearsal has verified the runtime stage with installed
Nginx and enforced AppArmor. The broader recovery lifecycle remains a release gate.

### PostgreSQL socket confinement

The bundled console AppArmor profile permits local PostgreSQL socket access under
`/run/postgresql/.s.PGSQL.*`. Install and load the matching profile before starting
the recovered console. A custom socket directory requires a reviewed profile rule;
do not disable AppArmor to accommodate it. `ProtectSystem=strict` and the console's
restricted writable data directory remain enabled.

A successful `apparmor_parser --skip-kernel-load --skip-cache` check establishes
syntax compatibility only. The installed VM rehearsal additionally verified the
actual database-backed login under the enforced profile. Retain this runtime
check on each target installation before removing the worker fence.

### Checkpointing the recovered console

The matching native build provides a read-only check:

```sh
sudo -u noisefence /opt/noisefence/current/noisefence \
  --config /var/lib/noisefence-standby/active/console.toml \
  management-recovery-check-console
```

It verifies the typed configuration, immutable credentials, MFA key, permanent local
console fence and matching PostgreSQL authorization. It returns
`console_authorization_verified`; it does not authorize a new installation, start a
listener or clear any fence. The check can run while the console is serving traffic.

The Debian VM rehearsal verified this export after a complete console/worker
reboot and a fresh authenticated worker heartbeat. The resulting archive contained
PostgreSQL and selected metadata, excluding mail bodies and recovery credentials.

After promotion, `standby.py export --recovered-console` selects the installed
`active/console.toml` and its data directory explicitly. The export runs the native
check before and after copying, archives the actual restored configuration, and
retains the console fence in SQLite. An incomplete or centrally revoked recovery is
not exportable. Mail bodies and private recovery credential files are excluded.

`standby.py push --recovered-console` forwards this selection to its export subprocess.
Before scheduling it, configure and verify the replacement receiver and pinned SSH
identity in the standby settings; the former standby is now the source. This change
does not set up the new receiver, remove its old promotion marker, or automatically
resume a timer. The installed promotion supervisor must complete that lifecycle.

### Snapshot and policy consistency

Completed SQLite backup copies are opened with SQLite's immutable, read-only mode.
This prevents validation from creating WAL/SHM files beside the signed-off inventory.
Copies containing WAL, SHM or rollback-journal sidecars are refused; live worker
queues continue to use normal read-only connections that observe their WAL.

The queue restore command receives `--management-config` explicitly. Before preparing
the console configuration, the supervisor sets its approved HTTPS origin and Secure
cookies together; a loopback development source must not carry insecure cookie
settings into an HTTPS recovery console.

A released rollout may have a newer `updated` timestamp in PostgreSQL than in the
unanimous installed caches after its last acknowledgement. That timestamp alone does not constitute a different policy, including between
installed peer caches. Worker attachment, preparation, policy receipts and worker
release use the same completed-policy identity, which excludes only this timestamp. Every
other journal field, phase, acknowledgement, epoch, digest and setting must still
match, or the normal newer-policy recovery rules must hold. Recovery records both
the restored and installed timestamps, then retains the unanimous installed journal.
It clears old heartbeat evidence rather than presenting the historical timestamp as
a current liveness signal. Repeating the same recovery still requires the committed policy identity; changes
to settings, acknowledgements, phase, epoch or membership are not ignored.

## Successive-checkpoint rehearsal

A second offline preparation from a checkpoint exported by a recovered console
has passed in the Debian VM with a new operation-specific PostgreSQL database.
This exposed and corrected the missing temporary replication pair described in
step 4. Native inventory checks also rejected synthetic PostgreSQL observations
that had been seeded without matching local history. Completing that lab fixture
allowed preparation to finish; the production inventory checks were not relaxed.
The result remained `authorized_services_stopped`. Replacement of a retired
installation's persistent service fences is a separate runtime transition.
