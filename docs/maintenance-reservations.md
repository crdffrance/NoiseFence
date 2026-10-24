# Durable native maintenance reservations

A maintenance reservation stops one installed MX and prevents unrelated supported
host operations from changing it after the controller disconnects. It is a building
block for the [paired upgrade procedure](paired-upgrades.md), **not an automatic
updater**. It never changes the release pointer, configuration, models, policy or
management backend. It cannot authorize a candidate or roll back a changed system.

Use a reviewed maintenance window: reserving both MXs interrupts SMTP reception
and the console. Mandatory two-copy admission means one remaining MX also defers
messages while its peer is stopped. Remote SMTP servers must retry. Do not start
this procedure merely to inspect a running installation.

## Supported installation and preparation

The helper supports a root-managed native Linux/systemd installation with:

- `/etc/noisefence/config.toml`, an absolute `/var/lib/noisefence` data directory,
  an identified coordinator/worker and configured two-copy replication;
- an unprivileged `noisefence` account and the explicit native `serve` command;
- a root-owned `/opt/noisefence/current` symlink into `/opt/noisefence/releases`;
- a complete installed release whose files match `SHA256SUMS`;
- readable format 6 local state or format 7 selected management state.

Custom wrappers, recovered console runtimes, transitioning services, unknown
storage, a changed selection, incomplete releases or an unrelated recovery fence
are refused. This does not replace archive-origin authentication, backup/restore
qualification, live policy/replica checks or the exact-release compatibility test.

Install the entire `deploy/postgresql/` helper directory from one reviewed source
revision into a root-owned, non-writable-by-others
`/usr/local/libexec/noisefence-management/` directory. Python 3.11 or newer is
required. Update the native installer, restricted deployment helper and HA helpers
from that same revision: **older installed helpers do not enforce this new
reservation**. Host installation remains an administrator operation, not a Web
setting or a permission granted to the application account.

## Reserve and inspect

Generate a canonical UUID for the maintenance operation. Use that same operation
ID on the two nodes, retaining each node's separate receipt. Before changing a
binary, a future coordinator must require both hosts to report `held`,
`reserved: true`, `service_hold: true` and `writers_stopped: true` for the intended
node identities.

```sh
sudo python3 /usr/local/libexec/noisefence-management/upgrade_reservation.py \
  begin --operation OPERATION_UUID
sudo python3 /usr/local/libexec/noisefence-management/upgrade_reservation.py \
  status --operation OPERATION_UUID
```

`begin` verifies the installed files without executing them. Its private receipt
binds the operation and node, original active units, current link, release
manifest/binary/build hashes, exact configuration bytes and selected management
identity. It then publishes persistent systemd conditions, reloads systemd,
publishes the service hold and stops known timers before their services. The
conditions cover the daemon, console and normal/recovered training and quality
jobs, including the URL feed job. Restart attempts cannot bypass the hold, even
after the initiating process exits or the host reboots.

The state directory is `/var/lib/noisefence-upgrade`, mode 0700. Per-operation
JSON receipts and markers are synchronized to disk with mode 0600. They contain
hashes and operational identities, not message bodies or credential values.
A `prepared` state is **not** proof that writers have stopped. Only `held` follows
successful stop checks and a repeated unchanged-installation check.

The `/run/noisefence-upgrade.lock` advisory lock serializes active host operations.
The persistent `active.json` reservation outlives that descriptor: migration
agents, recovery helpers, HA fence/promotion/retirement, the native installer and
restricted deployment operations refuse while it exists. Malformed markers and
broken marker symlinks also block those operations; they are not treated as an
expired reservation. There is no automatic timeout that releases a hold.

These controls coordinate the supplied administrative entry points. They are not
a security boundary against root. Do not run manual application CLI writers,
replace files, directly edit databases, remove conditions or invoke obsolete
helpers during the reservation. The service fence is the write barrier; it does
not freeze a still-running process between `prepared` and `held`.

## Interrupted operations and cancellation

If a connection closes or a stop/receipt write fails, inspect `status` and retry
`begin` with the **same UUID**. Another UUID cannot adopt an active reservation.
A failed operation does not automatically restart services. Disk-full errors and
unreadable state fail closed; repair storage before retrying.

Cancellation is permitted only while the recorded installation is unchanged:

```sh
sudo python3 /usr/local/libexec/noisefence-management/upgrade_reservation.py \
  cancel --operation OPERATION_UUID
```

Cancellation first finishes any interrupted stop, verifies the binding again and
persists a `releasing` intent. It removes the service hold and restarts only the
daemon and timers that were originally active. Interrupted oneshot jobs are not
rerun automatically; their timers schedule subsequent work. The durable operation
reservation remains until those units are active. A failed restart or lost final
response can therefore resume the same cancellation without creating a new plan.
A completed receipt remains available after `active.json` is removed.

Cancellation is not a rollback. If a binary, configuration or selected authority
changed, preserve the hold and use a reviewed recovery procedure. Do not manually
delete the marker to force a different installation to start. After cancellation
on both hosts, verify fresh authenticated policy exchange, actual running binary
hashes, SMTP readiness and message replica receipts. An active systemd unit alone
does not establish these facts.

## Evidence and remaining upgrade gates

The contract tests inject controller disconnects, disk-full receipt failures,
restart failure, changed installation, marker/condition corruption, concurrent
lock holders and a lost final acknowledgement. The disposable paired archive
fixture also exercises the real root helper and systemd conditions on both
selected-management nodes, checks refusal by the installer after the first helper
process exits, cancels the unchanged holds, and verifies fresh synchronization and
preserved accepted-message copies.

That fixture uses synthetic data and exact supplied archives; it does not qualify
an unattended production controller, starting new binaries under reservation,
rollback after schema/policy changes, current production models or arbitrary
release pairs. Those remain separate release gates.

The [candidate runtime validation mode](maintenance-validation.md) supplies a
separate bounded, authenticated probe router for a future supervisor while these
holds remain in force. It does not change this helper's cancellation contract or
make candidate activation automatic.
