# Preparing a release pair under maintenance

`deploy/postgresql/upgrade_promotion.py` adds a **pre-commit** stage to the native
[reservation](maintenance-reservations.md) and [candidate validation](maintenance-validation.md)
helpers. It can bind the reviewed original/candidate pair, stop the validation
processes and replace each `current` symlink while every normal service remains
held. It also restores the unchanged original pair before cancellation.

This helper has no activation command. A promoted pointer does not authorize SMTP,
Web administration, timers or background workers to start. Do not remove the hold
manually. The separate [activation helper](maintenance-activation.md) records the
pair decision before ordinary startup and verifies fresh policy/replica operation.
Rollback after the new runtime has written data remains a separate qualification.
This preparation is not an unattended updater or an accuracy qualification.
New preparation and promotion require the candidate version to be strictly newer
than the original, including prerelease ordering. Older receipts remain readable
and can restore their unchanged original pair before cancellation; they cannot
use a previously successful validation to authorize an unqualified downgrade.


## Prerequisites and trust boundary

Use the same reviewed helper revision on both root-protected native installations.
Python 3.11 or newer is required. The absolute native paths, unprivileged service
account, selected PostgreSQL authority and mandatory two-copy configuration follow
the reservation contract. Authenticate release origin and stage complete immutable
releases first; an internal checksum manifest does not authenticate a publisher.

The two candidates must already be running in validation mode with one operation
UUID, matching source commit and version, reciprocal node identities, the same
management database and settled policy, and an unexpired authorization. For promotion, the
retained originals must also have matching version and source commit, and each node
must keep its architecture across the transition. These compatibility restrictions
do not prevent restoring and releasing the exact originals after a refused preparation. The two nodes can have different
architectures and different binary hashes.

Exchange reports over an authenticated operator channel, such as SSH with pinned
host keys. On receipt, use physical root-owned files with mode 0600 under a private
root directory. Reports contain identities and digests, not message bodies or
secret values. They are not signed messages: root and the authenticated transfer
are the trust boundary. Never import an email attachment or an unverified report
as an operation authorization.

## Prepare and promote without activation

The commands below run as root on **each** MX. Replace the example operation UUID
and output filenames; keep the original reports. A shell redirect runs with the
shell's privileges, so enter a root shell before redirecting to `/root`.

```sh
umask 077
OPERATION=00000000-0000-4000-8000-000000000001
python3 /usr/local/libexec/noisefence-management/upgrade_promotion.py prepare \
  --operation "$OPERATION" > /root/mx-prepared.json
```

Obtain both prepared reports **before promoting either node**. Preparation records
an actual successful local validation readiness observation while the counterpart
validation process is still available. It binds the installed service definitions,
original symlink text, configuration, authority, policy and complete release
manifests. The durable receipt and marker prevent reservation cancellation, even
if the controller disconnects between the two writes.

Copy the counterpart's report to `/root/peer-prepared.json` on each MX, then:

```sh
python3 /usr/local/libexec/noisefence-management/upgrade_promotion.py promote \
  --operation "$OPERATION" --peer-report /root/peer-prepared.json \
  > /root/mx-promoted.json
python3 /usr/local/libexec/noisefence-management/upgrade_promotion.py status \
  --operation "$OPERATION"
```

Each promotion stops and revokes the validation process before replacing the
normal pointer. The root reservation and all normal service conditions remain in
place. The command rechecks the held writers, original policy, configuration,
selection, installed service definitions and candidate inventory. A changed file,
unknown pointer, pending systemd reload, other operation, missing hold or expired
preparation refuses promotion. Matching local schema numbers alone never authorize
this change.

`status` returns the durable operation phase, not a live readiness claim. Reports
are bound to the complete two-node descriptors through `pair_sha256`; this digest
is independent of controller arrival order. Repeating `promote` with the same
report can finish a lost response or interrupted pointer replacement. A different
peer, version or operation is not adopted. Expired preparations can be restored;
they cannot be silently renewed for promotion.

## Restore the original pair before cancelling

Before normal activation, restore both originals:

```sh
python3 /usr/local/libexec/noisefence-management/upgrade_promotion.py restore \
  --operation "$OPERATION" > /root/mx-restored.json
```

Exchange the two restored reports as `/root/peer-restored.json`, then release the
promotion stage on each node:

```sh
python3 /usr/local/libexec/noisefence-management/upgrade_promotion.py release \
  --operation "$OPERATION" --peer-report /root/peer-restored.json
```

`release` only removes the promotion marker. It requires the original local
installation and a matching restored counterpart. It does not remove the service
hold or start the daemon. Once **both** releases are confirmed, use the existing
reservation cancellation command on each MX, verify fresh authenticated policy
synchronization and replica readiness, and retain the receipts:

```sh
python3 /usr/local/libexec/noisefence-management/upgrade_reservation.py cancel \
  --operation "$OPERATION"
```

This restores the pre-maintenance installation without restoring an old database,
lowering a storage version, changing the policy or replaying accepted mail.
Unknown changed state stays held for recovery. It is not a rollback procedure for
a candidate that has already served traffic or migrated application data.

## One candidate fails before preparation

If one node prepared successfully but its counterpart failed before creating a
promotion receipt, the successful node can use `restore`. On the counterpart,
import that prepared or restored report and run:

```sh
python3 /usr/local/libexec/noisefence-management/upgrade_promotion.py abandon \
  --operation "$OPERATION" --peer-report /root/peer-prepared.json \
  > /root/mx-restored.json
```

This binds the original installation under its existing reservation and records a
restoration-only descriptor with `validated_at: null`. It never invents a successful
validation and can never authorize promotion. This also permits cancellation when
the candidate was accidentally the already installed directory on that peer. Any owned validation process is
stopped. Missing receipts alongside unowned candidate artifacts require manual
recovery; they are not silently removed. Exchange both restored reports and use
`release` and reservation `cancel` as above. If a promotion receipt already exists,
use its recorded `restore` path instead of replacing its identity with `abandon`.

## Faults and evidence

Receipts live in `/var/lib/noisefence-upgrade/<UUID>-promotion.json` and the active
marker is `promotion.json`. Phases are `prepared`, `promoting`, `promoted`,
`restoring`, `restored` and `released`. Intent is synchronized before pointer
changes; the pointer's parent directory is synchronized after replacement.
Operation-specific temporary symlinks are recovered only when root-owned and
pointing to one of the recorded releases. The old symlink's exact text is restored.

A full disk or lost process can leave an earlier receipt than the filesystem
mutation. Retry the same command with the same operation and reports. Do not
create a new UUID, delete receipts or clear fences to hide the discrepancy. Failed
restoration and failed final receipt writes preserve the reservation. After a
released operation, a repeated release returns the historical receipt and never
starts services or modifies a later operation.

The optional candidate path in the [paired lifecycle fixture](paired-upgrades.md#run-the-disposable-archive-pair-fixture)
exercises both actual Linux/systemd installations: validation, promotion, independent
restart refusal, repeated commands after helper exit, refusal to release just one
restored node, original-pair restoration and fresh policy synchronization. It checks
unchanged selected authority, policy, PostgreSQL rows and queued body/recipient
state during pre-commit work. Normal message acceptance is also exercised after
the separate [activation protocol](maintenance-activation.md) commits the candidate
pair; held promotion alone does not provide that evidence. Production activation
and architecture-specific release qualification remain separate gates.
