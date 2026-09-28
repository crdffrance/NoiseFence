# Starting an authorized recovered console

`recovery_runtime.py` performs the runtime half of selected PostgreSQL recovery.
It follows [offline preparation](RECOVERY-PREPARATION.md); it cannot substitute for
queue recovery, database restoration or native access authorization.

The runtime stage has passed a Debian 13 VM rehearsal with PostgreSQL 17,
AppArmor enforcement, a certificate-verified Nginx HTTPS route and the native
worker. The rehearsal used synthetic data. It verified administrator login and
logout, a fresh authenticated worker heartbeat, a completed-operation retry and
SMTP deferral while the second durable copy was unavailable. A subsequent full
guest reboot verified automatic console/worker startup, enforced AppArmor and
fresh HTTPS worker heartbeats again. The recovered console then exported a new
verified PostgreSQL checkpoint without mail bodies or recovery credentials. Production data was
not used or transferred.

An installed rehearsal exposed Nginx's asynchronous graceful reload: the first
probe reached the old upstream. The helper now retries transient routing replies
within a strict deadline, requiring both authenticated routes to pass together.
Failure retains the worker fence and rolls back an uncompleted proxy transition.

Checkpoint scheduling is covered by [the transport procedure](RECOVERY-CHECKPOINTS.md).
Separate [recovered research units](RECOVERY-JOBS.md) keep quality and training
on the restored authority. A [successive recovery rehearsal](RECOVERY-REENTRY.md)
also verified a new accepted message and renewed checkpoint scheduling after the
second restoration. Production transport and job dependencies still require
verification against the installed profile. This runtime result alone
does not establish cluster-wide recovery.
There is no option to bypass AppArmor confinement.

## Preconditions and authorization

The original coordinator must remain fenced. The matching offline preparation
must have reached `workers_authorized`; the surviving worker queue stays in place.
If this host has retired an earlier recovered console, complete the authorized
[guard replacement](RECOVERY-REENTRY.md) before starting the new runtime.
Use the same installed native binary and the bundled console systemd unit,
AppArmor profile and Nginx standby layout. Custom unit overrides are refused.

Install the profile as `/etc/apparmor.d/noisefence-console` and the unit as
`/etc/systemd/system/noisefence-console.service`, with root ownership and no group
or other write permission. Review their contents before authorizing their hashes.
Reload systemd after installation. The command loads the authorized AppArmor
profile and verifies both its enforced kernel state and the running process label.

The root-owned, mode-0600 authorization has these exact fields:

| Field | Meaning |
| --- | --- |
| `protocol` | `noisefence-recovery-runtime-1` |
| `operation` | Same canonical UUID as the completed offline recovery |
| `preparation` | Physical path to its root-owned offline authorization |
| `preparation_sha256` | SHA-256 of that file's exact bytes |
| `console_unit_sha256` | SHA-256 of the reviewed installed unit file |
| `apparmor_sha256` | SHA-256 of the reviewed installed profile |
| `fence` | Fresh original-source fencing receipt; same operation, method and checkpoint ordering as offline preparation |
| `expires_at` | Unix expiry, at most one hour ahead |

```sh
python3 /usr/local/libexec/noisefence-management/recovery_runtime.py \
  --authorization /etc/noisefence-recovery/runtime.json
```

The original source fencing receipt must still be recent. Recheck the original
fence before refreshing only its `created` verification time and the runtime
authorization expiry. These two time fields may change during a retry; the
original operation, `created_ns`, provider reference and every other identity
field remain pinned. Keep the offline authorization unchanged, even if its original
expiry has elapsed: the completed preparation receipt is the runtime prerequisite.
Keep the checkpoint,
offline authorization, database restoration receipt and operation directory.
Do not edit an existing operation's pinned identities to make a retry pass.

## Startup order

1. Verify the completed preparation, exact binary/configuration, actual systemd
   command and account, confinement settings and native PostgreSQL authorization.
2. Retain or reinstall the operation's persistent worker service fence.
3. Load the pinned AppArmor profile, create the matching console-only startup
   marker, start the console and verify health, process confinement and authority.
4. Verify the prepared administrator login, database-backed session lookup and
   logout over loopback. Credentials and cookies are never logged or passed on
   command lines. This check creates and then deletes a verification session.
5. Switch the managed Nginx include and verify certificate-checked HTTPS routes.
   A bounded ten-second probe tolerates old Nginx workers briefly serving the
   previous upstream during graceful reload. Both authentication routes must pass
   in the same attempt; TLS failures and unexpected HTTP replies still fail.
   Replication and worker health routes continue to target the local worker.
6. Under the surviving queue's source locks, repeat the authority, process and
   routing checks. Persist the release intent, remove only this operation's exact
   hold file, reload systemd and start the worker. The checked systemd condition
   drop-ins stay installed, so a later recovery can restore the hold atomically. Native startup checks
   its committed release, selected identity, route and installed credential again.
7. Persist and verify root-owned `multi-user.target` dependencies for the console
   and worker. Their native authorization and persistent service conditions still
   apply on reboot. Background timers are not enabled by this step.

Any incomplete failure retains or reinstalls the worker fence. The authorized
console may remain running after a later failure; it remains SMTP-disabled.
Retries reuse the same operation and never rotate credentials or replace queues.
A completed invocation checks the running installation and its persisted boot
dependencies without another login, service restart or proxy rewrite. A runtime
created by an earlier helper without a boot receipt gets that missing installation
step after successful live checks. Once recorded, missing or changed dependencies
are reported rather than silently re-enabled.

## What success proves

`console_and_worker_running` means the recovered console and surviving worker have
started after the checks above. It does **not** mean that SMTP can accept new mail:
the required second durable copy still needs an available, verified peer. The
original coordinator fence and the recovered console's permanent SMTP fence remain.

The command does not bring back the remote coordinator, resume background timers
or complete successive-promotion archival. Use the separate
[verified checkpoint installation](RECOVERY-CHECKPOINTS.md) after preparing a
replacement receiver and pinned transport.
The result explicitly reports those remaining availability/lifecycle gates rather
than claiming that the entire cluster has recovered.
