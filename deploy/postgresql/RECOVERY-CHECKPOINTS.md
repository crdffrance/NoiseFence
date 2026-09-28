# Checkpoints after console recovery

The recovered console needs a new checkpoint destination. Prepare that destination
and its restricted SSH receiver before enabling a schedule. An unavailable former
coordinator cannot serve as a working backup destination; no successful checkpoint
is reported until a receiver has accepted the exact archive.

The source uses `standby.py push --recovered-console`. Its immutable model files,
selected SQLite metadata, original MFA key and PostgreSQL dump are included. Mail
bodies and temporary recovery administrator credentials are excluded. The native
console authorization is verified before and after export.

## Receiver and transport

Install the matching release and HA helpers on the receiver. Its root-private
`/var/lib/noisefence-standby/settings.json` must identify the logical coordinator
as `owner`, and the receiver's intended `console_url`. Keep the existing active
console and worker queues separate: receiving a checkpoint does not restore them.
A host with an active `promoted.json` refuses incoming checkpoints until a reviewed
retirement/archive procedure has completed.

Use a dedicated SSH account and a key restricted to the bundled
[`receiver.py`](../ha/receiver.py) forced command. Disable forwarding and interactive
use with the SSH `restrict` key option; grant only the exact `standby.py receive`
sudo command needed by that receiver. Pin the receiver's host key from an
independently verified source. Do not trust a new host key merely because a scan
returned it.

On the recovered source, install the private transport key as
`/var/lib/noisefence-standby/transport.key`, root-owned mode 0600. Install the pinned
`known_hosts` beside it. Update the root-private `settings.json` with the logical
`owner` and `receiver` in `user@hostname` or `user@IPv4` form. The currently supported
transport uses SSH port 22. These changes are installation work, not Web settings.

The source checks the receiver's receipt against the exact exported snapshot UUID,
owner, creation time, revision, build, backend and archive member byte count.
A receipt for another snapshot cannot update the displayed successful-backup status.
After verification, the source also writes root-private
`/var/lib/noisefence-standby/last-transfer.json`. This records the receiver,
checkpoint receipt, exported configuration digest, start time and fencing
operation separately from the application-owned status file. A failed transfer
does not replace this last successful handoff evidence.

## Verified schedule installation

Install the bundled `noisefence-recovered-standby-push.service` and `.timer` under
`/etc/systemd/system`, with root ownership and mode 0644, then reload systemd.
These units select the recovered source explicitly; the normal coordinator timer
must not continue exporting the surviving worker's directory.

Create a mode-0600 root authorization for `recovery_checkpoint.py` with these exact
fields:

| Field | Meaning |
| --- | --- |
| `protocol` | `noisefence-recovery-checkpoint-1` |
| `operation` | Completed console recovery UUID |
| `runtime_authorization` | Path to its current root runtime authorization |
| `runtime_identity` | `authorization` digest in that operation's root `runtime.json` |
| `receiver` | Exact configured SSH destination |
| `key_sha256` | Digest of the reviewed installed transport key |
| `known_hosts_sha256` | Digest of the reviewed host-key file |
| `service_sha256`, `timer_sha256` | Digests of the reviewed installed unit files |
| `expires_at` | Unix expiry, no more than one hour ahead |

```sh
python3 /usr/local/libexec/noisefence-management/recovery_checkpoint.py \
  --authorization /etc/noisefence-recovery/checkpoint.json
```

The helper verifies the live runtime recovery, actual unit commands, timer target,
transport pins and coordinator identity. It disables the old schedule, waits for
any exporters to stop and runs one transfer through the real new service. Only a
fresh, successful selected-checkpoint receipt permits enabling the recurring timer.
A failed first transfer leaves the new timer disabled. Retrying the same authorized
installation is supported. An already completed retry checks its state without
sending another checkpoint or silently re-enabling a timer an administrator disabled.

The recurring service performs fresh native authorization on every export; the
one-hour setup authorization is not used as a background credential. Check service
failures and checkpoint age as part of normal supervision. SSH key rotation or a
change of receiver requires a reviewed transport update, not editing a receipt to
make an existing authorization pass.

## Validation scope

The installation, first transfer and subsequent scheduled transfers have passed
a Debian VM test using real SSH, a restricted receiver account and the production
receive/export implementations. A receiver refusing a transfer leaves both prior
successful receipts intact; removing the refusal allows a fresh transfer and
retains the two most recent checkpoints. Failed transfers remain visible through
the systemd service result: the previous success receipt is not a current health
assertion, so monitoring must check its age as well.
The test receiver had an isolated filesystem view in the same VM. That proves
protocol and scheduling behavior, not physical-host independence. Production
validation must still check the real remote destination and its failure behavior.

This procedure does not [retire an earlier promoted console](RECOVERY-RETIREMENT.md), move background
training jobs (see [research scheduling](RECOVERY-JOBS.md)), remove an original coordinator fence or resume its SMTP queue.
Those are separate, coordinated recovery lifecycle operations.

## Preparing another planned handoff

Run `fence.py --recovered-console` explicitly on the restored source. It verifies
the native console authority, persistently blocks and stops the colocated worker,
console, research and checkpoint units, and flushes replication using the worker's
configuration. If the peer is unavailable or a unit remains active, the receipt
stays `fenced: false` while startup remains blocked. That incomplete receipt cannot
authorize a planned promotion. Resolve the cause and retry the same command;
matching configuration and drop-ins preserve the operation UUID. A completed
retry also preserves the original fencing timestamp.

After a successful fence, run `standby.py push --recovered-console` manually to
send the final checkpoint; the periodic services intentionally remain blocked.
The final export must start after the verified fencing timestamp. Keep the old
console directory, database and receipts until the replacement authority has been
verified. This handoff preparation does not remove `promoted.json`, clear the
fence, archive an active installation or make it eligible to receive checkpoints.

The interrupted-handoff case has been exercised in the Debian VM: an absent
replication peer leaves an incomplete receipt, retry preserves it, and a reboot
still prevents SMTP, console, quality and checkpoint processes from starting.
A subsequent test started a separate native NoiseFence replica with its own
synthetic queue and the configured test credential. Retrying the same fence
completed the native flush; a final recovered-console checkpoint was transferred
over SSH. Its operation and export start time matched the completed fence, and
its private receipt matched the received manifest. Both peers were on the same
VM under the explicit loopback test exception. This proves protocol recovery,
not physical-host redundancy or restoration of a returning production server.
