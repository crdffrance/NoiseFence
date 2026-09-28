# Reusing a host after retiring its recovered console

This procedure replaces the old HA service guards with a new installation hold.
It does not start services, restore mail, delete the old database or enable jobs.
Use it only after [retirement](RECOVERY-RETIREMENT.md), reception of the reviewed
checkpoint, and a new [offline preparation](RECOVERY-PREPARATION.md) that reached
`workers_authorized`. Keep the original management source fenced throughout.

Create a fresh [runtime authorization](RECOVERY-RUNTIME.md) for the new operation.
Keep the completed offline authorization unchanged. Install `recovery_reentry.py`
beside the other management helpers and run as root:

```sh
sudo python3 /usr/local/libexec/noisefence-management/recovery_reentry.py \
  --authorization /etc/noisefence-recovery/runtime.json \
  --retired-operation <retirement-operation-uuid>
```

The helper verifies the completed retirement archive, old configuration hash,
new native management authority, stopped services, exact systemd configuration
and new installation hold. It disables known background timers, removes only
the expected old HA guard files and records the transition under the new
operation. The new installation hold remains. The retirement archive, original
database and worker queue are retained. Unknown or edited guards cause refusal.
An interrupted transition can be retried with the same authorization; do not
delete fences manually to make it pass.

Run the ordinary runtime helper next. Its login, AppArmor, HTTPS and worker
release checks still apply. If Nginx already points to the restored-console port,
the proxy helper requires the matching root-owned re-entry receipt before
adopting that route. A failed probe preserves the route present at entry.

Background timers stay disabled. After successful runtime verification, configure
[checkpoint transport](RECOVERY-CHECKPOINTS.md) for the new operation and review
[research jobs](RECOVERY-JOBS.md) separately before enabling them.

## Validation status

Two successive recoveries have passed a synthetic Debian VM rehearsal with
AppArmor enforcement and certificate-verified HTTPS. The second recovery copied
both retained message bodies with matching hashes, started the new console and
worker, accepted a new SMTP message only with two durable copies, and published
its history to the new PostgreSQL database. Checkpoint transport was resumed for
the new operation after a verified transfer.

This rehearsal previously exposed stale recovery receipts that skipped body
copies. Receipts are now scoped to the recovery operation; a native regression
test also covers successive metadata-only checkpoints. Unit tests cover wrong
authority, interrupted guard replacement, and failed proxy probes. The VM uses
an isolated receiver namespace and a local replica fixture; these checks do not
establish recovery across independent physical servers.
