# Two durable copies and a recovery console

## Guarantees and limits

The host-level `[replication]` configuration pairs two independent MX servers. Before replying `250`, the receiving MX sends every prepared message variant and its envelope to its peer over authenticated HTTPS. The peer verifies the digest, size and identity, synchronizes the body and directory, and commits durable SQLite state. The local acceptance transaction follows. Delivery progress is tracked per recipient; receiving a replica does not automatically authorize delivery from the peer.

If replication is unavailable because of the network, TLS, disk or capacity, NoiseFence returns **451**, including failures during DATA. The sending server retains responsibility and retries. There is no automatic one-copy fallback. Two servers cannot form an independent quorum to distinguish a network partition from a failed coordinator.

The intention to send is replicated before contacting the upstream. Local body removal waits for peer acknowledgement of terminal recipient states; a durable tombstone then permits remote deletion. Previously queued messages are protected before another delivery attempt. Copies received before the local acceptance transaction completes remain inert until manually reconciled; they are not assumed to be accepted mail.

SMTP cannot guarantee exactly-once delivery. A lost final acknowledgement creates uncertainty. During recovery, confirmed delivered recipients are not retried. An uncertain acceptance, `sending` state, or referenced failure notice missing from the journal is held without automatic expiry. Inspect remote SMTP records before releasing it. See [RFC 5321](https://www.rfc-editor.org/rfc/rfc5321.html#section-6.1).

The console uses consistent checkpoints, not a shared database. A 60-second interval plus transfer time is a typical starting point. Checkpoints use the [SQLite Online Backup API](https://www.sqlite.org/backup.html) and include accounts, MFA, settings, models and budgets. Queued bodies use the dedicated replication protocol. Checkpoints are private on disk and encrypted over SSH in transit; they are not a substitute for an independent encrypted backup.

## Installation

1. Install a compatible HA release on both MX servers, coordinator first. Preserve current queues, observation mode, identities and budgets. HA requires at least 0.17.3; use the current release on both nodes after a rolling upgrade.
2. Generate a shared 32-byte random peer key encoded as 64 hexadecimal characters. Store it as `/etc/noisefence/replication.key`, owned by `noisefence`, mode 0600, on both hosts. Do not reuse a console secret or publish the key.
3. Proxy `/api/v1/replication/` through verified HTTPS to the local API, without rewriting the path. Disable request buffering and bound request time and size to the SMTP maximum plus 256 KiB. Permit the service to read `/etc/machine-id` in AppArmor. No additional public API port is required.
4. Apply `config/replication.example.toml`, reversing node identities and peer URLs on the second MX. Restart both. SMTP remains temporarily deferred until the first peer acknowledgement. Verify heartbeat, initial copies and pending updates in the infrastructure view. Once activated, removing replication causes startup to fail; never bypass the `ha_required` marker.
5. Install `deploy/ha/*.py` under `/usr/local/libexec/noisefence-ha`, owned by root and not writable by the service. Install the supplied systemd units and console AppArmor profile. Create `/var/lib/noisefence-standby` mode 0700 on each host.
6. On the coordinator, create a dedicated checkpoint-transport key in that directory and pin the peer's SSH host key through an already authenticated channel. On the peer, use a restricted transport account with the forced receiver command, source-IP restriction and no general shell access. Its only sudo command is `/usr/bin/python3 /usr/local/libexec/noisefence-ha/standby.py receive`. Keep existing administrator SSH access.
7. Configure private `settings.json` on both hosts with `owner` (coordinator identity), `hostname` (peer TLS name) and `console_url` (standby HTTPS origin). Add `receiver` (`noisefence-standby@peer-address`) on the coordinator. Enable `noisefence-standby-push.timer` only on the coordinator. Verify the peer's `current/manifest.json`, file digests and `status.json`.
8. Prepare the peer's `/etc/nginx/noisefence-console-upstream.conf` with `set $noisefence_console 127.0.0.1:18080;` and a trailing newline. Console and cluster routes use this variable after promotion. **Replication and gateway health remain on the worker's API port 18080.** Before promotion the Web root redirects to the coordinator. Preserve TLS and authentication rate limits.

The local replication settings are never overwritten by distributed Web policy. `allow_loopback_http` is for isolated loopback tests only. Reaching the replica storage quota causes temporary failure; monitor unconfirmed candidates as well as accepted copies.

<a id="bascule-planifiée"></a>
## Planned console promotion

Promotion is an administrator operation, never triggered solely by a failed ping.

1. On the coordinator, run `sudo python3 /usr/local/libexec/noisefence-ha/fence.py`. Its private `fenced.json` receipt records the verified shutdown. A persistent systemd condition prevents restart; keep that fence in place throughout recovery.
2. On the stopped coordinator, run `sudo python3 /usr/local/libexec/noisefence-ha/standby.py push`. The final checkpoint must start after fencing and carry the same operation ID.
3. Transfer the receipt to the peer through the authenticated administration channel, mode 0600. Within one hour, run `sudo python3 /usr/local/libexec/noisefence-ha/promote.py --fence-receipt /private/path/fence.json`.
4. Restoration uses a separate `active` directory, verifies every retained body and preserves queue identifiers. It starts **only the console** on `127.0.0.1:18081`. The copied MFA key must decrypt all recorded secrets before activation. Promotion updates the HTTPS console route and worker coordination URL. It does not replace the worker's queue. Sign in again; old sessions are revoked.

If promotion fails, the old coordinator stays fenced. Inspect `active`, `promoted.json`, the service log and reverse proxy. The tool refuses to overwrite an already restored state. Do not delete its protections merely to rerun it.

<a id="sinistre-du-coordinateur"></a>
## Coordinator disaster

Power off or otherwise fence the old machine through the hosting provider and verify the result. Prepare a private receipt with `owner`, `operation` (UUID), `created` (Unix time), `fenced: true`, `method: "provider-poweroff"` and the verified operation `reference`. Network unreachability is not proof of fencing. Then use `promote.py --disaster --fence-receipt ...`.

Disaster recovery accepts a checkpoint no older than 24 hours. It disables restored accounts and invitations, creates a recovery administrator whose password stays in the private root-owned `recovery-admin.json`, and suspends new provider-budget allocations. Reconcile current access rights before re-enabling accounts. Reconcile credits still held by workers before removing `ha-recovery-budget-hold`. Verify that restored provider keys are still current.

<a id="revenir-à-deux-machines"></a>
## Return to two healthy nodes

The recovery console never starts an SMTP relay. New reception and retries remain deferred while the mandatory peer is missing. Do not remove `[replication]` to force availability.

Before restoring the coordinator on a replacement host, stop the recovery console and all other writers to its state. Take a fresh consistent snapshot of `active/data`, retain the original replicas and journals, and transfer the current recovered state to the stopped replacement using the coordinator's identity. Do not return to the older pre-recovery checkpoint. Adjust host paths and restore the authenticated HTTPS pairing.

On each stopped queue, run:

```sh
sudo -u noisefence /opt/noisefence/noisefence ha-resync /var/lib/noisefence
```

This preserves bodies and recipient states, advances generations and clears acknowledgements. It refuses to operate while the daemon holds the service lock. An old acknowledgement on the surviving worker does not prove that the replacement holds a copy.

Verify body digests, terminal recipients and acknowledgements of all generations before declaring reintegration complete. Point the worker back to the replacement coordinator, restart under the compatible configuration, and keep the old host fenced until reconciliation finishes. `ha-restore` refuses to overwrite a queue owned by another node. Never run two coordinators with the same identity or place an old backup over an active queue.

Reintegration is controlled, not an automatic failback. Resolve uncertain deliveries manually and retain private operation receipts.

<a id="contrôles-dexploitation"></a>
## Operational checks

- Verify two-copy mode, initial acknowledgements, pending updates, heartbeat and checkpoint age in the infrastructure view.
- Inspect `journalctl -u noisefence -u noisefence-standby-push`; monitor free space, replica quota and stalled generations.
- `/healthz` reports `smtp_ready: false` when the required peer is unavailable. A recovery-only console always reports false.
- Exercise restoration in a separate directory with an isolated network, without SMTP delivery or production accounts used for testing.
- HA activation uses storage schema 5. Do not run an older incompatible binary against it. Rollback must also preserve current policy and accepted-message state.
