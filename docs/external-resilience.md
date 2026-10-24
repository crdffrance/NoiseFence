# Independent monitoring and backup handoff

NoiseFence provides an external SMTP/TLS/HTTPS probe and encrypted backup pull
helpers. Installation files and local tests do not establish an independent
service: activation requires a host outside the MX failure domain, storage,
recovery keys and an alert destination that does not depend on the same mail path.
When these are unavailable, keep activation pending and record that limitation.
Do not describe a backup on an MX as protection against the loss of both MXes.

## Prepared components and their limits

| Component | Available evidence | Still required at the chosen destination |
| --- | --- | --- |
| External probe | Bounded DNS, verified TLS, SMTP admission without submitting mail, HTTPS response | Outbound port 25/443, working resolver, trusted OS CAs, expected DNS set |
| Saved-report consumer | Freshness, configuration/node binding and complete checks; no network calls | An independent scheduler and alert on nonzero exit, timeout or missing results |
| Encrypted backup pull | Fixed read-only source commands, restic producer failure checks, complete node-set validation | Dedicated source access, independent repository, separately recoverable encryption key |
| Archive verification | Hashes, SQLite consistency, queued-body checks for full archives; PostgreSQL remains pending | Isolated PostgreSQL restore and installed-system recovery rehearsal |

The probe tests one address per hostname. It does not prove all A/AAAA addresses,
recipient validity, accepted DATA replication, upstream delivery, mailbox placement
or authenticated console access. Continue checking local queue/replication health.
A metadata backup cannot recover queued bodies. Two live replicas and an encrypted
backup serve different recovery purposes.

## Inputs to record before activation

Record the independent host and its failure domain, both MX identities and pinned
SSH host keys, the backup repository, recovery-key custody, retention policy,
notification destination, responsible operator and expected recovery objectives.
Do not put private keys, passwords, provider credentials, original mail or private
reports into the repository or a public issue.

Keep observation, model selections, provider suspension, routes and the mandatory
second durable copy unchanged. Installing supervision is not an authorization to
restart SMTP, enable a provider, change retention or modify DNS.

## Install the external probe

Follow the [probe installation guide](../deploy/external-monitor/README.md) from a
verified release on the independent Linux host. Set the complete expected public
address sets where practical and allow only your own console redirect targets.
The installer starts a timer and immediately checks admission without RCPT or DATA.
Keep its private state directory; do not publish its report through a public URL.

Run the saved-report consumer from the independent monitoring scheduler about
once per minute, with a short execution timeout and the default 180-second age:

```sh
sudo python3 /usr/local/libexec/noisefence-external/probe.py \
  --config /etc/noisefence-external.json \
  --check-report /var/lib/noisefence-external/latest.json --max-age 180
```

Require exit 0 **and** delivery of a recent consumer result. Notify through the
separate alert channel on failure, timeout or missing observations. The probe
timer by itself sends no alert. A monitor hosted on the same machine as its
consumer also needs an external heartbeat check to detect loss of that machine.
There is no configured notification channel or external heartbeat provider in
these files; those destinations must be supplied by the operator.

## Prepare the independent backup collector

Use Python 3.11+, restic, OpenSSH client and Linux `unshare` on the collector.
Copy `deploy/hardening/central.py` and `restore-check.py` from the same verified
release into `/usr/local/libexec/noisefence-hardening/`, owned by root and mode
0755. Create `/etc/noisefence-hardening/backup` and
`/var/lib/noisefence-hardening` as root-only 0700 directories. Do not run the MX
hardening installer on the collector merely to install these two tools.

Initialize a **new**, independent encrypted restic repository using a private
password file, and retain a recoverable key copy outside both the MXes and the
collector. Provision a dedicated SSH key for the collector. On each MX, authorize
only the forced read-only backup entrypoint and exact sudo grants described in
[Linux hardening](../deploy/hardening/README.md#reports-and-backup-pull). Pin host
keys through an already authenticated channel. A working administrator shell is
not an appropriate backup account.

Prepare `/etc/noisefence-hardening/central.json`, root-owned mode 0600. Every MX
must use a remote `ssh` source; an empty entry means local files on the collector
and is inappropriate for an off-host collector. Replace all example paths/hosts:

```json
{
  "repository": "/independent-storage/noisefence-restic",
  "password_file": "/etc/noisefence-hardening/backup/restic-password",
  "known_hosts": "/etc/noisefence-hardening/backup/known_hosts",
  "ssh_key": "/etc/noisefence-hardening/backup/id_ed25519",
  "backup_mode": "metadata",
  "retention_days": 30,
  "body_retention_authorized": false,
  "nodes": {
    "mx1": {"ssh": "noisefence-backup@mx1.example.org"},
    "mx2": {"ssh": "noisefence-backup@mx2.example.org"}
  }
}
```

This template does not initialize storage, install source access or schedule jobs.
First check the approved source operations, disk budget and key recovery. Selected
PostgreSQL/coordinator metadata exports use the online path; legacy or full exports
may stop writers and defer SMTP. Do not schedule those paths without the reviewed
maintenance procedure. Keep the original retention decision. Full archives require
an explicit body-retention authorization and sufficient protected storage.

Once those prerequisites are met, the existing collector commands are:

```sh
sudo /usr/local/libexec/noisefence-hardening/central.py collect
sudo /usr/local/libexec/noisefence-hardening/central.py backup
sudo /usr/local/libexec/noisefence-hardening/central.py verify
```

The backup command also applies retention/pruning to this deployment's node/tag
sets. Schedule collection, daily backup and weekly isolated verification only
after reviewing that policy. The scripts use operation locks, but they do not
configure a scheduler or a notification destination. Arrange backup and verification
windows so repository pruning does not race with verification. Alert on command
failure, missing node reports and stale backup/verification timestamps.

## Interpret recovery evidence

`backup-status.json` must confirm a snapshot for each configured node. A partial
failure cannot replace it with a successful smaller set. The verifier rejects
missing/duplicate nodes, changed modes and malformed identities before fetching
archives. It retains the previous report on failure; consumers must inspect its
age and the job's latest exit status rather than treating an old success as current.

`restore-status.json` records the archive identities, verification time and original
backup time. `verified` means the listed archive checks passed. It does not mean
SMTP was started or a recovery objective was achieved. Metadata-only archives
explicitly report that they cannot restore queued bodies. A PostgreSQL dump retains
`requires_postgresql_restore` until a separate isolated database restore is proven;
checking a dump header and its checksum does not execute or validate that restore.

Do not restore an older database over accepted live mail or start cloned identities
alongside the original servers. Use the [HA recovery procedure](high-availability.md)
and [paired upgrade rehearsal](paired-upgrades.md) for installed-system validation.

## Acceptance at the new destination

Before declaring independent protection active, retain private evidence that:

1. Both MXes are checked from the destination with the expected public addresses,
   trusted certificates and no submitted mail.
2. Stopping the **probe timer on the monitoring host** makes the consumer fail
   after the freshness window and produces the intended independent alert.
   Restart the timer and verify recovery. This test does not stop an MX.
3. Missing/malformed reports and a changed test configuration fail closed. Use
   copies of the configuration/report for these tests, not production policies.
4. Each backup source is read-only, producer failure does not create a success
   receipt, and every node has a decryptable archive under the chosen retention.
5. A separate operator can recover the encryption key, and an isolated restoration
   using the selected authority passes the documented recovery checks.
6. Loss of the collector/monitor itself is noticed by the chosen outside channel.

Keep installation preparation, external reachability, alert delivery, archive
integrity and full recovery qualification as separate statuses. Local synthetic
tests support only the first of these until destination-specific checks are run.
