# Linux hardening for existing NoiseFence MX nodes

Debian 13, systemd and AppArmor are required. Install and validate the SMTP gateway,
Nginx, TLS certificates and local scanners first. These tools do not change mail
classification or DNS. Apply to one node at a time while another receives mail.

`deploy/ansible/harden.yml` installs the tools and executes separate network and
confinement transactions. Copy `inventory.example.yml` outside the public checkout,
set the administrator accounts and supply a reviewed validation program as an argv.
The validation must exercise fresh SSH, public SMTP STARTTLS with certificate checks,
known and unknown recipients, HTTPS, clean/EICAR scans over local sockets, OCR/QR/PDF,
cluster synchronization and model loading. Never send the antivirus test to real mailboxes.

```sh
ansible-playbook -i /private/inventory.yml deploy/ansible/harden.yml
```

The play resets its SSH connection before network commit. Root timers revert an
uncommitted transaction. An exception restores configuration and services; it never
restores an old mail database or queue. Public tooling contains no production
inventory, secret or message sample. Retain the personal administrator key until the
replacement access is independently proven. No fixed source IP or VPN is assumed
for administrators. The backup source key may be restricted to the coordinator IP.

## Network and service boundaries

- Own nftables table `inet noisefence_host`; no global ruleset flush. IPv4/IPv6,
  established connections, DHCP, ICMP and inbound TCP 22/25/80/443 are retained.
- Password and direct root SSH logins, forwarding and LLMNR are disabled.
- The mail service UID cannot connect to private/cloud-metadata networks. DNS,
  public HTTPS and outbound SMTP remain available, including DSNs to other MXes.
- Named AppArmor profiles confine the main daemon, Nginx, scanners and OCR.
  Root-owned legacy models have specific read-only paths. Site-specific model paths
  require review. Never solve an unexplained denial with broad read/write rules.
- A shared processing slice limits combined memory/CPU, with separate settings for
  4 GB and larger machines. Scanner updates and feedback training share the budget.
  ClamAV's signed-bytecode JIT remains supported; its scanning daemon has no network.
- Existing EDR/host firewall tables are preserved. No automatic IP ban based on spam
  scores is introduced. Kernel limits and persistent journals are bounded.

AppArmor may report an OCR startup `getattr` denial on an inherited disconnected
`dev/null` descriptor. Functional OCR tests must still pass. The monitor labels this
exact case separately; other denials remain actionable. The unsafe
`attach_disconnected` workaround is deliberately avoided. OCR's inactive service
with an active listening socket is a normal standby state.

## Reports and backup pull

`install-monitor.py` installs targeted audit watches and five-minute reports. Audit
exports allowlist event fields; raw argv, paths, message bodies, keys and cookies are
not forwarded. Journals are bounded at 256 MB and 30 days; audit rotation at 5 × 32 MB.
`central.py collect` pulls normalized reports and retains daily files for 30 days.
No external notification channel is implied: local reports must be consulted.

`central.json` is root-owned 0600 under `/etc/noisefence-hardening`. Its shape is:

```json
{
  "repository": "/var/backups/noisefence/restic",
  "password_file": "/etc/noisefence-hardening/backup/restic-password",
  "known_hosts": "/etc/noisefence-hardening/backup/known_hosts",
  "ssh_key": "/etc/noisefence-hardening/backup/id_ed25519",
  "backup_mode": "metadata",
  "retention_days": 30,
  "body_retention_authorized": false,
  "nodes": {"mx2": {"ssh": "noisefence-backup@192.0.2.20"}, "mx1": {}}
}
```

Initialize restic with a generated random password stored only in the password file.
Pin host keys through an already authenticated channel. The source account uses a
root-owned home and forced `backup-source.py`, `restrict`, a coordinator source IP,
and exact sudo grants for reading the normalized report and the two snapshot modes.
It cannot write/delete the central repository. Never grant a generic shell, SFTP
write access to backups, or interpreter sudo access to that account.

Snapshots copy the stopped node's SQLite, operational data, configured models,
worker artifact cache, identity, MFA key and configuration. Timers/background writers
are checked; a separate resume timer protects against interruption during the short
copy. The other node must remain healthy. Messages already accepted have independent
local queues: this is not synchronous replication and cannot promise zero data loss.

`metadata` excludes spool and incoming bodies and cannot recover queued mail by
itself. `full` includes them, requires `body_retention_authorized=true` and an explicit
1–30 day retention. Obtain the operator's choice before enabling it. Both modes
contain sensitive configuration/metadata and must remain encrypted. Backup retention
is distinct from live data deletion. Do not silently change this setting.

Restic `--stdin-from-command` rejects a failed producer; a truncated export is not
published as a successful backup. `central.py verify` decrypts the latest snapshots
into private temporary directories, verifies hashes and SQLite, and runs the verifier
in a network namespace. It starts no mail service or paid API call and deletes test
copies afterward. Schedule backup daily and isolated verification weekly; monitor
failures and freshness. A repository stored on mx1 is **not independent of mx1 loss**.
Keep a separately recoverable copy of the encryption key and add independent storage
when it becomes available.

## Restricted deployments and incident recovery

`deploy-entry.py` is a forced SSH entrypoint for a dedicated deploy user. Its root
helper allows only status, configuration verification, restart, and activation of a
release already staged and approved by root. Every release file must match its
manifest, be root-owned and unwritable by others. Release scripts never execute as
root through this helper. New bundle staging remains an administrator operation.
Do not remove the old automation key until both a new deploy session and the personal
administrator session have been tested. Do not grant the deploy account general sudo.

If a node is compromised, isolate its public network access, preserve its durable
queue for investigation, revoke its cluster identity and relevant provider keys,
and rebuild from a clean image. Revocation alone does not stop SMTP with cached policy.
Restore configuration/model/queue together offline, validate checksums and SQLite,
then reconcile accepted messages before reconnecting. Never run a cloned worker
identity alongside the original. Do not restore old LLM budget counters into an active
cluster. Keep schema compatibility checks before changing binaries; schema 4 is
required once a console account enables MFA.

For a failed rollout, inspect service and audit reports, correct the compatible
release, or activate a previous **schema-compatible** release. Never roll back the
state database. Emergency console MFA recovery is available to a local administrator
through `noisefence ... user-reset-mfa USER`; it revokes all sessions and writes an audit
event. Verify the account owner and enroll again. Password reset alone does not remove MFA.

References: [OpenSSH](https://manpages.debian.org/trixie/openssh-server/sshd_config.5.en.html),
[systemd isolation](https://manpages.debian.org/trixie/systemd/systemd.exec.5.en.html),
[AppArmor](https://manpages.debian.org/trixie/apparmor/apparmor.d.5.en.html),
[restic producer failure handling](https://restic.readthedocs.io/en/stable/040_backup.html),
[TOTP RFC 6238](https://www.rfc-editor.org/info/rfc6238/).
