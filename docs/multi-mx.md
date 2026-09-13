# Multiple MX servers

NoiseFence supports up to 16 nodes managed by one console. `coordinator` and `worker` describe management roles: both run SMTP filtering and relay directly to configured upstream routes.

```text
Internet ── MX priority 10 ── mx1: SMTP + durable queue ── upstream
         └─ MX priority 20 ── mx2: SMTP + durable queue ── upstream
                                  │
                                  └── authenticated HTTPS to mx1
                                      policies, models, credits, history
```

MX priority influences sender selection; it does not prevent direct connections to a secondary MX. Every public MX must filter mail. Keep upstream routes independent of the domain’s public MX records to avoid loops. Validate Proton’s internal routing and direct-delivery behavior before changing DNS.

<a id="ce-qui-est-partagé"></a>
## Shared policy and history

The coordinator distributes revisioned domains, aliases, routes, actions, levels, custom rules, preferences, RBL settings and detector configuration. Approved model artifacts have SHA-256 manifests. Downloads are streamed, verified and persisted before activation. A failed update retains the last valid policy; an existing SMTP transaction retains its captured configuration. Model replacement must pass the normal validation and reload procedure before distribution.

Each node has a private random 256-bit identity. The coordinator stores its hash. Production exchanges require HTTPS with certificate verification, without redirects or environment proxies. Loopback HTTP is restricted to tests. Artifact hashes verify integrity; TLS and the node identity establish authority.

Configured CRDF, VirusTotal, Scaleway and Spamhaus DQS credentials travel over this authenticated channel and are stored privately. Attached hosts and their administrators must be trusted. Custom RBL key references must be allowed in each node’s bootstrap configuration for the same provider and zone.

Standard policy synchronization does not copy SMTP certificates, ARC keys, Web accounts, sessions, passwords or Proton validation reports. Central history contains analysis, retained features, recipient states and the last five SMTP logs per delivery. It does not contain message bodies. Recipient permissions and Bcc visibility are checked when reading that history. Search supports all nodes, `local`, or a specific node such as `mx2`.

**Optional paired HA is a separate layer.** It copies accepted message bodies and journals, and produces protected console checkpoints containing accounts and recovery configuration. See [two durable copies and console recovery](high-availability.md). Standard cluster synchronization alone provides neither body replication nor console failover.

Remote quarantine release, discard and delivery retry use durable command receipts. Commands expire after five minutes if they are not executed. “Pending” is not confirmation of execution. Repeated receipt of a command does not repeat its action.

<a id="budgets-et-fonctionnement-dégradé"></a>
## Budgets and degraded operation

The LLM budget is shared. The coordinator reserves credits in €0.10 blocks using the same transactional accounting as local requests. Retried allocation requests return the same credits. Outstanding credits remain reserved while valid even if a node stops or is revoked. Displayed reservations can therefore exceed invoiced calls.

Limited CRDF and VirusTotal daily/minute quotas are allocated similarly; `0` means unlimited. Without a valid allocation, a check is unavailable, never evidence of spam. DNS caches, local reputation, campaign/correspondent memory and connection limits remain local. Selected SMTP admission and attempt quotas use a shared authority with fail-open behavior when unavailable; see [SMTP admission](smtp-admission.md). Update antivirus databases, local feeds and clocks on every node.

A synchronized worker can use its cached policy for `max_stale_seconds`: 24 hours by default, at most seven days. After expiry, or before its first synchronization, new SMTP transactions receive `451`. Reconnection renews policy and uploads retained history. A history upload error does not prevent a valid policy refresh; unsent records remain local.

**Mandatory two-copy replication adds a stricter requirement.** A cached policy does not permit accepting mail without a durable peer acknowledgement. A peer outage defers new mail and blocks delivery transitions that cannot be replicated. Console recovery requires fencing and controlled promotion, not an automatic DNS switch.

Without paired HA, accepted mail waits on its owning node until delivery or recovery. Backups and reliable storage remain necessary. SMTP can duplicate a delivery after a lost final acknowledgement; a NoiseFence ID does not provide exactly-once delivery.

## Installation

1. Install the same verified release on separate hosts. Check public IP, A/PTR records, inbound/outbound TCP 25, DNS, certificate validation and durable storage capacity.
2. Back up the existing coordinator consistently. Add `config/cluster-coordinator.example.toml` to its private configuration, retain observation, run `check-config` and restart.
3. Configure the HTTPS proxy using the cluster block in `deploy/nginx.conf` or `deploy/Caddyfile`. Keep the Rust API on loopback.
4. In **Administration → MX servers**, add the worker. Save the one-time identity in `/etc/noisefence/cluster/node.key`, owned by `noisefence`, mode 0600; its directory must be 0700. Never place it in Git, a URL or command arguments.
5. Give the worker its own hostname, certificates, ARC material, empty data directory and bootstrap routes. Set at most 100 recipients per transaction. Install required OCR, antivirus and signature services on each host. Add `config/cluster-worker.example.toml` with the coordinator’s real HTTPS URL.
6. The worker API exposes health rather than an independent user console. Users connect to the coordinator. Do not create separate worker accounts, clone its data directory or train an independent active model there.
7. Before publishing DNS, verify contact, policy revision, artifact digests, quotas, queue, disk space, content services and worker limits. Exercise authorized test recipients, STARTTLS, relay refusal, upstream mailbox placement, history aggregation and access isolation.
8. Configure and test [paired HA](high-availability.md) if required. With mandatory replication, test that loss of either peer produces `451`, while already accepted bodies remain protected. Without HA, test cached-policy behavior separately.
9. Publish only the intended gateway MX records after validation, for example priority 10 for `mx1.example.org` and 20 for `mx2.example.org`. DNS changes are installation operations, not Web policy revisions.

“Renew identity” invalidates the old credential. Replace the worker’s private file and restart it. “Disable” revokes synchronization and pending commands; it does not immediately stop a worker using a cached policy. To retire a receiving host, remove its DNS entry, stop new reception and resolve its accepted mail under the recovery procedure.

<a id="stockage-et-retour-arrière"></a>
## Upgrades and recovery

Upgrade the coordinator first within the explicit policy compatibility window, confirm old workers still synchronize, then upgrade workers one at a time. Compatibility is an audited list, not acceptance of arbitrary earlier or future releases. Never rewrite a cached bundle or its digest by hand.

Storage capabilities are: schema 3 for clustering, schema 4 for SMTP admission, and schema 5 for paired durability. A database retains its original node role and identity. Current release tooling supports schema 5; older binaries may refuse it. Never lower `user_version` to force a downgrade or run two instances with the same identity/data directory.

Keep a compatible prior release and consistent backups. After any new SMTP acceptance, restoring an old database can lose delivery responsibility or reuse spent credits. Stop/fence affected nodes, inventory accepted messages and reconcile accounting before recovery. See [installation](installation.md) and [HA recovery](high-availability.md).

Local CLI inspection uses the latest received policy. Local retry acts on the local queue; use the console for remote commands. A worker refuses local console-account reset.

<a id="validation-automatisée"></a>
## Verification

`cargo test --locked --test cluster` exercises isolated SMTP/HTTP nodes, synchronization, artifacts, history, Bcc permissions, idempotent commands, revocation, expiry and concurrent budgets. The HA tests additionally exercise persistence, lost acknowledgements, state replication and recovery. Synthetic tests do not establish Internet deliverability or Proton inbox placement.
