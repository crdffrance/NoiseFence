# Production readiness and incident recovery

A running process or HTTP 200 does not prove that an MX can accept mail. Verify
SMTP admission, policy freshness and replica acknowledgements together. With
mandatory two-copy durability, a peer failure deliberately defers new mail;
never disable that guarantee simply to make a dashboard green.

## Operational health monitor

The supplied Linux monitor targets a systemd installation with Nginx and Certbot.
It requires Python 3.11+, a loopback Web backend, OpenSSL, SQLite and cgroup v2.
For a different proxy or certificate manager, adapt the service checks before
installing it. Docker installations need equivalent checks in their supervisor.

Install from the same reviewed source checkout as your deployment:

```sh
sudo install -m 0755 deploy/health-check.py /usr/local/libexec/noisefence-health
sudo install -m 0644 deploy/noisefence-health.service deploy/noisefence-health.timer \
  /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now noisefence-health.timer
sudo systemctl start noisefence-health.service
sudo journalctl -u noisefence-health.service -n 10 --no-pager
```

Save the previously installed script and units before an upgrade. These checks
run as the gateway service account and do not change policies, queue state,
replica ownership or mail. They do not restart the gateway automatically.

| Check | What it establishes | Limitation |
| --- | --- | --- |
| `/healthz` JSON | `status=ok` and **`smtp_ready=true`** | A point-in-time local readiness result |
| SMTP greeting, EHLO, empty MAIL FROM, RSET | The listener responds and allows a new transaction | No RCPT or DATA; not an end-to-end delivery test |
| Replica heartbeat | Last successful replication contact is at most 15 seconds old | Does not prove every remote disk is healthy |
| Replica counters | Unprotected originals and pending metadata updates | Consecutive nonzero samples flag a backlog; sustained traffic may also keep counters nonzero |
| Policy synchronization | Worker policy age / enabled worker contact stays within configured staleness | Does not promote a standby |
| Memory | Service cgroup usage, limits, swap and new pressure/OOM events | Growth needs interpretation; it is not automatically a leak |
| Queue | Pending mail and delivery notifications reported separately | Old DSN retries must not be mistaken for an inbound outage |
| Dependencies | Disk reserve, certificates, signatures, configured LLM budget | Optional-provider failure is not evidence of spam |

The timer runs approximately once a minute, with up to five seconds of jitter.
A full check is bounded by a 90-second unit timeout; systemd does not run two
instances concurrently. SQLite queries are read-only and have a two-second
execution deadline in addition to a one-second lock wait.

The latest report is `/var/lib/noisefence/operational-health.json`. The rolling
history is `operational-health-history.json` in the same directory: at most 2,881
samples and at most 48 hours. Both are private files (0600), with atomic replacement.
History contains aggregate measurements only, without subjects, addresses,
message bodies, API credentials or raw remote responses. Gaps are visible in
sample timestamps; a missing sample is not a successful check.

The service exits nonzero for attention conditions and logs a JSON report. Local
files and journald **are not an independent alerting channel**. Configure external
monitoring to alert on a missing report, `smtp_ready=false`, stale replication,
new OOM events and sustained queue growth. Check from outside the host as well:
a successful loopback probe does not validate firewall rules, public DNS or TLS.

## Diagnose an unavailable MX

1. Check both nodes: service status, recent gateway journal, `/healthz` JSON,
   operational-health timestamps and queue counters. Separate inbound mail from
   old DSN retries. Never delete queued mail to clear an alert.
2. Check memory usage against the **effective** cgroup limits and host capacity.
   Inspect increases in `memory.events`, swap and the 48-hour history. Counters
   are cumulative; events from a previous incident are not a new failure.
3. Check peer reachability, policy age, pending replica metadata, free disk space,
   and proxy errors. A cluster `413` means the request exceeded a proxy body limit;
   `504` can indicate a stalled backend, including memory pressure.
4. Both `/api/v1/cluster/v1/` and `/api/v1/cluster/v2/` must use the cluster metadata
   limit. The shipped proxy templates allow 4 MB there while keeping a smaller
   console limit. Keep authentication and application-level limits in place.
5. After correcting the cause, recover one node at a time. Wait for model loading,
   activation gates, fresh policies and replication before considering it ready.
   A systemd `active` result can precede SMTP readiness.
6. Verify public STARTTLS with hostname/chain validation, SMTP admission on both
   nodes, fresh replication, stable queues and an authorized end-to-end test to
   a real mailbox. Observe subsequent real delivery acknowledgements.

Memory budgets depend on models, concurrency, scanners and machine capacity.
The [hardening profiles](../deploy/hardening/README.md) reserve separate budgets;
raising `MemoryMax` alone does not establish that growth is bounded. Collect a
full 24–48-hour representative window before declaring stability. Keep processing
and provider concurrency bounded and test changes under load in an isolated
installation, never by saturating the production MXs.

## Deployment checks

Run these regressions before promoting a deployment change:

```sh
python3 -m unittest discover -s tests_python -p 'test_operational_health.py' -v
python3 -m unittest discover -s tests_python -p 'test_cluster_proxy_paths.py' -v
python3 tests/proxy_smoke.py
```

The Docker proxy test starts real Nginx and Caddy instances on an internal network
with no published ports. It sends synthetic requests through the shipped routing
and size-limit rules: both protocol versions accept bounded metadata larger than
the console limit; oversized cluster requests and large console requests fail.
It uses HTTP inside that private network and does **not** qualify public TLS,
cluster authentication, mixed-version application compatibility or crash recovery.
CI runs it in the deployment job. Images are version-tagged; record their resolved
digests with release evidence.

Use [performance measurement](performance.md) for isolated SMTP load and the
[HA recovery procedure](high-availability.md) for controlled recovery and fencing.
A filesystem backup check is not proof that a promoted system can deliver mail.
Keep a verified backup outside the MX failure domain; a backup stored only on the
coordinator cannot protect against loss of that server.

## Filter quality is a separate release gate

Availability tests cannot establish capture or false-positive rates. Follow the
[filter qualification procedure](filter-qualification.md): freeze one candidate,
label recent traffic independently, separate campaigns and future holdouts, then
measure Spam/Ham/Pub decisions against those labels with confidence intervals.
Rspamd is a second opinion, never the label or the authority for NoiseFence.

Do not tune scores merely to match Rspamd or advertise a global success rate from
a selected regression set. Preserve observation until the quality and upstream
compatibility gates pass. Record the binary, policy, prompt, model and proxy
configuration versions used for each measurement and keep a compatible rollback.
