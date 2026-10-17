# Independent SMTP and console probe

Run this probe on a Linux host outside the MX pair and its failure domain. Running it on an MX is useful for diagnostics but cannot detect the loss of both MX hosts. It requires Python 3.11+, a current OS CA trust store, DNS, and outbound TCP 25/443. There are no Python package dependencies, provider credentials, mail bodies, or paid services.

## Install when an independent host is available

Copy this directory from a verified release. Copy `config.example.json` to a configuration file and replace the example hosts. `expected_addresses` optionally pins the **complete** set of public A/AAAA answers; an empty list accepts any exclusively public DNS answer set. Keep this list current when changing DNS. `console_redirect_hosts` allows a worker console to redirect to its coordinator; list only hosts you operate.

```sh
python3 probe.py --config /path/to/monitor.json
sudo sh install.sh /path/to/monitor.json
sudo systemctl status noisefence-external.timer
sudo journalctl -u noisefence-external.service --since '10 minutes ago'
sudo cat /var/lib/noisefence-external/latest.json
```

The installer validates configuration before changing files. Re-running it updates the probe and configuration. A failed first check makes installation return nonzero; the timer remains installed and continues checking. Review the report before treating installation as healthy. The service runs with a dynamic unprivileged user and a private state directory. The timer runs about once per minute; systemd does not overlap service runs.

## What the report proves

- DNS resolves only to public addresses, optionally matching the expected set.
- The selected address accepts SMTP on TCP 25, advertises STARTTLS, and presents a trusted certificate matching the configured hostname. After TLS, EHLO, `MAIL FROM:<>` and RSET must return 250. **No RCPT, DATA, AUTH, or message is submitted.**
- HTTPS on TCP 443 presents a trusted certificate matching that hostname. `/` returns 200 or an explicitly allowed HTTPS redirect. Redirects are recorded but never followed. Response bodies are discarded.
- A certificate expiring in fewer than 14 days requires attention.

Connections are pinned to one address from the validated DNS answer set, with the original hostname retained for TLS verification. `checked_address` identifies that address. Other addresses are checked through DNS only: this probe does **not** prove connectivity for every A/AAAA record. SMTP checks do not prove recipient acceptance, replicated DATA persistence, upstream delivery, or mailbox placement. A public console response does not prove authenticated API/database health. Continue using the local [health monitor](../hardening/README.md), queue metrics, and isolated recovery drills.

Each node has a 25-second hard deadline, including DNS resolution. Up to four nodes run concurrently, with at most eight configured nodes. A timed-out child is terminated. Results contain status, response codes, timing and certificate expiry, but no remote error text or content. The report is atomically replaced with permissions 0600.

## Alert integration and freshness

Exit codes are 0 (all checks healthy), 1 (one or more checks need attention), and 2 (invalid configuration or report/runtime failure). The JSON schema is `noisefence-external-health-1`. A monitoring consumer must check both `status` and `checked_at`; an absent report or a report older than three minutes is an outage/monitoring failure, never a healthy result. A failed service may leave the previous report on disk.

No notification destination is configured by the installer. Forward service failures and stale reports to an independent monitoring/alert service when one is available. Merely installing this timer does not create off-host alerts. If no independent host is available, keep this directory ready and leave external activation pending.

## Remove

```sh
sudo systemctl disable --now noisefence-external.timer
sudo systemctl stop noisefence-external.service
sudo rm /etc/systemd/system/noisefence-external.service /etc/systemd/system/noisefence-external.timer
sudo systemctl daemon-reload
sudo rm -r /usr/local/libexec/noisefence-external
```

Keep `/etc/noisefence-external.json` and the state directory until any needed monitoring history has been retained. Removal never changes MX services, queues or DNS.

## Validation

`python3 -m unittest discover -s tests_python -p test_external_monitor.py -v` runs synthetic local TLS/SMTP/HTTPS fixtures. It covers a valid STARTTLS transaction, a 451 response, CA and hostname failures, DNS address restrictions, HTTPS errors and redirect restrictions, deadlines, certificate expiry and private report permissions. These tests do not certify reachability from a particular future monitoring host.
