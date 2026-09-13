# Linux operations

<a id="contrôles-réseau-et-diagnostics"></a>
## Network controls and diagnostics

The SMTP service allows `AF_NETLINK` for local interface inventory (`getifaddrs` on Linux). URL resolution uses this inventory to exclude the host’s own addresses. If inventory fails, active URL requests remain suspended. `sudo python3 tests/systemd_network.py` checks this capacity with the restrictions delivered, in a temporary unit. Internal addresses, unauthorized redirections and invalid certificates remain blocked.

New reports show separately the availability of this inventory. Connector and LLM errors expose a limited cause, without copying a remote response. Unlimited quotas still enforce time and concurrency limits. `protection.max_parallel` limits provider network queries for all messages; each report processes no more than three indicators at a time. The omissions counter includes the non-result indicators after interruption, in addition to the work ceiling per message.

OCR's unavailability does not exempt other security checks. The message remains explicitly incomplete and is not prefixed. The "PUB Indices" filter finds the promotions/newsletters detected, including those whose decision remains Spam or To be checked; it does not constitute a list of secure messages.

The acceptance of all addresses in a domain in NoiseFence must correspond to the configuration of the downstream receiving server. A `550 5.1.1` to `RCPT TO` reports a recipient refused by this server; it should not be turned into a success, nor silently transfer addresses to another box. Check the supplier's aliases and catch-all reception. `RCPT` tests followed by `RSET` do not require sending a message.

## Installation

Compile on the Linux target with `cargo build --release --locked`. The compilation done on macOS does not produce a Linux binary. CI checks the Rust code and console on Linux; see [GitHub Actions](https://github.com/crdffrance/NoiseFence/actions) for the result corresponding to the deployed commit.

The archive of [ GitHub releases](https://github.com/crdffrance/NoiseFence/releases) `noisefence-VERSION-linux-amd64.tar.gz` and `noisefence-VERSION-linux-arm64.tar.gz` are built in Linux Bookworm containers with Rust 1.98. Choose the architecture corresponding to `uname -m` (`x86_64` → amd64, `aarch64` → arm64). They require glibc 2.36 or more recent, for example Debian 12 or Ubuntu 24.04. They are not suitable for Alpine/musl. After extraction, check `sha256sum -c SHA256SUMS`. The binary is `noisefence` and the `web` folder contains only the public console. Install these two elements at the locations below. `build.json` records the image and the source digest.

For a versioned installation, run `sudo sh deploy/install.sh /path/to/release /path/to/config.local.toml`. Releases are kept under `/opt/noisefence/releases/VERSION`; the installer updates `current` and preserves existing configuration. It refuses a different build with the same version. Keep a consistent backup before upgrading. Rollback requires compatible storage and policy; see [installation](installation.md) and [HA recovery](high-availability.md).

The [first installation guide](getting-started.md) details the download, configuration preparation, administrator creation and controls.

A first isolated installation can bind SMTP on loopback port 2525 and the API on 18080, in observation with no real upstream route. In this case, consult the console with a `ssh -L 18080:127.0.0.1:18080 USER@HOST` tunnel, then open `http://127.0.0.1:18080`. Then create the account via `user-add` and enter its password on the server. The switch to SMTP public/25 requires DNS, certificates, actual recipients and Proton validation; it does not automatically result from the installation of the binary.

Compile the console with `npm ci` then `npm run build` in `web`. The public directory to distribute is **`web/dist/client`**. Do not serve `web/dist/server`, sources, or configuration files.

Create a system account `noisefence`. Install binary under `/opt/noisefence/noisefence`, static files under `/opt/noisefence/web`, configuration under `/etc/noisefence/config.toml`, and data under `/var/lib/noisefence` (owner `noisefence`, mode 0700). Secrets and keys must be readable by this account without being accessible to other users.

Install `deploy/noisefence.service` and configure an HTTPS proxy with the `deploy/Caddyfile` model. Provide valid SMTP certificates for the gateway hostname; the HTTPS certificate of the proxy is not automatically that of the SMTP. Provide for the renewal and restart of the service to load the new certificates.

### Let’s Encrypt SMTP certificate

The `deploy/certbot-deploy.py` hook requires Python 3.11+, OpenSSL and systemd. The server's name A must point to its IP, the reverse must be consistent, and the TCP/80 port must be accessible for the HTTP-01 challenge. Only publish an AAAA if IPv6 works. Certbot standalone mode temporarily uses port 80; it must be kept available for renewals. If an HTTP server is installed then, adapt the ACME method to its webroot or DNS.

On Debian, install Certbot and then get the hostname certificate actually configured in NoiseFence. Replace the example values:

```sh
sudo apt-get install --no-install-recommends certbot
sudo certbot certonly --standalone --preferred-challenges http \
  --non-interactive --agree-tos --email admin@example.org \
  --cert-name mx.example.org -d mx.example.org --key-type rsa --rsa-key-size 2048
```

Configure `smtp.tls_cert = "/etc/noisefence/tls/current/fullchain.pem"` and `smtp.tls_key = "/etc/noisefence/tls/current/key.pem"`. The hook does not change the SMTP listening address, the recipients, or the filtering mode.

```sh
sudo install -d -m 0755 /usr/local/libexec /etc/letsencrypt/renewal-hooks/deploy
sudo install -m 0755 deploy/certbot-deploy.py /usr/local/libexec/noisefence-certbot-deploy
sudo ln -sfn /usr/local/libexec/noisefence-certbot-deploy \
  /etc/letsencrypt/renewal-hooks/deploy/noisefence
sudo env RENEWED_LINEAGE=/etc/letsencrypt/live/mx.example.org \
  /usr/local/libexec/noisefence-certbot-deploy
sudo systemctl enable --now certbot.timer
```

Only the certificate whose Certbot name matches the NoiseFence hostname is processed. Before activation, the hook checks the trusted chain, the DNS name, the validity for at least 24 hours and the correspondence of the private key. It prepares a version directory in `root:noisefence`, files 0640 and directories 0750, then atomically replaces the link `current`. It restarts the service if it is active to load the new certificate. If the restart command fails, it restores the previous link and tries to restart the old version. The old versions of the certificate are kept in `tls/versions` for the return.

Check future renewal with `sudo certbot renew --cert-name mx.example.org --dry-run`. This simulation does not deploy its test certificate and does not execute default deployment hooks. Also check `systemctl list-timers certbot.timer`, `journalctl -u certbot.service` and expiration of the certificate actually submitted by SMTP. Add an alert if it expires within 14 days.

On the port actually configured, validate STARTTLS and certificate name:

```sh
openssl s_client -starttls smtp -connect 127.0.0.1:2525 \
  -servername mx.example.org -verify_hostname mx.example.org \
  -verify_return_error -brief </dev/null
```

Use `mx.example.org:25` to check a public listening already enabled. The SMTP certificate does not set the web console to HTTPS and does not validate the Proton relay. Reference: [certbot guide](https://eff-certbot.readthedocs.io/en/stable/using.html).

Keep the configured API port on loopback. Expose SMTP/25 and HTTPS/443, plus the port required by the chosen method of obtaining certificates. Origin checks and secure cookies remain active in production.

Create accounts and their addresses via the CLI before giving access to the console. By default, sync `recipients` with active Proton addresses. To accept all addresses of a domain without declaring them in NoiseFence:

```toml
[[domains]]
name = "example.org"
next_hops = ["mail.protonmail.ch", "mailsec.protonmail.ch"]
accept_all_recipients = true
```

`alice@example.org` is transmitted to `alice@example.org`, with its local part unchanged and the domain normalized to lowercase. `recipients` can be omitted; the entries present retain their canonical spelling. Explicit aliases remain priority and may target an authorized box in another domain. Alias chains and unconfigured domains remain refused; the option does not include subdomains.

The gateway does not create a box at Proton and does not search its recipients before acceptance. Provide the necessary mailboxes, aliases or Proton-side catch-all. A definitive refusal from Proton follows the existing processing of the failure notifications; a temporary refusal remains in queue for five days. Check the configuration with `check-config`, then restart the service. Public MXs always determine the server that receives the emails; this option does not change the DNS.

`user-add --addresses alice@example.org` can assign this box without entry to `recipients`. The rights remain accurate by address, including for hidden copies. The admin role gives access to messages from all domains of the organization and to global measurements. Ordinary users remain limited to the addresses and domains assigned to them.

<a id="réputation-et-dns"></a>
## Reputation and DNS

Configure `filter.spamhaus_key_env = "SPAMHAUS_DQS_KEY"` only with authorized DQS access. Set the key through the Web console, or in `/etc/noisefence/secrets.env` mode 0600. Never commit it. Web-managed credentials take precedence. Queries contain IPs and domain names, no body or attachments. Provider error, refusal or limitation responses do not become spam signals.

The system resolver is used by Hickory. The DQS cache is limited to 10,000 entries and 60 seconds. A message check shares a network deadline of five seconds. A partial scan does not add a prefix.

<a id="suivi-et-disponibilité"></a>
## Monitoring and availability

- `journalctl -u noisefence` displays JSON events with queue ID, score, duration and result; no body or password is logged.
- `GET /healthz` indicates that the API is responding. This is not proof of Proton's availability.
- `GET /api/v1/metrics`, with admin session, exposes queue size, oldest-message age, failures, incomplete analyses and free space.
- `noisefence queue` allows operator inspection; `retry UUID` only advances the next attempt of recipients still waiting.

Since 0.4.1, the relay logs the DNS, connection, banner, EHLO, STARTTLS and TLS steps verified, MAIL, RCPT, DATA and final response. Structured events carry message/delivery identifiers, attempt and remote server, including when accepting the message. Response texts are bounded and neutralized for display. Envelope command arguments and bytes transmitted during DATA are not recorded. Analysis events add the model version, decision settings and signal identifiers/weights; a separate event confirms the lasting persistence of the message before the incoming `250` is issued.

`GET /api/v1/messages/UUID/diagnostics`, with an authorized session, provides explanations and the last 50 server attempts per recipient. The initial response is limited to 100 transcripts for the entire message; `?delivery_id=DELIVERY_ID` loads the history of a single authorized recipient. The console reports partial history and allows it to be loaded on request. Each transcript keeps up to 32 events and 2,048 bytes per text field. It is stored in `delivery_attempts` in the same transaction as the delivery result. These traces follow the preservation of the metadata of the message and their deletion in cascade; unresolved messages remain accessible. The retention of the systemd log remains managed separately by journald. A stop during an attempt can leave its steps only in log; the console does not invent a final result. Possible SMTP duplicates after a lost final response remain subject to the usual rules of new attempt.

SMTP transcripts were introduced as an additive migration. Current HA installations require schema 5 regardless of when this table was added; follow the current compatibility checks for rollback. Diagnoses never expose learning vectors or other recipients of a message out of account rights.

Set alerts on free space below the reserve, queue age over 30 minutes, recurring Proton errors, unreported failures, incomplete analysis rates and absence of events. The systemd unit restarts the service after error, with limitation of restarts.

Retries use exponential backoff, approximately 30 minutes, 1 hour, 2 hours, then 4 hours with jitter. After five days, resolve the failure under the DSN and anti-backscatter policy. The SMTP client can wait until protocol time during a delivery; a clean stop grants 30 seconds to active sessions before interruption and restarting.

Only one instance of the daemon can own the spool, via a system lock. The CLI can be used in parallel. Never share the same data directory between two servers or on NFS. Paired HA requires a second durable copy before acceptance. Peer outages deliberately cause temporary deferrals; see [high availability](high-availability.md).

The disk reserve threshold stops acceptance by temporary error before saturation. It does not replace sizing: forecast the volume of several days of messages and the actual average size. The systemd 2GB memory budget must be measured on the 4 vCPU / 8 GiB reference target before increasing traffic.

## Backup and recovery

For an initial consistent backup, stop the service, copy the complete data directory and the configuration/keys with their permissions, then restart. Do not copy only the SQLite file while its WAL changes. The database and pending bodies must form one consistent snapshot.

On startup, interrupted local deliveries return to pending. Paired recovery separately holds uncertain outcomes for review; do not use local restart behavior as a disaster-recovery procedure. Unaccepted receiving files and orphaned ones are cleaned. If a message referenced by the database has lost its body, the server refuses to start: restore consistent backup and diagnose storage. The delivered marked files must not be reinjected blindly, under penalty of duplication.

<a id="entraînement-périodique"></a>
## Periodic training

Optional connector setup is documented in [antivirus](antivirus.md) and [Scaleway isolation](scaleway.md). The [evaluation roadmap](detection-roadmap.md) describes comparison methods and activation criteria.

Create `/var/lib/noisefence/models` before installing the provided timer. It exports the current annotations and trains a candidate; it explicitly fails when a subset does not contain both classes. Its activation is voluntarily independent of the SMTP reception.

Compare the candidate on a recently retained corpus for validation. A model that respects its textual evaluation still requires the validation of the complete pipeline. `model-activate` checks the model hash and report, then substitutes atomically for the active model. Restart the service to load the new version. Keep the previous version for a backward return.

<a id="mise-à-jour-vers-04"></a>
## Storage compatibility

Quarantine originally introduced schema 2; later features and paired replication use newer schemas, up to schema 5. Back up the current database, spool and configuration consistently. Do not run an incompatible older binary or restore an old database over accepted mail. Observation and routes are preserved during installation. Monitor `quarantined_deliveries`, queue age and free disk space; see [recovery](high-availability.md).
