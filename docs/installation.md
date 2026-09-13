# Installation

Choose the local Docker evaluation below, or install a verified Linux release for a public MX. Both include the English console. No account, password, API key or trained model is created automatically.

## Local Docker evaluation

Use Docker Engine with Compose on Linux. Both Compose examples use host networking: no port publishing or additional TCP proxy is needed. For a desktop evaluation, enable host networking in Docker Desktop 4.34 or later; see [Docker’s host networking guide](https://docs.docker.com/engine/network/drivers/host/). The example binds SMTP and the API to loopback.

Requirements: Docker with Compose and enough disk space for the Rust/Node build. The runtime example limits memory to 2 GiB; model-heavy deployments need separate sizing. The image includes native semantic support but no model weights, OCR worker or ClamAV daemon.

Use the source checkout for Docker builds; native release archives contain prebuilt binaries, not a Docker build context. Select a specific release:

```sh
git clone https://github.com/crdffrance/NoiseFence.git
cd NoiseFence
git checkout v0.18.0
```

From the checkout root:

```sh
docker compose build
docker compose run --rm noisefence init
docker compose run --rm noisefence user-add admin --admin
docker compose up -d
docker compose ps
```

Enter the administrator password interactively. Open `http://127.0.0.1:18080` with exactly this origin. SMTP listens at `127.0.0.1:2525` on the host. Only `alice@example.test`, `bob@example.test` and the explicit billing alias are accepted. Observation is enabled; no external provider has credentials and no working upstream is configured.

Send a synthetic local message to see it in the console:

```sh
python3 - <<'PY'
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from smtplib import SMTP
m = EmailMessage()
m['From'] = 'sender@example.test'
m['To'] = 'alice@example.test'
m['Subject'] = 'NoiseFence local evaluation'
m['Date'] = formatdate(localtime=False, usegmt=True)
m['Message-ID'] = make_msgid(domain='example.test')
m.set_content('Synthetic local message for the NoiseFence console. No external recipient.')
with SMTP('127.0.0.1', 2525, timeout=20) as smtp:
    smtp.send_message(m)
PY
```

The message is deliberately queued: the example route points to an absent loopback sink, and the default relay policy blocks private addresses. For an isolated local relay test, start a sink and explicitly allow its loopback address in the host relay configuration. For real delivery, provide a valid explicit upstream. Do not use this example unchanged for public mail.

Useful commands:

```sh
docker compose logs --tail=100 noisefence
docker compose exec noisefence noisefence --config /etc/noisefence/config.toml queue
docker compose exec noisefence noisefence --config /etc/noisefence/config.toml user-reset-password admin
docker compose down
```

`down` preserves the named data volume. **Do not use `down -v` on a queue you need to keep.** The image runs as UID/GID 10001 with a read-only root filesystem. `/var/lib/noisefence` contains the database, spool, credentials and local models; back it up consistently. The image’s health check tests the API process. If you change the API port, set `NOISEFENCE_HEALTH_URL` to its loopback `/healthz` URL. SMTP readiness is the separate `smtp_ready` field in `/healthz`.

## Linux release installation

Use Linux amd64 or arm64 with glibc 2.36 or newer, systemd and Python 3.11 or newer. Debian 12/13 are suitable baselines. Provide an explicit upstream route, authorized recipient/domain policy, public hostname, working forward/reverse DNS, a verified certificate and inbound/outbound TCP 25. Size storage for the maximum queue age and optional replicas.

1. Download the matching archive and `.sha256` file from a specific [NoiseFence release](https://github.com/crdffrance/NoiseFence/releases). Check the outer SHA-256 before extracting, and the archive's `SHA256SUMS` before installation.
2. Copy `config/production.example.toml` to a private installation file. Set the actual hostname, domain and recipients, explicit next hops, certificate/key paths and console HTTPS origin. Keep `filter.mode = "observe"`. No catch-all is enabled by default.
3. Configure an HTTPS reverse proxy for the console and API. Keep the API on loopback, and make `web.public_origin` exactly match the public URL. Use secure cookies. A host TLS certificate must also be readable by the SMTP service; test STARTTLS independently of browser HTTPS.
4. Run the verified installer as root with the extracted archive and your initial configuration:

```sh
sudo sh deploy/install.sh /path/to/extracted-release /path/to/private-config.toml
sudo -u noisefence /opt/noisefence/noisefence --config /etc/noisefence/config.toml user-add admin --admin
sudo systemctl status noisefence
sudo journalctl -u noisefence --since '10 minutes ago'
```

The installer creates the service account, keeps the durable state under `/var/lib/noisefence`, installs versioned releases under `/opt/noisefence/releases`, and preserves existing configuration. Later policy edits belong in the Web console. Run `check-config` after host-level changes.

See [operations](operations.md), [SMTP standards and TLS](standards.md), and the [Linux hardening guide](../deploy/hardening/README.md). Do not enable a firewall rule or change SSH identities without retaining a verified administrator access path.

## Public MX in Docker

`deploy/compose.production.yaml` is a Linux host template, not a migration tool. It uses host networking to retain the original SMTP client IP for SPF, IP reputation and rate limits. A generic bridged or proxied TCP deployment can hide that identity; validate it before enabling those checks.

Create private configuration and durable data directories on the host. The runtime uses UID/GID 10001; the data directory must be owned by that account and mode 0700. Mount the complete configuration directory read-only so atomic certificate renewal symlinks remain visible. Certificate/key permissions must allow that UID or group to read them. Keep secrets out of the image and build arguments.

Start from the production TOML example and set:

```toml
data_dir = "/var/lib/noisefence"
[smtp]
listen = "0.0.0.0:25"
[web]
listen = "127.0.0.1:18080"
public_origin = "https://console.example.org"
static_dir = "/opt/noisefence/web"
secure_cookies = true
```

Merge these sections into the file; do not duplicate TOML tables. Supply real TLS paths, domains and routes. The template grants only `NET_BIND_SERVICE` in addition to the normal non-root runtime; verify binding to TCP 25 on your Docker/host configuration. Run an HTTPS reverse proxy on the host. External OCR/antivirus sockets and model mounts require explicit host setup and matching permissions.

```sh
export NOISEFENCE_CONFIG_DIR=/srv/noisefence/config
export NOISEFENCE_DATA_DIR=/srv/noisefence/data
docker compose -f deploy/compose.production.yaml build
docker compose -f deploy/compose.production.yaml run --rm noisefence check-config
docker compose -f deploy/compose.production.yaml run --rm noisefence user-add admin --admin
docker compose -f deploy/compose.production.yaml up -d
```

Do not mount a data directory used by a running native installation. Do not run two containers against the same SQLite/spool directory. For paired replication and console recovery, use the [HA procedure](high-availability.md); the native systemd recovery scripts are not automatically configured by Compose.

## Before changing public MX records

Verify certificate validation, authorized recipients, relay-loop prevention, retained peer IP, upstream acceptance and actual mailbox placement. Compare direct and forwarded Proton delivery with the [compatibility matrix](proton-validation.md). Validate `[SPAM]` and `[PUB]` separately before changing subjects. Keep observation until those checks and a representative quality evaluation pass.

## Upgrades and recovery

Build or install a specific release, retain its checksum and preserve current state. Stop the old process cleanly before replacing it. Check configuration, API health, SMTP readiness, queue age, pending deliveries, replication acknowledgements and upstream errors after restart.

On paired MX deployments, upgrade the coordinator first within the documented compatibility window, then workers. A temporary peer outage deliberately produces `451`; it must not fall back to one copy. Preserve the five-day retry responsibility and all accepted bodies.

Database schema 5 requires an HA-compatible release. Never restore an old database over current accepted mail or downgrade past the recorded schema/policy compatibility. Binary rollback, restoring a Web policy revision and disaster recovery are different operations. Keep the previous verified release, current backups and the [HA recovery procedure](high-availability.md) available before upgrading.
