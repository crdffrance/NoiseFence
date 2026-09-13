<a id="première-installation"></a>
# First installation

This guide installs release 0.18.0 on a dedicated Linux server. Archive includes the Rust binary, static console and systemd services; Node and Rust are not required on the server. No account, secret or trained model is provided.

<a id="prérequis"></a>
## Prerequisites

- Debian 12 or later, or distribution with glibc 2.36+, systemd and Python 3.11+. Archives do not target Alpine/musl. Architectures x86-64 and ARM64.
- `sudo` rights, valid TLS certificates and server DNS name. To receive public mail: 25 incoming/outgoing port and consistent A/PTR records.
- Existing domain and boxes at the destination provider. NoiseFence's explicit routes do not create Proton boxes.
- Space for queue, quarantines and backups. Start with the concurrency limits in the example and measure before increasing; see [performances](performance.md).

<a id="télécharger-et-vérifier"></a>
## Download and check

On the server, in an empty work directory:

```sh
sudo apt-get update
sudo apt-get install --no-install-recommends ca-certificates curl python3 openssl
nf_version=0.18.0
case "$(uname -m)" in
  x86_64) nf_arch=amd64 ;;
  aarch64) nf_arch=arm64 ;;
  *) echo 'Unsupported architecture'; exit 1 ;;
esac
nf_archive="noisefence-${nf_version}-linux-${nf_arch}.tar.gz"
nf_url="https://github.com/crdffrance/NoiseFence/releases/download/v${nf_version}"
curl --fail --location --proto '=https' --proto-redir '=https' --remote-name "$nf_url/$nf_archive"
curl --fail --location --proto '=https' --proto-redir '=https' --remote-name "$nf_url/$nf_archive.sha256"
sha256sum --check "$nf_archive.sha256"
tar -xzf "$nf_archive"
cd "noisefence-${nf_version}-linux-${nf_arch}"
sha256sum --check --quiet SHA256SUMS
./noisefence --version
```

Both checks must succeed. `build.json` identifies the version, commit, architecture and storage schema. The corresponding sources are available from the GitHub tag; licenses are included in the archive.

<a id="préparer-le-serveur-et-la-configuration"></a>
## Prepare server and configuration

Create a private copy of `config/production.example.toml` outside the archive, for example `../config.local.toml` with `umask 077`. Adapt as a minimum:

| Adjustment | Value to be provided |
| --- | --- |
| `hostname` | The DNS name of the gateway corresponding to the SMTP certificate |
| `smtp.tls_cert`, `smtp.tls_key` | TLS chain and key readable by system account `noisefence` |
| `web.public_origin` | The exact HTTPS URL of the console |
| `domains` | Authorized domains, boxes or aliases and their explicit routes |
| `relay.postmaster` | An existing and configured postmaster address |

Keep `filter.mode = "observe"` during initial validation. Keep the API linked to loopback and `secure_cookies = true` behind the HTTPS proxy. An empty recipient list refuses the mail: fill in `recipients`, or activate `accept_all_recipients = true` for a domain that is scheduled to be received by Proton. Also declare `postmaster@domaine` or its alias.

For an isolated first test, use loopback SMTP on port 2525 without changing public MX records. The [operations guide](operations.md) covers paths, permissions, domain routing, the reverse proxy and certificate renewal. Adapt `deploy/nginx.conf` or `deploy/Caddyfile` to your domain. Never serve configuration or data directories through the Web proxy.

<a id="installer-et-créer-ladministrateur"></a>
## Install and Create Administrator

The installer creates the system account `noisefence`, installs the release, controls the configuration and starts the service. Certificates must be ready at this stage. On an existing installation, the configuration in place is kept.

```sh
sudo sh deploy/install.sh "$PWD" "$(realpath ../config.local.toml)"
sudo -u noisefence /opt/noisefence/noisefence \
  --config /etc/noisefence/config.toml user-add admin --admin
sudo systemctl is-active noisefence
sudo journalctl -u noisefence -n 30 --no-pager
curl --fail http://127.0.0.1:8080/healthz
```

The password of at least 12 characters is entered twice in the terminal. There is no default password. Once the proxy and its certificate are configured, open the chosen HTTPS URL and log in. Then create user accounts and their access from [the administration](console.md).

<a id="vérifier-le-traitement"></a>
## Check treatment

First analyze a local test message without delivery:

```sh
sudo -u noisefence /opt/noisefence/noisefence \
  --config /etc/noisefence/config.toml analyze /readable/path/message.eml
```

This command uses activated connectors but does not create input into the delivery history. To view the decisions in the console, pass a message through SMTP to a configured test recipient. Follow the [Proton tests and the pilot domain](proton-validation.md), then check the queue and the arrival folder on the Proton side. SMTP acceptance does not prove a inbox placement. The activation of the spam/PUB marking requires the corresponding reports.

Enable [actions](actions.md), [OCR/QR](vision.md), [antivirus](antivirus.md) and [reputation providers](protection.md) as required. External services require authorized access and are optional. Missing classification evidence and provider failures must remain visible. Capture and false-positive targets are not demonstrated performance guarantees.

<a id="mettre-à-niveau"></a>
## Upgrade

Read the changelog and keep the previous verified release. Stop all writers before an offline backup of `/var/lib/noisefence` and `/etc/noisefence`, or use the documented consistent backup procedure. Verify the new archive before installation. HA storage uses schema 5; never restore an older database over current accepted mail or downgrade to an incompatible binary. See [installation](installation.md) and [recovery](high-availability.md). Publishing a GitHub release does not automatically upgrade a server.
