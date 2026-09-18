# NoiseFence

**A Rust SMTP security gateway with an English management console.**

NoiseFence receives mail for configured domains, records the analysis, stores accepted messages durably, and forwards them to an explicit upstream route. It supports Proton Mail as an upstream, with separate compatibility checks before subject tagging.

```text
Internet → NoiseFence MX → upstream mail service → recipient
                  ↓
       Web console: messages, policies, diagnostics
```

NoiseFence is open source under **GPL-3.0-only**. Release archives contain Linux binaries for amd64 and arm64, the console, configuration examples, deployment tools and documentation. No default account, password, paid API key or trained model is included.

> Optional temporary R&D originals: encrypted collection with an automatic stop date, expiry and per-MX quotas. Configure **Filters → R&D archive**; see [research archive](docs/research-archive.md).

## Start here

| Task | Guide |
| --- | --- |
| Try NoiseFence with Docker or install a Linux release | [Installation](docs/installation.md) |
| Configure domains, gateways, filters, RBLs and budgets | [Web configuration](docs/web-configuration.md) |
| Understand scores, classifications and delivery actions | [Filtering policy](docs/filter-policy.md) |
| Read message headers and remote SMTP replies | [Headers](docs/message-headers.md), [SMTP diagnostics](docs/smtp-diagnostics.md) |
| Deploy more MX servers and protect accepted messages | [Multiple MX servers](docs/multi-mx.md), [Two-copy availability](docs/high-availability.md) |
| Evaluate accuracy with human labels | [Quality](docs/quality.md), [Validation results](docs/validation-results.md) |
| Browse the remaining guides | [Documentation index](docs/README.md) |

## Local Docker evaluation

Install Docker Engine with Compose on Linux, then run from a checkout. Docker Desktop requires its host-networking option (4.34 or later):

```sh
docker compose build
docker compose run --rm noisefence init
docker compose run --rm noisefence user-add admin --admin
docker compose up -d
```

Enter a password when prompted. Open **http://127.0.0.1:18080**. The example publishes SMTP on **127.0.0.1:2525**, accepts only the example recipients, and has no working external delivery route. Messages remain queued until you provide a test sink or a valid upstream. It is an evaluation setup; follow the installation guide before accepting real mail. `docker compose down` preserves the named data volume.

## What the gateway does

- SMTP/ESMTP, STARTTLS, SIZE, 8BITMIME and PIPELINING, with recipient allowlists or explicit domain catch-all policies. Connections, message size, parsing and processing are bounded.
- Durable disk spool and SQLite WAL; acceptance follows persistence. Each recipient has independent retry and delivery state. Optional paired MX replication requires **two durable copies before `250`**.
- Native Rust content rules, authentication, DNS/IP/domain reputation, local classifiers and advisory comparison models. Optional integrations include ClamAV, local OCR/QR, CRDF, VirusTotal and Scaleway text analysis.
- A **0–100 risk index**, a separate classification, analysis coverage and recorded delivery policy. A high score can coexist with a review decision. Missing results never become a fabricated zero or a clean verdict.
- Observation, tagging and quarantine policies; organizational, domain and recipient profiles; custom rules; marketing classification; user feedback and controlled candidate evaluation.
- An English Web console with scoped message search, remote SMTP transcripts, filter explanations, accounts, MFA, invitations, provider credentials and quotas, configuration revisions and multiple MX management.

All messaging and filter policies can be managed through the console. Host installation remains server-side: ports, TLS keys and certificates, storage, worker sockets, model artifacts and replication identities. Model replacement follows its validation procedure; the Web editor cannot bypass it with an arbitrary file path.

## Defaults and limits

**Observation is the default.** It records decisions while delivering without subject tagging or quarantine. Paid providers are inactive until configured with an authorized key and budget. Optional active URL following is off by default; it has separate network restrictions and resource limits.

The content risk index is **not a calibrated spam probability**. Native points, log-odds, model confidence and fusion estimates have different meanings. NoiseFence does not add them together as independent votes. See the filtering policy for the exact precedence and units.

The target of at least 95% capture with at most 0.1% false positives requires measurement on recent, representative, independently labelled traffic. It is not a demonstrated product-wide guarantee. Historical public corpora and selected user corrections alone cannot establish it.

Proton may evaluate forwarded mail differently because the connecting IP changes and subject modification can break DKIM. ARC sealing does not automatically make the gateway trusted. Keep the existing delivery path until the [Proton compatibility matrix](docs/proton-validation.md) passes; tagging has a separate gate for `[SPAM]` and `[PUB]`.

SMTP is not exactly-once delivery: a lost final acknowledgement can cause a retry and duplicate delivery. Paired replication protects accepted bodies, but console recovery still requires verified fencing and a controlled promotion. With mandatory two-copy durability, an unavailable peer delays new mail with `451`.

## Build and test

The validated build toolchain is Rust 1.98 and Node 24. Use a Unix development host; production targets Linux.

```sh
cargo build --locked --features semantic
cd web
npm ci
npm test
npx tsc --noEmit
npm run lint
npm run build
cd ..
cargo test --locked --features semantic
cargo fmt --check
cargo clippy --locked --all-targets --features semantic -- -D warnings
```

For development without Docker, copy `config/development.toml` to a private configuration, set `web.public_origin` to the exact browser origin, then run `init`, `user-add admin --admin` and `serve` with that configuration. The example SMTP route is a loopback test sink, not an Internet relay.

`scan message.eml` performs local extraction and classification. `analyze message.eml` runs configured checks without queuing or delivering the message; external providers may receive the configured indicators or text excerpts. See the CLI help and [installation guide](docs/installation.md) for an isolated SMTP test that also appears in the console.

Bodies and attachments are removed after all recipient outcomes and required replica acknowledgements are resolved. Pending or held messages follow their queue/quarantine policy. Metadata and retained features normally expire after 30 days. Exports and backups have independent retention; hashed features are not an anonymity guarantee.

Contributions are welcome: read [CONTRIBUTING.md](CONTRIBUTING.md). Report vulnerabilities through [SECURITY.md](SECURITY.md). See [THIRD_PARTY.md](THIRD_PARTY.md) for dependencies and upstream acknowledgements.

Optional: [independent Rspamd comparison](docs/rspamd-comparison.md) provides asynchronous engine comparisons in the console without changing NoiseFence delivery decisions.

The [calibration workbench](docs/calibration-workbench.md) compares NoiseFence and Rspamd against human labels, isolates holdouts, and manages shadow candidates from the Web console.
