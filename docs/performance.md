<a id="mesurer-le-traitement-complet"></a>
# Measuring performance

Measure analysis latency, SMTP acceptance latency and delivery throughput separately.
A fast result from a disabled, timed-out or incomplete detector does not establish
successful analysis. The historical results below are controlled experiments, not
current production capacity or version 1.0 qualification.

## Choose the measurement tool

| Tool | Measures | Important exclusions |
| --- | --- | --- |
| `native-benchmark` | Native MIME normalization, OSB features, sketches, rules and composites, with concurrent tasks and a warmup | Trained Bayes inference, fuzzy database, historical lexical/semantic engine, network checks, OCR, queue and relay |
| `model-benchmark` | MIME/text features and the selected lexical model, optionally with its matching semantic combination | Connectors, queue, relay and model loading; the first measured call is not a separate warmup |
| `pipeline_probe` | Repeated `Engine::process` calls with the configured models and connectors | File reads, model loading, SMTP, durable queue and relay |
| `scripts/smtp_load.py` | Synthetic SMTP reception, configured local analysis, durable queue and delivery to a loopback sink | Real senders, Proton, TLS, DNS authentication and external reputation/LLM services |

Each tool measures only the components it actually enables. Keep the configuration,
software and model hashes with every result. See [calibration qualification](calibration-workbench.md#qualification-and-latency)
for the separate native and full-pipeline release gates. Repeating a handful of
synthetic cases does not establish representative traffic latency or detection quality.

## Measure the configured analysis pipeline

```sh
cargo build --release --locked --features semantic --example pipeline_probe
python3 tests/pipeline_probe.py target/release/examples/pipeline_probe
```

The manual GitHub workflow **pipeline probe build** produces a Linux x86-64 probe
and build metadata. It does not package production configuration, messages or trained
models. Its schema-2 `build.json` binds the executable, commit, Git tree and immutable
build image to `sources.json`, which lists hashes and modes of every tracked file,
including nested Rust/SQL modules, build scripts and runtime protocols. Capture
refuses a dirty checkout, symlinks, submodules or existing metadata. This is workflow
provenance, not a signature proving that an arbitrary executable was built from the
listed sources. Verify the workflow and artifact origin as well as their hashes.
Older probe metadata hashed only top-level Rust files and cannot establish complete
source equivalence.

<a id="définir-les-cas"></a>
### Define cases

Create a private manifest such as `reports/cases.json`:

```json
[
  {
    "id": "wanted-text",
    "path": "wanted.eml",
    "source_ip": "192.0.2.10",
    "helo": "sender.example.test",
    "mail_from": "sender@example.test"
  }
]
```

The probe accepts one to eight cases, 1–100 measured iterations per case and 1–5
warmups per case. Paths may be absolute or relative to the manifest. Each input must
be a regular, valid message file of at most 1 MiB. Use case identifiers without
private information. The documentation IP above is synthetic; it does not establish
authentication. Supply the actual recorded SMTP context when measuring authentication,
or clearly identify a synthetic context.

Configure the models and connectors being measured. Record CPU architecture, CPU and
memory limits, concurrent workload, model hashes and scanner database versions.
Use the same thread limits when comparing configurations.

```sh
RAYON_NUM_THREADS=4 CANDLE_NUM_THREADS=4 TOKENIZERS_PARALLELISM=false \
  target/release/examples/pipeline_probe \
  --config config/local.toml --cases reports/cases.json \
  --output reports/pipeline.jsonl --iterations 30 --warmup 3 --interval-ms 100
```

Cases run sequentially on a Tokio runtime with four workers. Warmup calls are
recorded but excluded from quantiles, as are inter-call intervals. Measurements
include header rewriting inside `Engine::process`. This probe does not start an SMTP
server, enqueue messages or deliver mail; it is not an SMTP throughput test.

### External content and costs

Configured DNS checks and scanners run normally. A configured paid LLM requires
`--allow-paid-llm` and uses the durable shared budget under `data_dir`. Warmups may
also incur charges. Do not point the probe at a fresh budget directory to bypass a
limit. The flag does not grant permission to disclose private content: use authorized
inputs and explicitly approved external services. Synthetic messages can be used for
connector latency tests. An offline run and a run with DNS or LLM calls measure
different workloads.

<a id="lire-les-résultats"></a>
### Interpret the report

The JSONL output contains configuration, one record per call, and a final
`record: "summary", run_finished: true` record. A missing final record means the run
did not finish. Existing output files are refused.

Per-case p50, p95 and maximum timings use microseconds and the nearest-rank method.
`all_trials` includes incomplete analyses and errors. `complete_trials_only` is a
supplementary view, not permission to hide failed checks. Inspect component statuses:
a disabled, skipped, budget-limited or unavailable LLM did not complete a request.

Reports include scores, model versions, reason identifiers, component timings and
message hashes. They omit bodies, subjects, LLM explanations and feature vectors.
Keep private inputs and reports out of Git and apply an explicit retention policy.

Do not sum overlapping component timings. Do not pool synthetic cases as if their
frequency matched production traffic. A representative latency claim requires an
appropriate message distribution, complete accounting of failures and a documented
machine and concurrency profile. Capture and false-positive claims additionally
require independent human labels.

## SMTP concurrency and backpressure

The daemon uses Tokio tasks for concurrent SMTP connections and relay workers.
CPU-heavy inference and database work use bounded execution paths. Network checks
may overlap with inference. Their combined cost must be measured; adding threads
does not make every stage parallel.

Three limits have different roles:

- `smtp.max_connections` bounds concurrent SMTP sessions (default 128).
- `smtp.max_processing` bounds DATA reception, analysis and persistence together
  (default 4, configurable from 1 to 64, no greater than `max_connections`). A busy
  processing pool returns SMTP 451 before DATA so the sender can retry. Slow DATA
  uploads also occupy these slots.
- `relay.workers` bounds concurrent outbound deliveries (default 8).

The production example starts at `max_processing = 1` for a single semantic/OCR
worker. Increase it only after measuring complete analyses under load. Each active
DATA receiver also has a 64 KiB disk buffer; the message size limit is not an estimate
of total engine memory. Semantic waiting and inference share a deadline, and a CPU
operation retains its capacity slot until it actually finishes, even after a timeout.

Size `TOKIO_WORKER_THREADS`, `RAYON_NUM_THREADS` and `CANDLE_NUM_THREADS` together.
Several pools configured to use every CPU can oversubscribe the machine. More clients
or DATA slots can increase throughput while making more analyses incomplete.

### Reproducible SMTP load test

`scripts/smtp_load.py` creates a new private spool, starts the selected binary and
sends synthetic messages to a local SMTP sink. It does not import the production
configuration and does not allow a remote recipient. Existing output directories are
refused. Workload size, concurrency and duration are bounded. On Linux, enforce CPU
and memory limits with systemd or an isolated container and record those limits.

```sh
python3 scripts/smtp_load.py --binary ./noisefence \
  --output-dir /var/tmp/nf-load-small-unique --messages 200 --concurrency 8 \
  --processing 4
python3 scripts/smtp_load.py --binary ./noisefence \
  --output-dir /var/tmp/nf-load-large-unique --messages 40 --concurrency 4 \
  --message-bytes 1048576 --processing 4
```

These basic examples omit trained models and scanners. Add `--lexical-model`,
`--semantic-encoder`, `--semantic-combination` and the appropriate
`--antivirus-socket`, `--signatures-socket` or `--vision-socket` to exercise them.
Use `--native` to include native rules with an empty Bayes model and fuzzy store;
it does not train or import a model. `--protection` includes local advisory checks
without external provider calls. Report untrained and unconfigured capabilities
separately from completed checks.
A vision worker receiving a text-only fixture does not measure OCR throughput.
Omit `--processing` only when comparing older binaries that do not support the setting.
Use identical hardware, software and inputs when comparing settings.

The summary reports software/model hashes, component statuses, complete/incomplete
analyses, accepted and delivered throughput, and acceptance latency including retries.
The top-level `complete` count describes core analysis; it does not assert that every
supplementary check completed. The summary reports statuses for semantic, antivirus,
signatures, vision, LLM, mailing, native rules/Bayes/fuzzy, local protection, feed,
campaign, CRDF and VirusTotal. Missing/null reports remain `absent`,
malformed statuses become `invalid`, and unknown status strings remain visible.
An HTML complexity limit can produce `limited` for native/local protection while
core analysis remains complete. Preserve those cases and do not present their latency
as successful full analysis. Inspect retained scans for details and any additional
components introduced by a newer binary. URL resolution has per-chain completeness,
not a single status field, and is disabled in this offline load test.
It verifies every synthetic identifier, detects missing/extra/duplicate deliveries,
checks exact body preservation and durable `delivered` state, and runs SQLite integrity
checks. `correctness_passed` proves those delivery checks, not detection quality or
analysis completeness. A failed delivery check produces a failure report and a nonzero
exit status.

Daemon RSS is sampled every 100 ms and CPU time comes from the daemon process.
Scanner services are excluded; the Python sender/sink and monitor still consume
resources on the benchmark machine. The true memory peak can exceed a sampled peak.
The test includes the first messages after startup but excludes model-loading time
from the traffic interval. Both SMTP hops use plaintext loopback. Separate tests are
needed for TLS, peer replication, failover, Proton and real sender retry schedules.

## Historical measurements

The following results describe September 2026 experiments on early 0.3 development
builds. Their settings and prices are historical observations, not current production
configuration or recommendations. They do not qualify a later release.

<a id="mesure-du-7-septembre-2026"></a>
### Pipeline measurements, 7 September 2026

The [aggregate report](../research/pipeline-latency-20260907.json) covers
`0.3.0-dev.5` with `research-hybrid-e5-20260907` on Debian 13, nominally 4 vCPU and
8 GB RAM. Each of three sequential profiles measured four synthetic cases 30 times
after three warmups, with concurrency 1. All 360 measured analyses completed without
errors. Both local scanners and configured DNS checks were active. No messages were
delivered.

| Synthetic case | Size | p95 without LLM | p95 LLM range 20–98 | p95 LLM range 80–98 |
| --- | ---: | ---: | ---: | ---: |
| French professional email | 836 bytes | 257 ms | 2,104 ms | 1,207 ms |
| Short French message | 435 bytes | 68 ms | 1,027 ms | 67 ms |
| Synthetic wallet lure | 502 bytes | 127 ms | 119 ms | 132 ms |
| Repeated French paragraph | 1 MiB | 389 ms | 1,623 ms | 1,605 ms |

Raising the lower LLM boundary to 80 skipped the short message, whose local score
was 49.42. This explains that case's improvement; variations in other cases do not
establish an effect of the setting. The lure exceeded the upper boundary of 98 and
never called the LLM. The paid profiles made 165 requests including warmups and added
EUR 0.035320 to the shared ledger. This is the cost of that experiment, not a current
price or average cost per incoming email.

For the historical schema-3 rule, the maximum positive LLM contribution was 1.5
logit units. At the configured threshold of 95, a starting index of 80 could reach
at most `100 × sigmoid(log(80/20) + 1.5) = 94.7165`. Because this transformation is
monotonic, calls below 80 could not cross that particular threshold. Replaying the
120 recorded decisions and testing the 80–98 profile did not change classifications
for these cases, although scores, reasons and completeness could change. This
calculation is specific to that implementation and its weights; 80 is not a universal
boundary.

The change still left LLM cases above the 500 ms target. The 1 MiB repeated-text case
crossed the content threshold after LLM advice and required a separate quality review.
Four unsigned, repeated fixtures cannot establish capture, false positives or actual
traffic p95. Detailed inputs and measurements remained private.

<a id="vérification-de-la-version-030-dev11"></a>
### Follow-up on 0.3.0-dev.11

The [follow-up report](../research/pipeline-latency-0311-20260907.json) used the same
four cases, machine and models with the exact `0.3.0-dev.11` code. The measurement
profile disabled the LLM; production remained in observation. DNS, SMTP policy,
the hybrid model and both scanners were included.

| Synthetic case | Size | p95 without LLM |
| --- | ---: | ---: |
| French professional email | 836 bytes | 279 ms |
| Short French message | 435 bytes | 77 ms |
| Synthetic wallet lure | 502 bytes | 130 ms |
| Repeated French paragraph | 1 MiB | 428 ms |

All 120 measured calls completed without errors, after 12 warmups. Quantiles were
recomputed from the 132 retained observations. Observed process peak memory was
1,253,998,592 bytes, excluding scanner services. No mail was delivered or new paid
calls made; configuration and models were preserved.

The report records the release commit and a recursive source fingerprint. Its older
workflow fingerprint, which omitted Rust submodules, is identified separately. It
does not measure LLM-enabled latency, concurrent traffic, capture or false positives.
No threshold was tuned from these fixtures.

<a id="résultats-sur-le-vps-du-8-septembre-2026"></a>
### SMTP load on 0.3.0-dev.12 and 0.3.0-dev.13

The [full report](../research/smtp-capacity-20260908.json) includes successful and
incomplete profiles on Debian 13 with 4 vCPU and 7,757 MiB RAM. The daemon and client
shared a three-core, 3 GiB limit; scanners used their existing services. Official
release archives were compared without production configuration or real messages.

| Synthetic profile | Messages / clients | Old delivered throughput | New delivered throughput | Complete analyses, new build |
| --- | ---: | ---: | ---: | ---: |
| 1 KiB text, no model/scanners, 4 processing slots | 200 / 8 | 7.99/s | 151.36/s | 200/200 |
| 1 MiB text, no model/scanners, 4 processing slots | 40 / 4 | 6.39/s | 12.99/s | 40/40 |
| 1 KiB burst, no model/scanners, 16 processing slots | 1,000 / 128 | Not measured | 149.52/s | 1,000/1,000 |
| Model + antivirus, 1 processing slot, 4 CPU threads | 100 / 8 | Not measured | 2.91/s | 100/100 |
| Model + antivirus, 2 processing slots, 2 CPU threads | 100 / 8 | Not measured | 4.85/s | 100/100; no images |
| Model + antivirus + image/QR, 1 processing slot | 20 / 8 | Not measured | 1.35/s | 20/20 |
| Model + antivirus + image/QR, 2 processing slots | 20 / 8 | Not measured | 6.08/s | **4/20; OCR busy for 16** |

Delivering 200 small messages decreased from 25.02 to 1.32 seconds. For 40 large
messages, acceptance p95 decreased from 785 to 315 ms and sampled daemon CPU time
from 10.64 to 1.26 seconds. All 2,120 messages across the experiments were present in
the sink and durable `delivered` state, with no duplicates or altered bodies.

The selected historical profile used one processing slot, one semantic worker,
four computation threads and eight relay workers. Text analysis p95 was **339 ms**,
with observed daemon peak RSS of 1,154,224,128 bytes. For a 1,300 × 650 image in an
approximately 27 KiB message, p95 was **672 ms** and all 20 texts and QR codes were
decoded. That OCR case exceeded 500 ms. Two processing slots improved text throughput
but saturated the OCR worker on mixed mail.

With four processing slots and one semantic worker, only 2/100 old-build analyses
and 3/100 new-build analyses completed under the burst. Increasing concurrency alone
was not sufficient. The selected text run recorded 163 SMTP 451 replies and
acceptance p95 of 30.71 seconds including retries; the OCR run recorded 79 such
replies and acceptance p95 of 13.68 seconds. Internet senders may retry much later.
**Analysis p95 is not arrival latency under load.**

To reproduce the OCR fixture, install Pillow, `qrencode` and DejaVu fonts, then use
`scripts/smtp_load_vision.py` with the text benchmark options and `--vision-socket`.
It uses the public synthetic image in `tests/vision_worker.py` and checks decoded
text and QR output for complete responses. The old `0.3.0-dev.13` archive contains
the text benchmark; the OCR extension and report are in the repository. DNS and LLM
were excluded only from those isolated tests. Sustained capacity with current
software, representative traffic, TLS, replication and Proton remains a separate
measurement.
