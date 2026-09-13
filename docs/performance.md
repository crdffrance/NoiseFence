<a id="mesurer-le-traitement-complet"></a>
# Measuring the complete processing

`model-benchmark` measures local extraction and inference. To measure connectors as well, the `pipeline_probe` bench calls the same `Engine::process` as the SMTP reception, several times in a single process. It loads the model once and keeps caches between tests. It does not start any SMTP server, does not file any messages and does not deliver any emails.

```sh
cargo build --release --locked --features semantic --example pipeline_probe
python3 tests/pipeline_probe.py target/release/examples/pipeline_probe
```

The manual workflow `pipeline probe build` also provides a Linux x86-64 executable with the prints of the executable, engine and bench sources. It does not contain production configuration, corpus, or driven model.

<a id="définir-les-cas"></a>
## Define cases

Create a private manifest, here `reports/cases.json`, containing one to eight cases:

```json
[
  {
    "id": "legitime-texte",
    "path": "legitime.eml",
    "source_ip": "192.0.2.10",
    "helo": "sender.example.test",
    "mail_from": "sender@example.test"
  }
]
```

The path is relative to the manifest, or absolute. Each message must be a regular, valid file of size less than or equal to 1 MiB. Case names are identifiers, without private content. The example IP address above is reserved for documentation: it does not represent an authenticated sender. For DNS checks, indicate the context actually observed at the reception or explicitly document the synthetic character of this context.

The configuration must designate the models and connectors to be measured, with their usual parameters. Keep the same number of CPU threads and the same limits as on the reference server. Save CPU, RAM, concurrent load, model fingerprints and version of the antivirus databases separately.

```sh
RAYON_NUM_THREADS=4 CANDLE_NUM_THREADS=4 TOKENIZERS_PARALLELISM=false \
  target/release/examples/pipeline_probe \
  --config config/local.toml --cases reports/cases.json \
  --output reports/pipeline.jsonl --iterations 30 --warmup 3 --interval-ms 100
```

The bench executes cases sequentially, with four workers Tokio. The heating cycles are shown in the file but are excluded from the quantiles. The interval between calls is also excluded. The measurements include `Engine::process`, including the rewriting of headers, but exclude file playback, model loading, SMTP reception, persistence and relay. It is not a flow or overload test of the SMTP server.

## External content and costs

DNS checks and scanners follow the engine configuration. A paid LLM configured requires the explicit flag `--allow-paid-llm`. It can receive authorized text extracts and uses the sustainable budget of `data_dir`. Do not replace this directory with an empty directory to bypass the budget. Heat cycles can also produce paid calls.

Use only authorized content for these connectors. External cost and latency testing can be done on synthetic messages. The results of a private message analyzed without a network are not comparable to a whole chain test with DNS and LLM.

<a id="lire-les-résultats"></a>
## Read the results

The JSONL file starts with the check configuration, contains one line per call, then a `record: "summary", run_finished: true` summary. The absence of this summary indicates a missed or failed execution. An existing file is refused; the bench does not overwrite an earlier measure.

Each case has p50, p95 and maximum in microseconds, by nearest row, as well as the number of complete, incomplete and error analyses. Chess remains in `all_trials`. `complete_trials_only` is a complementary view: it must not hide outdated deadlines or services unavailable. Also check the status of components: a LLM limited by the budget or deemed useless did not execute a complete request.

The score, version of the model, the reasons and the durations of the components are recorded, without body, object, LLM explanation or vectors of characteristics. The report contains the imprint of the message. Private entries and results remain excluded from Git; their retention is the responsibility of the operator.

Do not add up all the durations of the components: some controls overlap. Do not aggregate several cases as if they represented the actual frequency of these messages. A p95 on some synthetic messages checks these cases on this machine; it does not demonstrate the p95 of the actual traffic, nor the capture, nor the false positives. Then measure a recent representative set, with the status of the controls and the uncertainties, before any global claim.

<a id="mesure-du-7-septembre-2026"></a>
## Action of 7 September 2026

The [aggregate report](../research/pipeline-latency-20260907.json) measures engine 0.3.0-dev.5 and `research-hybrid-e5-20260907` on Debian 13 with nominal 4 vCPU and 8 GB RAM. Each profile runs 30 measurements after three warmups for each of four synthetic messages. Profiles run sequentially with concurrency 1. All 360 measured analyses completed without errors; both local scanners and configured DNS checks were active. No messages were delivered.

| Synthetic case | Taille | p95 without LLM | p95 LLM 20–98 | p95 LLM 80–98 |
| --- | ---: | ---: | ---: | ---: |
| French professional e-mail | 836 bytes | 257 ms | 2 104 ms | 1 207 ms |
| French Short Message | 435 bytes | 68 ms | 1 027 ms | 67 ms |
| Synthetic wallet lure | 502 bytes | 127 ms | 119 ms | 132 ms |
| Repeated French paragraph | 1 MiB | 389 ms | 1 623 ms | 1 605 ms |

The low 80 markup removes the LLM call from the short message, whose local score is 49.42. The gain on this case is explained by this avoided call. The variations of other cases between executions do not show an effect of setting. The fictitious decoy already exceeds the high 98 markup and does not call the LLM in any profile. The two paid profiles total 165 requests, including heating, and an increase in the shared registry of €0.035320. This amount describes these tests, not an average rate per email received.

For scheme 3 and threshold 95, the maximum positive LLM adjustment is 1.5 in the sigmoid scale before transformation. Starting with a score of 80, it leads to at most `100 × sigmoid(log(80/20) + 1.5) = 94,7165`. The transformation is increasing: therefore, calls below 80 cannot cross the threshold. The high limit remains at 98. The rereading of the 120 recorded decisions, then the separate test of profile 80–98, does not change any ranking on these cases. The scores, reasons and indicators of completeness of omitted calls may change. This justification must be recalculated if the threshold or weights change; 80 is not a universal value to be copied in any configuration.

This setting is active on the observation pilot server. It does not solve the 500 ms exceedance for cases still using the LLM. The repeated load text on 1 MiB crosses the threshold after the LLM notice: this behavior requires a separate quality assessment. These four cases, unsigned and repeated, do not allow to publish any false positives rates or p95 of the actual traffic. Detailed entries and measurements remain private; the public report contains their fingerprints and aggregated results.

<a id="vérification-de-la-version-030-dev11"></a>
## Verification of version 0.3.0-dev.11

The [follow-up report](../research/pipeline-latency-0311-20260907.json) uses the same four cases and server with the exact 0.3.0-dev.11 code and unchanged models. Only the measurement profile disables the LLM; the production configuration remained in observation. DNS, SMTP policy, the hybrid model and both scanners were included in measured processing.

| Synthetic case | Taille | p95 without LLM |
| --- | ---: | ---: |
| French professional e-mail | 836 bytes | 279 ms |
| French Short Message | 435 bytes | 77 ms |
| Synthetic wallet lure | 502 bytes | 130 ms |
| Repeated French paragraph | 1 MiB | 428 ms |

The 120 measurements, after 12 heat calls, are complete and error-free. Quantiles have been recalculated from the 132 observations kept. The observed memory peak of the process is 1,253,998,592 bytes; it excludes scanners, which run in their own services. No email is delivered and no new pay calls are made. The file, models and production configuration are preserved.

The report links the proof to the commit of the version and to the recursive footprint of its sources. The old workflow print, which omits the Rust submodules, remains separately identified. Statuses and durations are retained without content. This result does not measure the profile with LLM, competition, p95 of the actual traffic, capture or false positives. No threshold has been adjusted from these cases.

## SMTP and relay concurrency (0.3.0-dev.13)

The daemon already uses the Tokio multithread runtime: one task per SMTP connection and several competing deliveries. Semantic calculations and SQLite run in the blocking pool; the encoder also uses CPU threads. Network operations of scanners overlap with inference. MIME parsing and lexical extraction remain synchronous and limited in processing tasks; their cost is part of the measurements.

Three distinct limits control the server: `smtp.max_connections` (128 by default), `smtp.max_processing` (4 by default, between 1 and 64), and `relay.workers` (8 by default). `max_processing` covers the DATA download, analysis and persistence, and cannot exceed the number of connections. Each DATA occupies a slot; other senders receive 451 before the body and must try again. Slow uploads therefore also occupy a slot. Increase this limit consumes more memory and can saturate scanners. The DATA disk buffer adds 64 KiB per active processing; the message's limit size is not an estimate of the total memory of the engine.

With a semantic worker and an OCR worker, start with `max_processing = 1` as in the production example. Then mount according to the measurements; connections and deliveries remain competing. The waiting time of the semantic engine is shared with the inference, and a CPU task that goes beyond its time-limit retains its slot until it is complete. The OCR worker remains sequential and a configured LLM can still add latency: multiple connections do not multiply the capacity of these components. Incomplete results must be tracked separately. `TOKIO_WORKER_THREADS`, `RAYON_NUM_THREADS` and `CANDLE_NUM_THREADS` variables can limit pools; avoid dimensioning them each as if the others did not consume any core.

### Reproducible SMTP benchmark

`scripts/smtp_load.py` starts the selected binary, a **new private file** and a local SMTP receiver. No remote recipient is configurable. The bench never imports the configuration of the service and disables DNS, DQS and LLM. It refuses an existing directory. The parameters limit messages, size, competition and duration; under Linux, add systemd CPU/memory limits.

```sh
python3 scripts/smtp_load.py --binary ./noisefence \
  --output-dir /var/tmp/nf-load-small-unique --messages 200 --concurrency 8 \
  --processing 4
python3 scripts/smtp_load.py --binary ./noisefence \
  --output-dir /var/tmp/nf-load-large-unique --messages 40 --concurrency 4 \
  --message-bytes 1048576 --processing 4
```

Add `--lexical-model`, `--semantic-encoder`, `--semantic-combination` and options `--antivirus-socket`, `--signatures-socket`, `--vision-socket` to measure real local components. A configured worker vision here receives text without image: this checks its MIME path but **does not measure OCR rate**. Omit `--processing` to compare version 0.3.0-dev.12, which required four slots. The same binary and hardware must be used to compare settings. The messages are synthetic and repetitive; they do not constitute a quality evaluation dataset.

The summary contains the versions and prints, all the statuses of the scanners, the complete/incomplete analyses, the accepted and delivered flow rate, as well as the acceptance latency (including company). It checks each identifier, the absence of duplicates and the exact preservation of the bodies, then the durable state `delivered` and SQLite integrity. `correctness_passed` concerns delivery; also examine `complete` and `incomplete`. The program fails if delivery is not verified, but maintains a failure report. The peak memory sampled at 100 ms and the time CPU are on the demon, without the scanner services. The Python receiver, the journal and the monitor are part of the measurement environment; the actual peak may be higher than the observed sample.

These tests use SMTP plain on loopback, include the cold start of the first messages and exclude the loading time of the flow model. They complement STARTTLS tests, resume after existing interruption and access. They do not measure Proton's, TLS's, or real Internet traffic. Any message projection/day requires a sustainable representative profile.

<a id="résultats-sur-le-vps-du-8-septembre-2026"></a>
### Results on the VPS of September 8, 2026

The [full report](../research/smtp-capacity-20260908.json) retains all profiles, including those that skipped checks. It compares official 0.3.0-dev.12 and 0.3.0-dev.13 archives on Debian 13 with 4 vCPU and 7,757 MiB RAM. The isolated daemon and client together were limited to three cores and 3 GiB; scanners used their usual services. The benchmark did not use production configuration or messages.

| Synthetic profile | Messages / clients | Old delivered throughput | New delivery | Complete analysis, new version |
| --- | ---: | ---: | ---: | ---: |
| Text 1 KiB, light motor, 4 treatments | 200 / 8 | 7.99/s | 151.36/s | 200/200, without model or scanners |
| Text 1 MiB, light motor, 4 treatments | 40 / 4 | 6.39/s | 12.99/s | 40/40, without models or scanners |
| Rafale 1 KiB, light motor, 16 treatments | 1 000 / 128 | Not measured | 149.52/s | 1000/1 000, without models or scanners |
| Model + antivirus, 1 processing, 4 threads CPU | 100 / 8 | Not measured at this setting | 2.91/s | 100/100 |
| Model + antivirus, 2 treatments, 2 threads CPU | 100 / 8 | Not measured at this setting | 4.85/s | 100/100, no image |
| Model + antivirus + image/QR, 1 treatment | 20 / 8 | Not measured | 1.35/s | 20/20 |
| Model + antivirus + image/QR, 2 treatments | 20 / 8 | Not measured | 6.08/s | **4/20: OCR occupied for the remaining 16** |

The delivery of the 200 small messages is increased from 25.02 to 1.32 seconds. For the 40 large messages, the acceptance p95 is increased from 785 to 315 ms and the CPU time sampled from the daemon from 10.64 to 1.26 seconds. These comparisons include the Python receiver and durable scripts; they do not measure the TLS relay to Proton. The 2,120 messages from all the tests were found in the receiver and in durable condition `delivered`, without doubling or changing body.

The profile chosen for the server is `max_processing = 1`, a semantic worker, four calculation threads and eight relay workers. On the text, the p95 analysis is **339 ms**, with an observed RSS peak of 1,154 224 128 bytes for the daemon. With the synthetic image of 1,300 × 650 pixels (mail of about 27 KiB), the p95 is **672 ms**: the 20 texts and QR codes are decoded. The latter case exceeds the initial target of 500 ms. The two-processed profile is faster for the text, but its OCR saturation does not allow to retain it for mixed mails.

The old admission of four treatments produces only 2 full analyses in 100 during the burst with a semantic worker. The limited wait of the new version, alone, is not sufficient: at four treatments, 3/100 are complete. The adjustment of the admission is therefore necessary with these models and this material. It involves temporary answers before DATA: on the selected text lot, 163 responses 451 and a acceptance p95 of 30.71 seconds, included. On the selected OCR lot, 79 responses 451 and a acceptance p95 of 13.68 seconds. Real customers can wait much longer before their next attempt. The analysis p95 **** should not be presented as a latent of arrival under gust.

To reproduce the OCR case from the repository, with Pillow, `qrencode` and the installed DejaVu fonts, use `scripts/smtp_load_vision.py` with the same options as the text bench and `--vision-socket`. This complement uses the public image of `tests/vision_worker.py`, without private content; it also checks the text and QR for each complete OCR response. The v0.3-dev.13 archive contains the text bench; the complement and this report are available in the repository. The settings of the service's model, antivirus, OCR and LLM remain active; DNS and LLM have been excluded only from isolated testing. A sustained production capacity, with the actual traffic, TLS and Proton, remains to be measured.
