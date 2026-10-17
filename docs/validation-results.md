# Validation status and reproducible checks

NoiseFence separates software verification, filter qualification and deployment validation. Passing the build does not establish a spam capture rate. A high internal index is not a calibrated probability.

## Filter quality

The targets remain **at least 95% spam recall** and **at most 0.1% false positives on wanted mail**, measured on a recent, independent population with confidence intervals. These are qualification targets, not established product guarantees.

Use [Filter quality](calibration-workbench.md) to freeze a representative sample, record recipient confirmations and compare NoiseFence with the separate Rspamd observer on the same messages. Keep wanted promotions distinct from spam: HAM/PUB describe wanted message categories; both belong to the wanted denominator for false-positive measurement. Rspamd and LLM opinions are predictions, never human labels.

A development report must retain:

- Message and campaign counts, label coverage, detector cohort and operating availability.
- Paired recall, false-positive rate, precision and confidence intervals, plus excluded or non-final verdicts.
- Five chronological, campaign-separated partitions for fitting, selection, calibration, threshold selection and development testing.
- Missing classes and additional campaign counts. More annotations of the same campaign do not provide independent examples.
- Base-model data provenance and a future, untouched qualification population.
- Frozen ablations that remove lexical, semantic, LLM, identity and reputation families. These expose dependence on correlated evidence or unavailable providers.

Risk fitting can proceed without complete mail-type labels when its own gates pass. An insufficient sample generates a readiness report and no candidate. A fitted shadow candidate does not authorize production enforcement. Raising a threshold, importing old public spam, or adding broad sender exceptions does not substitute for independent qualification.

Private traffic, subjects, addresses, raw messages, features and annotation evidence stay outside the public repository. Publish only an appropriately scoped aggregate report when its evaluation protocol and limitations can be stated. Never report a small development sample as a population guarantee.

## Software verification

The [checks workflow](../.github/workflows/check.yml) is the current list of automated gates. It covers Rust formatting/lint/tests, frontend types/lint/rendering tests, Python research/deployment tests, isolated PostgreSQL persistence, proxy limits and Linux container smoke tests. The container matrix includes amd64 and arm64. Release jobs validate the exact source revision and package checksums.

Useful local commands from the repository root:

```sh
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
python3 -m unittest discover -s tests_python -v
cd web
npm ci
npx tsc --noEmit --incremental false
npm run lint
npm test
npm run build
```

Python research tests require the locked dependencies in `research/requirements.txt`. Tests marked for disposable PostgreSQL, Linux systemd, OCR or container services need their documented fixtures; a skipped test is not a successful integration test. Inspect the exact commit's CI results, including deployment and architecture jobs, before releasing.

## Recovery and availability

An archive checksum or successful `pg_dump` is not a restored service. A recovery rehearsal must verify database identity, original MFA material, restored users and policy, revoked stale sessions, durable queued bodies, per-recipient delivery states and reconciliation receipts. Verify authenticated console login and SMTP fencing before allowing a worker to resume. Preserve the two-copy requirement and account for uncertain upstream acknowledgements. See [high availability](high-availability.md) and [PostgreSQL recovery](postgresql-development.md).

The [external probe](../deploy/external-monitor/README.md) checks DNS, verified STARTTLS, SMTP admission and HTTPS without submitting mail. It requires an independent host and a separate alert destination for off-host monitoring. It does not prove end-to-end delivery or authenticated console/database health.

Record the start/end times and exact tested source, dataset size, image/platform, failures and manual steps for every rehearsal. A synthetic local restore duration is not a production recovery-time guarantee. Test installation, upgrades and removal separately from disaster recovery; never overwrite an active queue to rehearse them.

## Delivery and performance

[Proton compatibility](proton-validation.md) must be verified for the actual domain and routing. Upstream SMTP acceptance does not prove inbox placement or ARC trust. Subject tagging remains a separate deployment gate from observation.

[Performance measurements](performance.md) must state hardware, message sizes, concurrency, cache state, provider availability and which stages are included. A MIME microbenchmark does not establish full SMTP throughput or the end-to-end p95 analysis target.

## Historical experiments

The [6 September 2026 development report](archive/validation-2026-09-06.md) is retained for traceability. Its old-corpus metrics, early test counts, infrastructure state and incomplete delivery experiments must not be quoted as current release results.

<a id="résultats-locaux--6-septembre-2026"></a>
<a id="connecteurs-de-la-version-de-développement"></a>
<a id="modèle-candidat--objectifs-non-atteints"></a>
<a id="rapidité-et-robustesse"></a>
Legacy section links now refer to the historical report above.
