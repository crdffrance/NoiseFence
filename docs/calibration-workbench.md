# Calibration workbench

NoiseFence 0.25 adds a reproducible research workflow under **Filter quality**. It does not claim perfect filtering or Rspamd-equivalent accuracy. A regression fix, agreement with Rspamd and a passing software test are different from measured performance on future mail.

## Prepare the data

Create a sample with an immutable purpose:

| Purpose | Intended use | May fit a candidate? |
| --- | --- | --- |
| Development | Training, calibration, threshold selection and development testing | Yes |
| Regression | Previously examined messages, including user-confirmed invoices and notifications | No |
| Independent holdout | Future traffic reserved for a frozen candidate | No |

Sampling is uniform among currently authorized messages in the selected period and domain. Development samples may select one detector cohort; holdout samples cannot filter out incompatible or incomplete observations. Administrators may draw up to 5,000 messages, other users up to 200. Selection is frozen and pagination does not redraw it.

Annotate risk and mail type separately. A wanted newsletter may be legitimate and a newsletter; it is not a spam example. “Uncertain” is not converted into a legitimate label. Annotation remains blind to scores. Inspect the original in your mailbox before labelling it.

Quality annotations are stored separately from operational Spam/Legitimate corrections. They neither create nor delete ordinary feedback, and ordinary feedback does not overwrite a quality label. Evaluation labels are excluded from periodic learning and live sender/campaign trust. Protected evaluation messages and nearby campaign fingerprints are excluded from content trainers. Quality fitting additionally removes whole connected campaign groups that overlap reserved references. Existing models cannot retroactively unlearn examples: their original training history must still be audited before claiming independence.

Previously reviewed regression messages must remain reserved. They are useful for detecting regressions, but cannot serve as an independent final test.

## Compare and train

Select a sample, then **Compare this sample**. NoiseFence and Rspamd are evaluated against the same human labels. Rspamd is an independent prediction, never an automatic label or training target. Reports include recall, false-positive rate, precision, confidence intervals, review counts, campaign-level metrics and mail-type slices. Timeouts, soft rejections and missing results remain review outcomes. Unlabelled messages are counted separately. PUB is a mail type, not a maliciousness label.

The historical 0–100 score is an index. Its reliability bins and Brier diagnostic do not turn it into a calibrated probability. Extreme scores on legitimate mail must be corrected using separate calibration data rather than arbitrary score scaling.

**Train a shadow candidate** fits the existing regularized risk/type model from a development sample. Five chronological partitions cover training, model selection, calibration, thresholds and testing. Campaigns crossing partitions are excluded. Each risk partition needs at least 12 independent campaigns with both classes. The mail-type head has its own readiness requirements; missing type annotations do not discard usable risk labels. Detector cohorts cannot be silently mixed.

The candidate learns the joint detector features, including availability and overlapping evidence. Ablations show whether lexical, neural, LLM, identity or reputation features help. It is not a replacement for independent human labels. An insufficient dataset produces a readiness report and no model. No provider is called by this workflow and no message is retransmitted.

The offline worker exports a consistent SQLite snapshot into private temporary storage, runs trusted release scripts, and verifies risk and mail-type prediction parity with the same Rust binary. Models are data-only JSON. The queue is global, limited to four pending/running jobs and 100 retained jobs. Revoked administrators cannot start jobs; interrupted jobs are marked interrupted rather than silently retried. Jobs, reports and labels follow the 30-day metadata window. Candidate files referenced by retained configuration revisions are kept for explicit rollback. Temporary feature exports are deleted when the worker exits.

## Observe, evaluate and roll back

Use **Use in observation** to select a prepared, unexpired candidate with a matching file hash and detector cohort. This creates a normal versioned configuration revision. The existing cluster artifact mechanism transfers the candidate and validates its digest on each MX. Upgrade all nodes before selecting a managed candidate. A policy/model change may invalidate its cohort; incompatible observations remain unavailable rather than receiving fabricated predictions.

Selecting an earlier compatible candidate rolls observation back. **Disable shadow candidate** stops candidate observation. Neither action changes the active delivery policy, the historical score, accepted messages or LLM budgets. Review the existing cluster status to verify every MX has applied the new revision; configuration distribution is asynchronous, not simultaneous.

After freezing a candidate, create a new holdout from later traffic and run **Evaluate on this sample**. The evaluation verifies campaign separation, chronology, base-model provenance and missing observations. A previously examined holdout cannot qualify as a fresh independent test. Both per-message and per-campaign results must be reviewed. Candidate selection bias, repeated tuning against a holdout and message families that dominate the sample invalidate broad accuracy claims.

The Web workbench activates **shadow observation only**. Final decision activation remains governed by the separate fusion promotion certificate and operational checks; a quality-model report is not a fusion certificate. No current production model is recalibrated or promoted merely by installing this release. Without enough independent labels, the honest result is “not validated”.

## Qualification and latency

The existing `noisefence-fusion-promotion-1` contract is unchanged: at least 10,000 legitimate and 2,000 unwanted test messages, its false-positive confidence bound and recall target, and total pipeline p95 below 500 ms.

The explicitly versioned `noisefence-fusion-promotion-2` contract separates local and external-service latency. It additionally requires:

- Native warm-cache p95 below 500 ms on at least 1,000 messages of at most 1 MiB, with a separate hashed benchmark report.
- A reviewed total pipeline p95 budget between 500 and 5,000 ms, also measured on at least 1,000 messages.
- Spam and legitimate review counts included in the respective class denominators.
- 95% Wilson recall lower bound at least 95%, false-positive upper bound at most 0.1%, and review-rate upper bound at most 5%.

The original minimum class counts, model/manifest/report hashes, full population accounting, review references and expiry checks remain mandatory. This is not an automatic relaxation of existing certificates. A recorded end-to-end latency cannot establish native latency. Neither contract replaces the real Proton compatibility checks required before subject marking.

## Install the Linux worker

Install the verified release normally on the coordinator. Use Python 3.11 or newer and the locked research dependencies:

```sh
sudo python3 -m venv /opt/noisefence-learning
sudo /opt/noisefence-learning/bin/pip install -r /opt/noisefence/current/research/requirements.txt
sudo install -m 0644 /opt/noisefence/current/deploy/noisefence-quality.service /etc/systemd/system/
sudo install -m 0644 /opt/noisefence/current/deploy/noisefence-quality.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now noisefence-quality.timer
```

The timer processes only explicitly requested Web jobs. It does not create samples, send notifications or retrain automatically. It runs without networking, as `noisefence`, with private temporary storage, two CPU equivalents, 4 GiB RAM and a 35-minute limit. Do not enable it on SMTP worker nodes. Service hardening/AppArmor policies must permit reading the verified research runtime and writing the existing private state directory.

Inspect `journalctl -u noisefence-quality.service` and the Web job status. The API does not expose subprocess stderr because it may contain private message-derived data. A failed job leaves the active model untouched. After a coordinator failover, install the same worker runtime before processing jobs; selecting an old, inactive candidate also requires its private files, which are not promised by active-artifact replication alone.

## Optional Docker worker

Build the optional target from the same source revision as the gateway:

```sh
docker build --target calibration -t noisefence-calibration:0.25.0 .
```

Run it alongside the coordinator with `--network none`, `--read-only`, `--memory 4g`, `--cpus 2`, a writable `/tmp` tmpfs and the same private data volume at `/var/lib/noisefence`. Mount the coordinator configuration read-only at `/etc/noisefence/config.toml`; keep UID/GID 10001 consistent. The gateway must initialize its database first. This worker image loops over user-requested jobs once per minute. It does not need published ports. The default final Docker target remains the smaller SMTP runtime.

Keep datasets, labels, campaign manifests, model weights derived from private traffic and archived messages out of GitHub. Publish only reviewed aggregate results and reproducible software tests.
