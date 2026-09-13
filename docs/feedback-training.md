<a id="apprentissage-à-partir-des-corrections"></a>
# Learning from corrections

The `export-learning` command retains schema 3 features and multi-lingual encoder vectors after removal of the delivered bodies. It does not use raw emails. The export is private: the learned characteristics are not anonymization and should not be published with the source code.

Since 0.3.0-dev.8, the additional field [evidence](decision-evidence.md) retains the reliable controls of the new SMTP sessions. Local, manually provided and historical contexts remain excluded from this field. The current content trainer ignores; he prepares the necessary entries for a future fusion learned.

## Export

```sh
noisefence --config /etc/noisefence/config.toml export-learning feedback.jsonl --require-semantic
```

The JSONL `noisefence-learning-1` output contains a pseudonym ID, the dates of receipt and correction, the human label, the campaign prints, the lexical characteristics and, if available, the semantic vector with its encoder, revision, prefix, method of normalization and limits. It does not contain any object, body, sender, recipient/BCC or user account. It is not accessible in the console API.

Only active account corrections still having a right to an envelope recipient are retained. Disagreements, automatic notifications, incomplete local extractions and metadata of more than 30 days are excluded. A DNS, scanner or LLM failure does not remove a correction whose local characteristics are complete and verified. This status is recorded before external checks; an old incomplete analysis without this status remains excluded. The `exported_with_incomplete_checks` counter makes this distinction visible. It does not change delivery without a prefix in case of incomplete analysis. The old lines without a verifiable campaign footprint or protocol are not reconstituted by supposition. Exclusions are counted in the result. `--require-semantic` excludes lines whose encoder is not exactly the expected one; omiting allows a lexical candidate.

The export reads a SQLite snapshot in WAL, written in stream in a temporary file 0600, synchronizes the data and replaces the previous output atomically. An invalid read error or vector preserves the previous full export. This command does not return to the queue and does not change the status of the deliveries.

<a id="entraîner-un-candidat"></a>
## Train a candidate

For a correction that preserves the reference model and a rehearsal corpus, see [corrective learning](corrective-learning.md). The program below fits a complete model from available corrections.

The digital runtime is separated from the SMTP service. The versions of `research/requirements.txt` are pinned; use a Python environment compatible with these versions (e.g. Python 3.11). No download of encoder is necessary: its vectors are already registered by Rust.

```sh
python3.11 -m venv /opt/noisefence-learning
/opt/noisefence-learning/bin/python -m pip install -r /opt/noisefence/current/research/requirements.txt

OPENBLAS_NUM_THREADS=2 OMP_NUM_THREADS=2 /opt/noisefence-learning/bin/python \
  /opt/noisefence/current/research/train_feedback.py \
  feedback.jsonl candidat-nouveau --hybrid
```

The destination folder must be new. `--hybrid` requires a compatible vector for each line; it does not fold silently on a lexical training. Without this argument, the lexical features alone are used.

The treatment includes canonical prints and distant SimHash of up to three bits, eliminates groups with contradictory labels and retains one representative per group. This heuristic does not guarantee the detection of all variants of a campaign. The partitions per group are 60% training, 10% development, 10% calibration and 20% test. Each partition must contain both classes; otherwise the treatment fails without publishing a candidate.

The test does not select weights, hyperparameters, or thresholds. The test results are based on the weight of the tester and the weight of the tester are adjusted only on the training. The adjustment, the lexical model and the semantic combination are selected on the development. The threshold uses only legitimate calibration messages.

The published atomic file contains `model.json`, `report.json`, `predictions.json` and, for hybrid mode, `native-combination.json` linked to the exact SHA-256 footprint of the lexical model. All of these files remain private. Predictions allow you to control the match with Rust without keeping the bodies. There is neither executable pickle nor network access during training. The `--aggregate-only` option omits `predictions.json` and retains the aggregate weights and metrics. Periodic service always uses this option. A valid dataset that lacks examples of both classes returns code 3 with `status: insufficient_feedback`, without a candidate; an invalid export or an error of the solver remains a separate failure.

<a id="exécution-périodique-et-limites"></a>
## Periodic implementation and limitations

`deploy/noisefence-train.service` chooses the pipeline according to the configured model: legacy Rust training for historical characteristics, new runtime for the 3 scheme. The Python environment must be prepared before turning on the timer for the latter. Another path can be indicated by `NOISEFENCE_TRAIN_PYTHON` in `/etc/noisefence/training.env`.

The service is limited to two CPUs, 4 GB of memory and 35 minutes, with a disabled network and an OOM priority less favorable than the SMTP service. A lock prevents two simultaneous training runs. Exporting and training use the same resolved release of binary, even during an update. Candidates are written in `/var/lib/noisefence/models/candidates/`; `latest-candidate.json` is the last successful training run. A failure preserves the previous candidate. The snapshot of the service is found in the private `/run/noisefence-learning` directory, managed by `RuntimeDirectory` of systemd. It is deleted after processing, including during a sudden termination of the service; a restart of the server also erases this temporary storage. This behavior is tested under Linux with normal output and SIGKILL. Aggregated applicants are prepared on their file system and then published by atomic renamation. They do not contain any list of messages, individual labels, or message vectors. A sudden shutdown can leave a `.candidate-stage-*` folder of partial weight, without any guarantee. Partial output is never treated as a validated candidate.

`last-training.json` indicates `candidate_prepared`, `insufficient_feedback` or `failed`, with aggregated dates and meters. A lack of corrections lets the service end normally and preserves the previous candidate. A real error fails; a sudden termination is also visible in the systemd state and can prevent the writing of the last JSON status. The service creates its directories at the first boot.

After installation of runtime and release:

```sh
sudo install -m 0644 /opt/noisefence/current/deploy/noisefence-train.service /etc/systemd/system/
sudo install -m 0644 /opt/noisefence/current/deploy/noisefence-train.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl start noisefence-train.service
sudo systemctl enable --now noisefence-train.timer
sudo cat /var/lib/noisefence/models/last-training.json
systemctl status noisefence-train.service noisefence-train.timer
```

A manual launch can choose a private directory with `--scratch-directory`. Without a systemd, it does not benefit from cleaning after SIGKILL. Manual exports, individual search predictions and backups must be purged separately depending on the storage at 30 days; they are not managed by the timer.

**A candidate from the only corrections always wears `eligible: false`.** The reported errors are a biased sample, and the same tests can be reviewed during periodic training. Therefore, the report does not allow any automatic activation. A recent, independent and representative evaluation of the complete chain is required before the marking is activated. A hybrid model must be deployed with both compatible files; replacing its only lexical model would invalidate the verified link at startup.

Corrections may be incorrect or abusive. Grouping limits the over-representation of the same campaign; it does not replace the review of data and does not guarantee resistance to poisoning by an authorized account.
