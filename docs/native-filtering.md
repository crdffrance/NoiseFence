<a id="mécanismes-de-filtrage-natifs-rust"></a>
# Rust native filtering mechanisms

Since 0.4.15, NoiseFence has a complementary observation engine, written in Rust. It transposes the principles of [Rspamd's components](https://docs.rspamd.com/configuration/composites/), its [similarity detection](https://docs.rspamd.com/modules/fuzzy_check/) and [statistical classifications](https://docs.rspamd.com/configuration/statistic/). The implementation is specific to NoiseFence: its results and formats are not interchangeable with those of Rspamd. The Lua modules and `.cf` rules do not load in this engine.

Since 0.9.0, a [structured bank of twelve rules](rspamd-rules.md) completes the patterns: HTML, MIME metadata and displayed identity. The names and first binary signatures of attachments are examined locally; they are not added to text or external calls.

<a id="activer-la-collecte"></a>
## Enable collection

Add this table to the configuration file and restart service after `noisefence --config /etc/noisefence/config.toml check-config`:

```toml
[native_filter]
mode = "observe"
max_bytes = 1048576
max_parallel = 2
timeout_ms = 500
fuzzy_memory = true
# bayes_model = "/var/lib/noisefence/native/candidate/model.json"
```

The absence of a table disables the module. `observe` is the only accepted mode: the calculated points do not change the historical score, nor the selection of the second review, nor the ranking, nor the delivery actions. A limited scan remains an unobserved observation. The existing Proton mode is independent of this table. The Bayes model is optional; `untrained` means that no weights are loaded.

The CPU analysis is performed outside of the Tokio asynchronous workers, with a limited number of tasks. Bursts wait for capacity in the total time budget. A cancelled task retains its permit until its actual end. The module does not contact any external service. SQLite memory has its own concurrency limit, a delay of 200 ms and a request interruption. The configuration imposes 1 to 8 tasks, 50 to 1,000 ms, 1 KiB to 2 MiB per message. The model artifacts are loaded at startup. Web revisions reuse the loaded model while applying validated rule and resource settings to future messages.

## Patterns and composites

`regex::RegexSet` compiles patterns by view: decoded object, visible text, and HTML. This is a Rust cluster search, with no C link to Hyperscan/Vectorscan. The old SPAM/PUB tags are removed from the object being analyzed; the old antispam headers, transport identities and attachments do not fit into textual features. The expressions apply to the limited views: 500 object characters, 32,000 text and 32,000 HTML. Maximum 200 MIME parts are allowed. Exceeding these views limit what the detector can see; a complete report refers to the controls on these views.

A given pattern table replaces the default bank, as well as composites. An autonomous minimum example to place after `[native_filter]`:

```toml
[[native_filter.patterns]]
id = "ACCOUNT_REQUEST"
label = "Account verification request"
family = "content"
weight = 0.5
target = "body"
pattern = '(?i)verify your account|confirmez votre compte'

[[native_filter.patterns]]
id = "ACCOUNT_URGENCY"
label = "Account-related urgency"
family = "content"
weight = 0.3
target = "body"
pattern = '(?i)immediately|immédiatement'

[[native_filter.composites]]
id = "ACCOUNT_PRESSURE"
label = "Urgent verification request"
family = "content"
weight = 1.0
all = ["ACCOUNT_REQUEST", "ACCOUNT_URGENCY"]
replace = ["ACCOUNT_REQUEST", "ACCOUNT_URGENCY"]

[native_filter.caps.content]
min = -0.5
max = 1.5
```

Names, weights and expressions are validated before starting. Limits: 256 patterns of 512 bytes, 64 composites, 32 references per composite, limited compilation memory. Unknown references, name collisions and cycles are denied. `all` imposes all the evidence, `any` at least one. `none` accepts only local patterns whose search is complete: the absence of a DNS or external result never becomes negative proof.

`replace` removes absorbed symbol weights once while retaining their reasons and consuming composites. Dependencies use deterministic evaluation order; repeated symbols do not multiply their weight. Families are `lexical`, `semantic`, `content`, `authentication`, `reputation`, `smtp`, `llm`, `campaign`, `bayes` and `other`. Each has positive and negative caps. Omitted families inherit defaults; caps are bounded to [-5, 0] and [0, 5].

The lexical contribution is capped by default at 1.5 points in this comparative calculation. The active calculation retains its original value. These ceilings are parameters to be assessed, not calibrated risk thresholds. The module never treats a score as a probability and does not infer consent to a PUB.

<a id="similarité-et-corrections-humaines"></a>
## Fuzzy similarity and human corrections

The text is standardized, cut into word trigrams and summarized by 32 min. chopped. Another print describes the order of the HTML elements, without their attributes. The sizes are limited to 2,048 tokens. The similarity compares the minima; the thresholds of 0.875 for text and 0.9375 for HTML are search thresholds, not statistical confidence levels.

The submission examines up to 1,000 recent messages with human corrections of still active and authorized administrators. It requires a single destination domain and at least 24 text shingles. Two separate originals reported spam and no corresponding legitimate examples allow an advisory symbol. The current message and its exact retransmissions are excluded. A similarity of HTML structure only remains informative, as legitimate newsletters and transactional messages also reuse templates.

Contradictory corrections prevent reinforcement. Originals of more than 30 days, deactivated accounts and withdrawn rights are excluded. An incomplete, saturated or interrupted request does not produce a positive symbol. Historicals lacking the new features are not rebuilt from their only objects or scores.

<a id="osb-bayes-et-évaluation"></a>
## OSB Bayes and evaluation

The Rust extraction uses separate word pairs of 1 to 4 positions in two distinct spaces for the object and body. Presences are chopped in 65,536 boxes, with a maximum of 8,192 unique characteristics per message. The model preserves the documentary frequencies per class, applies additive smoothing and balanced a priori. At the inference, a maximum of 150 known clues contribute; less than five gives `insufficient_features`. No verdict of the filter becomes a learning annotation.

Export domain corrections as an administrator, then select time lines **before** to view results:

```sh
noisefence --config /etc/noisefence/config.toml native-export \
  --username admin --domain example.org \
  --output /var/lib/noisefence/native/labels.jsonl

noisefence native-train /var/lib/noisefence/native/labels.jsonl \
  --output /var/lib/noisefence/native/candidate \
  --version osb-candidate-1 \
  --train-until "$TRAIN_UNTIL" --validation-until "$VALIDATION_UNTIL"
```

The two borders are UTC Unix seconds. Three periods: learning, threshold choice, final test. The exact and similarity grouping precedes the cutting: campaigns across a border or bearing contradictory labels are excluded and counted. Learning/validation labels must have been available before the end of their period. Each period requires at least 12 campaigns, two of which are in each class. This software minimum is much lower than the requirement of 0.1% false positives.

The threshold is selected only on validation, with an empirical rate of false positives at the most 0.1%. The final test retains this threshold. The report publishes recall, accuracy, false positives, unavailable results and 95% Wilson intervals. It keeps `may_activate: false` even when the results appear good. A private manifest keeps all the campaigns consulted, including excluded, to detect recoveries during a future independent test:

```sh
noisefence native-evaluate /var/lib/noisefence/native/new-labels.jsonl \
  --model /var/lib/noisefence/native/candidate/model.json \
  --manifest /var/lib/noisefence/native/candidate/manifest.json \
  --training-report /var/lib/noisefence/native/candidate/report.json \
  --output /var/lib/noisefence/native/independent-report.json
```

The evaluation checks the fingerprints of the files, the domain and the protocol; it requires observations after the model and counts campaigns already seen, duplicates and omissions. `independent` describes this separation; it does not certify a representative population or capture objectives. A new selection of the same messages to adjust the model would invalidate their use as an independent test. The classifier does not provide a calibrated probability. Its models expire 30 days after their creation. An expired model becomes unavailable and leaves the gateway to start; no Bayes contribution is produced. Independent evaluation also excludes observations outside the validity period of the model.

The files are created without crushing, with permissions 0600 (directory 0700). The vectors and fingerprints remain private despite their hashing. The retention base follows the 30 days of metadata; the operator must also delete exports, historical and models expired off base.

<a id="diagnostic-et-débit"></a>
## Diagnostics and throughput

The details of a message show the native result, the gross and capped contributions, the absorbed symbols, Bayes availability and campaign memory. The API applies the usual rights per recipient and only displays the report, without vectors, correspondence or text.

```sh
noisefence native-benchmark tests/fixtures/message.eml \
  --iterations 1000 --concurrency 4
```

The command is local: MIME normalization, OSB extraction, fingerprints, search and composites. It reports bitrate, p50/p95/p99, incomplete tasks and a comparison of 128 group/individual patterns with parity verification. It explicitly excludes the inference of a trained model, SQLite, SMTP, persistence and other analyzers. An acceleration on this measure therefore does not demonstrate the complete output of the server, nor an increase in antispam quality. Also use SMTP tests and `pipeline_probe` measurement for the complete system, with the models and services actually deployed.

<a id="contexte-des-motifs-depuis-050"></a>
## Context of patterns since 0.5.0

The search view normalizes the ASCII full hunt and certain invisible cut-off characters, without converting confusing alphabets into Latin letters or deleting multilingual joins. Active lexical models keep their entries. Inert HTML comments and blocks do not become native forms.

The optional field `exclude_negated = true` applies only to `target = "body"` motifs. Each correspondence is examined separately: local formulations such as "never provide", "do not enter" or "never communicate" are ignored. The native rule of requesting a recovery phrase uses by default. A warning in a sentence does not mask an explicit request in the following. This limited control in English/French does not constitute a general understanding of the speech or a white list: quotations, complex denials and content beyond sight remain cases to be measured on the recent corpus.

The native points also feed the calibrated candidate, in observation, with separate ablation. See [Reliability](reliability.md) for rule measurement, collection compatibility, limits and migration of 0.4.x models.
