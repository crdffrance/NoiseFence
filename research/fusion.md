<a id="fusion-apprise-des-observations"></a>
# Fusion learnt from observations

NoiseFence can lead to and then evaluate an off-line decision based on the observations of the detectors. This chain produces JSON search models that can be executed natively in Rust. The service can compare this fusion model in observation, then use its decision after explicit validation. A candidate requires a recent representative test, the audit of his data, the measurement of the complete processing and the validation of delivery at Proton.

<a id="entrées-communes"></a>
## Shared inputs

The [versioned protocol](fusion-protocol.json) fixes 218 features and their terminals. Its print is on the exact bytes of the file; Rust takes these same bytes. The extraction uses exclusively the typical observations of `noisefence-evidence-1`: local bounded logits, authentication and alignments, DQS categories and roles, SMTP consistency, categories of scanners and LLM reviews. Each control keeps its status, including absence, unavailability and saturation. The values declared by the LLM are characteristics, not labels or already calibrated probabilities.

The historical score, manual weights, the score that selects LLM calls, labels, explanatory texts, identities and durations are excluded from the vector. The historical score remains available only for reference comparison. DQS error codes are refused; the categories of legitimate areas compromised do not become suspicious identity characteristics.

The artifacts identify the models actually loaded, the application version, the dependency lock, the semantic protocol, the control parameters and the prompt. An export mixing several configurations is refused. A prediction requires the same set of artifacts; a change in configuration or version must be the subject of a new experiment. The exact fingerprints of the definitions loaded by ClamD and the cloud revision of the LLM remain unknown when they are not attested by the suppliers.

<a id="préparer-un-jeu-privé"></a>
## Prepare a private dataset

After annotation allowed in the console, export the data:

```sh
noisefence --config /etc/noisefence/config.toml export-learning /private/path/learning.jsonl
noisefence fusion-export /private/path/learning.jsonl --output /private/path/vectors.jsonl
```

The second command is completely offline and does not load the server configuration. It only keeps the context from the SMTP reception. Analyses with a manually supplied envelope and old messages without observations are omitted with explicit meters. An export without exploitable SMTP observation fails. Incomplete controls remain present: we must not artificially improve the results by removing them.

The files are created atomically with `0600` rights, without overwriting an existing export. They remain sensitive even without body and must follow the 30 day retention. Corrections alone do not represent traffic: also annotate a predefined sample of correctly classified messages. Keep the drawing method and permission to use in the manifest.

Prepare `annotations.jsonl`, one line per export observation:

```json
{"id":"<64 hexadecimal characters>","campaign":"<campaign digest>","label":"legit","split":"train","language":"fr","kind":"invoice"}
```

Labels follow the [labelling protocol](labeling-protocol.md): `legit`, `spam`, `phishing`, `uncertain`. Preserve `unwanted_binary` when an older Spam correction has not been reviewed into a subclass. Certain annotations must agree with the exported human feedback. Exclude uncertain labels from fitting and metrics, and report their count.

Assign campaigns to five lots **before** experiment: `train`, `development`, `calibration`, `threshold`, `test`. Controls are transitively regrouping identical prints, declared campaigns, and SimHash at a distance of no more than three. Any group crossing two lots or the history of the basic models is failing the experiment. The conflicting binary labels are also failing. A deterministic representative per campaign is retained: metrics are for these representatives, not a rate weighted by the volume of copies. This grouping remains a heuristic to be completed by the audit.

Prepare `base-history.json` with the campaign footprints already used for the lexical and semantic models concerned. Also include the development, calibration, threshold and test batches already consulted to select these models. It is a question of choosing a separate fusion batch, not of reusing the driving predictions of the same engines:

```json
{
  "schema": "noisefence-base-history-1",
  "lexical_model_sha256": "<loaded model digest>",
  "semantic_model_sha256": null,
  "complete_for": ["fit", "development", "calibration", "threshold", "previous_tests"],
  "rows": [{"fingerprint":"<digest>","simhash":"<16 hexadecimal characters>","campaign":"<digest>"}]
}
```

Use `null` for an absent model. A loaded model prohibits an empty history. The completeness of this history must be verified; the software can detect a declared overlap, not prove the absence of an omitted campaign or audit the fundamental pre-training of a third-party encoder.

The `experiment.json` manifest binds files by SHA-256:

```json
{
  "schema": "noisefence-fusion-experiment-1",
  "version": "fusion-research-20260907",
  "purpose": "research",
  "protocol_sha256": "<SHA-256 of fusion-protocol.json bytes>",
  "vectors": {"path":"vectors.jsonl","sha256":"<digest>"},
  "annotations": {"path":"annotations.jsonl","sha256":"<digest>"},
  "base_history": {"path":"base-history.json","sha256":"<digest>"},
  "sampling": {
    "kind": "representative",
    "description": "<actual sampling method and scope>",
    "authorization": "<authorization reference>",
    "start_at": 1788739200,
    "end_at": 1788825599
  }
}
```

The paths are relative to the manifest, or absolute. Unix dates limit the reliable receiving dates exported. Use `corrections` or `synthetic` for these respective sources; a `representative` declaration remains to be audited. Exports are limited to 50,000 observations and 512 MiB. Each lot must keep both classes after grouping.

<a id="entraînement-calibration-seuil-et-test"></a>
## Training, calibration, threshold and test

Install locked dependencies in an isolated Python environment:

```sh
python3 -m venv /private/path/fusion-venv
/private/path/fusion-venv/bin/pip install -r research/requirements.txt
/private/path/fusion-venv/bin/python research/train_fusion.py fit experiment.json /private/path/candidate
```

The trainer adjusts a normalization on `train`, then a logistic regression L2 for `C ∈ {0.1 ; 1 ; 10}`. He chooses C on `development`, under the constraint of false positives of 0.1%, without priority class based on language. He folds the normalization in weights and bias for the Rust inference.

A monotonous sigmoid calibration is adjusted on `calibration`. The proportion of undesirables in this batch is recorded: the resulting probability is related to this mixture and the observed availability. The logit threshold is then selected on `threshold`, with a single threshold for all messages. Ex æquo remains indivisible, and a numerical margin separates the selected groups. The selection constraint is empirical; the final test also publishes statistical uncertainty.

The five variants are frozen before the test: content, content + identity, reputational addition, addition of scanners, together with LLM. These ablations remove families of characteristics on the same observations; they do not simulate the cost or effects of a new routing of connectors. In particular, the LLM opinion still depends on the historical call policy.

The model retains the availability profiles present in both training and calibration. An unknown profile cannot trigger the prefix. Incomplete analysis, an unavailability of control required or an ARC chain that cannot extend it also prevent it, even with a high logit. These cases remain in the denominator of the recall. The main contributions are expressed in logit; they explain the equation, not a causality or a proof of spam.

Evaluate the test, without readjustment:

```sh
/private/path/fusion-venv/bin/python research/train_fusion.py evaluate experiment.json /private/path/candidate
noisefence fusion-predict /private/path/learning.jsonl \
  --model /private/path/candidate/full.json --output /private/path/native-predictions.jsonl
```

`fit.json` binds manifest and fingerprint models. `test.json` contains TP/FP/FN/TN, recall, accuracy, false positives, 95% Wilson intervals, results by language, type, label and availability, Brier, log-loss and reliability diagram in the form of digital classes. The prints are reverified before evaluation; a test already consumed in this folder cannot be restarted. It remains consumed if the operator copies or moves the folder.

The documentary criterion requires at least 10,000 legitimate and 2,000 representative undesirables, an observed recall of at least 95% and an upper bound of the false positives consistent with 0.1%. No result of this chain is sufficient to permit production alone. Historical corpuses, corrections and synthetic examples are used for separate development and diagnosis.

<a id="vérification-logicielle"></a>
## Software verification

```sh
cargo build --locked --bin noisefence --example fusion_fixture
python3 research/verify_fusion.py var/fusion-parity
```

This control builds 400 synthetic observations, learns the five variants, varies all control families, compares 2,000 Python/Rust predictions and checks the rule without prefix for limited analyses, reputational errors and LLM saturations. It then checks 400 lines of a synthetic population and 2,000 additional predictions: absent data, old rankings, human conflicts, analytical limits and refusal to reuse the test. No email or detector call is produced. The IC executes this control with other tests; its success is not a measure of antispam quality.

<a id="décision-du-service-et-de-la-console"></a>
## Service and Console Decision

Without a `[fusion]` table, the historical behavior remains active with a persistent decision: `legitimate`, `unwanted` or `undetermined`. SMTP, message lists, search and statistics use the same recorded decision, even if the configured threshold changes later. Older records retain their historical score interpretation; incomplete analyses are not counted as unwanted. The legacy `scan.score` remains available for comparisons and LLM selection. Header contract version 11 groups the decision and its source in `X-NoiseFence-Policy`, while `X-NoiseFence-Verdict` carries the user-facing class. Incoming lookalike fields are removed before local results are added, and generated diagnostics are included in the ARC seal. LLM unavailability or saturation leaves the decision undetermined; voluntary skips and budget limits remain separate states.

To observe a candidate actually trained on the same detectors:

```toml
[fusion]
model = "/var/lib/noisefence/models/fusion.json"
mode = "observe"
```

The start-up checks the bytes of the model and the exact equality of its artifacts with the loaded detectors. `check-config` checks the configuration structure; the complete loading of the artifacts is performed at the start of the service. A change in version, dependencies, detectors or policy requires a new experiment. The `[fusion]` table is excluded from the fingerprint of the detector policy: it does not change their observations or the LLM selection and avoids a circular dependence between the candidate file and its entries.

In observation, `scan.fusion` keeps the result, the main contributions and the availabilities without changing the active decision. `scan.decision` is the result used for delivery. The console distinguishes this search comparison from the active ranking. Probabilities only make sense for the population and calibration profiles; contributions are not evidence. A diagnosis `scan` or `analyze` never becomes a SMTP reception.

`mode = "decision"` also requires `validation_report`, an admin review JSON folder, limited to 32 KiB, according to `noisefence-fusion-promotion-1`. It contains:

- SHA-256 of the bytes of the model, the frozen manifest, the test report, the population coverage and the latency of the complete treatment.
- `reviewed_at`, `observation_start`, `observation_end` in seconds Unix and a review reference `review_reference`. Review less than 30 days, observations less than 90 days; `sampling = "representative_smtp"`.
- `tp`, `fp`, `fn_count`, `tn` on the recent independent test, including cases without prefix due to lack of usable analysis. At least 10,000 legitimate and 2,000 undesirable; recall ≥ 95% and Wilson higher terminal at 95% of false positives ≤ 0.1%. No message left out of balance (`unaccounted_messages = 0`).
- `pipeline_p95_ms < 500` and `pipeline_samples >= 1000`, measured for messages ≤ 1 MiB, warm caches, on the reference machine and with active controls.

The exact names and types are defined in `src/fusion/runtime.rs` (`Validation`). These references and numbers are a ** review certificate**, not proof automatically verified by the hashes alone: audit and keep source reports, perimeter, independence, exclusions and measurements. Never copy the manufactured numbers of software tests to activate a real model. A `train_fusion.py` report on campaign representatives alone or on corrections alone does not attest to SMTP traffic coverage.

At the start and for each decision, the service reverifies the conditions and age of this certificate. An unvalidated profile, failure, incomplete analysis or expired attestation produces an indeterminate decision, without exploitable fusion score or prefix. The threshold is for the frozen raw logit; neither the rounding of the console nor `filter.threshold` replace this threshold. The observation of the detectors remains distinct from an unavailability of the fusion.

The prefix still requires `filter.mode = "tag"` **and** the valid Proton report already required by the gateway. The receipt remains in observation until this delivery validation is established. No training or user return automatically activates a new version.

<a id="couverture-de-toute-la-population-retenue"></a>
## Coverage of the entire population retained

`export-learning` selects usable text vectors. To audit its perimeter without concealing MIME boundaries or missing data:

```sh
noisefence --config /etc/noisefence/config.toml export-population /private/path/population.jsonl \
  --since 1788739200 --until 1788825600
```

Adapt these Unix terminals to a **real interval of the last 30 days**, included start and end excluded. The `noisefence-population-1` file contains a header, a line per incoming message retained and a final report, in a single SQLite transaction. Notifications generated by the service are counted separately. This scope covers accepted and retained messages, not SMTP refusals or already deleted metadata. It is never declared representative by default (`sampling = "unreviewed"`).

Each line keeps reliable timestamps, hashed identity, fingerprints of original bytes when available, campaign prints when computable, decision and SMTP observations typed. The gross print does not replace an absent campaign print. No sender, recipient, object, body, attachment or text vector is exported. The old absent fields remain unknown; no header provided by the sender reconstructs controls.

Votes are rechecked with active accounts and their rights in the same instant. Returns revoked, disagreements, absence of annotations, corrupted data, manually provided context and incomplete controls are counted and remain visible. An error of parsing kept at the base does not make the line disappear. Several recipients do not multiply the number of messages. Label meters are exclusive; availability meters can cover.

This report prepares the annotation and reconciliation with the test: it does not calculate capture rates from absent labels. A population still unknown or contradictory prevents to claim full coverage. The export is reserved for the CLI administrator, limited to 50,000 messages/512 MiB, atomic, `0600`, without crushing even in competition. Choose a shorter interval if necessary; no silent truncation. The files remain private and subject to the conservation of 30 days, even after removal of the bodies of the line.

<a id="évaluer-un-candidat-figé-sur-cette-population"></a>
## Assessing a candidate frozen on this population

The following native command keeps **all** lines, even without a label or campaign print. It does not load the configuration, does not consult the DNS and does not send any email:

```sh
noisefence fusion-population-predict /private/path/population.jsonl \
  --model /private/path/candidate/full.json --output /private/path/predictions.jsonl
```

It links the SHA-256 of the model to the same bytes as those parsed and that of the population to the bytes read up to the final report. Header, report, accounts, duplicated identities and JSON fields are checked. A truncated export does not publish any results. The output is atomic, `0600`, without replacing an existing file. The `automatic_dsn` and `invalid_scan` meters of the export v1 are not reconstructible per line; their terminals are verified and this limit remains declared.

A valid and compatible SMTP observation gives the same prediction as the native engine. An unknown failure or profile gives `would_tag = false` and remains in missed capture opportunities. An absent, invalid, non-SMTP or related to other artifacts gives `prediction = null`: it is a **unknown result**, never a real supposed negative. A model error interrupts the command. The completeness of the original detectors is true, not the decision of a former candidate stored in the message.

This result is hypothetical: it assumes a valid promotion review, the marking mode and Proton compatibility. `tagged` keeps the prefix recorded during the original processing; it should not be confused with the new prediction or with the final destination folder in Proton.

For a controlled assessment, prepare an annotation by population identity, without consulting the candidates' predictions.

```json
{"id":"<SHA-256>","label":"legit","campaign":"<SHA-256 or null>","language":"fr","kind":"invoice","basis":"reviewed","review_reference":"<human review reference>","reviewed_at":1788825600}
```

Labels are `legit`, `spam`, `phishing`, `unwanted_binary` or `uncertain`. `basis = feedback` requires consistent exported consensus. `reviewed` accepts human review of an unlabelled message or a label consistent with consensus. `adjudicated` requires an explicit review reference to resolve conflict or correct consensus. Unresolved cases use `basis = unresolved`, with `review_reference` and `reviewed_at` both `null`. Automatic scores are not annotations. Unknown campaigns remain `null`; do not invent a SimHash to fill a dataset. Review records can remain private without person names in this file.

The `population-evaluation.json` manifest uses the `noisefence-population-evaluation-1` schema and the following fields:

| Champ | Contenu |
| --- | --- |
| `population`, `annotations` | Each private file in `{ "path": "…", "sha256": "…" }` format |
| `experiment` | Original training manifest, in the same form bound by hash |
| `fit` | Received `candidate/fit.json`, bound by hash |
| `models` | Object with exactly `content`, `identity`, `reputation`, `scanners`, `full`, each bound by path and hash |
| `binary` | Binaire NoiseFence local audited, bound by path and hash; it will be executed |
| `sampling` | `kind`, `description`, `authorization`, `start_at`, `end_at`; same convention as training, exclusive end here and identical terminals to export |
| `review` | `reference`, `reviewed_at`, `blinded` and `independent_campaigns`; the last two are booleans attesting to the actual review |

Launch with the locked Python environment:

```sh
python3 research/evaluate_population.py /private/path/population-evaluation.json \
  /private/path/population-test
```

The evaluator checks the frozen files and launches the five variants of the binary itself. He does not retrain anything and chooses no new threshold on this test. He checks campaigns against **all** lines of the original experience, including its duplicates, uncertain cases and old tests, then against the history of the basic models. The grouping is transitive: identity, raw print, content print, declared campaign and distance SimHash ≤3. The absent fields never connect two lines between them.

The report publishes conditional measures on the only known results, their exact coverage, and then a conservative limit on all the known truth: an unknown result applies to a legitimate and FN for an undesirable. Unknown truths are counted separately and prohibit a conclusion on the entire population. The measurements by language, type and availability keep this same accounting.

Wilson's intervals per message imply the independence of messages, often violated by repeated campaigns. An additional measure of stability counts a legitimate campaign in error as soon as a copy is marked, and an undesirable campaign as captured only if all its copies are. Mixed or unknown truth campaigns remain reported. This conservative measure is not a bootstrap; its intervals still involve independent campaigns, to be audited.

`target_supported_on_this_population` requires a blind and representative review, no results or labels unknown, complete campaign prints, at least 10,000 legitimate and 2,000 unwanted **per message and campaign**, a low booster terminal ≥ 95% and a high mark of false positives ≤ 0.1%. This criterion is more demanding than the simple one-time target. `production_eligible` remains false: the latency of the complete treatment and Proton tests are separate validations.

A receipt is created before the predictions in the output folder and in `candidate/population-tests/<digest>.json`. A second execution on the same dataset with this candidate folder is refused, even to another release. Failure after the prediction starts also consumes the test. Copying the records, modifying the labels after examining the predictions or reusing the campaigns does not make the test new. Hashs and declarations prevent accidental confusion; they do not prove the sincerity of a review or the completeness of a history against an operator who would falsify them.

References: [probability calibration](https://scikit-learn.org/stable/modules/calibration.html), [threshold selection on separate data](https://scikit-learn.org/stable/modules/classification_threshold.html), [preventing train/test leakage](https://scikit-learn.org/stable/common_pitfalls.html#data-leakage).

## Version-2 candidates with family limits

Use experiment schema `noisefence-fusion-experiment-2` to fit the capped native
model. Keep all version-1 manifest fields and add an inline `combination` object:

```json
{
  "schema": "noisefence-fusion-family-caps-1",
  "families": {
    "lexical": {"minimum": -1.5, "maximum": 1.5},
    "semantic": {"minimum": -1.5, "maximum": 1.5},
    "authentication": {"minimum": -1.5, "maximum": 1.5},
    "smtp_policy": {"minimum": -1.5, "maximum": 1.5},
    "reputation": {"minimum": -1.5, "maximum": 1.5},
    "antivirus": {"minimum": -1.5, "maximum": 1.5},
    "signatures": {"minimum": -1.5, "maximum": 1.5},
    "llm": {"minimum": -1.5, "maximum": 1.5}
  }
}
```

These numbers are **synthetic verification values**, not recommended production
limits. Choose the policy using fitting/development data and freeze it before
calibration and the independent test. It is covered by the manifest hash. There
is no unbounded fallback for an omitted, unknown or invalid family. A version-1
manifest cannot silently acquire this field.

The fitting objective is regularized logistic loss over
`bias + sum(clamp(X_family * weights_family, minimum, maximum))`. Optimization
uses training-only feature scaling without centering so family origins remain
unchanged. Exported coefficients are converted back to native feature units.
Calibration sees the capped logits. The five frozen ablations, grouped/time
splits, immutable fitting receipt and single-use test policy remain unchanged.

Run fitting and evaluation with the existing commands:

```sh
python research/train_fusion.py fit /private/experiment/manifest.json /private/experiment/candidate
python research/train_fusion.py evaluate /private/experiment/manifest.json /private/experiment/candidate
```

For software-only verification, save the example policy object as
`/tmp/synthetic-family-caps.json`, build `noisefence` and `fusion_fixture`, and run:

```sh
cargo build --locked --bin noisefence --example fusion_fixture
python research/test_fusion_caps.py
python research/verify_fusion.py /tmp/new-capped-parity --family-caps /tmp/synthetic-family-caps.json
```

The parity verifier requires at least one prediction actually affected by a cap,
compares logits/probabilities/decisions across Rust and Python, and separately
checks population evaluation. It uses no real emails or external services.
Without `--family-caps`, it still verifies version-1 model compatibility.
Production activation requires a fresh version-2 promotion report bound to the
exact capped model; passing synthetic parity never supplies that report.
