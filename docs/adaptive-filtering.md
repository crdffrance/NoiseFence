<a id="catégories-adaptatives-locales"></a>
# Local Adaptive Categories

NoiseFence 0.8 adds an independent Rust module for `legitimate`, `publicity`, `spam`, `phishing` and `scam`. The binary Bayes and the delivery engine remain separate. This module is **exclusively in observation**: its category and proposed action does not participate in the score, marking or quarantine. A fraudulent advertisement must be annotated spam, phishing or scam; PUB here refers to a legitimate commercial campaign. An uncertain annotation remains empty.

## Algorithms and limits

Bayes uses the presence of OSB pairs, class-based documentary frequencies, additive smoothing, balanced a priori, and the 150 strongest discriminant characteristics. Less than five known characteristics result in forbearance. Standardized likelihoods are not calibrated probability of threat.

The 16×16×5 network uses a hidden tanh layer and a softmax output. Its inputs are text/HTML sizes and structures, six explicit local patterns (e.g. emergency, identifiers, yield, recovery phrase, form, unsubscribe), object length, capitals, digits, HTTPS links and exclamations. These entries are bounded and versioned with the configured patterns. The network does not use the verdicts of other models, composites, human corrections as characteristics, or the identity of a box. It completes the existing E5 encoder; it does not replace it and does not call it.

The training is deterministic, with balancing of classes, penalty L2, bounded weights and early stop on validation, at the maximum 120 epochs. Both classifiers must agree and exceed their thresholds and margins. A high softmax output alone is not enough. Failure, expiration or incomplete observation is not a spam signal.

## Collection and domain policies

The collection is disabled in the absence of configuration. Example to be incorporated into the existing configuration, without duplicate `[native_filter]`:

```toml
[native_filter]
mode = "observe"
max_bytes = 1048576
max_parallel = 2
timeout_ms = 500

[native_filter.adaptive.domains."example.org"]
# Omit model to collect before the first training run.
# model = "/var/lib/noisefence/adaptive/example.org/candidate/model.json"

[native_filter.adaptive.domains."example.org".classes.phishing]
min_strength = 0.95
min_margin = 0.25
proposed_action = "quarantine"

[native_filter.adaptive.domains."example.org".classes.publicity]
min_strength = 0.95
min_margin = 0.25
proposed_action = "tag"
```

The default values are 0.9 and 0.2, with `observe` action. `tag` and `quarantine` actions are **simulated**, including if the main filter is in application mode. No setting of this module allows to enable their execution. The legitimate class accepts only observation. A threshold from validation cannot be lowered by domain policy.

The domains are those of the **delivery recipients** after resolution of aliases. Each model has exactly one domain; no global training or folding on the model of another domain. An envelope aimed at several domains does not collect adaptive vectors and does not display any tenant predictions. This abstention also protects recipients in hidden copy. The rest of the analysis and delivery continues normally.

Maximum sixteen configured domains, 8 MiB per domain, five thousand examples per export. Inference re-uses workers, semaphores, MIME limits and overall time frame of the native filter. A cancelled worker retains its permit until its end. Model files are loaded on startup, never by message. A configuration or model change requires a controlled restart.

<a id="annotations-et-entraînement"></a>
## Annotations and training

In the message sheet, "Local Learning" allows to annotate one category per accessible domain. Phishing/scam also put the general correction to spam; PUB remains legitimate for binary risk. A new general correction removes the old precision. Remove only the detailed category leaves the general correction intact. Messages already delivered do not change.

The API uses existing sessions, origin and tokens. All readings and writings check the current rights on the recipients, the 30-day period and the account status. Exports require an active administrator account and also re-evaluate the current rights of the annotators. Conflicts between annotators are excluded; no prediction is automatically converted into human truth. Ancient spam/PUB annotations do not artificially become phishing/scam annotations.

```sh
noisefence -c /etc/noisefence/config.toml adaptive-export \
  --username admin --domain example.org --output /private/review/examples.jsonl

noisefence adaptive-train /private/review/examples.jsonl \
  --output /private/review/candidate --version example-20260912 \
  --train-until 1788825600 --validation-until 1788998400

noisefence adaptive-evaluate /private/review/future.jsonl \
  --model /private/review/candidate/model.json \
  --manifest /private/review/candidate/manifest.json \
  --training-report /private/review/candidate/report.json \
  --output /private/review/future-report.json
```

Adapt the Unix dates to the collected traffic. The three periods must contain at least **20 independent campaigns per class to the training**, then five per class to the validation and five in the test. These are technical minima, not proof of quality. Each annotation must have been available before the border of its period. Today's annotations on old messages do not allow to simulate an apprenticeship that would have taken place yesterday: continue collecting and setting realistic boundaries.

The exact prints and similar text sketches group the campaigns before the separation. Groups crossing a border or bearing contradictory categories are excluded. This method does not guarantee to recognize all the variants of a campaign; to audit the populations manually as well. The comparison budget refuses to accept too complex games.

The network and thresholds are selected on the validation alone. For a class to be able to issue a notice, validation requires at least five correct notices without error on the threshold grid. The test does not adjust any parameters. The manifest keeps campaigns of all periods and exclusions; the subsequent evaluation checks the prints of artifacts, dates and overlaps.

The reports give the 5×6 matrix (including forbearances), precision, recall, false positives and 95% Wilson intervals. False threat positives include legitimate categories and PUB. The confusion between these two categories remains visible in the matrix. Zero false positive on a small batch does not show a rate of less than 0.1%. No ratio allows automatic activation.

Run these commands off the SMTP path, possibly from a periodic operating task. Review the results before reference to a model in observation. There is no automatic retrain since the scores.

<a id="mesures-locales-confidentialité-et-retour-arrière"></a>
## Local measures, confidentiality and reverse

```sh
noisefence -c /etc/noisefence/config.toml adaptive-check /private/sample.eml \
  --domain example.org --iterations 1000
```

This command does not request DNS, delivery, or write in the queue. It restores the public ratio and the local p95 of extraction and native filter, with re-use of the model. It does not measure the full SMTP flow rate or latency of external services. Without the configured model, it measures the collection.

Private features remain in native observations during the retention of the message; queued messages follow existing rules. Annotations expire at 30 days, even if the message remains in queue. Exports do not contain bodies, attachments, or individual addresses, but their textual characteristics remain sensitive. Files created in 0600, candidate directories in 0700; the operator must delete expired exports and templates, no external files are deleted automatically.

This feature’s original migration was additive. Current paired installations require storage schema 5 and a compatible release. Do not downgrade the database, remove its HA marker or restore an older backup over accepted mail. See [installation](installation.md) and [HA recovery](high-availability.md) for current upgrade and rollback procedures.

## Inspiration and licensing

Independent implementation in Rust of published techniques, without copy of C/Lua code. Rspamd documents a [Multiclass Bayes](https://docs.rspamd.com/configuration/statistic/) separated from binary risk, as well as a [neural module](https://docs.rspamd.com/modules/neural/) learning from local signals. NoiseFence retains its own artifacts, limits and validation steps; no binary model compatibility is claimed. Rspamd is distributed under [Apache 2.0](https://github.com/rspamd/rspamd/blob/b86f72ae34ec515802aa23b60b535e9d25684d65/LICENSE.md); NoiseFence retains its GPL-3.0-only license.

## Translated labels and upgrades

Pattern labels are included in retained adaptive fingerprints. From 0.18.0, startup preserves saved labels when the installed defaults differ only in their display text and every semantic field and the pattern order still match. The installed model must still match that exact retained protocol, including when the module is disabled in the Web policy. Changing an expression, target, weight, family or order continues to require model validation. No historical policy or model file is rewritten by this compatibility step.
