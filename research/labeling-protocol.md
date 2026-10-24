<a id="étiquetage-et-validation-du-filtrage"></a>
# Labelling and filter validation protocol

Human labels describe the recipient's expected mail and any demonstrated threat.
They are separate from model predictions, recipient rules, delivery actions and
Proton's chosen folder. Use the [calibration workbench](../docs/calibration-workbench.md)
for the supported workflow and [model provenance](../docs/model-provenance.md)
for compatibility boundaries.

<a id="étiquettes"></a>
## Risk and mail type are separate

The quality workbench stores these risk labels:

| Risk | Meaning |
| --- | --- |
| `legitimate` | Wanted correspondence without an identified malicious purpose |
| `spam` | Unwanted solicitation, fraud or phishing; the positive **unwanted** target |
| `uncertain` | Insufficient context, unknown consent or unresolved disagreement |

Mail type is independently optional: `conversation`, `transactional`,
`notification`, `newsletter`, `promotion` or `other`. A wanted newsletter has
legitimate risk and newsletter type. An unwanted promotion has spam risk and
promotion type. A type label alone does not establish consent or safety.

The older fusion annotation format uses `legit`, `spam`, `phishing`,
`unwanted_binary` and `uncertain`. `legit` maps to the wanted binary class;
`spam`, `phishing` and `unwanted_binary` map to the unwanted class. Preserve the
original subtype when it is supported by evidence. A binary spam annotation does
not establish whether the message is phishing. These labels are not interchangeable
JSON values: use the schema expected by the relevant exporter/trainer.

HAM, SPAM and PUB are operational categories. They do not replace the two
annotation axes. A user's preference for handling publicity is distinct from
whether the message was expected. Neither a newsletter header nor a functioning
unsubscribe link proves consent. Suspicious wording, an invoice, urgency, a URL
or an SPF/DMARC failure alone is insufficient evidence of phishing.

`uncertain` remains excluded from supervised binary fitting and class-specific
accuracy metrics. Count and explain these cases; never convert uncertainty into
a wanted label to fill a missing class. Research reports may use `review` for an
abstention or unavailable prediction. This is evaluation accounting, not a new
recipient delivery category.

## Annotation provenance

Retain the source and scope of every reference label: message identity, reliable
receipt time, annotator, annotation time, consent/context and permitted use. If an
assistant records an explicit recipient confirmation, retain that confirmation
reference. An assistant's own judgement, an LLM output, a Rspamd verdict or a folder
placement is not a human confirmation. Keep machine annotations separate from
human evaluation truth. Third-party corpus labels retain their source provenance.

Review the original where available. Do not infer consent from the subject alone,
load remote images, follow links or execute attachments to annotate a message.
Recipient-specific preferences must not silently become a global allow/block rule.
Operational corrections and protected evaluation annotations use different paths;
see [correction scopes](../docs/calibration-workbench.md#prepare-the-data).

<a id="constitution-du-corpus-récent"></a>
## Construct a representative corpus

Use the gateway's recorded receipt time, not the sender-controlled `Date` header.
Preserve source, language, type, authorization and campaign identities. Sample
correctly classified mail as well as errors. A disagreement or corrections-only
collection is useful for diagnosis but cannot establish a population false-positive
rate. Include wanted transactions, technical notifications, newsletters, forwarded
mail and conversations alongside diverse unwanted campaigns.

For content training, remove prior filter headers and other label artefacts.
Filesystem paths, folders, corpus names, annotation explanations and previous
verdicts must not become detector inputs. Deduplicate exact messages and group
related campaigns before allocating data. Similarity hashes are heuristics;
audit related campaign families when reliable contextual evidence is available.

Protected regression and holdout references remain protected even when they
reduce training coverage. A missing identity is a provenance problem, not
permission to remove the reservation. Restore it only from verified evidence.
Synthetic data tests software behaviour; it does not replace current, naturally
occurring traffic for accuracy qualification.

<a id="séparation-des-usages"></a>
## Keep fitting and evaluation uses separate

1. Fit vocabulary, IDF, lexical weights and semantic heads on their declared base
   training data. Retain the campaign history of these base models.
2. Generate joint-model inputs without having trained the base model on the same
   campaigns. Use disjoint data or documented out-of-fold predictions grouped by
   campaign. Reusing base-model training predictions leaks information.
3. Use development data for the predeclared candidate choices. Examined results
   cannot later be called an independent test.
4. Calibrate on a separate period. Document its class prevalence: probabilities
   calibrated on an artificial balanced mixture need not match live traffic.
5. Choose thresholds on a distinct reserved period. Do not tune a separate
   threshold after inspecting test errors in a language or source.
6. Freeze the full candidate before reserving a later independent holdout.
   Reusing that holdout to select another candidate consumes its independence.

The quality trainer uses five fixed chronological development partitions:
50% fit, 15% model selection, 15% calibration, 10% threshold selection and 10%
development test. All retained timestamps set the boundaries, including unlabelled
and unavailable observations. Campaigns crossing boundaries or carrying conflicting
labels are excluded and counted. Each risk partition requires at least 12 campaigns
and both risk classes. The optional type head has its own class requirements.
These are software prerequisites, not a qualification sample-size guarantee.

The separate historical 60/10/10/20 split belongs to older content experiments.
It does not supply the additional data needed for joint fitting and later
prospective validation. Never silently mix detector cohorts, rewrite stored
feature digests or relabel an examined sample as a fresh holdout.

<a id="décision-et-preuves-nécessaires"></a>
## Required evidence and release gates

Compare candidates against the same human labels and explicit denominators.
Report TP/FP/TN/FN, recall, false-positive rate, precision, unavailable predictions,
abstentions and confidence intervals, at both message and campaign level. Retain
language/type slices with their sample sizes. No examples in a class means its
rate is unavailable, not zero. Repeated campaign messages are correlated.

Test availability states separately: disabled, not run, complete, unavailable,
busy, skipped and limited. Missing checks cannot count as clean results or spam
votes. Preserve observed evidence without double counting correlated signals.
Compare current behaviour, bounded lexical alternatives and joint candidates;
freeze each variant before independent evaluation. A historical 0–100 index is
not a spam probability merely because it uses that scale.

Qualification uses the versioned [promotion contracts](../docs/calibration-workbench.md#qualification-and-latency).
Both require at least 10,000 wanted and 2,000 unwanted messages, recorded model/data
identities, representative population accounting and reviewed evidence. Version 2
adds the recall and review confidence bounds and separates native from external
latency. A workbench pilot or confidence-bound result is not a promotion certificate.
Keep the exact statistical method and denominator attached to each report; do not
interchange exact-binomial workbench intervals with the runtime's Wilson checks.

The native latency target is warm-cache p95 below 500 ms for messages at most
1 MiB, measured on the stated reference hardware. External calls and failures
must remain visible in total-pipeline measurements. Code tests, Rspamd agreement
and an error-free small sample establish neither this throughput nor filtering
accuracy. Verify Proton mailbox placement, subject changes and ARC separately
before enabling marking. Model selection must not silently change delivery policy.
