<a id="qualité-du-filtrage--observations-annotations-et-candidats"></a>
# Filter quality: observations, labels and shadow candidates

Use **Quality & research → Samples & evaluation** to label recipient-visible mail,
compare recorded engines and prepare a shadow candidate. A shadow candidate cannot
tag, quarantine or replace the applied decision. Shipping this workflow does not
ship a private trained model or establish a production accuracy claim.

The [workbench guide](calibration-workbench.md) covers installation and Web controls.
The [labelling protocol](../research/labeling-protocol.md) defines ground truth;
[model provenance](model-provenance.md) defines compatibility. See
[decision exports](decision-exports.md) for engine, recipient policy and action
accounting.

<a id="corriger-sur-un-échantillon-représentatif"></a>
## Start with a representative sample

The Web console uniformly samples up to 200 messages for a user or 5,000 for an
administrator, within the selected period, domain and current access grants.
Development samples may select a detector cohort. Population, seed and members
are frozen; later arrivals do not change the sample. Incomplete analyses remain
in the population. Sampling does not select messages by score.

Review the original and annotate the two axes independently:

- **Risk:** legitimate, spam/fraud or uncertain.
- **Mail type:** conversation, transactional, notification, newsletter, promotion
  or other; this field is optional.

A wanted newsletter is legitimate risk and newsletter type. A fraudulent promotion
has spam risk even though its type is promotional. The subject, a sender name or
another detector's verdict is not ground truth. Preserve uncertainty when the
original or recipient context is missing. The annotation form hides model scores.
Risk and type coverage counters do not establish chronological readiness or quality.

### Bulk annotation

Select a retained sample, then use **Select visible** or individual row checkboxes.
Search matches subjects and senders on the current page; **Unannotated only** hides
existing labels. A page contains at most 200 messages. Selection clears on changes
to page, sample, refresh or search.

Choose **Risk for selected messages**, optionally set a mail type, and choose
**Apply to N selected**. Leaving type unchanged preserves existing type labels.
Existing annotations are skipped unless **Replace my existing annotations** is
checked. The response reports saved and skipped counts. PUB is not a consent label;
record the risk separately.

The server validates ownership, recipient grants and every selected message before
committing. Requests contain at most 200 distinct messages and are atomic on both
SQLite and PostgreSQL. Annotation does not move mail, rewrite saved decisions or
start training. Evaluation annotations remain separate from operational feedback
and sender trust. Session, origin and CSRF checks protect mutations; Bcc addresses
do not become visible to other accounts.

<a id="préparer-un-candidat-sur-le-serveur"></a>
## Prepare a candidate offline

Prefer the Web workflow on a managed coordinator. The CLI can sample up to 50,000
messages from a population of at most 50,000. Dates are gateway receipt times in
Unix UTC seconds within the retained 30-day window. Run commands as the installation
account with its authorized configuration. Substitute the annotator, interval,
cohort and returned batch ID below:

```sh
noisefence --config /etc/noisefence/config.toml quality-sample \
  --purpose development --username "$ANNOTATOR" \
  --since "$SINCE" --until "$UNTIL" --count 10000 \
  --domain example.org --cohort "$COHORT_SHA256"

noisefence --config /etc/noisefence/config.toml quality-export \
  --username "$ANNOTATOR" --batch "$BATCH_ID" \
  --output /var/lib/noisefence/quality/development.jsonl

OPENBLAS_NUM_THREADS=2 OMP_NUM_THREADS=2 /opt/noisefence-learning/bin/python \
  /opt/noisefence/current/research/train_quality.py \
  /var/lib/noisefence/quality/development.jsonl \
  /var/lib/noisefence/quality/candidate-01 --version candidate-01 \
  --base-history /var/lib/noisefence/quality/base-history.jsonl
```

Create the private parent directory and install the locked research dependencies
first. Existing export/candidate paths are not overwritten. The export excludes
bodies, attachments, subjects, mailbox addresses and private sender-lookup keys.
Feature vectors, campaign fingerprints and dates still constitute private data.
Keep them out of GitHub. Manage file retention explicitly; SQLite's metadata
cleanup does not delete arbitrary offline exports.

Five chronological partitions use all retained timestamps: 50% fitting, 15% model
selection, 15% calibration, 10% threshold selection and 10% development testing.
Labels and observation availability cannot move these boundaries. Exact/near
campaigns crossing partitions and conflicting campaigns are excluded and counted.
Each retained campaign contributes one deterministic representative.

Every risk partition requires at least 12 independent campaigns and both classes.
Otherwise training returns `insufficient_labels` and exit code 3, without a model.
The optional type head requires 12 campaigns and all six types per partition.
Missing type coverage does not prevent a usable risk head; it produces no invented
type distribution. Type conflicts do not erase consistent risk labels, or vice
versa. These minima permit fitting; they do not qualify production performance.

Risk fitting uses regularized logistic regression, separate Platt calibration and
two thresholds. Type fitting uses six classes and separate temperature calibration.
Reports include recall, false positives, precision, exact-binomial 95% intervals,
abstentions, Brier diagnostics, type confusion and fixed ablations. Ablations cover
LLM, providers, history, behaviour, native features/Bayes, semantic, lexical,
identity/authentication, vision, mail type and content-only inputs. Each variant is
refitted on the designated partitions; test labels do not select its threshold.
An ablation measures conditional usefulness, not causal independence.

The threshold partition enforces empirical counts: at most
`floor(wanted × 0.001)` false positives and `floor(unwanted × 0.01)` false negatives.
Inclusive ties and the native/Python numerical guard matter. If no thresholds
satisfy the constraints, preparation stops. Saturated scores cannot be repaired by
silently relaxing the constraints. Unsupported detector profiles remain research
abstentions; unavailable checks never become malicious votes or clean evidence.

`--base-history` records campaign identities from base-model training and previous
evaluations, and checks overlap with the proposed data. Omitting it leaves an
explicit provenance limitation. The version-two model binds a private
`training-manifest.json` containing all seen campaigns, including exclusions and
supplied history. Keep that manifest with the weights. A model hash alone cannot
reconstruct missing history. Unknown protected campaign identities stop fitting;
never discard reservations to obtain a model.

<a id="évaluer-sur-un-nouveau-lot-indépendant"></a>
## Evaluate a frozen candidate on future mail

Freeze model bytes, profiles and thresholds before the next observation period.
Create a **holdout** sample from later traffic. Holdouts cannot filter away
incompatible observations. Annotate without using either engine as truth. Export
once for the frozen candidate, retaining its exact SHA-256:

```sh
noisefence --config /etc/noisefence/config.toml quality-export \
  --username "$ANNOTATOR" --batch "$HOLDOUT_BATCH_ID" \
  --candidate-sha256 "$CANDIDATE_SHA256" \
  --output /var/lib/noisefence/quality/independent.jsonl

OPENBLAS_NUM_THREADS=2 OMP_NUM_THREADS=2 /opt/noisefence-learning/bin/python \
  /opt/noisefence/current/research/evaluate_quality.py \
  /var/lib/noisefence/quality/independent.jsonl \
  --model /var/lib/noisefence/quality/candidate-01/model.json \
  --training-manifest /var/lib/noisefence/quality/candidate-01/training-manifest.json \
  --output /var/lib/noisefence/quality/evaluation-01.json
```

Export-use tracking records previous access and related campaigns. A failed or
repeated export cannot reset freshness. The evaluator verifies model/manifest
identity, chronology, base history, campaign overlap and coverage. Missing labels,
rights loss, incompatible observations and unavailable predictions remain counted.
An examined development sample cannot be renamed into an independent holdout.

The report distinguishes the recorded engine, recipient policies, pure shadow
candidate and candidate with the recorded antivirus priority. It reports message
and campaign results, calibration, type confusion and publicity precision/recall.
It does not replay provider requests, changed LLM-selection policy, recipient
preferences or Proton placement. Research `review` means an abstention or missing
prediction; it is neither a captured spam nor a true negative.

A pilot needs at least 20 unwanted and 100 wanted independent messages, complete
coverage and no regression in false positives, captures or abstentions, with at
least one improvement. Exact one-sided confidence checks are reported separately.
Neither a passed pilot nor `meets_final_confidence_bounds` is a promotion
certificate: reports always retain `may_activate: false`. The evaluator exits 0
for a passed pilot and 3 otherwise. The distinct
[versioned promotion contracts](calibration-workbench.md#qualification-and-latency)
retain their own counts, Wilson bounds, latency and operational requirements.

<a id="expliquer-les-erreurs-sans-exporter-les-messages"></a>
## Explain errors without changing receipts

Message details separate the saved engine verdict, recipient policy, requested and
effective action, delivery state, primary evidence and missing checks. Historical
score components are reconciled before they are used in averages. A combined
component cannot be retroactively split when its decomposition was not recorded.
Text and MIME weights share hashed buckets; diagnostics do not invent an exact
attribution between them.

The local `audit-confirmation` diagnostic reads a SQLite database without contacting
providers. Its correction sample is biased and does not measure population accuracy.
Do not treat obsolete SQLite management mirrors as authoritative after PostgreSQL
selection; use the managed workbench and its current permissions and receipts.

## Select shadow observation through reviewed settings

After reviewing provenance and native/Python parity, use **Use in observation**
on a prepared, unexpired compatible candidate. This creates a normal versioned
configuration change. Managed MX nodes validate the transferred artifact and their
loaded cohort before applying it. Review cluster state; distribution is asynchronous.

A candidate is data-only JSON, bounded to 2 MiB. Model, policy, protocol, dimensions
and supported profiles must match. Expired or incompatible candidates produce no
invented prediction. The risk/type results remain separate from the applied
classification. No training job, model selection or report automatically promotes
its actions. Loading or restoring a candidate does not rewrite historical mail.

<a id="identité-liens-et-réputation"></a>
## Context and availability remain evidence

Authenticated sender history uses earlier authorized operational feedback, bounded
retention and campaign diversity. It is a signal, not an unconditional allowlist.
Evaluation labels cannot leak into that live memory. Missing or overloaded lookups
remain unavailable. See [capture coverage](capture-coverage.md) and
[context controls](context-review.md).

Identity, Reply-To, OCR/QR, final URL destinations and provider reputation retain
their scope and collection time. A trusted tracker does not approve the final site.
A provider match for one URL does not automatically establish a malicious sender
or every page on its domain. Deduplication, age, conflicts and availability must
remain explicit; see [shared provider eligibility](unified-decisions.md#shared-provider-eligibility-and-native-accounting).

## Provider evidence contract migration

`provider-target-evidence-1` binds vectors to request-time eligibility, deduplicated
targets and scoped cross-provider agreement. Semantics can change the protocol
digest without changing vector dimensions. Retain old history, collect compatible
observations and independently evaluate a refitted candidate. Do not edit a model's
or historical vector's digest to bypass compatibility.

<a id="vérifications-logicielles-et-exploitation"></a>
## Software tests and operations

Native quality/compatibility tests cover provenance, ranges, permissions, frozen
samples and preservation of the original verdict. Python tests use synthetic
fixtures and compare native/Python inference within the declared tolerance. These
tests establish software behaviour for their cases, not production accuracy.

Current local formats are 5 for paired replication, 6 for management transport and
7 for selected PostgreSQL management. A matching format alone cannot authorize a
rollback. Preserve accepted queues and authority markers; follow
[paired upgrade preparation](paired-upgrades.md) and [HA recovery](high-availability.md).

**Quality & research → Rule reliability** presents signal groups and comparisons.
See [rule reliability](reliability.md). Its measurements do not grant promotion.

## Direct annotation links

Open `/?view=quality` on the console host after sign-in. A selected sample exposes
**Direct link to this annotation sample**, using
`/?view=quality&sample=<batch UUID>`. Links grant no additional access: ownership,
session and recipient permissions are still checked by the server.
