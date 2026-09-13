<a id="qualité-du-filtrage--observations-annotations-et-candidats"></a>
# Quality of filtering: observations, annotations and candidates

Since 0.4.8, NoiseFence has maintained an attached observation of the content, controls, reputation and type of mail. The ranking applied remains separate **from the observer candidate**, who cannot tag, quarantine or replace the delivery decision. No private model is delivered with the software.

<a id="corriger-sur-un-échantillon-représentatif"></a>
## Correct on a representative sample

The **Quality of the filter** page is available to administrators and users. It draws 25 to 200 messages from among those to which the account has access, within a selected period and domain. The proposed period begins with the collection related to the current engine and protocol. It includes incomplete analyses. The draw does not consult any score; its seed, population and members are frozen. The messages arrived then do not change the lot.

Check the original in the recipient's box, then annotate separately:

- risk: legitimate, spam/fraud or uncertain;
- type: conversation, transaction, notification, newsletter, promotion or other.

An agreed newsletter is legitimate and newsletter-type. A fraudulent advertisement can be spam and promotional type. The type never neutralizes the risk. The object alone does not constitute proof; choose "I cannot conclude" if the original is not available. No label is deducted from the filter. The scores are hidden during this annotation.

The console shows separately the number of risk and type annotations associated with exploitable observations, the missing observations and the number of detector configurations present. The type is optional: it does not block a certain annotation of the risk. These meters do not validate the number per period or a future model.

Some labels also update the historical corrections. "Uncertain" removes the previous binary vote. A new historical correction invalidates the double annotation that has become obsolete. The messages already delivered remain unchanged. Access is rechecked on the server side at each read and write, with session, original control and CSRF for mutations. Hidden copies do not become visible to other accounts.

<a id="préparer-un-candidat-sur-le-serveur"></a>
## Prepare a candidate on the server

For a larger evaluation, the LTC allows up to 50,000 messages in a population of up to 50,000. The same batch sssnotes in the console per 200 pages. The dates are Unix UTC seconds, within the last thirty days. Example to adapt, by replacing the variables with the period, the account and the ID returned by the first order:

```sh
noisefence --config /etc/noisefence/config.toml quality-sample \
  --username "$ANNOTATOR" --since "$SINCE" --until "$UNTIL" \
  --count 10000 --domain example.org

noisefence --config /etc/noisefence/config.toml quality-export \
  --username "$ANNOTATOR" --batch "$BATCH_ID" \
  --output /var/lib/noisefence/quality/sample.jsonl

OPENBLAS_NUM_THREADS=2 OMP_NUM_THREADS=2 /opt/noisefence-learning/bin/python \
  /opt/noisefence/current/research/train_quality.py \
  /var/lib/noisefence/quality/sample.jsonl \
  /var/lib/noisefence/quality/candidate-01 --version candidate-01
```

Create the private directory and install `research/requirements.txt` in a dedicated Python environment. The Python path of the example is to be adapted. The export refuses to overwrite a lot. It does not contain any body, attachments, object, correspondent address, or private key of join; the vectors, campaign prints and dates remain private data. Do not publish them on GitHub. Exports and models outside SQLite have a retention to be managed by the operator, unlike the database metadata that expires after 30 days.

Training requires human annotations in five fixed time periods: 50% training, 15% parameter selection, 15% calibration, 10% thresholds, 10% final test. Accurate or close campaigns do not go through these periods. Contradictory campaigns and campaigns that cross a border are excluded and counted. A conserved campaign contributes a deterministic representative. Since 0.4.13, both heads are driven separately on the same temporal boundaries, fixed with all messages kept, even unannotated or incomplete. Each risk period must contain at least 12 campaigns and both risks: otherwise the order comes out with code 3 and a `insufficient_labels` ratio, without a model. The type uses its own annotations and requires 12 campaigns and the six types per period. If they are missing, only the risk is generated; the type indicates `not_trained` and no distribution of types is invented. A type conflict does not remove a consistent risk annotation, and vice versa. This minimum software does not guarantee sufficient statistical evaluation.

The logistic regression is regulated. The risk receives a calibration of Platt and a zone of forbearance; the six types receive a calibration of temperature. The ratio measures recall, false positives, accuracy and exact binomial intervals at 95%, abstentions, Brier, matrix of types, results by type, comparison to the applied ranking and twelve predefined ablations: without LLM, reputation, history, behavior, native engine, Bayes native, lexical model, semantic model, identity/authentication, vision, type of mail, then contained alone. Each variant is re-entered and calibrated over the same periods; it does not settle on the final test. Remove a family measure its conditional contribution, not its causal independence. The control profiles not encountered at the training are abstentions. Unavailable controls are never transformed into malicious verdicts.

The test unit is **the campaign**, not all traffic. Messages without annotation, inaccessible, incomplete or excluded remain counted. A subset easy to annotate does not demonstrate the rate of false positives of the population. For a claim on traffic, then reserve an independent population, annotate its messages and count omissions and abstentions. Do not set the thresholds on the lot used to publish the results. A lack of error on a few dozen of mails does not show the target of 0.1%.

The `--base-history chemin.jsonl` option also checks the absence of common campaigns with the games of the basic models or previous tests. This private file contains `fingerprint`, `simhash` and `campaign`, such as fusion exports. Its absence remains an explicit limit of the ratio; no activation certificate is produced.

The `noisefence-quality-model-2` model binds by SHA-256 a private manifest containing all the campaigns already consulted, including those excluded from the training, as well as the historical supplied. The availability profiles of the two heads are distinct. In case of exact equality of the probability of type, the last category in the order of protocol wins, as in the historical runtime Rust. Keep `training-manifest.json` with the weights; it must not be published. The format 1 remains legible, but only the format 2 carries this provenance.

<a id="évaluer-sur-un-nouveau-lot-indépendant"></a>
## Evaluate on a new independent batch

Fig the model before the beginning of the next period. Then export a completely annotated uniform reprint, without consulting it to adjust the candidate. Do not mix several versions of detector during training: the print includes the version of the application. An update requires new observations compatible; it does not retroactively make the old ones compatible.

```sh
OPENBLAS_NUM_THREADS=2 OMP_NUM_THREADS=2 /opt/noisefence-learning/bin/python \
  /opt/noisefence/current/research/evaluate_quality.py \
  /var/lib/noisefence/quality/independent.jsonl \
  --model /var/lib/noisefence/quality/candidate-01/model.json \
  --training-manifest /var/lib/noisefence/quality/candidate-01/training-manifest.json \
  --output /var/lib/noisefence/quality/evaluation-01.json
```

This command does not change any threshold, model, message or setting. It refuses to overwrite the report and checks the footprint of the manifest. Common campaigns with all previous games, duplicates, conflicts, absent labels, loss of rights, incompatible observations and expired models prevent a complete validation. An unknown source of the basic corpus also blocks this validation. Unavailable predictions count as omissions, never as good answers.

The report compares the ranking recorded to the pure candidate and the candidate with the main antivirus priority already observed. It separates message and campaign units, risk calibration and PUB accuracy/recall (newsletter or promotion), with a matrix of the six types including an unavailable column. PUB metrics refer to messages also annotated at risk. Recipient corrections and Proton's chosen folder are not replayed; registered supplier/LLM calls do not validate another selection policy for these calls.

Pilot criteria: at least twenty spams and one hundred legitimate independents, less false positives, as many spams captured and no more abstentions. The final targets are on the unilateral binomial terminals at 95%: capture at least 95%, false positives at the most 0.1%, abstentions at the most 5%. They ask for much more examples and a review of their representativeness. The report still contains `may_activate: false`, even if these digital tests pass. The output code is 0 if the pilot passes, 3 otherwise; it does not allow any activation.

<a id="expliquer-les-erreurs-sans-exporter-les-messages"></a>
## Explain errors without exporting messages

The detail of a message breaks down the historical score before saturation between lexical, semantic, rules, authentication, reputation, SMTP and LLM. A combined historical contribution remains indivisible if its decomposition is lacking. The sum is verified against the recorded score; a divergence remains visible. The weights learned from the text and the MIME structure share hashbuckets: this report does not pretend to separate them retroactively.

`noisefence audit-confirmation /var/lib/noisefence/state.sqlite3` also produces these aggregates by false positives, spams detected, errors and omissions, as well as errors specific to the second opinion, its status, its cost recorded and its durations. Only reconciled decompositions are included in contribution averages. Conflicting and inaccessible returns are excluded explicitly. These are targeted corrections, therefore biased, not a measure of traffic. The audit does not open bodies, does not call any supplier and does not rewrite SQLite.

## Load in observation only

After reviewing the Python/Rust report and checking parity:

```toml
[quality]
candidate = "/var/lib/noisefence/quality/candidate-01/model.json"
```

The model is a JSON of weight, without executable code, limited to 2 MiB. Restart the service after validation of the configuration. Protocol, policy footprint, basic models, profiles and dimensions must match. A candidate expired after 30 days or incompatible with abstinent. The console indicates its status separately from the ranking applied. This version does not propose any activation of its actions. Historical training tasks remain unchanged; this pipeline is explicitly launched once the batch has been annotated, without automatic training on the predictions of the filter.

<a id="identité-liens-et-réputation"></a>
## Identity, Relationships and Reputation

A correspondent's history requires a native SMTP source, a single From, an aligned DKIM validated by DMARC and a single recipient domain. It uses only the previous corrections of active and authorized administrators, over 30 days. Five legitimate campaigns over three separate days, without unwanted or conflict, establish a confidence signal; never a white list. The local-part keeps its break. An interrupted or saturated request becomes unavailable, under an external terminal of 200 ms included in the global delay d'analyse.

The phishing context brings together protected name, displayed domain, Reply-To domain, OCR/QR link and final site of a complete redirect chain. An exception on a tracker does not exempt control of the final site. Existing terminals on redirects, DNS, public addresses and volumes remain active. No new attachment download or content execution is added. New contextual signals feed observations and candidates; they do not force the historical ranking alone.

Each CRDF/VT observation retains a digest of the indicator, its scope, status, date of request and age of cache. For VT, the identity and type of object must correspond; analyses longer than seven days remain unavailable. For CRDF, a match on a specific page remains suspicious at the host scale, and the date of analysis is unknown if it is not proven. A synthetic request at the root does not attest all pages of the domain. Meters distinguish between common staves and indicators between suppliers. See [CRDF documentation](https://threatcenter.crdf.fr/api/doc/) and VT objects [domain](https://docs.virustotal.com/reference/domain-info) and [file](https://docs.virustotal.com/reference/file-info).

<a id="vérifications-logicielles-et-exploitation"></a>
## Software verifications and operation

`tests/quality.rs`, console tests and connector tests cover the provenance, range, freshness, rights, private export and maintenance of the original decision. `tests_python/test_quality.py` uses only synthetic fixtures; the IC compares the probabilities of Python to Rust weights within 1st-9. Competitive SMTP tests always check the durable file and unchanged bodies. These tests do not constitute a capture measure in production.

This feature’s original migration was additive. Current paired installations require storage schema 5 and a compatible release. Do not downgrade the database, remove its HA marker or restore an older backup over accepted mail. See [installation](installation.md) and [HA recovery](high-availability.md) for current upgrade and rollback procedures.

Since 0.5.0, native entries and their availability complete the candidate. The table **Reliability** describes the collection groups and comparisons. See [procedure and migration](reliability.md).


Since 0.6.0, the thresholds use the exact numbers of the reserved period: `floor(legitimate_count × 0,001)` false positives and `floor(spam_count × 0.01)` false negatives maximum over this period. The upper threshold is the lowest permissible starting from 0.5, with a digital guard of 10−9 for the Python/Rust parity; the lower threshold extends the legitimate coverage up to 0.5 with the same guard. Inclusive and tied values comparisons are counted. A saturation at 0 or 1 that makes these constraints impossible interrupt the preparation; a removal cannot be indicated separately. This empirical choice does not validate a rate in the traffic: independent testing, coverage, intervals and activation rules remain necessary. See [coverage and behavioral memory](capture-coverage.md).
