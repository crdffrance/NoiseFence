<a id="étiquetage-et-validation-du-filtrage"></a>
# Filter labelling and validation

This protocol defines the common target of the local model, the combination of signals and evaluations. It does not transform either an automatic score or a Proton folder into a real training.

<a id="étiquettes"></a>
## Tags

| Label | Criterion | Examples |
| --- | --- | --- |
| `legit` | Expected or agreed correspondence, without attempted deception | Professional exchanges, invoices, order confirmation, real security alert, newsletter to which the recipient is a subscriber |
| `spam` | Unwanted or unconsented solicitation, without sufficient evidence of phishing | Unsolicited prospecting, repetitive promotion, generic spam |
| `phishing` | Trompery intended to obtain a secret, payment or action in jeopardy | False authentication portal, provider usurpation to change a RIB, fake update trapped |
| `uncertain` | Background, insufficient consent or evidence, or disagreeing annotators | Newsletter whose subscription is unknown, commercial message whose recipient cannot confirm the origin |

A security alert, invoice, link or urgent vocabulary is not enough to justify `phishing`. A failure of SPF/DMARC or an unavailable reputation does not determine the label. Consent must be known to distinguish a legitimate newsletter from an unwanted solicitation. A legitimate message reported as undesirable by personal preference keeps this information separate; it does not automatically become a global rule for all users.

The currently deployed classifier is binary: `spam` and `phishing` form the "desirable" target. Publish the reminders of these two subclasses separately when annotations allow. An old binary label `spam` does not prove the absence of phishing. The "Spam / Legitime" console produces a binary return; it does not provide an annotation in three classes alone.

The `uncertain` cases remain in a revision batch, excluded from the adjustment and binary metrics. Keep their number and reason for uncertainty. Third party corpus labels are source labels until they are reviewed. A LLM can help prioritize revisions; it does not validate its own predictions.

<a id="constitution-du-corpus-récent"></a>
## Constitution of the recent corpus

Keep a verifiable source for each message: original print, source, known receipt period, use authorization, language, message type, label and annotation mode. The reliable receipt date is not deduced from the `Date` field provided by the sender. Do not visit links, load remote images or execute attachments during annotation.

Also sample correctly classified messages. An export made up of corrections only measures known errors, not the server population. Automatic notifications, mailing lists, transfers, invoices and professional exchanges in France must be present in the legitimate dataset. Synthetic texts are a source of increase or a separate diagnosis, not a substitute for these actual messages.

Before any separation, remove the old filter headers and group the exact duplicates and campaign variants. The paths, labels, folders, corpus identifiers and explanations of the annotators remain outside the detector entries. Any campaign that joins a held-out dataset must be excluded from the adjustment batches. Canonic similarity/SimHash is a heuristic: complete the audit by dates, domains and campaign families when these data are reliable.

<a id="séparation-des-usages"></a>
## Separation of uses

1. **Engine training**: vocabulary/IDF, lexical coefficients and semantic head only learn about this batch.
2. **Development**: limited and announced choice of variants; observed results do not become an independent test.
3. **Training of the combination**: use engine outputs that have not learned about the corresponding campaigns, by separate batch or off-ply predictions grouped by campaign. Do not learn the combination about the driving predictions of the same engines.
4. **Calibration of probabilities**: adjust on a separate lot. The proportion of this lot must be documented; a probability calibrated on an artificial 50/50 mixture does not automatically apply to the actual traffic.
5. **Threshold selection**: reserved lot separate from the test. Select a common threshold under the constraint of false positives; do not set a different threshold to mask errors in a language or source.
6. **Frozen final test**: to announce its perimeter and freeze artifacts before producing predictions. Any test consulted becomes a historical result; to reuse it to select another candidate withdraws its independence.

The historical separation 60/10/10/20 is used for existing content experiments. It does not automatically provide the additional batches necessary for learning and calibration of the complete combination.

<a id="décision-et-preuves-nécessaires"></a>
## Decision and evidence required

Compare layers with the same constraint of false positives: content alone, content + SMTP authentication/policy, reputation, signatures, and then LLM. Explicitly represent the controls disabled, unsolicited, complete and unavailable. A DNS error should not be encoded as a "healthy" result. Test faults and conditional selection of the LLM, keeping the transmission rule without prefix when the analysis is incomplete.

For each candidate, keep the fingerprints of the code, data and models, the versions of the characteristics, rules, signature bases and prompts. Publish actual, TP/FP/FN/TN, recall, accuracy, false positives and 95% intervals, as well as the results by language and legitimate critical category. Measure calibration separately from the ranking ability. A 95/100 suspicion index does not mean 95% probability without this validation.

The recent independent test target includes at least 10,000 legitimate and 2,000 undesirable. The target recall is ≥ 95%, with false positives rate ≤ 0.1% and a 95% higher limit compatible with this limit. Publish intervals even if these targets fail. A small batch without false positives is not enough; subgroups also require interpretable numbers.

Measure the complete pipeline on the reference machine (4 vCPU, 8 GB), with target p95 < 500 ms for messages ≤ 1 MB and warm caches. Cases using LLM, incidents and unavailable controls must remain visible in the measurements. Then check the destination folder at Proton separately from the NoiseFence score, including after object modification or ARC sealing.

References: [probability calibration](https://scikit-learn.org/stable/modules/calibration.html), [threshold selection](https://scikit-learn.org/stable/modules/classification_threshold.html), [non-training predictions for combination](https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.StackingClassifier.html).
