<a id="candidat-noisefence-du-6-septembre-2026"></a>
# Candidate NoiseFence of 6 September 2026

**Statute: Rust driven and verified model, not approved for automatic classification in production.** Measurements show progress, not perfect detection or validation of all combined engines.

<a id="modèle-et-protocole"></a>
## Model and Protocol

The successful candidate is a logistic regression L2 on TF-IDF, with supervised weighting of the characteristics by a Bayesian likelihood ratio. The parameters are learned on the emails; this model is not a list of written rules for the cases tested. JSON weights run directly in Rust, without Python or LLM service during the local inference.

Diagram 3 uses 262,144 hashed features: words, bigrams, groups of 3 to 5 characters and message structure. Unvisible HTML text and old antispam markers are excluded. Local observations already learned are not added a second time as manual weights. The decision keeps the score unrounded; rounding is useful only for display.

The 61,512 emails prepared come from Apache SpamAssassin, the raw Enron-Spam archives and Nazario 2015–2025. The export retains 61,198 messages; the others are empty, incomplete or beyond limits. The heuristic grouping retains 46,361 representatives and excludes 14,837 duplicates or similar variants. Ten old examples sharing a group with 2025 are excluded from learning.

| Partition | Emails | Usage |
|---|---:|---|
| Training | 27 497 | TF-IDF, Bayesian ratios and weight |
| Development | 4 694 | Character family and regularization |
| Calibration | 4 648 | Threshold position, with legitimate emails only |
| Test interne | 9 096 | Measurement after choice of model |
| Archive Nazario 2025 | 426 | External test, excluded from all tuning |

Sixteen candidates are compared: two schemes, two families of linear models, four regularizations. The choice is fixed on the development before the final evaluation. Diagram 3 with Bayesian weighting, C=100, is used. The numerical margin of the threshold avoids the decision differences due to the order of floating additions between BLAS and Rust. This score is an index, not a calibrated probability.

<a id="résultats-après-calibration"></a>
## Results after calibration

| Metric | Internal test | Phishing from the 2025 archive |
|---|---:|---:|
| Legitimate messages | 3 989 | 0 |
| Spams/phishings | 5 107 | 426 |
| Detections | 4 882 | 399 |
| Recall | **95.59 %** | **93.66 %** |
| 95% recall interval | 95.00–96.12 % | 90.94–95.61 % |
| False positives | **2** | Not measurable |
| False-positive rate | **0,0501 %** | Not measurable |
| 95% false positives interval | **0,0138–0,1826 %** | Not measurable |
| Accuracy | 99,959 % | Unrepresentative: No legitimate |

The upper limit of 0.1826% exceeds the target of 0.1%. The 93.66% recall on the external test remains less than 95%. Hams are historical: even a numerical success on this corpus would not demonstrate quality on current professional boxes, particularly in French. The grouping by similarity does not prove the absence of any shared campaign. Intervals involve independent observations and must be interpreted with this limit.

<a id="exécution-native"></a>
## Native execution

The characteristics and decisions of 22 emails kept away from training, including legitimate ones close to the threshold, were compared between Python and Rust. Maximum absolute error of score: **1.42 × 10−14**. The analysis without delivery was also verified. A private case of regression, excluded from independent learning and metrics, now exceeds the threshold with the local model alone.

On the Mac ARM64 used for R&D, already loaded model:

| Message | Iterations | p50 | p95 | p99 |
|---|---:|---:|---:|---:|
| 10 127 bytes | 1 000 | 0,961 ms | 1,106 ms | 1,246 ms |
| 1 048 521 bytes | 100 | 16,907 ms | 17,386 ms | 30,233 ms |

On the reference Debian 13 x86-64 server, 4 vCPU and 8 GB RAM:

| Message | Iterations | p50 | p95 | p99 |
|---|---:|---:|---:|---:|
| 10 127 bytes | 1 000 | 1,777 ms | 1,837 ms | 2,166 ms |
| 1 048 521 bytes | 100 | 30,308 ms | 31,819 ms | 64,954 ms |

These measures include MIME/text extraction and model. They exclude DNS, antivirus, LLM, file, model loading and relays. The R&D binary was executed separately with a reduced priority, then the temporary files were deleted. The active service has not been replaced. The complete pipeline remains to be measured.

<a id="traçabilité-et-suite"></a>
## Traceability and follow-up

- Model: `research-nb-logistic-1788730448-calibrated`.
- SHA-256 weight: `eda9070844f4d7472aa828ff9fcf504526232d6401670dc5ec5cd207bdab3854`.
- [Detailed measurements by source](model-report-20260906.json).
- [Big Sources and Assignments](sources.lock.json).
- [Reproduce the experiment](README.md).

Weights and work data are stored locally. No candidate has been activated in production, no MX has changed and no additional email was delivered during this experiment. Proton compatibility remains a separate milestone. Historical corpuses sometimes contain a mbox separator line, which is not a SMTP command or model feature.

Further research must cover recent false negatives, multilingual generalization, representative recent legitimate mail and combinations with other engines. A [local multilingual encoder comparison](semantic-card-20260907.md), Rust port and VPS measurements are available. Previously inspected datasets become development references for later iterations; a new independent validation is required for a final quality claim. Never choose a threshold on the test set to manufacture success.

Methodological references: [scikit-learn logistics](https://scikit-learn.org/stable/modules/linear_model.html#logistic-regression), [bayesian and linear reports, Wang and Manning](https://aclanthology.org/P12-2018/), [generalization limits of phishing corpus, E-PhishGen](https://arxiv.org/abs/2509.01791).
