<a id="apprendre-des-erreurs-sans-masquer-les-régressions"></a>
# Learning from mistakes without masking regressions

The historical score can be raised on legitimate messages whose style differs from the training corpus. Adding rules or raising a threshold can simultaneously reduce false positives and capture. `research/adapt_feedback.py` allows testing a weight correction, with explicit measures of this compromise. It does not change configuration, message, or active decision.

## Calculation

The lexical model schema 3, its IDF and its bias constitute the fixed reference. The semantic head remains the same when it is supplied; its imprint must correspond exactly to that of the model. The correction learns a regularised logistic regression in the space covered by the characteristics of the corrected messages. The loss balances the two classes and adds a corpus of replay. The intercept, extraction and threshold 95 remain fixed.

The correction coefficients are added to the existing lexical weights. The Rust engine loads the same JSON format and performs the same scalar product: no new inference of encoder, external request or neighbour search is added to the SMTP processing. This does not in itself validate the candidate's performance.

The `--regularization` parameter is 1 by default and `--replay-weight` is 1. Human loss is a balanced sum; the total weight of the recall corresponds to the number of human campaigns, multiplied by `replay-weight`. Set these parameters before evaluation. Change them after examination of the results turns the affected batches into development data; a new validation remains necessary.

<a id="entrées-et-confidentialité"></a>
## Entry and confidentiality

Use the server-side [feedback export](feedback-training.md). The exporter checks annotator access, retention, conflicts and feature completeness. It does not open mailboxes, attachments or URLs. Retained vectors and fitted weights remain private.

```sh
noisefence --config /etc/noisefence/config.toml export-learning \
  /run/noisefence-learning/feedback.jsonl --require-semantic

OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 /opt/noisefence-learning/bin/python \
  research/adapt_feedback.py /run/noisefence-learning/feedback.jsonl \
  replay.jsonl.gz reference/model.json corrective-candidate \
  --semantic-head reference/native-combination.json
```

The JSONL replay corpus, possibly gzip, has one line per campaign:

```json
{
  "schema": "noisefence-content-replay-1",
  "feature_version": 3,
  "id": "<SHA-256 of the raw message>",
  "fingerprint": "<SHA-256 of canonical text>",
  "group": "<SHA-256 of the campaign>",
  "simhash": "<16 hexadecimal characters>",
  "spam": false,
  "partition": "train",
  "stratum": "historical",
  "external_test": false,
  "features": [[123, 1.0]]
}
```

`partition` accepts `train` or `control`. Group hashes must match the frozen `train_linear.py` partitions; test/external groups cannot be declared training data. Controls use test or external groups. `stratum` accepts `historical`, `french_synthetic` or `external`. Both classes are required in training and control data. The example illustrates the format; placeholder hashes are not valid input.

The vectors must come from the Rust extraction, remain standardized and respect the boundaries of the scheme. A campaign duplicate is refused. A close replay of a member of the human corrections is excluded, even if this member belongs to a campaign removed for conflict. The limits cover 256 human campaigns, 20,000 replay lines, 1 GiB decompressed and 40 million values. Prepare and deduce sources before selection; the SimHash distance does not prove the independence of all variants.

## Measurement and activation gates

Each human campaign is first predicted by a trained corrector without this campaign. Temporal validation uses the 30% of the most recent campaigns: no campaign member or training annotation can exceed the cut-off date. Campaigns through this cut and late annotations are counted as exclusions. A lack of previous classes gives an unavailable result, never a success.

The final candidate then learns all the selected campaigns. The replay checks remain excluded from the weight calculation. They compare the lexical alone, by stratum; the comparison of the corrections also uses the frozen semantic head when it is available. These controls do not replay the SMTP pipeline, LLM calls or suppliers conditioned by the score.

`report.json` contains the number, recall, accuracy, false positives and their Wilson intervals, exclusions, parameters and fingerprints. Message accounts must accompany the rates; a correction reported by the user does not represent a uniform circulation of traffic.

The development door refuses a loss of capture or more false positives on a control, as well as the lack of off-campaign progress or time control. Even in the absence of these regressions, the result remains `needs_independent_validation`, `may_activate: false`, `eligible: false`. A threshold reached on some corrections does not show 0.1% false positives on real traffic. The corpus already examined serve as regression references.

The private file contains the JSON weights, the head linked to their new print and the report, including for a rejected candidate. It is created atomically and cannot replace an existing file. No details by message is written. Delete the work export after the checks; keep the source data only according to the period of retention allowed.

<a id="vérification"></a>
## Verification

`tests_python/test_feedback_adaptation.py` covers the direction of correction, recall, campaign separation, late annotations, invalid entries, refusal of regressions and retention of frozen parameters. The IC also compares predictions to the Rust `feedback_probe` program, with synthetic data. No email or private weight is distributed with the project.
