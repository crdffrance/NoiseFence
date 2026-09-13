<a id="comparer-un-apport-de-données-sans-masquer-les-régressions"></a>
# Compare data input without masking regressions

`adapt_content.py` compares lexical and semantic models on already frozen training and development scores. It produces a private candidate and a report. It does not read any calibration/test set, does not change any active model and does not publish any weights. The rights of use of corpus remain applicable to the artifacts produced.

<a id="entrées"></a>
## Entries

Install `research/requirements.txt` versions in a local environment. The calculation does not require network access or LLM calls.

The JSONL feature file uses the `features-export` 3 schema, after consolidation of campaigns. Each line keeps `fingerprint`, `group`, `raw_sha256`, `spam`, `features`, `feature_version` and adds:

- `partition`: `train` or `development`, consistent with the group hash;
- `stratum`: name of the evaluation subset, e.g. `historical` and `french_synthetic`.

All external, calibration and test campaigns must be missing from the file. The program refuses them even if their declared partition is falsified. Each group must have a single representative. Check the close duplicates and variants between **all** sources and partitions before preparing the file; the player identity check does not replace this similarity audit.

The embedding directory contains `embeddings.npy` (float32 normalized vectors), `ids.json` (raw digests in vector order) and `protocol.json`. The latter matches `semantic-protocol.json` exactly and adds `complete: true`, `embeddings_sha256` and `ids_sha256`. Identities must match the feature file exactly. Do not load a held-out test cache into this tool.

The names of the sources, labels and partitions are used for the organization of the experiment and for the weighting of the training; they are not characteristics of the detector. Each stratum must include both training and development classes.

Example grid, to be fixed before testing:

```json
{
  "augmentation_strata": ["french_synthetic"],
  "sample_weights": [1, 5, 20],
  "lexical_C": [10, 100],
  "semantic_C": [1, 10],
  "semantic_weights": [0, 0.1, 0.5, 1, 2, 4],
  "lexical_families": ["tfidf_logistic", "nb_logistic"],
  "target_fpr": 0.001
}
```

```sh
OPENBLAS_NUM_THREADS=2 OMP_NUM_THREADS=2 \
python3 research/adapt_content.py \
  corpus/private/train-development.features.jsonl \
  corpus/private/train-development.embeddings \
  corpus/private/grid.json \
  models/reference/model.json models/reference/native-combination.json \
  models/private-content-candidate
```

The output folder must be new. The created files and directories are private (`umask 077`). The features, weights and predictions remain in locations ignored by Git.

## Choices and limits

The IDF learns about unique training messages only. The weighting of the input applies to the learning function and Bayesian frequencies, without duplicating the messages or changing the evaluation staff. A failure of convergence interrupts the experience.

Each combination uses a single development threshold: the most restrictive of the thresholds necessary to meet the empirical budget of false positives in each stratum. The choice maximizes the lowest recall among the strata, then the average recall and the average PR-AUC. This prevents a large source from masking the errors of a small source; this does not prove the generalization on future messages. Intervals and numbers remain indispensable.

The semantic model alone appears as ablation. The exported candidate meets the current native contract: logit lexical + semantic contribution. SMTP contributions, authentication, reputation, signatures and LLM require a distinct combination experience with their reliable receiving context.

Outputs include `specification.json`, `development.json`, development predictions, `raw-model.json` and `raw-head.json`. The threshold is not calibrated in these raw weights. Do not install them directly in production. Fig the selection, calibrate the threshold on a reserved lot, then measure the independent test only once and check Rust predictions before activation. A score obtained by moving the bias to correspond to threshold 95 remains an index of suspicion, not a calibrated probability.

The [validation protocol](labeling-protocol.md) specifies the requirements for recent data, probabilities, regressions, latency and Proton.
