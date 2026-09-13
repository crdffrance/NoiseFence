<a id="noisefence--expériences-de-détection"></a>
# NoiseFence: detection experiments

The [labelling and validation protocol](labeling-protocol.md) defines classes, separate data uses and the evidence required for a common decision across engines. It also applies to diagnostics and new corpora.

The [data-augmentation comparison](content-augmentation.md) fits a lexical/semantic candidate while controlling false positives by development source, without opening reserved datasets or activating a model.

The model is learned on labelled emails; adding a rule for each example received does not replace this learning. The private case provided during R&D is a known regression, excluded from the training sets and independent test metrics. It remains private and should not be published with the code.

## Protocol

1. Archive the sources, dates, licenses and footprints of public corpus. Never visit their links, load their images or execute their attachments.
2. Extract visible text, words and characters, as well as MIME structure and relationships between identities and links. Exclude scores from old filters, folders, corpus paths, recipients and transport dates.
3. Consolidate close duplicates and variants before any partition. Remove label conflicts; maintain an audit of exclusions. Isolate recent campaigns and external sources to measure generalization.
4. Separate training, hyperparameter selection, threshold calibration and final test. Test results do not select the model or threshold.
5. Compare regularized logistics, Bayes and linear models with Bayesian likelihood ratios; compare words, characters and structure by ablation. Study a multilingual local encoder if these models remain insufficient.
6. Export versioned weights usable in Rust, then check the equal predictions between training and execution. Measure actual memory and latency.
7. Assess the complete decision separately: authentication, reputation, signatures, local model, LLM selection and combination. Do not present a text evaluation alone as a validation of the entire gateway.

Publish recall, accuracy, false positives, Wilson's intervals, PR-AUC, numbers and results by source. The target remains recall ≥ 95% and false positives ≤ 0.1% on recent representative emails; a small series without error does not prove this target. Activation remains conditioned by independent validation.

## Initial sources

- [Apache SpamAssassin](https://spamassassin.apache.org/old/publiccorpus/) : historical start, not proof of performance on 2026.
- [Nazario](https://monkey.org/~jose/phishing/), years 2015 to 2025: real phishing, manually ranked by Jose Nazario; CC BY 4.0 according to his [README](https://monkey.org/~jose/phishing/README.txt). Only one source box, possible ranking errors. Archive dates do not guarantee the dates declared in each email. Year 2025 reserved for the initial external test.
- [Enron-Spam](https://www2.aueb.gr/users/ion/data/enron-spam/): historical exchanges and spam, to distinguish from recent professional emails.
- [E-PhishGen, AISec 2025](https://arxiv.org/abs/2509.01791): highlights the generalization limits of historical benchmarks; corpus generated to distinguish from actual emails, and license to verify before any redistribution or incorporation.

The data and work models remain in `corpus/`, `models/` and `reports/`, excluded from Git. Publish code, manifests and measurements; do not publish private emails. Search downloads do not change production.

<a id="reproduire-lexpérience-linéaire"></a>
## Reproduce linear experience

The prints of the Nazario and Enron downloads are in `sources.lock.json`. The extraction is executed by the same Rust code as the inference. Python is used for optimization and statistics, not as production service.

```sh
python3 -m pip install -r research/requirements.txt
python3 scripts/fetch_corpus.py corpus/apache
python3 scripts/research_fetch.py corpus/research/nazario
python3 scripts/research_fetch.py corpus/research/enron --enron
python3 research/prepare_corpus.py corpus
cargo build --release --locked
```

For each diagram (1 and then 3), export the characteristics and group the campaigns before training. Use 16,384 dimensions for diagram 1 and 262,144 for diagram 3. Each training output must be a new folder.

```sh
target/release/noisefence features-export \
  --manifest corpus/research/prepared/manifest.jsonl --root corpus \
  --output corpus/research/features-v3.raw.jsonl --feature-version 3
python3 research/group_campaigns.py corpus/research/features-v3.raw.jsonl \
  corpus/research/features-v3.grouped.jsonl
OPENBLAS_NUM_THREADS=2 OMP_NUM_THREADS=2 python3 research/train_linear.py \
  corpus/research/features-v3.grouped.jsonl models/research-mixed-v3-dev \
  --dimension 262144 --feature-version 3 --development-only
```

After the two development selections, freeze the choice before opening the calibration and test metrics:

```sh
python3 research/finalize_linear.py models/research-mixed-final \
  models/research-mixed-v1-dev models/research-mixed-v3-dev
```

`selection-frozen.json` records the choice before the final evaluation. Weights are not executable pickle. The IDF transformation is adjusted exclusively on the training split. The exported score is an index with a threshold of 95/100, not a calibrated probability of spam. Local observations already learned from Figure 3 are not added a second time as manual weight.

The grouping uses canonical text and a SimHash distance ≤ 3, with a single representation per group. Any component affecting the external test is excluded from learning. This method does not ensure to find all campaigns: it reduces leakages, without constituting a proof of perfect independence.

<a id="analyser-un-email-sans-lenvoyer"></a>
## Analyze an email without sending it

```sh
noisefence --config config/local.toml analyze message.eml \
  --source-ip IP_DE_L_EMETTEUR --helo SENDER_HOST \
  --mail-from TEST_SENDER --output reports/analysis.json
```

This command uses the configured connectors, can make DNS and Scaleway queries, and consumes the shared LLM budget if this connector is requested. It does not record any message in the file and does not deliver it to any recipient. Use a private search configuration for candidate models.

<a id="comparer-un-encodeur-multilingue-local"></a>
## Compare a local multilingual encoder

Use Python 3.11 or 3.12 in a separate environment. Since release 0.4.0, the dependencies of this experiment use PyTorch 2.13.0 and Transformers 5.10.1 to integrate their security patches. Historical reports retain their original results and versions: any environment change requires recalculating the insertings and revalidating before a model is activated. These Python packages are not used by the SMTP Rust server nor included in binarys.

The optional experiment uses [multilingual-e5-small](https://huggingface.co/intfloat/multilingual-e5-small), published under MIT license. The revision and fingerprints of the files are pinned in `encoder.lock.json`. Only Safetensors, tokenizer and configuration weights are loaded; no code from the model repository is executed. The pre-entered model remains frozen. A logistic head is learned on emails, then compared to the lexical model and their development combination only. A pre-entered encoder is not a zero developed SMTP engine: it is an optional dependence studied, distinct from the native Rust engine.

```sh
python3 -m venv var/research-venv
var/research-venv/bin/python -m pip install --upgrade pip
var/research-venv/bin/python -m pip install -r research/semantic-requirements.txt
python3 research/fetch_encoder.py models/encoders/multilingual-e5-small
python3 research/prepare_semantic.py corpus/research/features-v3.grouped.jsonl \
  corpus/research/prepared/manifest.jsonl corpus/research/semantic
cargo build --release --locked --example research_text
target/release/examples/research_text corpus/research/semantic/manifest.jsonl \
  corpus corpus/research/semantic/texts.jsonl
HF_HUB_OFFLINE=1 TOKENIZERS_PARALLELISM=false var/research-venv/bin/python \
  research/encode_local.py corpus/research/semantic/texts.jsonl \
  models/research-e5-dev-256 --encoder models/encoders/multilingual-e5-small \
  --device cpu --max-tokens 256
var/research-venv/bin/python research/train_semantic.py \
  models/research-e5-dev-256 corpus/research/semantic/rows.jsonl \
  models/research-mixed-final/predictions.jsonl models/research-e5-comparison
```

On a compatible Mac, `--device mps` uses the local GPU. The text is extracted by the same Rust module as the lexical model. No email is sent to the model provider. The sequences are limited to 256 tokens in the initial experience: a long message end can be lost. The already observed test sets are not reused to choose the combination. A development result does not validate the Rust inference of this encoder, nor its production performance, nor a multilingual target. An unknown recovery with the pre-train data remains possible.

To measure the selected combination on the historical references already examined, freeze the choice first. These measurements should be reported as re-used R&D references, not as a new independent validation.

```sh
var/research-venv/bin/python research/freeze_semantic.py \
  models/research-e5-comparison models/research-mixed-v3-dev/raw-model.json \
  models/research-e5-dev-256
python3 research/prepare_semantic.py corpus/research/features-v3.grouped.jsonl \
  corpus/research/prepared/manifest.jsonl corpus/research/semantic-evaluation \
  --evaluation-only
target/release/examples/research_text corpus/research/semantic-evaluation/manifest.jsonl \
  corpus corpus/research/semantic-evaluation/texts.jsonl
HF_HUB_OFFLINE=1 TOKENIZERS_PARALLELISM=false var/research-venv/bin/python \
  research/encode_local.py corpus/research/semantic-evaluation/texts.jsonl \
  models/research-e5-evaluation-256 --encoder models/encoders/multilingual-e5-small \
  --device cpu --max-tokens 256
var/research-venv/bin/python research/finalize_semantic.py \
  models/research-e5-comparison models/research-e5-evaluation-256 \
  corpus/research/semantic-evaluation/rows.jsonl \
  models/research-mixed-final/predictions.jsonl models/research-e5-reference
```

The threshold is adjusted only to the legitimate calibration. The `combination.json` file describes a Python reference; it is not a model compatible with the Rust activation command. The scripts do not activate anything in production.

<a id="exécuter-la-combinaison-en-rust"></a>
## Run the combination in Rust

Optional porting uses Candle on CPU and local files pinned. Export manifest related to lexical calibrated model, then compile:

```sh
var/research-venv/bin/python research/export_native_hybrid.py \
  models/research-e5-reference/combination.json \
  models/research-mixed-v3-dev/raw-model.json \
  models/research-mixed-final/model.json \
  models/research-e5-reference/native-combination.json
cargo build --release --locked --features semantic
```

In a private copy of the search configuration, keep the lexical template calibrated in `filter.model` and add:

```toml
[filter.semantic]
encoder_dir = "models/encoders/multilingual-e5-small"
combination = "models/research-e5-reference/native-combination.json"
max_parallel = 1
timeout_ms = 500
```

The paths are relative to the current directory. For a service, use absolute paths and set `RAYON_NUM_THREADS=4`, `CANDLE_NUM_THREADS=4`, `TOKENIZERS_PARALLELISM=false` in its environment. The configuration and files must match the same experience; prints, revision, schema and threshold are checked. Without the compilation option, a semantic configuration causes an explicit error at startup.

The SMTP inference uses a bounded blocking worker. The delay does not interrupt the already launched CPU calculation: its niche remains reserved until its end. In case of occupation or failure, the lexical score calibrated is kept and the message is treated as an incomplete analysis, without prefix. `scan` remains an offline synchronous command; `analyze` uses the asynchronous path without delivery.

To measure the two models with the same extractions as the inference:

```sh
RAYON_NUM_THREADS=4 CANDLE_NUM_THREADS=4 TOKENIZERS_PARALLELISM=false \
  target/release/noisefence model-benchmark message.eml \
  --model models/research-mixed-final/model.json \
  --semantic-combination models/research-e5-reference/native-combination.json \
  --encoder models/encoders/multilingual-e5-small --iterations 100
```

Model loading is outside timed iterations. Measurements exclude DNS, scanners, LLM and queue persistence. See [native results](native-hybrid-validation-20260907.json). Encoder vectors are sensitive features with 30-day retention and are excluded from console responses. Manifest export and local tests neither validate production accuracy nor activate a model.

To include DNS, scanners and LLM, use the [full-pipeline benchmark](../docs/performance.md). The [September 7, 2026 latency report](pipeline-latency-20260907.json) compares three profiles on four synthetic messages, records skipped LLM calls and describes measurement limits. It does not establish quality on live traffic.

The [corpus audit and short-text diagnostic](corpus-audit-20260907.md) also document frozen-model generalization limits, heavy duplication in a public dataset and the need for recent representative data.

The [fusion learned from the observations](fusion.md) now provides a Rust export, a regularized trainer, a separate calibration and five ablations frozen before the test. Orders remain offline; the service continues to use the current score until a candidate is validated.
