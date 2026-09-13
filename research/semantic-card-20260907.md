<a id="comparaison-multilingue-locale-du-7-septembre-2026"></a>
# Local multilingual comparison of 7 September 2026

**R&D on development, no deployment or final quality validation.** An optional pre-entry encoder completes the locally learned classifier; the SMTP engine and the lexical Rust model remain distinct from this encoder.

<a id="protocole-figé-avant-les-mesures-de-référence"></a>
## Protocol frozen before baseline measures

- Same training: 27,497 campaign representatives.
- Same development: 2,022 legitimate and 2,672 spam.
- [multilingual-e5-small](https://huggingface.co/intfloat/multilingual-e5-small), `614241f622f53c4eeff9890bdc4f31cfecc418b3` revision, MIT licence declared.
- Frozen weight, vectors of 384 dimensions, `query: ` prefix, masked average then normalization L2, truncated sequences to 256 tokens. PyTorch local inference, without external service, tools, visited links or executed attachments.
- Four L2 logistics heads: C = 0.1 / 1 / 10 / 100.
- Combinations of lexical logit + α × semantic logit, with α among 0.1 / 0.25 / 0.5 / 1 / 2. Thresholds compared to 0.1 % of false empirical positives.
- Selection of the development recall, PR-AUC in case of equality. No choice made on calibration, internal test or archive 2025.

<a id="résultat-de-sélection"></a>
## Selection result

| Candidate | Detections / 2 672 | Recall | False positives / 2 022 |
|---|---:|---:|---:|
| Native lexical model only | 2 569 | 96.15 % | 2 |
| Best encoder alone, head C=10 | 1 930 | 72.23 % | 2 |
| Lexical + 0.1 × semantic C=10 | **2 600** | **97.31 %** | **2** |

The gain is 31 net developmental detections. The lexical model remains essential; the head on encoder alone gives a much lower recall than the same level of false positives. The 2 errors out of 2,022 legitimate give a range of Wilson at 95% from **0.0271 to 0.3599%**. This does not prove the production target and the choice among several candidates adds a selection bias.

The 32 191 texts were encoded in 216.2 seconds on the local Mac GPU, in batches of 16. This preparation rate is not a production latency on the VPS. The Safetensors and associated files were checked against the fingerprints of the preload lock file. This Python selection was then carried out in Rust and verified as described below.

[Candidate details](semantic-development-20260907.json) and [reproduction](README.md#comparer-un-encodeur-multilingue-local).

<a id="mesures-de-référence-après-calibration"></a>
## Reference measures after calibration

The above combination was frozen before these calculations. The threshold is adjusted to the 2 008 legitimate calibration, without changing the weights or α. Reference partitions had already been examined in the previous lexical experiment.

| Mesure | Lexical seul | Frozen combination |
|---|---:|---:|
| Reminder, 5,107 Spams from the Historical Test | 95.59 % (4 882) | **95.83 % (4 894)** |
| False positives, 3,989 historical legitimates | 2 (0,0501 %) | **1 (0,0251 %)** |
| 95% recall interval | 95.00–96.12 % | 95.25–96.34 % |
| 95% false positives interval | 0,0138–0,1826 % | **0,0044–0,1419 %** |
| Reminder on the 426 Nazario 2025 phishings | 93.66 % (399) | **94.84 % (404)** |
| Recall interval 2025 to 95% | 90.94–95.61 % | 92.30–96.57 % |

The external gain is five net detections. **94.84 % remains below 95%**; the high limit of the false positives rate remains above 0.1 %. No legitimate 2025 is present in the archive, so its false positives rate is not measurable. Status remains `eligible: false`. These observations justify continuing R&D, not changing the threshold on this test or enabling automatic marking.

[Detailed results and selection digests](semantic-reference-20260907.json).

<a id="portage-rust-et-limites-dexécution"></a>
## Rust implementation and limits

The `semantic` compilation option loads local Safetensors files with Candle 0.11.0 and tokenizer 0.22.2, without a download client. The three required files must match exactly the pinned fingerprints. The combination manifest binds the coefficients to the lexical calibrated SHA-256, the encoder revision, the text schema and the threshold.

The 24 control messages give the same tokens and decisions. The maximum complete score difference Python/Rust is **0.0000033 points out of 100**. Eight legitimate close to the calibration threshold are part of these controls. Five other synthetic entries cover French, Arabic, Japanese accents, empty text and maximum length; the maximum deviation of vectors is 1.60 × 10−7. These match checks do not measure quality in these languages.

On the Debian VPS 13 x86-64, 4 vCPU / 8 GB, 100 iterations and loaded model:

| Message | p50 | p95 | p99 |
|---|---:|---:|---:|
| 10 127 bytes | 296,460 ms | **340,490 ms** | 380,506 ms |
| 1 048 521 bytes | 340,415 ms | **373,483 ms** | 393,923 ms |

The benchmark includes MIME, lexical features, encoder and combination. It excludes DNS, antivirus, LLM, file and initial loading. During the benchmark, the observed resident memory is 794 032 KiB, with a peak of 1,220 424 KiB including loading. This one-time reading does not prove a maximum limit under all loads. The process consists of nine threads, including threads for running and calculation; the calculation pools are configured to four threads.

The server inference runs out of network threads, with a default CPU slot and a delay of 500 ms. If a calculation exceeds its time, its niche remains occupied until its end; a new busy request does not stack any other calculations. The lexical calibrated score is retained and the analysis becomes incomplete, without prefix. The vectors are kept with the other features for 30 days; the user API exposes the status and latency, not these vectors.

[Native measurements](native-hybrid-validation-20260907.json). In that experiment the production service was not replaced, and temporary VPS files were removed.

## Limits

The legitimate ones are historical and do not validate the current French traffic. A multilingual encoder does not make this multilingual evaluation: there is a lack of recent representative messages, annotations by language and a measurement by sub-group. A cover with the pre-training of the encoder is unknown. The long text is truncated and the contents of the attachments are not used.

The combination selection is frozen before a measurement on the other partitions. These tests have already been examined during the first lexical experiment: they now serve as R&D references and do not constitute a new independent validation. The combination with SPF, DMARC, reputation, antivirus, signatures and LLM reviews remains to be evaluated separately. There are no results presented here that allow to announce perfect detection.
