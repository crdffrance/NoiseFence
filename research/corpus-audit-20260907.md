<a id="données-récentes-et-diagnostic-sur-textes-courts"></a>
# Recent data and diagnostics on short texts

In this additional diagnostic the frozen model detected **9 of 23 texts labelled phishing**, with no false positives among **77 texts labelled legitimate**. The [JSON report](text-challenge-20260907.json) records counts and limitations. This does not validate live-traffic capture; it illustrates why success on one private email cannot evaluate a model.

<a id="provenance-vérifiée"></a>
## Verified source

A recent publication does not guarantee recent emails. The corpus [MeAJOR](https://arxiv.org/html/2507.17978v1) includes the former TREC 2005–2007. The [DataPhish project described in 2025](https://arxiv.org/html/2511.21448v1) announces more recent messages, but its referenced repository responds 404 during the control of September 7, 2026. Its data have not been acquired.

[Sting9](https://sting9.org/dataset) refers to threats. Its access page mentions CC0, while its [related license](https://sting9.org/license) sets out trade restrictions. It is not used here; no legitimate representative cohorts have been established there.

The [University dataset of Milchev, Rangelov and Genchev, v1](https://zenodo.org/records/13474746) is accessible under [CC-BY-4.0](https://creativecommons.org/licenses/by/4.0/). It mixes real and synthetic. The audited CSV audit finds 2,000 lines, but only 100 separate texts from 68 to 103 characters. It contains no date per message, no actual/synthetic indicator, or original SMTP context. The original texts are not redistributed in NoiseFence.

<a id="méthode-et-résultats"></a>
## Method and results

Before any prediction, the weights, threshold 95, prints and selection of the 100 separate texts were frozen. Each text becomes the body of a MIME `text/plain; charset=utf-8`, encoded in 8 bits with the SMTP ends of `email.message.EmailMessage`. No object, sender, recipient or time stamping is invented. The CSV labels remain separate from the characteristics.

The examples Rust `research_text`, `semantic_probe` and `feedback_probe`, with `features-export --feature-version 3`, use extraction and existing local models. The 100 predictions are complete. No DNS, scanner, external LLM, learning or SMTP sending is involved in this diagnosis.

| Selection | Legitism | Phishing | Phishing detected | False positives |
| --- | ---: | ---: | ---: | ---: |
| Distinct exact texts | 77 | 23 | 9 | 0 |
| Representatives of similar groups | 59 | 19 | 9 | 0 |

The lexical model and its E5 combination give the same rankings. The groups use canonical text and a SimHash distance of not more than three bits, with a representative chosen by print before prediction. No reconciliation with the 61 198 messages from the existing sources is found by this heuristic; it is not an absolute proof of independence.

Repetitions and the selection of short examples prevent the deducing of a false production positive rate or a representative confidence interval. Some phishing labelled formulations could also appear in a legitimate notification: without a sender or real link, the text alone can be ambiguous. The result is reported against the labels provided by the authors.

Weights and production configuration remain unchanged. This dataset remains excluded from training and cannot serve as a new blind validation after examination. The next calibration requires recent emails that are authorized, annotated and representative, with separate campaigns and reception context.
