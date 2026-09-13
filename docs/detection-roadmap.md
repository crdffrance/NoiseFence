<a id="renforcer-noisefence--architecture-et-entraînement"></a>
# Strengthening NoiseFence: architecture and training

The objective is measured protection, not the largest number of engines. The September 6 research candidate achieved 95.59% recall on its internal test and 93.66% on the Nazario 2025 phishing archive. Those results did not justify activation: statistical evidence and recent representativeness were insufficient. See the [model card](../research/model-card-20260906.md). Adding antivirus or an LLM does not turn this into a capture guarantee. Each layer needs independent evaluation of incremental benefit, errors, latency, memory and external calls.

<a id="état-de-la-version-de-développement"></a>
## Status of the development version

Implemented: ClamAV scan connectors on separate sockets, verdict storage and display, logistics classifiers and Bernoulli Bayes, Scaleway client with sustainable budget and JSON validation. Scaleway scanners and client have been tested locally and on the server. LLM automated tests use a simulated HTTPS server; actual diagnostics are distinct from quality measurements. [antivirus](antivirus.md) and [Scaleway](scaleway.md) guides describe activation.

The historical comparison uses the same 4,659 examples of training, 609 validation and 606 testing. Bayes detects 1 spam out of 192 (0.52%), compared to 117 out of 192 (60.94 %) for logistics; no false positives observed on only 414 legitimate messages. Both candidates are refused. Therefore, adding Bayes does not constitute a demonstrated gain; there remains an experimental point of comparison.

The new comparison uses 46,361 representatives from similar groups, with separate learning, development, calibration and testing. Schema 3 adds character groups and a clean HTML text; its export is verified with the Rust inference. The protocol and sources are in `research/`.

A frozen multilingual encoder and logistic heads were also compared offline. The combination chosen on development data detected 31 additional spam messages with the same observed false-positive count; see the [comparison](../research/semantic-card-20260907.md). Its Rust port reproduced the 24 control decisions and measured 373.5 ms p95 for a roughly 1 MB message on the VPS, excluding connectors. A recent representative independent corpus, calibration with other checks, language-specific evaluation and full-pipeline measurements are still required. These historical measurements do not authorize a delivery-policy change.

The [SMTP/DNS controls](smtp-policy.md) add a layer of consistency of transport identities. Their candidate score is observed separately before calibration; no capture improvement is yet demonstrated.

<a id="chaîne-de-décision"></a>
## Decision-making chain

1. **SMTP and authentication.** Explicit recipients, limits, TLS, SPF, DKIM, DMARC and ARC on the original, durable file. Errors in protocol, resources and content verdicts remain separate.
2. **Local Antivirus.** Send the message to ClamAV by Unix socket with INSTREAM. ClamAV decodes MIME and archives within time, size and depth. FreshClam maintains the official bases. No attachment is executed.
3. **Add a conservative selection of unofficial databases, with integrity/signature verification and reload control. A spam/phishing signature or encrypted archive alone does not constitute proof of a virus. Keep the supplier and the name of the trigger.
4. **Combined local analysis.** IP/domain reputation, identity alignment, MIME/HTML/link rules, text and structural classifications. No link download, no script execution or macro. Unavailability is visible.
5. **LLM Scaleway on ambiguous cases.** Dedicated IAM project and application, project-limited key, Chat Completions compatible API, JSON output with closed schema. Send only a bounded text extract; no binary attachment. The message is a hostile data, never an instruction for the assistant. No tools or navigation accessible to the model. A delay, budget or invalid response leaves the decision to the local pipeline.
6. **Determination and traceability.** Keep the results of each engine, their versions, reasons and latency. The LLM provides a signal, not an order for delivery, deletion or modification of permissions.

Antivirus policies and the LLM ceiling are explicit operator parameters. Forty malicious files, if enabled, will be distinct from the antispam ranking. Unofficial signatures with high false positives should not automatically cause the retention of a legitimate message.

<a id="jeu-de-données"></a>
## Dataset

- Use SpamAssassin history only for start-up and regressions. Add recent authorized examples, in French and in the languages actually received: trade exchanges, invoices, notifications, lists, transfers, phishing, usurpation, commercial spam and messages with attachments.
- A user's corrections only concern its recipients. Keep their source; exclude contradictions and limit the influence of an account or campaign. A return never directly alters the active model.
- Remove old scores, folders, corpus markers and filter headers. Regroup exact duplicates and campaign variants before separation. Keep domains, languages and dates to control leak effects and drift.
- For a representative assessment, target at least 10,000 legitimate messages and 2,000 independent spams in the final test. This volume does not guarantee that subgroups are large enough; publish their numbers and intervals.
- The bodies delivered are removed from the spool. Make a separate raw corpus only with messages allowed for training and explicit retention. The chopped characteristics do not make messages anonymous.

<a id="comparaison-des-modèles"></a>
## Comparison of models

First build a reproducible reference: logistic regression L2 on TF-IDF and structure, then Bayesian model on the same data. Then compare a tree model on the structured signals and, if the gain justifies it, a multilingual local encoder. Large models must justify their memory and latency on 4 vCPU / 8GB. The LLM output can be a feature of the combination model; it must not serve as a training truth alone.

Separate four uses: training the basic models, adjusting the combination, calibration the thresholds, and then frozen test. When the dates are known, the test contains campaigns more recent than training. Campaign groups do not cross any partition. If the corpus does not allow this, explicitly indicate the limit and refuse a conclusion of production quality.

Publish for each candidate recall, false positives, accuracy, PR-AUC, calibration, confidence intervals and results by language/type of message. Compare the ablatives: local only, local + reputation, local + antivirus/signatures, then add the LLM. Also measure the share of messages that view Scaleway and its actual cost.

## Activation requirements

- Capture target: at least 95% on the independent test; publish also the confidence interval, without presenting the target as already achieved.
- False positives: not more than 0.1%, with 95% interval top end compatible with this target. A tiny zero error test is not enough.
- Measure the complete pipeline, not just the text score. No engine must significantly degrade a legitimate critical category without prior correction.
- Target p95 below 500 ms on messages up to 1 MB with warm caches; separately publish expensive antivirus cases, LLM calls and incomplete analyses.
- Version model, schema of features, rules, signatures and prompt LLM. Activate a validated candidate first in observation and then gradually. Keep the previous model and a reverse procedure.
- Proton compatibility remains a distinct milestone. The first direct and relayed tests arrive in spam; they do not validate the modification of Subject or ARC.

## Operations and isolation

ClamAV uses a local Unix socket, not a public port without authentication. User access is via HTTPS and SMTP STARTTLS. Scaleway keys remain in server secrets; the repository contains only examples. The Scaleway project, the IAM application and the key must be NoiseFence-specific, with the minimum permissions to call the selected templates. No permanent GPU instance is required to start with serverless APIs.

The monthly budget must be monitored and reserved before each request so that competing calls do not exceed the ceiling. Also count interrupted requests whose billing is uncertain. A local limit does not replace the supplier's billing controls and alerts.

References: [ClamAV and its scan protocol](https://docs.clamav.net/manual/Usage/Scanning.html), [official databases](https://docs.clamav.net/manual/Usage/SignatureManagement.html), [Scaleway Generative APIs](https://www.scaleway.com/en/docs/generative-apis/api-cli/using-generative-apis/).
