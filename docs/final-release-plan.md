# Final release qualification plan

This is a release plan, not a claim that NoiseFence has achieved the detection targets. A deployable, tested gateway and a qualified statistical filter are separate deliverables. Keep production in observation until the candidate meets the agreed gates. Do not add more engines before qualifying the existing combination.

## 1. Freeze a reproducible baseline

Record application build, policy revision, model digests, feature schema, LLM prompt/provider model, provider settings, Rspamd profile and SMTP evidence provenance. Separate native arrivals, reconstructed-envelope replays, encrypted messages and historical software cohorts. Preserve arrival-time results; candidate projections and replays belong in separate records.

Use human labels, not Rspamd verdicts, as reference truth. Retain unsolicited marketing as an explicit preference rather than assuming every newsletter is malicious. Track message and campaign denominators. Split campaigns before development, calibration and sealed prospective evaluation; do not tune on the final evaluation set. Known corrected examples remain regression fixtures, not independent accuracy evidence.

Deliverables: immutable evaluation manifests, reproducible per-message comparisons, label provenance, campaign splits, and a complete coverage report.

## 2. Repair the evidence and LLM contract

Prioritize current sender requests and action links within the existing shared 12,000-byte limit. Separate quoted material, conditional account-security instructions, completed transaction notices, newsletters, technical threat reports, attachment/OCR text and untrusted service-template fields. Preserve malicious action links even inside authenticated third-party services.

Compute registrable-domain relationships and observed SPF/DKIM/DMARC/ARC facts in Rust. The LLM must cite supplied evidence identifiers for suspicious domains, redirects, impersonation or attachment behaviour; unsupported assertions must not become positive evidence. A matching authenticated domain is useful context, never a blanket allowlist. Unknown consent is not proof of phishing, and model confidence is not a calibrated spam probability.

Use structured risk, mail-kind, requested-action and evidence outputs. Internal uncertainty is permitted; final automatic policy uses the calibrated risk contract rather than exposing a manual backlog. Test legitimate security alerts against lookalike attacks, threat feeds against live lures, invoices against fraudulent payment changes, and service templates with attacker-controlled fields. Validate the candidate on both wanted and unwanted controls before any activation.

## 3. Produce one qualified score

Replace the uncalibrated historical ranking as the final operating score. Start with a small, regularized fusion model over named signal families and explicit availability features. Prevent correlated lexical, semantic, rules and LLM evidence from being counted twice. Compare ablations so that each active component has a demonstrated benefit at the same false-positive constraint.

Calibrate on disjoint data and evaluate reliability by score band, language, mail kind, tenant and coverage profile. Missing providers cannot count as benign evidence. Include a qualified fallback for partial coverage; never manufacture a zero after failed extraction. Keep malware priority separate from the statistical score.

Sensitivity levels select validated, monotonic thresholds on the same score. Domain and recipient settings override policy with documented precedence, without secretly changing units or model inputs. Existing raw detector outputs remain diagnostic only. Automatic threshold resolution is an explicit compatibility option; it does not itself calibrate a score.

Deliverables: one versioned score contract, calibration report, model provenance, threshold table, independent ablations and rollback artifact.

## 4. Make every surface use the same result

Use one Rust assessment contract for engine risk, mail kind, recipient classification, coverage and delivery action. Evaluate each recipient policy once. The Web list, message detail, search totals, API, SMTP headers, exports and comparison workbench consume that contract.

Display separately: **risk index**, **classification**, **mail kind**, **analysis coverage**, **effective action**, and **model/policy version**. Show active, unavailable, untrained and observation-only engines accurately. Never compare Rspamd points numerically with a 0–100 NoiseFence index. Historical results retain their original model and policy, with any current-policy projection clearly labelled.

Test threshold boundaries, multiple recipients with different profiles, complete/partial/unscannable content, contradictory advice, configured fail-open, confirmed malware, historical projections, tenant permissions and repeated evaluation. Add shared fixtures for Web/API/headers and verify equal results on both MXs with fixed recorded observations.

## 5. Qualify coverage and operational reliability

Measure CRDF timeouts and response parsing separately from provider listings. Preserve unavailable/stale/quota states, bound retries and caches, and avoid disabling useful providers globally after one unsupported response. Respect current licences, quotas and budgets.

Improve bounded URL processing from measured stop causes: prioritize action links, resolve HTTP redirects before final-body processing, distinguish oversized final pages from unresolved redirects, and expose client-side navigation as unsupported unless a separately isolated implementation is qualified. Never relax private-network/SSRF, response-size or deadline guards to improve coverage counts.

Test queue persistence, required peer copies before SMTP acceptance, worker restart, lost SMTP responses, disk exhaustion, downstream temporary and permanent errors, unknown recipients, console failover and rolling upgrades. On the agreed 4-vCPU/8-GiB reference machine, report native warm-cache analysis and full external-service latency separately. Keep the native p95 target below 500 ms for messages up to 1 MiB and external checks within the configured five-second envelope; measure throughput, memory and queues under overload.

## 6. Release gates

| Gate | Evidence required |
| --- | --- |
| Detection | Independent recent corpus; spam and phishing recall at least 95%, with confidence intervals and campaign-weighted results. |
| False positives | At most 0.1% of wanted messages classified unwanted; publish an upper confidence bound and classify marketing according to user preference. |
| Statistical support | For orientation, 2,995 independent wanted observations with zero errors are needed for a one-sided exact 95% upper bound at or below 0.1%. Correlated campaigns and a selected correction set do not satisfy this requirement. More observations are needed if errors occur. |
| Comparative claim | NoiseFence and Rspamd on the same eligible originals and transport evidence; frozen profiles, human truth, missing-result accounting, campaign splits, false positives, misses and indecisive actions reported. |
| Coherence | Shared decision fixtures pass across Rust, API, headers and Web; identical software, model and policy digests on every MX. |
| Reliability | Durable acceptance and failover tests pass; no silent loss; bounded resources and documented possible SMTP duplicates. |
| Deployment | Observation, then qualified canary, then explicit action activation; automated rollback on regression and a tested rollback package. |
| Open-source package | English documentation and UI, installation/upgrade/uninstall procedures, Docker/systemd smoke tests, example configuration without secrets, dependency licences, vulnerability review, changelog and signed/checksummed artifacts. |

A finite test cannot establish perfect detection against every future message. Version 1.0 should mean the declared functional and statistical contracts have passed, with known limits and monitoring, rather than a 100% capture promise. Freeze the evaluation protocol before observing the final holdout; if it is used for a repair, reserve a new final set.

References: [Rspamd actions and scores](https://docs.rspamd.com/configuration/metrics/), [NIST exact binomial confidence limits](https://itl.nist.gov/div898/software/dataplot/refman2/auxillar/exacbino.htm).

## Candidate 0.27.0: implemented qualification safeguards

- Prompt 10 requests bounded evidence references and a separate mail kind. Rust assigns identifiers to exact bounded text records and validates references against the actual request, current versus quoted text, observed authentication failures and supplied domain relationships. Unsupported declared ownership/attachment claims have no LLM scoring weight or definite opinion and are unavailable inputs to fusion. This is a consistency check on declared evidence, not proof that a quote entails a verdict, nor a prompt-injection guarantee.
- Conditional security notices are evaluated as context; neither a brand name nor successful authentication grants a sender an allowlist. Synthetic counterexamples retain explicit malicious requests.
- The quality page exposes read-only, recipient-scoped current-cohort label and coverage counts. These include development samples and do not certify accuracy or trigger training/activation. The existing promotion contract requires at least 10,000 wanted and 2,000 unwanted test messages, in addition to independence and confidence-bound gates; the statistical illustration above does not relax it.
- CRDF preserves valid targets within a structurally valid mixed batch. Invalid target responses are unavailable and uncached. An invalid response does not impose account-wide backoff; authentication/rate-limit responses still do.
- URL inspection can follow complete early meta redirects from a bounded oversized-page prefix. A truncated page without a usable redirect remains incomplete. Reaching HTTP 2xx, resolving the full chain and scanning a complete page remain distinct diagnostics. SSRF, DNS revalidation, hop and time limits are unchanged.

### Operator procedure

1. Keep **Filters → observation** and freeze detector/model/policy digests. Upgrade all MX software before collecting a new qualification cohort; mixed-version rolling-upgrade traffic is not one evaluation cohort.
2. Open **Filter quality**, inspect **Evidence before activation**, and create distinct development and regression samples from the current cohort. Label messages without using engine scores as truth. Put previously corrected examples in regression, not the final holdout.
3. Use the existing calibration workbench to export/train an observation-only candidate. Preserve rejected preparation reports when classes, campaigns, provenance or profiles are insufficient; do not force a fit or lower the statistical gates to obtain a model.
4. Compare frozen NoiseFence and Rspamd results on the same human-labelled messages. Report missing analyses, unresolved actions, campaign denominators and results by mail kind/coverage. LLM-only regressions and reconstructed excerpts are separate experiments, never gateway accuracy results.
5. Reserve a new prospective holdout after all prompt/rule changes. Qualify native and external latency separately on the reference hardware. Only activate actions after the independent promotion gates pass; keep the prior artifact and policy revision for rollback.

No sample count, passing software test or selected regression result alone qualifies version 1.0. Historical arrival decisions and user delivery policies are not rewritten by this candidate.
