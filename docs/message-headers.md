# Message diagnostic headers

Newly prepared messages use **`X-NoiseFence-Header-Version: 9`**. The API and headers use the same receipt-time assessment, version 1. Already delivered or queued messages keep their original bytes and header version; this release does not rescan or resend them.

## Risk, classification and delivery

| Header | Meaning |
| --- | --- |
| `X-NoiseFence-Id` | Queue identifier; not an authorization token |
| `X-NoiseFence-Header-Version` | Wire contract version, currently `9` |
| `X-NoiseFence-Activation` | Recorded activation sequence, configuration revision and policy/model bundle SHA-256, or `not_recorded` |
| `X-NoiseFence-Assessment-Version` | Shared API/header assessment contract, currently `1` |
| `X-NoiseFence-Record-Version` | Receipt decision schema version, currently `2`, or `not_recorded` |
| `X-NoiseFence-Classification` | `legitimate`, `publicity`, `spam`, `phishing`, `malware`, `unassessed`, or `not_recorded` |
| `X-NoiseFence-Coverage` | `complete`, `partial`, `unavailable` (content extraction unavailable), or `not_recorded` |
| `X-NoiseFence-Policy-SHA256` | Fingerprint of the applied policy, threshold, rules and action; not a signature |
| `X-NoiseFence-Action-Requested` | Requested `deliver`, `tag` or `quarantine`, or `not_recorded` |
| `X-NoiseFence-Action-Effective` | Effective preparation-time action, or `not_recorded` |
| `X-NoiseFence-Action-Coverage` | Action evaluator version, partial-action policy, basis, evidence eligibility, required and missing fact codes; `not_recorded` on old records |
| `X-NoiseFence-Version` | NoiseFence software version |
| `X-NoiseFence-Mode` | Processing mode: `observe`, `tag` or `enforce` |
| `X-NoiseFence-Score` | Selected finite risk value, one decimal place, or `unavailable` |
| `X-NoiseFence-Score-Scale` | `0-100` |
| `X-NoiseFence-Score-Type` | `content`, `decision`, `advisory`, `partial`, `internal` or `unavailable` |
| `X-NoiseFence-Score-Source` | `decision`, `raw` or `unavailable` |
| `X-NoiseFence-Model` | Identifier of the model associated with the selected score |
| `X-NoiseFence-Raw-Score` | Recorded content score |
| `X-NoiseFence-Decision-Score` | Usable non-antivirus decision score, or `unavailable` |
| `X-NoiseFence-Status` | Required analysis coverage: `complete` or `incomplete` |
| `X-NoiseFence-Decision` | Engine outcome: `legitimate`, `unwanted` or `undetermined` |
| `X-NoiseFence-Decision-Recorded` | `yes` for a stored decision; `no` for a historical fallback |
| `X-NoiseFence-Decision-Source` | `legacy`, `fusion` or `antivirus` |
| `X-NoiseFence-Verdict` | Primary grouping: `spam`, `ham` or `pub`; independent of Rspamd |
| `X-NoiseFence-Category` | Recorded delivery classification: `spam`, `publicity`, `legitimate` or `undetermined` |
| `X-NoiseFence-Classification-Source` | `recipient_policy`, `recorded_decision` or `historical_fallback` |
| `X-NoiseFence-Content-Threshold` | Content threshold captured at analysis time; `unavailable` when absent |
| `X-NoiseFence-Score-Boundary` | Versioned comparison for the selected score: native unit/value/cutoff, mapped index cutoff, inclusive comparison result and optional fusion model hash; `not_recorded` for missing history, `unavailable` without a usable score |
| `X-NoiseFence-Policy-Version` | Recorded decision policy version, or `not_recorded` |
| `X-NoiseFence-Delivery-Policy` | Original requested/effective action and a bounded reason code, or `not_recorded` |
| `X-NoiseFence-Subject-Tag` | Prefix actually added: `none`, `spam` (`[SPAM]`) or `publicity` (`[PUB]`) |

Version 2 mixed coverage and actual tagging in `Status` (`incomplete`, `spam`, `pub`, `observed`). **Consumers must branch on Header-Version.** Versions 3 and 4 preserve these aliases: read `Category` for classification, `Status` for coverage and `Subject-Tag` for modification. Observation can therefore record `Category: spam` with `Status: complete`, delivery effective `deliver`, and `Subject-Tag: none`.

Version 4 adds the explicit receipt decision fields. `Category` remains a compatibility grouping: phishing and malware belong to spam; `Classification` provides the detailed recorded finding. `unassessed` is not a verified legitimate classification. Legacy rows without a receipt record emit `not_recorded` for the new fields.

Version 5 preserves those aliases and adds `Action-Coverage`. Its `eligible=yes`
means evidence requirements are met; it does not override observation mode or
Proton validation. Read `Action-Effective` for the action actually prepared.

Version 6 adds `Activation`, captured from the MAIL-pinned runtime before analysis
and header preparation. Receipt schema 2 binds the same identity into analysis
and recipient records. Replication/history reject missing or contradictory
identities in these new records. The assessment schema remains version 1.
Legacy schema-1 receipts remain readable, including unavailable scores; an old
transport-only epoch never fills missing canonical identity. Uncoordinated and
offline analyses emit `not_recorded`. Hashes identify configuration, not detection
quality or authentication. Existing queued bytes are not rewritten.
Upgrade all replica/history readers and the console before enabling schema-2
producers. Older strict receivers may reject new receipts, causing SMTP deferral
under mandatory two-copy acceptance. Never downgrade a receipt to bypass this
check; mixed-version deployment remains a qualification gate.

The additive `Score-Boundary` field uses boundary version 1. `content_index`
compares the selected content index with its recorded recipient threshold.
`fusion_logit` compares the uncalibrated fusion logit with the model's own cutoff;
`index-cutoff` is its mapped 0–100 display value, not another comparison rule.
Native comparisons are inclusive (`value >= cutoff`). Flat calibration and
floating-point saturation can map opposite sides of a cutoff to the same index.
Boundary numbers retain round-trip precision, using scientific notation when
needed; the existing one-decimal score and content-threshold aliases are unchanged.
Evidence and recipient rules can override a score-based classification, and
delivery restrictions can alter its action. This field describes the score's
operating point, not sole authority to classify or quarantine a message.
Older receipt snapshots retain missing boundaries; readers never substitute the
current content setting for a missing fusion cutoff.
For example, `basis=score_threshold; eligible=no; missing=subject_rewrite;`
explains why a scored spam was delivered without the requested subject prefix.

The risk index is not generally a spam probability. A missing decision score does not erase a valid content index. Malware does not become a fabricated 100. The captured content threshold is not a fusion model's decision threshold. The delivery-policy header describes preparation time, not a later manual quarantine release or the destination's inbox placement.

## Check details

| Header | Recorded information |
| --- | --- |
| `X-NoiseFence-Analysis` | Completion flag and elapsed milliseconds |
| `X-NoiseFence-Checks` | States of lexical extraction, authentication, SPF/DKIM/DMARC/ARC, DNS reputation, semantic analysis, antivirus, signatures, SMTP, LLM, vision and fusion |
| `X-NoiseFence-Authentication` | Recorded SPF, DKIM, DMARC alignment and ARC outcomes; complements standard `Authentication-Results` |
| `X-NoiseFence-Incomplete-Reasons` | Known missing-check codes, `none` when complete, or `unspecified` |
| `X-NoiseFence-Arbitration` | Baseline, second opinion and agreement/disagreement resolution |
| `X-NoiseFence-Rules` | Retained ledger rule contributions in log-odds, with total/shown/omitted counts; legacy signals only when exact accounting was not recorded |
| `X-NoiseFence-Score-Combination` | Recorded combination policy, retained rule total and total logit, or `not_recorded` |
| `X-NoiseFence-Rule-Adjustments` | Bounded rule IDs with duplicate, unavailable-evidence or composite-consumption adjustments; includes the consuming rule where recorded |
| `X-NoiseFence-LLM` | Status, advisory category, category/probability coherence, usable opinion, bounded failure code and duration |
| `X-NoiseFence-Antivirus` | Primary antivirus and complementary signature outcomes and duration |
| `X-NoiseFence-Vision` | OCR status, inspected parts/pages, QR/other code counts, errors and duration |
| `X-NoiseFence-Vision-Errors` | Known bounded failure codes; at most 16 |
| `X-NoiseFence-Reputation` | CRDF/VirusTotal states, checked/malicious/suspicious/unknown counts, cache, omissions and failure |
| `X-NoiseFence-RBL` | IP checks before DATA, independent listings and actual admission action |
| `X-NoiseFence-Native` | Native analysis state/mode, calibration and delivery-effect indicators |
| `X-NoiseFence-Native-Rules` | Unabsorbed native symbols and points before family caps; distinct from content log-odds |

`complete` means a check finished, not that its result was clean. `disabled`, `not_run`, `skipped`, `limited`, `busy`, `unavailable`, `unknown` and `not_recorded` do not mean safe. An advisory check can fail without making the entire required analysis incomplete. LLM `not_needed` means the message was not selected for that check.

A shortened synthetic example:

```text
X-NoiseFence-Header-Version: 9
X-NoiseFence-Assessment-Version: 1
X-NoiseFence-Mode: observe
X-NoiseFence-Score: 87.4
X-NoiseFence-Score-Type: partial
X-NoiseFence-Score-Source: raw
X-NoiseFence-Score-Scale: 0-100
X-NoiseFence-Raw-Score: 87.4
X-NoiseFence-Decision-Score: unavailable
X-NoiseFence-Status: incomplete
X-NoiseFence-Decision: undetermined
X-NoiseFence-Category: undetermined
X-NoiseFence-Classification-Source: recorded_decision
X-NoiseFence-Delivery-Policy: requested=deliver; effective=deliver;
 reason=observation;
X-NoiseFence-Subject-Tag: none
X-NoiseFence-Incomplete-Reasons: vision_incomplete
```

## Size, privacy and authenticity

Generated fields use bounded ASCII tokens. Folding targets 78 columns between atoms; an atom is at most 256 characters. Each rule list includes at most 24 entries, with identifiers at most 64 characters and explicit omission counts. Log-odds and native points do not sum to 100. Detailed explanations remain in the authorized console.

These diagnostics exclude bodies, subjects, full URLs, recipient/Bcc addresses, recipient profile names and provider secrets. Untrusted free text is not copied into headers. Incoming `X-NoiseFence-*` fields are stripped before local results are added.

All generated diagnostic fields are included in the ARC signing inventory when sealing succeeds. The unsealed fallback still adds diagnostics without claiming they are authenticated. A signature does not establish that the upstream trusts this intermediary. See [RFC 5322](https://www.rfc-editor.org/rfc/rfc5322.html#section-2.2.3), [RFC 8617](https://www.rfc-editor.org/rfc/rfc8617.html) and the [Proton validation guide](proton-validation.md).

As of 0.21.0, `X-NoiseFence-LLM` includes `coherent=yes|no|not_recorded` and `opinion=legitimate|unwanted|undetermined|none`. A completed response can still be inconsistent and supply no definite opinion. No explanation text or authentication identity is exported in this field. A corroborated threat can have `Decision: unwanted` and `Status: incomplete` together; the partial index and missing-check reasons remain separate from delivery policy.

### LLM citation diagnostics (0.27.0)

`X-NoiseFence-LLM` includes `grounding=supported`, `unsupported` or `not_recorded`.
`status=complete` means a provider response was received and parsed; it does not
imply useful evidence. With unsupported citations the LLM has zero advisory
weight, no definite opinion and unavailable fusion inputs. `supported` means the
declared citations passed bounded consistency checks, not that the verdict is
correct or that its confidence is calibrated. Older observations are
`not_recorded`, never retrospectively certified. The header contains no message
excerpts, private URL paths, provider keys or model explanation text; it remains
part of the existing signed internal-header set.

`response-issue=output_limit|invalid_envelope|unsupported_completion|invalid_json|model_mismatch|schema_or_verdict|none`
distinguishes a rejected provider response without storing its body or exception
text. The same fixed diagnostic is available in the API and message detail.

Prompt 10 supplies Rust-generated text record IDs and accepts references to those
records, rather than asking the provider to reproduce quotes. The indexed records
contain each bounded source field exactly once; indexing does not increase the
12,000-byte content allowance. A model can still misunderstand a valid referenced
passage. Reference validity must not be presented as calibrated accuracy.

## Version 8 authentication eligibility

When captured evidence is present, `X-NoiseFence-Authentication` starts with
`eligibility=transport-evidence-1`; otherwise it remains `not_recorded`.
It exposes only captured results accepted by the same eligibility checks used by
scoring, confirmation and LLM context. Incompatible schemas, inactive parents,
missing result pairs, temporary errors and oversized DKIM result lists produce
`not_recorded` rather than a misleading pass/fail. ARC remains independently
eligible when the SPF/DKIM/DMARC group is disabled.

`X-NoiseFence-Checks` remains the captured execution-state summary; completing a
check is distinct from obtaining usable evidence. Normalized diagnostic exclusions
explain the distinction. Existing queued bytes and historical receipts keep their
original header version. No original Authentication-Results header supplies these
internal facts, and this change does not modify score thresholds or delivery policy.

## Three-way verdict (header version 9)

The primary console badge, the message-list and diagnostic API `verdict` field,
and `X-NoiseFence-Verdict` use **Spam / Ham / Pub** (lowercase on the wire).
Phishing and malware belong to Spam; their detailed findings remain in
`X-NoiseFence-Classification` and detector details. Ham describes the delivery
classification, not a guarantee of safety. Coverage, missing scores and failures
remain visible separately. Recipient policy still determines each copy.

Existing category identifiers (`legitimate`, `publicity`, `spam`) remain stable
in the API, filters and immutable receipts for compatibility. Old undecided
records use the neutral Ham fail-open grouping with an explicit explanation.
Their original undecided assessment remains available for auditing and evaluation. This display does not rewrite the
original decision, delivery, score or queued message. Rspamd is never used.
