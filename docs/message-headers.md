# Message headers

NoiseFence adds a versioned set of diagnostic headers to newly prepared messages. The current wire contract is **version 11**, identified by `X-NoiseFence-Header-Version`. Every generated NoiseFence header is included in the ARC signing inventory when sealing succeeds.

The headers describe the analysis and policy recorded when the message was accepted. They do not prove that the destination placed the message in an inbox, and a risk index is not a spam probability. Rspamd is an independent comparison and never supplies or changes the NoiseFence verdict.

## Header catalog

The contract keeps the same 25 fields in a stable order. Details that describe the same subject are grouped into a small number of semicolon-delimited fields; values are bounded ASCII tokens and may be folded across lines as permitted by RFC 5322.

| Header | Meaning |
| --- | --- |
| `X-NoiseFence-Header-Version` | Wire schema version. Current value: `11`. |
| `X-NoiseFence-Id` | Queue/message identifier. It is not an authorization token. |
| `X-NoiseFence-Version` | NoiseFence software version. |
| `X-NoiseFence-Verdict` | User-facing class: `spam`, `ham` or `pub`. Phishing and malware map to `spam`. |
| `X-NoiseFence-Classification` | Recorded detailed classification, such as `spam`, `phishing`, `malware`, `publicity`, `legitimate`, `undetermined` or `unassessed`. |
| `X-NoiseFence-Coverage` | Receipt-time required-analysis coverage: `complete`, `partial`, `unavailable` or `not_recorded`. Coverage is separate from the verdict. |
| `X-NoiseFence-Score` | Selected finite risk value from 0 to 100, one decimal place, or `unavailable`. |
| `X-NoiseFence-Score-Type` | `content`, `decision`, `advisory`, `partial`, `internal` or `unavailable`. |
| `X-NoiseFence-Mode` | Processing mode recorded at receipt: `observe`, `tag` or `enforce`. |
| `X-NoiseFence-Score-Details` | `scale`, score `source`, `model`, original `content` score, usable `decision` score and content `threshold`. A missing score is `unavailable`, never an invented zero. |
| `X-NoiseFence-Score-Boundary` | Versioned score comparison: unit, precise value and cutoff, mapped display cutoff, comparison result and optional model digest. `fusion_logit` is compared in its native unit. |
| `X-NoiseFence-Policy` | Explicit `record-version`, `assessment-version`, `policy-version`, `classification-source`, decision outcome/source/recorded state, `policy-sha256` and activation identity. Digests identify configuration; they are not signatures. |
| `X-NoiseFence-Delivery-Policy` | Requested and effective action, bounded reason, subject tag, and action-prefixed coverage requirements. The action is the gateway's recorded preparation-time action. |
| `X-NoiseFence-Analysis` | Whether required checks completed, elapsed milliseconds, bounded incomplete-check codes and supplementary gaps. |
| `X-NoiseFence-Checks` | Execution state for lexical, authentication, SPF, DKIM, DMARC, ARC, DNS reputation, semantic, antivirus, signatures, SMTP, LLM, vision and fusion checks. |
| `X-NoiseFence-Authentication` | Eligibility version and accepted SPF, DKIM, DMARC-alignment and ARC outcomes. It complements standard `Authentication-Results`; it does not replace it. |
| `X-NoiseFence-Rules` | Score-combination version and totals, bounded adjustment records, and retained rule ledger with explicit units/counts. Native points and log-odds are not percentage points. |
| `X-NoiseFence-Arbitration` | Baseline and advisory second-opinion relationship. It is diagnostic and does not delegate the verdict to Rspamd. |
| `X-NoiseFence-Score-Resolution` | Recorded automatic threshold resolution, including previous and resulting outcomes when available. |
| `X-NoiseFence-LLM` | Provider-check status, bounded category/opinion, coherence, grounding, fixed failure code and duration. No prompt, explanation or excerpt is exported. |
| `X-NoiseFence-Antivirus` | Main antivirus and complementary signature status and elapsed time. |
| `X-NoiseFence-Vision` | OCR/QR analysis status, inspected parts/pages, decoded-code counts, bounded error codes and elapsed time. |
| `X-NoiseFence-Reputation` | CRDF and VirusTotal status/count/cache/failure summaries. |
| `X-NoiseFence-RBL` | Early SMTP admission checks, listing counts, unavailable/skipped counts and the admission action. |
| `X-NoiseFence-Native` | Native engine state, mode, delivery effect, calibration, duration and bounded symbol ledger. |

Grouped headers use simple `key=value;` atoms. Lists use commas. Consumers should parse field names case-insensitively, unfold legal header continuations, and ignore unknown keys so additive details can be introduced without renaming the wire contract. Do not parse the folded display lines as independent fields.

## Example

```text
X-NoiseFence-Header-Version: 11
X-NoiseFence-Id: 58a05c8a-413e-474a-a4c0-6898ffa10e2e
X-NoiseFence-Verdict: spam
X-NoiseFence-Classification: phishing
X-NoiseFence-Coverage: partial
X-NoiseFence-Score: 99.6
X-NoiseFence-Score-Type: partial
X-NoiseFence-Score-Details: scale=0-100; source=raw; model=content-v4;
 content=99.6; decision=unavailable; threshold=95.0;
X-NoiseFence-Policy: record-version=2; assessment-version=1;
 policy-version=policy-v3; classification-source=recorded_decision;
 decision-outcome=unwanted; decision-source=legacy;
 decision-recorded=yes; policy-sha256=not_recorded; activation-sequence=14;
 activation-revision=81; activation-sha256=...
X-NoiseFence-Delivery-Policy: requested=quarantine; effective=quarantine;
 reason=policy_match; subject-tag=none; action-version=1;
 action-partial-policy=no; action-basis=score_threshold; action-eligible=yes;
 action-required=score; action-missing=none;
X-NoiseFence-Analysis: complete=no; elapsed-ms=1245;
 incomplete=vision_incomplete; supplementary-gaps=url_resolution;
```

The values above are illustrative. In particular, the message identifier, activation and policy digests, score, classification and action are generated per message.

## Safety, privacy and compatibility

- Incoming `X-NoiseFence-*` fields are removed before NoiseFence writes its own results. Sender-supplied lookalikes are never trusted as local findings.
- The wire format excludes message bodies, subjects, full URLs, recipient/Bcc addresses, user profile names, credentials and free-form model explanations. Rule and error identifiers are bounded and allowlisted.
- Headers are folded at whitespace boundaries. Generated values use bounded ASCII atoms; header line lengths follow the RFC 5322 folding limit. Internal headers are ARC-signed when an ARC seal is successfully created. An unsealed fallback does not claim authentication.
- Old queued or delivered messages are not rewritten. They keep their original header version. Readers must treat versions before 11 as historical formats and must not infer current field semantics from the old `Status`, `Category`, `Decision` or `Subject-Tag` aliases.
- Ham is a delivery classification, not a guarantee that a message is safe. `complete` means checks ran; it does not mean they passed. `disabled`, `not_run`, `skipped`, `limited`, `busy`, `unavailable`, `unknown` and `not_recorded` are not clean results.
- The action describes the gateway's recorded policy, not a later release from quarantine or destination inbox placement. SMTP can retry after a lost final acknowledgement, so exactly-once delivery is not guaranteed.

See [filter policy](filter-policy.md), [SMTP diagnostics](smtp-diagnostics.md), [Proton validation](proton-validation.md), [RFC 5322](https://www.rfc-editor.org/rfc/rfc5322.html#section-2.2.3) and [RFC 8617 (ARC)](https://www.rfc-editor.org/rfc/rfc8617.html).
