# Message diagnostic headers

Newly prepared messages use **`X-NoiseFence-Header-Version: 3`**. The API and headers use the same derived assessment, version 1. Already delivered or queued messages keep their original bytes and header version; this release does not rescan or resend them.

## Risk, classification and delivery

| Header | Meaning |
| --- | --- |
| `X-NoiseFence-Id` | Queue identifier; not an authorization token |
| `X-NoiseFence-Header-Version` | Wire contract version, currently `3` |
| `X-NoiseFence-Assessment-Version` | Shared API/header assessment contract, currently `1` |
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
| `X-NoiseFence-Category` | Recorded delivery classification: `spam`, `publicity`, `legitimate` or `undetermined` |
| `X-NoiseFence-Classification-Source` | `recipient_policy`, `recorded_decision` or `historical_fallback` |
| `X-NoiseFence-Content-Threshold` | Content threshold captured at analysis time; `unavailable` when absent |
| `X-NoiseFence-Policy-Version` | Recorded decision policy version, or `not_recorded` |
| `X-NoiseFence-Delivery-Policy` | Original requested/effective action and a bounded reason code, or `not_recorded` |
| `X-NoiseFence-Subject-Tag` | Prefix actually added: `none`, `spam` (`[SPAM]`) or `publicity` (`[PUB]`) |

Version 2 mixed coverage and actual tagging in `Status` (`incomplete`, `spam`, `pub`, `observed`). **Consumers must branch on Header-Version.** In version 3, read `Category` for classification, `Status` for coverage and `Subject-Tag` for modification. Observation can therefore record `Category: spam` with `Status: complete`, delivery effective `deliver`, and `Subject-Tag: none`.

The risk index is not generally a spam probability. A missing decision score does not erase a valid content index. Malware does not become a fabricated 100. The captured content threshold is not a fusion model's decision threshold. The delivery-policy header describes preparation time, not a later manual quarantine release or the destination's inbox placement.

## Check details

| Header | Recorded information |
| --- | --- |
| `X-NoiseFence-Analysis` | Completion flag and elapsed milliseconds |
| `X-NoiseFence-Checks` | States of lexical extraction, authentication, SPF/DKIM/DMARC/ARC, DNS reputation, semantic analysis, antivirus, signatures, SMTP, LLM, vision and fusion |
| `X-NoiseFence-Authentication` | Recorded SPF, DKIM, DMARC alignment and ARC outcomes; complements standard `Authentication-Results` |
| `X-NoiseFence-Incomplete-Reasons` | Known missing-check codes, `none` when complete, or `unspecified` |
| `X-NoiseFence-Arbitration` | Baseline, second opinion and agreement/disagreement resolution |
| `X-NoiseFence-Rules` | Rule identifiers and log-odds contributions, with total/shown/omitted counts |
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
X-NoiseFence-Header-Version: 3
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
