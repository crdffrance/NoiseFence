# Filtering policy and score semantics

Every message has four separate pieces of information: **risk index, classification, analysis coverage and delivery policy**. The console, message-search API and new SMTP diagnostic headers share the same Rust assessment contract, version 1.

## Risk index

The displayed range is **0–100**. Use a finite, in-range recorded decision score when available, except for antivirus decisions; otherwise use the recorded content score. Preserve real zero values. Invalid or genuinely absent values remain unavailable. A missing decision score is an abstention and does not erase a valid content score.

| Type | Meaning |
| --- | --- |
| Content | Recorded content risk index; not a spam probability |
| Decision | Fusion estimate for the model's validated population |
| Advisory | A usable index remains, but the engine abstained or malware priority overrides it |
| Partial | Index computed from available evidence while required analysis is incomplete |
| Internal | Stored value for a NoiseFence-generated delivery notification, not an incoming content scan |
| Unavailable | No usable numeric value was retained |

The index is not a sum of independent detector votes. Content contributions are expressed in **log-odds**, converted through a sigmoid to the content index. The model contribution already includes the recorded lexical/semantic combination and must not be counted twice. Native rule points are separately capped by family and remain advisory where indicated. Bayes outputs, neural confidence, LLM opinions and fusion estimates retain their own units and calibration limits.

## Classification and priority

Primary antivirus malware detection takes priority over the content index. A low content score therefore does not negate malware detection. Otherwise the canonical decision uses the configured model, evidence and corroboration policy. Conflicting or ambiguous opinions can produce **Needs review**, even with a high content index. Missing reputation or provider results are not evidence of spam.

Marketing is separate from security risk. A newsletter signal does not make malicious content legitimate. API category identifiers remain `spam`, `publicity`, `legitimate` and `undetermined` for compatibility; the English console calls `publicity` **Marketing**. Existing subject prefixes remain `[SPAM]` and `[PUB]`.

Recipient rules may produce a recorded delivery classification distinct from the engine decision. Both remain available in diagnostics. The UI does not replace the category with “Partial analysis”: coverage is displayed separately. This keeps a recorded malware/spam classification visible when another check is incomplete.

## Coverage and delivery

“Complete” means the configured required analysis completed, not that the message is safe. Disabled, skipped, limited, busy and unavailable checks remain distinguishable. Advisory checks can fail without necessarily making the entire required analysis incomplete.

The requested delivery action and the effective action are recorded separately. In observation mode the effective action is delivery without prefix or quarantine. Incomplete required analysis prevents subject tagging; the primary-malware quarantine exception remains explicit. Subject modification still requires the relevant Proton/ARC validation. Personal rules do not bypass these safeguards.

The original policy records the content threshold, mode, policy version and weight overrides. Older records without a decision use their recorded threshold when present. If the threshold is absent, the historical fallback is identified instead of presenting the current threshold as a fact about the past. None of this rewrites old messages or recomputes their original scores.

## Measuring quality

Keep representative human labels separate from model predictions. Report recall, precision, false-positive rate, review/partial coverage and confidence intervals on an independent recent sample. Selected corrections are useful for finding defects but are not an unbiased estimate of traffic-wide accuracy.

NoiseFence does not claim perfect filtering. The current feature set and passing regression tests do not establish 95% capture or a 0.1% false-positive rate. See [quality](quality.md), [reliability](reliability.md) and [validation results](validation-results.md).
