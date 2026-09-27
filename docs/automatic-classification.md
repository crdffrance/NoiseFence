# Automatic classification of uncertain results

Starting with decision-policy-8, automatic resolution is mandatory for new messages. The legacy `resolve_uncertain_by_score` setting remains readable for compatibility but cannot disable resolution. The console no longer exposes a manual-review action. Upgrade every MX together before activating this policy.

This is an operator policy, not a new model or evidence of better accuracy. On an unresolved decision, the recorded content index is compared with the applicable content threshold: greater than or equal means spam; lower means legitimate or marketing according to the existing mail-kind assessment. A completed decisive fusion decision and antivirus priority are preserved. Recipient profiles use their own applicable threshold, and explicit recipient actions remain distinct from the engine decision.

A disagreement with the LLM or missing corroboration remains in the diagnostic record but no longer creates a manual review category for new messages. If extraction failed or there is no finite index in 0–100, automatic classification fails open; the score is unavailable rather than a fabricated zero. Incomplete coverage remains visible. The default action policy requires complete analysis; the separately enabled [partial-action policy](unified-decisions.md#evidence-requirements-for-actions) checks explicit evidence requirements. Observation continues to deliver messages regardless of the classification.

## Evidence and historical records

`score_resolution` records the original decision, resolved decision, threshold, usable score, partial coverage and policy version. The signed `X-NoiseFence-Score-Resolution` header exposes these bounded facts, or `none` when the policy did not apply. Existing category, score, status and action headers retain their separate meanings.

History preserves receipt-time decisions. Changing the policy or a threshold, no longer reclassifies previously accepted messages in lists, search counts, statistics or diagnostics. Records without a decision can use their original recorded threshold; when both are absent their historical classification is unavailable. Explicit rule simulations are separate from history and never rewrite queued or delivered messages.

An advisory score can be high on legitimate messages. Before enabling enforcement, preview the policy on human-labelled messages and qualify the score on representative, independent campaigns. Reducing undecided counts alone does not demonstrate better detection. See [the final release qualification plan](final-release-plan.md).
