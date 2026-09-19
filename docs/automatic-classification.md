# Automatic classification of uncertain results

Since 0.26.0, administrators can enable **Resolve uncertain results using the score** under the global filter settings. The corresponding setting is `filters.resolve_uncertain_by_score` in a Web revision, or `filter.resolve_uncertain_by_score` in the installation configuration. It defaults to false for existing and new installations. Upgrade every MX before enabling it; old worker bundles cannot represent an enabled policy.

This is an operator policy, not a new model or evidence of better accuracy. On an unresolved decision, the recorded content index is compared with the applicable content threshold: greater than or equal means spam; lower means legitimate or marketing according to the existing mail-kind assessment. A completed decisive fusion decision and antivirus priority are preserved. Recipient profiles use their own applicable threshold, and explicit recipient actions remain distinct from the engine decision.

A disagreement with the LLM or missing corroboration remains in the diagnostic record but no longer creates a manual review category when this option is active. If extraction failed or there is no finite index in 0–100, automatic classification fails open; the score is unavailable rather than a fabricated zero. Incomplete coverage remains visible and existing incomplete-analysis delivery guards still apply. Observation continues to deliver messages regardless of the classification.

## Evidence and historical records

`score_resolution` records the original decision, resolved decision, threshold, usable score, partial coverage and policy version. The signed `X-NoiseFence-Score-Resolution` header exposes these bounded facts, or `none` when the policy did not apply. Existing category, score, status and action headers retain their separate meanings.

With this mode active, console history, search counts, statistics and diagnostics project unresolved historical results using the threshold recorded with each message. Older records without a threshold use the current fallback. The projection is identified explicitly: it does not rewrite the database, past headers, feedback or completed deliveries. Disabling the option restores the original historical view. Records actually resolved at receipt retain their recorded policy.

An advisory score can be high on legitimate messages. Before enabling enforcement, preview the policy on human-labelled messages and qualify the score on representative, independent campaigns. Reducing undecided counts alone does not demonstrate better detection. See [the final release qualification plan](final-release-plan.md).
