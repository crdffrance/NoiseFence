# Offline score-combination comparison

Use `scoring-compare` to measure a **controlled aggregation change** over saved
SMTP observations. It does not replay the historical engine, call providers,
train a model, evaluate recipient actions or modify accepted messages.

```sh
noisefence scoring-compare private-inputs.jsonl \
  --output private-comparison.jsonl --threshold 95
```

The threshold is an explicit experimental operating point, not a recommended
setting. The command runs before configuration loading; it needs neither live
credentials nor a running gateway. Keep inputs and reports outside the public
repository. Output is created atomically with mode `0600`, without replacing an
existing file or symlink. Standard output contains aggregate counts; redirect it
under a private umask when saving it.

## Inputs and provenance

Each JSONL row wraps a retained scan:

```json
{"schema":"noisefence-score-comparison-input-1","id":"<64 lowercase hexadecimal characters>","scan":{"...":"original recorded fields"}}
```

`id` is a stable local SHA-256 identity used to reject duplicate records. When
preparing inputs, preserve the source export hashes and the mapping privately.
Use the same identity for a receipt seen on both MXs; recipient copies are not
independent messages. The tool does not deduplicate similar campaigns or certify
label, sampling or original-transport authenticity.

The input adapter selects only `feature_version`, `score`, `evidence`, `reasons`,
`semantic`, `llm`, `smtp_policy` and `message_context.encrypted`. No subject,
sender, label, rule explanation, Rspamd verdict or recipient decision enters the
combination. The complete original evidence/artifact structure is required.
Additional scan fields are ignored; absent required observations are counted as
skipped, rather than filled from current settings. Invalid JSON or duplicate IDs
abort the complete export without publishing a partial report. Limits are
50,000 rows, 512 MiB total, 2 MiB per row and 2,048 rule entries per row.

Only supported `smtp_session` evidence is considered. Lexical output must be an
explicit finite logit with complete or limited extraction; the latter is counted
separately as `partial_lexical` and never becomes complete coverage. A rules-only
baseline is allowed for explicitly
opaque content with no applied lexical output, or an explicitly disabled and
absent lexical model. Missing or failed lexical output for readable
content is not reconstructed from the historical combined score. Opaque inputs
with an applied lexical logit are contradictory and skipped.

## What the comparison means

Both projections use the **current** semantic and LLM input adapters:

- `reference`: aggregation without the v2 evidence reconciliation step.
- `candidate`: the actual current Rust combiner, including reconciliation.
- `historical_score`: the separately retained numeric receipt value, when valid.

The reference ledger names the v1 aggregation contract. It is **not** a rerun of
the old application, prompt, provider queries or model that produced the receipt.
An old SMTP-policy version, for example, may retain its proposed contribution in
the reference while the current combiner excludes it as unavailable. This is a
compatibility finding, not evidence that the candidate detected spam better.

Original detector artifact hashes define separate report cohorts. Mixed cohorts
remain visible; aggregate counts do not make them a calibration dataset. The
report records the comparison executable's detector build hash and a digest of
the exact input bytes, distinct from the original cohort identities.

Numeric score and threshold projections require an explicitly recorded current
feature schema (`3`). Without it, the tool still compares rule/logit totals but
emits `null` scores and threshold results. It never infers precision from a model
name or treats missing/future schema versions as rounded legacy scores. Invalid
combinations retain unavailable totals, with a separate count.

`crossed_up` and `crossed_down` count only rows with both threshold projections.
Always read them with `threshold_comparable`; zero comparable rows means no
measured threshold transitions. A threshold crossing is not a classification or
delivery-action change: fusion, antivirus, recipient rules, observation and
marking constraints are outside this experiment.

## Before calibration

Do not use this report as a false-positive rate, recall estimate, new LLM test or
production promotion decision. A valid next dataset needs current native
observations, human labels, complete provenance, disjoint campaigns and frozen
training/development/calibration/threshold/final-test partitions. Previously
inspected wanted examples remain regression references. See
[release qualification](final-release-plan.md) and [fusion research](../research/fusion.md).
