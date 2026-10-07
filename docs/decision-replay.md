# Private offline decision replay

Use this diagnostic to compare recorded classifications with the current native
policy on frozen, human-labelled observations. It does not retrain a model,
recompute provider responses, send content, queue mail or change historical rows.
Rspamd never supplies the native verdict.

## Input

Prepare a private JSONL export with one confirmed message per line:

```json
{"label":"legitimate","category":"spam","scan":{}}
```

Replace the empty `scan` object with the complete recorded `Scan`, including its
recipient assessment and receipt-time threshold. The example above is the row
shape, not an executable analysis fixture. `label` must be `legitimate` or `spam`;
consented newsletters are legitimate for this binary risk comparison. Preserve
mail type separately. Exclude probes and uncertain or conflicting labels, and
record the exclusion counts alongside the evaluation.

The tool rejects unsupported labels and missing recorded thresholds. Inputs may
contain private addresses, subjects, derived features and detector explanations;
store them outside Git with private permissions. Use a frozen read-only database
snapshot or transaction. Do not substitute current settings for historical facts.

## Run

```sh
cargo run --locked --features semantic --example decision_replay -- private-labelled-scans.jsonl
```

Output contains aggregate counters for the recorded decision, current native
replay and a separate experiment with required corroboration. That experiment is
not a recommendation to enable the setting: a reduction in false positives can
come at the expense of most detections.

## Interpret

- Report false positives over all human-labelled wanted mail, and misses over all
  human-labelled unwanted mail. Keep marketing type separate from unwanted risk.
- Review any custom recipient rules separately: this tool replays the native
  decision policy, not a full historical recipient-policy configuration.
- Compare equivalent observation coverage. A gain using saved LLM responses does
  not establish an equivalent gain when that provider is suspended.
- Exclude Rspamd temporary actions such as `greylist` from comparable content
  verdicts; report their count rather than treating them as Ham.
- Preserve campaign and time separation. A batch used to find and correct a defect
  is a regression set, not an untouched final quality benchmark. Repeated messages
  from one campaign do not constitute independent validation samples.
- Never train on these labels automatically or activate enforcement from replay
  counts alone. Use the [qualification procedure](filter-qualification.md).
