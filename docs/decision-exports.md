# Recorded decisions in evaluation exports

A saved detector opinion, a recipient verdict, a requested action and a delivery
result answer different questions. Evaluate them separately. A Spam verdict with
`effective=deliver` is expected in observation mode; it does not establish that the
message reached the recipient, a spam folder or quarantine.

## Exported contract

Both `quality-export` and the full retained-population export include the bounded
`decision_snapshot` contract (`noisefence-quality-decisions-1`):

| Field | Meaning |
| --- | --- |
| `provenance` | Recipient receipt, analysis-only receipt, legacy projection, or invalid stored data |
| `engine` | Original detector source, outcome, analysis completeness and raw index |
| `final` | Recorded recipient category, detailed classification, classification source, completeness and selected index |
| `action` | Requested and effective action at preparation time |

The snapshot uses receipt-time values even when legacy fields change later. It
contains no subject, body, recipient, policy name, rule IDs or provider excerpts.
Its whitelist is validated before native population prediction and again before
Python evaluation. Unsupported versions, extra fields, contradictory classes,
missing required fields, and invalid scores fail validation. Invalid stored scans
are retained as an explicit `invalid` snapshot with no results, not omitted or
replaced by an apparent Ham verdict.

An `unassessed` classification remains unknown in accuracy calculations. The
console may group it under Ham for the fail-open delivery policy; that grouping
is not evidence of legitimate content. Pub remains distinct in the snapshot and
is on the wanted side of binary spam metrics. Human unwanted/wanted labels remain
independent of these predictions.

## Population format and compatibility

New exports use `noisefence-population-2`. Every row includes its decision snapshot.
The old top-level `decision`, `complete` and `tagged` fields are preserved as legacy
diagnostics; they must not replace the recorded recipient result. SQLite and
PostgreSQL exports share the same projection. Existing access, retention,
private-file permissions and atomic publication rules are unchanged.

The native population predictor reads both population versions 1 and 2 and emits
`noisefence-population-predictions-2`. Version 1 input has no snapshot and receives
an explicit null snapshot in the prediction output. It cannot acquire a receipt
from today's settings. Upgrade the offline predictor with the exporter: old
strict readers intentionally reject the new schema rather than discard fields.

`research/evaluate_population.py` reads prediction versions 1 and 2. Its report
adds `recorded_baseline`, separate from the hypothetical candidate variants:

- Engine and recipient-policy metrics, each with its own unknown denominator.
- Snapshot provenance counts, including unavailable legacy receipts.
- Requested/effective actions by wanted, unwanted and unknown truth.
- Action transitions such as quarantine requested but delivery effective.

Version 1 populations can supply an explicit old engine verdict but no final-policy
baseline. A missing final receipt is never inferred from a tag or engine score.
Candidate inference still uses only its frozen detector observations: adding or
changing a saved receipt cannot change a candidate prediction.

## Validation and limits

Regression checks cover recipient overrides, partial coverage, changed legacy
fields, unknown results, schema compatibility, privacy and atomic failures. The
synthetic native/Python population rehearsal checks receipt preservation alongside
prediction parity; these fixtures do not measure detection quality.

Use a frozen candidate, independent campaigns, recent human labels and the
existing exposure journal to qualify accuracy. Do not mix model cohorts, tune on
the final holdout or infer a quality claim from Rspamd agreement. Exported action
counts do not measure subsequent quarantine release, delivery completion or Proton
folder placement; those belong to the operational delivery history.

See [receipt decisions](unified-decisions.md), [quality evaluation](quality.md)
and [filter validation](filter-validation.md).
