# Evaluate identity and correspondent memory

Use the offline replay before enabling identity contributions. It processes recorded
messages in receipt-time order, compares each message with earlier accepted
observations, and only then retains an eligible sample. It never delivers mail,
contacts a provider, loads a production model, reads a production key or changes a
policy. The same eligibility and assessment functions serve SMTP and replay.

This tool measures **identity candidates**, not final HAM/PUB/SPAM decisions. A
candidate proposes at most one additional log-odds unit; observation still applies
zero. These figures cannot establish the full filter's capture or false-positive
rate. Rspamd and LLM opinions are never truth labels.

## Reproduce the synthetic contract cases

From a source checkout:

```sh
cargo build --locked --example contact_memory_replay
# Use a new location; an existing fixture directory is refused.
mkdir -p var
target/debug/examples/contact_memory_replay --synthetic-fixture var/identity-fixture
target/debug/examples/contact_memory_replay var/identity-fixture/events.json > var/identity-fixture/results.json
python3 research/evaluate_identity.py var/identity-fixture/results.json var/identity-fixture/labels.json > var/identity-fixture/evaluation.json
```

The fixture contains authenticated recurring supplier observations, repeated
campaign copies, and 18 evaluation messages covering new contacts, recipient
isolation, legitimate supplier changes, forwarding, unavailable authentication,
delegation, homonyms, spoofing, compromised accounts and wanted marketing. Its
explicit authentication values are **synthetic test facts**, not verification of a
real email. Labels stay in a separate file that the Rust replay never opens.

The fixture intentionally retains limitations instead of selecting only successful
cases: an unchanged compromised identity, payment language not covered by the
current narrow request rules, and a legitimate account migration that proposes a
candidate. These are contract cases for research, not a qualification corpus.
CI runs the example tests and the complete fixture-to-report command sequence.

## Prepare a private recorded replay

The input protocol is `identity-replay-input-1`. Use the generated fixture to see
the exact JSON representation, then export **originals and their own recorded
NoiseFence analysis** from an authorized gateway archive. Keep these private files
outside Git and public CI artifacts. The input is capped at 64 MiB, 4,096 events
and 2 MiB per original. It does not read paths supplied inside a message.

| Field | Meaning |
| --- | --- |
| `provenance` | `gateway_recorded` for real receipt-time exports; `synthetic` only for explicit fixtures |
| `evaluation_after` | Positive Unix receipt-time boundary; earlier events establish history, later events are evaluated |
| `settings` | Memory window, campaign/day minimums and reset cutoff; omit `key_id` because each replay installs a disposable key |
| `events[].id` | Unique opaque identifier, up to 100 ASCII letters/digits, dots, hyphens or underscores |
| `events[].received_at` | Server receipt timestamp; events must be ordered, never sorted by the email's Date header |
| `events[].accepted` | Whether the gateway durably accepted this message; a rejected transaction cannot teach memory |
| `events[].envelope_sender` | Recorded SMTP envelope sender; empty bounce senders cannot teach memory |
| `events[].recipient` | Actual envelope recipient for this observation; never merge aliases or hidden recipients |
| `events[].original_base64` | Exact original message bytes, before NoiseFence header/subject modification |
| `events[].scan` | Corresponding typed NoiseFence analysis, including receipt-time evidence and original SHA-256 |
| `events[].directory` | Optional catalog actually available for this event, with original source timestamps; omit when unknown |

The runner checks the original SHA-256 and current-build normalized campaign
fingerprint against the supplied analysis. A mismatch fails the replay. Re-export
compatible evidence rather than replacing its digests. The export's trust still
comes from the authorized source: this tool does **not** cryptographically attest
that a JSON record came from a gateway, reverify historical DKIM, or infer trust
from an imported `Authentication-Results` header. Missing/content-only evidence
remains ineligible. Do not invent a successful authentication check to complete a
corpus.

A temporary, private HMAC key isolates each replay from real installation history.
Outputs contain opaque event IDs, campaign groups, counts and component reports;
they omit originals, addresses and private join tokens. Retained samples disappear
with the process. Current native/antivirus evidence is replayed as recorded; model
scores and recipient decisions are not recalculated. URL-domain extraction is
local and bounded, without following links. This is a single-recipient replay;
it does not measure live cache deadlines, multi-recipient admission pressure,
projection freshness or SMTP delivery. Those require the integration/load tests.

Walk-forward evaluation may learn from **earlier accepted evaluation messages**,
just as a live gateway does. It never reads their holdout labels. Reset/retention,
current-campaign exclusion, day caps and capacity limits still apply. The replay
does not simulate human-feedback mutations: keep evaluation labels separate from
operational corrections and test feedback behavior through the dedicated fixtures.

## Label and report independently

Use `identity-evaluation-labels-1` with `provenance: human_confirmed`, bind
`input_sha256` to the replay output's exact input digest, and supply `cases` with
`id`, `label` (`ham`, `pub`, `spam`) and a short scenario `family`. Both HAM and
PUB count as wanted. Never derive these labels from model scores, Rspamd or an
assistant's prediction. A missing label remains unlabelled.

The evaluator checks the chronological boundary, excludes campaigns seen in the
history partition, and takes the earliest labelled evaluation observation per
remaining campaign without consulting its candidate result. Conflicting labels
exclude the campaign and are reported. Duplicate copies, differing candidate
results and unlabelled records remain visible in the exclusions. Unavailable
checks remain in the metric denominator. Rates with no denominator are unknown,
not zero; nonempty rates include 95% Wilson intervals.

Report candidate rate on wanted mail, candidate rate on unwanted mail, candidate
precision, unavailable evidence, scenario coverage and the IDs needing inspection.
A low false-candidate count from a small corpus cannot establish a ≤0.1% production
false-positive rate. The report always keeps `efficacy_qualified: false`: temporal
and campaign separation alone do not prove that the corpus was never used to tune
a rule or model. Reserve a recent independent corpus before tuning, record its
provenance, and evaluate final message decisions separately before activation.
