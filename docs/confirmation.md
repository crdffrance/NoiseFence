<a id="limiter-les-classements-spam-insuffisamment-étayés"></a>
# Corroboration and automatic decisions

`filter.require_corroboration = true`, also available in the Web console, requires
additional evidence before a high legacy content score is accepted as an engine
verdict. Without that evidence, the internal verdict is `undetermined`; the score
and analysis coverage remain recorded. This is not proof of legitimacy.

Automatic classification remains mandatory, but a complete legacy analysis with
missing required corroboration is accepted as Ham (or Pub when supported by the
existing mail-kind assessment). The original content index cannot undo the
corroboration requirement. `score-resolution-2` records the guard; the
`X-NoiseFence-Score-Resolution` header includes `guard=corroboration_required`.
This is an operator policy, not a calibrated probability of legitimacy. Explicit
recipient rules, observation mode, partial-analysis restrictions and Proton
marking guards remain separate. Existing receipts are never reclassified.

## Eligible evidence

`confirmation-5` retains these eligible observations:

- Malware detected by the primary antivirus.
- Verified DMARC failure on both alignment branches.
- An observed injected-reward lure with a positive retained content contribution.
- A verified DQS malicious-IP or domain response: ZEN 2/3/4/9 or DBL 2/4/5/6.

SPF alone, policy IP listings, compromised-domain categories, SMTP anomalies,
advisory signatures, HTML/OCR features and unavailable checks do not independently
confirm a verdict. The lexical and semantic models already contribute to the
content score. The LLM is also a bounded contributor, not an independent vote;
its reported confidence is not a validated probability. Successful authentication
does not establish benign intent, and imported email headers cannot supply these
internal observations.

Scoring, confirmation, context safeguards and normalized diagnostics share
`transport-evidence-1`. Schema and parent status must permit completed results.
A partial request can retain individually completed checks, while a disabled or
unexecuted parent cannot supply results. ARC has its own switch. Provider errors,
mixed-zone answers, missing authentication pairs, temporary failures and oversized
signature lists are excluded. Every consumer examines at most twelve DQS domains.
An empty completed DNS answer means not listed, not safe.

Eligibility and decision strength are separate: a completed DMARC failure branch
may affect the score, while confirmation still requires both branches to fail.
Injected-reward confirmation requires the current ledger's retained contribution;
missing/incompatible accounting, zero weights and conflicting inputs cannot be
replaced by raw reason text.

The LLM receives authentication facts and citation IDs only for eligible checks,
with the additional requirement of an original SMTP session. Invalid or missing
facts are null and cannot support an `authentication_failure` citation. When the
existing `review_unconfirmed_high` selection option is enabled, absence of
corroboration can make a high-score message eligible for LLM review under the
existing disclosure, quota and budget settings. Eligibility validation itself
performs no network request and adds no message content to the provider payload.

A validated fusion retains its own decision policy; primary antivirus evidence
keeps priority. See [filter policy](filter-policy.md) and
[shared receipt decisions](unified-decisions.md). This correction changes no
configured threshold and does not activate enforcement.

<a id="vérification"></a>
## Verification and limits

`cargo test --test transport_evidence --test confirmation --test decision --test observations`
checks shared availability, malformed facts, domain bounds, ARC independence,
retained contributions and decision-specific requirements. Additional LLM tests
verify that invalid authentication cannot become a trusted citation. Fixtures are
synthetic; no production message is published.

`noisefence audit-confirmation /var/lib/noisefence/state.sqlite3` compares recorded
decisions with explicit current-policy projections. It opens SQLite read-only,
loads no model, reads no message bodies and makes no external request. It checks
annotation access, account status, conflicts and retention, and reports exclusions.
It neither rewrites history nor evaluates a different LLM prompt.

Correlated sources are not independent votes. Corroboration can reduce capture of
spam recognized only by content models. Report abstentions and final automatic
actions alongside false positives: moving an error into an unresolved state does
not make it correct. Feedback samples and regression fixtures do not establish
population accuracy; qualify the full pipeline on independent human-labelled mail.
