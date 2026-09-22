# Unified receipt decisions

Implementation in progress. These changes establish receipt-time consistency;
they do not qualify a new detection model or authorize enforcement.

## Implemented contract

Incoming SMTP processing captures two additive, versioned fields in the persisted
`Scan` JSON. Existing queue databases need no destructive migration:

- `analysis_result`: original content digest, detector/artifact versions, selected
  risk index, original engine verdict, coverage, missing checks and reasons.
- `recipient_decision`: preparation time, effective policy fingerprint, profile,
  matching rule IDs, detailed classification, coverage and shared assessment.

The shared assessment freezes the applied threshold, requested/effective action,
action reason, score source and semantics. A subsequent setting change does not
re-evaluate an accepted message. API history, diagnostics, search and statistics
use recorded decisions. Legacy messages retain their explicit original verdict,
or their recorded original threshold. When neither exists, the category is
historically unknown; today's settings are never substituted.

The risk index is not a calibrated spam probability. Classification, score,
coverage and delivery action remain separate. Failed content extraction does not
produce a fake zero or a verified legitimate finding. `unassessed` describes
missing or inconclusive classification; the configured automatic delivery policy
still applies. Primary malware evidence takes priority over this absence.

Global and custom policies now share operational action constraints. Observation
still delivers; existing incomplete-analysis and Proton marking guards remain.
Recipient copies only share SMTP bytes when their effective policy fingerprints
match. A different threshold, matched rule, profile or action creates a distinct
copy. Each copy exposes only its own decision in version 4 diagnostic headers.

The existing limit of six distinct wire copies per SMTP transaction remains. It
is checked before allocating a seventh copy; disk admission reserves capacity
when mailbox preferences can create variants as well as administrator rules.
A transaction exceeding that bound is temporarily rejected, not partly accepted.
Senders can retry smaller recipient batches. Streaming more policy variants is
separate capacity work, not enabled by this change.

Persisted JSON and SMTP bytes already travel in the durable replication manifest.
This change does not relax the two-copy acceptance requirement. Coordinated
upgrade, mixed-version validation and failover qualification remain required
before production rollout. A policy hash is a consistency identifier, not an
authentication mechanism.

## Remaining implementation and qualification

1. Normalize detector states, provenance and shared evidence; cap contributions
   by family and prevent the same LLM opinion becoming independent corroboration.
2. Replace the broad incomplete-analysis action guard with tested, explicit
   coverage requirements per decision. Keep subject-signature constraints separate.
3. Extend effective-profile inheritance and fixed-sample policy simulation with
   complete precedence traces and administrator safety restrictions.
4. Complete frozen-context parity and recovery tests across both MX versions,
   including policy/model bundle activation and rollback.
5. Evaluate the whole pipeline on recent independent human-labelled messages,
   reporting capture, false positives, precision, uncertainty, coverage and
   action-level mistakes. Regression fixtures and Rspamd agreement are not a
   substitute for ground truth.

Production must remain in observation until the existing quality, latency and
Proton gates pass. The current research model has not established the targets of
at least 95% capture and at most 0.1% false positives. No new provider or private
message disclosure is required for this structural refactor.

See [automatic classification](automatic-classification.md),
[message headers](message-headers.md) and
[release qualification](final-release-plan.md).
