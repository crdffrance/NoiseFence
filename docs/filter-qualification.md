# Filter qualification procedure

NoiseFence renders Spam, Ham or Pub independently of Rspamd. A definitive verdict
is an operational decision, not proof that the score is calibrated. Coverage and
delivery remain separate: observation can deliver a message classified as Spam.

## 1. Verify evidence delivery

Exercise local synthetic failures before collecting a new detector cohort:
DNS timeout, cancelled LLM/provider siblings, denied quota, malformed responses
and missing authentication. Retain completed observations and findings exactly
once. Missing observations must not supply votes or imply safety. Check that the
receipt, headers and console use the same recorded decision. Keep Rspamd as an
asynchronous observer and verify that its result cannot change that decision.

## 2. Build a labelled development sample

Use **Filter quality** to freeze a development sample from one installed detector
cohort. Label wanted/unwanted risk and mail type independently, without using
NoiseFence or Rspamd predictions as truth. Include recurring wanted reports,
transactions, notifications and newsletters, as well as scams and phishing.
Keep uncertain examples explicitly uncertain. Review campaign diversity rather
than counting repeated messages as independent examples.

Run comparison for descriptive disagreement and latency coverage. With no human
labels, report coverage only: recall and false-positive rates are not measurable.
Older mixed-version traffic is not a replay of the current engine. Previously
examined examples belong in development or regression, not a final holdout.

## 3. Calibrate without bypassing provenance

Use the workbench readiness tables to fill missing risk/type classes in each
chronological partition. Restore any missing protected campaign identities from
verified originals before fitting. If restoration is impossible, design and audit
a separate dataset with provable separation; do not delete protected references
to make the existing trainer pass.

Fit a joint candidate, check its Rust/Python parity, and inspect ablations for
lexical, LLM, authentication and reputation evidence. In particular, test extreme
lexical scores on wanted messages rather than arbitrarily lowering their weight
or changing the global threshold. Select a shadow candidate only after its
provenance and cohort are compatible. No shadow result changes delivery.

## 4. Freeze and evaluate on future mail

Freeze candidate bytes, prompt, model identities and thresholds before reserving
a future independent holdout. Preserve export-use tracking and campaign separation.
Measure both engines against the same human labels and report message/campaign
recall, false positives, precision, coverage and confidence intervals. Rspamd
`greylist` is a deferral proposal, not a final spam verdict. Include incomplete
analyses in coverage and test encrypted/unreadable mail separately.

Use the existing versioned [qualification contract](calibration-workbench.md#qualification-and-latency),
including its minimum class counts and confidence bounds. Regression successes
and software test counts do not establish the production false-positive target.
Measure native latency separately from the total provider-inclusive pipeline.

## 5. Release in observation, then decide on enforcement

Publish a versioned candidate with tests and documented limits. Upgrade nodes
consistently, check health, queue durability, replica state and observation mode,
and collect fresh coverage counters. Keep a compatible rollback artifact. Do not
activate subject tagging until the Proton validation is complete, or change
quarantine/rejection policy as a side effect of model installation. Promotion
requires measured qualification and an explicit policy activation.
