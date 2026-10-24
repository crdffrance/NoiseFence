# Model identity, provenance and compatibility

A release number, a feature schema and a trained model identify different things.
NoiseFence keeps these boundaries separate so an application update cannot silently
reuse incompatible observations or claim that a new detector was evaluated on old
traffic. This document describes the current implementation, not a certificate of
production accuracy.

## Identity layers

| Layer | What it binds | What it does not prove |
| --- | --- | --- |
| Application release | Published product version and installed release manifest | Detector equivalence or model quality |
| `nf1` detector build digest | Normalized package manifests, all Rust/SQL sources, declared runtime inputs and build context | Equivalence to a different digest |
| Feature protocol digest | Exact feature definitions, ranges and declared evidence semantics | Which model, policy or detector produced the vector |
| Loaded model digests | Bytes actually loaded into the runtime | Complete training history, calibration or consent |
| Quality cohort (`artifacts_sha256`) | Compatible detector/artifact view, quality policy and native policy/Bayes binding | Campaign independence, labels or representative traffic |
| Training manifest | Dataset, cohort/protocol, time cuts and all recorded seen campaigns, including supplied base-model history | Missing or undocumented earlier use |
| Evaluation/promotion evidence | Frozen candidate identity, population accounting, quality and latency checks | Permission to bypass operational or Proton gates |

The current `build_support.rs` boundary is intentionally conservative. It includes
all `src/**/*.rs` and `src/**/*.sql`, not only the text extractor. Shared storage,
policy or API changes can therefore create a new detector build digest. It also
includes the dependency manifests, build scripts, fusion/quality/semantic protocols,
encoder runtime lock, OCR worker and URL-feed updater. Compiler identity, target,
profile, optimization, feature flags and relevant Rust flags enter the build
context. Builds for different architectures are not assumed equivalent.

Only NoiseFence's own application version is normalized in Cargo metadata.
Dependency versions and checksums remain significant. Standalone frontend,
documentation or installer changes do not enter this source boundary unless they
also change an included input. This is narrower than a Git commit hash and broader
than a single extractor version.

For an `application` identity carrying a valid `-nf1.<digest>` suffix, the compatible
artifact view uses that build digest instead of the product version. Its raw lockfile
hash is redundant because the normalized lockfile is already bound into the build.
All other artifact fields still participate. Older observations without this suffix
retain exact application/lock binding; they are not retroactively normalized.

## Cohorts and observation states

The quality snapshot and loaded engine derive cohort identity from the same
compatible artifact view plus policy/model bindings. Changing a lexical model,
semantic model, prompt, relevant policy or native Bayes model can change the cohort
even if the application version stays constant. Retained model files are not
necessarily the models currently loaded; use the running engine identity and its
recorded receipts.

A vector must have the supported protocol, correct dimensions and ranges, valid
campaign identity, native `smtp_session` origin and complete feature extraction.
`complete_features` means the vector can represent the recorded checks, including
unavailable checks. It does not mean every detector succeeded or the message is
safe. Local scans and supplied envelopes are not interchangeable with native SMTP
observations. Candidate availability profiles are checked separately for risk and
mail type; an unavailable type head does not erase a valid risk observation.

Protocol semantics can change without changing the number or order of fields.
`provider-target-evidence-1`, for example, binds deduplicated provider targets and
frozen request-time eligibility. Equal vector lengths cannot establish compatibility.
Never edit stored protocol/cohort hashes or a model's declared binding to force a
match. Compare mixed historical cohorts descriptively, but fit one compatible cohort.

## Review a candidate's provenance

1. Record the release manifest, native build identity, feature-protocol digest,
   loaded model hashes and effective cohort. Preserve the relevant build context.
2. Reconcile each human label with its recipient/annotator evidence and scope.
   Keep content-based machine judgement separate from recipient confirmation.
3. Account for unavailable observations, protected campaign overlap, repeated
   campaigns, cross-period groups and conflicting labels before fitting. Review
   every chronological partition, not just the total number of annotations.
4. Preserve base-model training and earlier evaluation campaign histories. A
   model digest identifies bytes; it cannot recover a missing training history.
5. Retain the candidate's private training manifest, dataset digest, complete
   model bytes, profiles, thresholds and expiry. Compare Rust/Python inference
   on the same admissible observations and check unsupported inputs too.
6. Freeze the candidate before reserving later, previously unexamined traffic.
   Evaluate against human labels and the versioned qualification contract.

Source/artifact equality permits the documented compatibility checks; it is not a
statistical validation. Numerical parity on a fixture verifies two implementations
for those inputs; it does not prove full equivalence of different detector builds.
There is no supported cross-digest override. A future narrower extractor boundary
would need an audited dependency boundary and semantic equivalence evidence before
it could admit older vectors. This release does not introduce such an override.

## Known limits must remain explicit

- ClamD does not attest its exact loaded definition bytes for each INSTREAM, so
  unknown per-message signature digests remain unknown.
- A mutable cloud model name is not an immutable LLM revision. Expired pricing,
  suspension, quotas and missing responses remain recorded availability states.
- Replaying an archived message cannot reconstruct historical DNS, provider
  reputation, sender history or the original SMTP connection. Keep the replay's
  source and time distinct from arrival-time observations.
- Rspamd is an independent comparison. It does not supply human labels, authorize
  model promotion or change NoiseFence's saved verdict.
- Retention can remove messages and reference identities. Missing provenance is
  a limitation to resolve, not evidence of non-overlap.

The [labelling protocol](../research/labeling-protocol.md),
[workbench](calibration-workbench.md), [decision exports](decision-exports.md) and
[retained model sets](model-catalog.md) describe the corresponding workflows.
Private datasets, campaign fingerprints, annotations and learned weights belong
outside the public repository. Publish reviewed aggregate evidence and synthetic
software fixtures instead.
