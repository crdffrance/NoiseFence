# Improving a filter with reproducible evidence

NoiseFence makes its own Spam, Ham or Pub decision. Rspamd is a separately
recorded opinion. Neither engine supplies human labels, and agreement between
them does not establish correctness. A wanted newsletter is legitimate risk
with a newsletter or promotion type; unwanted advertising is spam risk.

## Diagnose before fitting

1. Draw a frozen sample in **Filter quality**, recording its purpose and time
   window. Compare campaign-level and message-level results, mail types, engine
   versions and actual detector availability.
2. Confirm suspected errors with the recipient. Keep AI assessments separate.
   A sample chosen because its messages were classified incorrectly is a
   regression set, not a representative false-positive-rate estimate.
3. Inspect the receipt-time policy, retained inputs and availability. Unavailable
   checks are not detections. Observation-only protection findings must not
   influence the live decision, including by preventing a contextual safeguard.
   Active reputation evidence must match a usable recorded target. A completed
   malicious target remains evidence when other targets hit a quota.
4. Make a bounded correction and add both a benign example and an adversarial
   lookalike. Check unauthenticated copies, credential demands, malware and
   missing evidence. Do not add unconditional brand or subject allowlists.

## Calibrate without test leakage

Use a **development** sample from one compatible detector cohort. Keep
regression and independent holdout messages, including related campaigns, out
of fitting. The workbench checks five chronological partitions and requires both
wanted and unwanted campaigns in each. A single spam campaign repeated many
times is not a diverse training set.

**Train a shadow candidate** reports missing classes, insufficient independent
campaigns and incomplete protection provenance. A failed readiness check does
not justify lowering the gate, manufacturing campaign identities or reusing the
holdout. Continue labelling development traffic and keep the existing model.
After fitting, freeze the candidate and evaluate it on later independent mail.
Use [the calibration workbench](calibration-workbench.md) for the full protocol
and [release gates](final-release-plan.md) for qualification requirements.

## Review policy effects separately

The Web policy simulator accepts up to 50 messages for one recipient. It reuses
retained observations and does not call providers, resend messages or rewrite
historical decisions. Its report binds the draft fingerprint, configuration
revision, recipient, evaluation time and sample fingerprint.

Compare category changes and effective-action transitions. Missing rule facts,
missing or unsupported receipts, absent original actions and inaccessible
messages are reported explicitly. Incomplete comparisons are not counted as
unchanged. Repeat for each affected recipient; a result for one mailbox does
not establish the effect on another. The simulator is not a content-model
replay or an accuracy test.

## Make the result explainable

Message details show the recorded verdict, guard or recipient policy, risk
index, check coverage and intended delivery action. **Leading recorded inputs**
shows up to three strongest retained contributions in the selected calculation.
Negative contributions remain visible. Legacy and fusion accounting are never
mixed; Rspamd is excluded. A priority rule can override these contributions,
and an intended delivery is not evidence of downstream delivery.

**Installed versions** distinguishes the running engine, loaded models, rule
policy, score combination, configuration revision and current console. An old
browser tab can run a different console bundle from the server; reload when
the fingerprints differ. These current versions do not replace receipt-time
identities on historical messages.

## Record deployment provenance

`noisefence build-identity` prints the compiled version and engine build hash
without loading configuration or opening storage. Vite embeds a deterministic
console source fingerprint in the bundle and emits `web/version.json`.

The installer writes `deployment.json` next to the configured Web directory
after a successful service start. It lives outside immutable release assets.
For a custom installation using `/opt/noisefence/web`, record a verified
activation with:

```sh
sudo python3 /opt/noisefence/current/deploy/record-deployment.py /opt/noisefence
```

Run this only after health checks succeed. Custom activation and rollback tools
must record the actual active bundle, including a frontend overlay if used.
The API displays the timestamp only when the receipt matches the engine and
console. Missing, stale or malformed receipts remain **Not recorded**. A
deployment receipt is operational metadata, not a signature or a supply-chain
attestation. No automatic installation is performed by the Web console.
