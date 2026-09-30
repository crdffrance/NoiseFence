# Filter validation and coverage

A software regression test is not evidence of improved spam capture. Before
promoting an arbitration or score change, use the following staged protocol.

1. Preserve the recorded decisions and effective actions. Reserve the full
   historical window as **regression**, including unassessed messages and all
   detector disagreements. Prioritizing disagreements for annotation is useful,
   but evaluating only that subset would bias an accuracy estimate.
2. Annotate wanted/unwanted risk and mail kind separately. The user decides
   whether a newsletter is wanted. Detector scores, Rspamd actions and LLM
   opinions are not labels. Do not turn missing labels into ham.
3. Fit calibration only on development campaigns, with the existing
   `research/train_quality.py` workflow. Regression and holdout campaigns remain
   excluded. Freeze the candidate and its policy before prospective sampling.
4. Collect a future **independent holdout** using Filter quality. Evaluate the
   frozen candidate once under the existing exposure journal. Include incomplete
   observations in coverage denominators and compare engines on the same eligible
   labelled messages. Report spam recall, ham false positives, precision,
   publicity errors and confidence intervals, by message and campaign.
5. Keep observation enabled until the resulting evidence supports activation.
   A required-corroboration acceptance can reduce false positives and increase
   missed spam. Never claim an improvement from a lower spam count alone.

## Operational coverage

Run `research/filter-health.sql` on the PostgreSQL coordinator to obtain aggregate
coverage, provider failures, mail-kind distribution and Rspamd actions. It uses a
read-only transaction and does not return content or recipient identities.
It excludes DSNs, but does not identify synthetic test mail; exclude known probes
when preparing a quality population. The report is not an accuracy benchmark.

Treat provider states separately:

- `quota`: the local request allowance is exhausted. Check usage against the
  actual licence before changing the Web quota. Unlimited CRDF access does not
  imply unlimited VirusTotal access.
- `rate_limit`: the remote provider rejected the rate. Honour shared credential
  cooldown and Retry-After; increasing a local quota cannot fix HTTP 429.
- `timeout`: inspect provider latency and the total analysis budget. Prefer cache
  reuse and bounded work; do not remove the deadline or resolve arbitrary links
  outside the existing network protections.
- `invalid_response`: inspect the adapter using redacted structural diagnostics;
  never treat an unparsable response as clean or malicious.
- `stale`: the cached result does not meet the freshness policy. Do not mark it
  current merely to improve coverage statistics.
- `omitted`: count skipped indicators separately from whole-message failures.

A missing reputation result is not a vote for either class. Encrypted/opaque
content remains explicitly unassessed, even when delivery policy groups it as
Ham. Publicity must remain a distinct mail-kind decision; do not downgrade an
observed security threat solely because unsubscribe or bulk-mail headers exist.
