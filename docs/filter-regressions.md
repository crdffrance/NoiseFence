# Filter regression fixes and evaluation

Version 0.24.0 addresses reproducible coverage and content-pattern defects. It does not make the historical 0–100 index a probability, automatically activate learned fusion, or claim Rspamd-equivalent accuracy.

## URL candidates

Plain-text `www.example.org/path` candidates enter the same bounded local inventory as explicit HTTP(S) URLs, using HTTPS as the candidate scheme. The hostname must have a recognized public suffix. Email addresses, other URI schemes, defanged URLs and ambiguous user-info forms are excluded. Paths and queries are not sent to domain reputation providers. Existing DNS/IP validation, redirect checks, concurrency limits and deadlines apply before any request. Recognition is not proof of maliciousness or safety.

## Submitted profile-field lures

The `injected_reward_lure` rule requires a subscription-confirmation scaffold, an echoed first-name field, an explicit cryptocurrency reward amount, an immediate claim instruction and a URL on a different registrable site. Quoted/forwarded incident contexts and HTML blockquotes are excluded. It is deliberately narrower than a rule that treats any financial wording or authenticated newsletter as spam.

The default logit contribution is 1.5. Administrators can adjust it under **Filters → Rule weights**; zero disables both the contribution and its use as corroborating content evidence. The rule can resolve an ambiguous second opinion only when the combined index crosses the configured threshold. A definite legitimate second opinion continues to require review. Incomplete analyses cannot gain automatic enforcement from this rule. Main antivirus and validated fusion priority are unchanged. Upgrade all MX nodes before configuring the new weight explicitly.

## Marketing is a separate dimension

`mailing-3` adds wording such as “save up to 40%”, a promotion code, a free app trial and a savings-service call to action. It still requires distribution evidence and multiple commercial signals. The same percentage must not be counted twice as independent commercial evidence. Transaction notices, security codes, service updates and conversations retain their exclusions.

A marketing observation does not override an undetermined security decision. The console can show marketing evidence while delivery remains review/observation. Neither an unsubscribe header nor a successful authentication proves consent.

## Unlimited quotas on workers

Finite quotas still use exact-window escrow allocations. An authenticated unlimited credit also installs a 30-second rollover lease. It only applies while the effective local quota is explicitly unlimited; it cannot lift a finite quota or a monetary LLM budget. Empty authority replies revoke rollover leases, bounded credits revoke them, and disconnected workers lose the rollover grace when it expires. No finite credit is reused in a later window. A poll interval longer than the grace can still leave a coverage gap; deployments normally poll every ten seconds.

## Coverage, headers and explanations

Assessment schema 1 adds `supplementary_gaps`. The console distinguishes **Core analysis complete** from **Core complete · limited checks**, listing optional checks whose results were unavailable, stale, omitted or limited. The diagnostic is read-only and does not reinterpret a retained risk decision.

Newly prepared messages also carry `X-NoiseFence-Supplementary-Gaps`, containing fixed identifiers (`crdf`, `virustotal`, `link_inventory`, `url_resolution`, `rbl`, `mailing`) or `none`. It is included in the ARC signing inventory. Header schema 3 and `X-NoiseFence-Status` retain their existing core-analysis meaning. An empty gap list describes the recorded observers; it is not a guarantee that every possible detector was configured. No raw URL, LLM explanation, credential or recipient identity is copied into this header.

The LLM prompt is `noisefence-classify-7`. Authentication must come from structured gateway observations; the LLM's prose can still contain mistakes and must not replace those observations. New prompt predictions need fresh evaluation.

## Validation protocol

Use synthetic regression fixtures for URL ambiguity/limits, forwarded reports, genuine transactions with promotional footers, template-field injection and quota rollover/revocation. Replay private retained messages locally with recorded external observations to test deterministic changes, without fetching URLs or calling providers. Such a replay does **not** measure a new prompt's accuracy or live provider availability.

Measure harmful-message detection, false positives, abstention, promotional classification and coverage separately. Treat Rspamd as an independently configured comparator, not reference truth. Obtain human labels, deduplicate campaigns and separate development/calibration data from a later evaluation set before claiming performance parity. Do not automatically train on either engine's predictions. Preserve observation until the relevant deployment and policy validations are complete.
