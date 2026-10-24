<a id="couverture-et-contexte-du-filtrage--060"></a>
<a id="coverage-and-context-of-filtering--060"></a>
# Filter coverage and sender context

<a id="réputation-et-redirections"></a>
## Reputation and redirects

NoiseFence checks cached results for up to twelve priority targets before applying
request capacity, quota and provider cooldown limits. Final redirect destinations
have priority, followed by ranked content hosts. Additional targets are counted
as omitted. Missing information, a stale VirusTotal report or a provider error is
unavailable evidence, never proof of spam or safety.

[CRDF search_urls](https://threatcenter.crdf.fr/api/doc/) accepts a batch of domain
roots. NoiseFence sends at most twelve synthetic HTTPS roots, without email
addresses, message bodies, URL paths or query parameters. Each response must bind
exactly once to a requested target. Missing, foreign or duplicate targets invalidate
the batch; a malformed entry within a correctly bound batch leaves valid siblings
usable. A match against one page does not establish that its entire hosting domain
is malicious. VirusTotal lookups use existing domain or file-hash reports and
never submit attachments or message content.

Quotas count request reservations made after acquiring network capacity. A send
failure can consume a reservation without producing a response; accounting remains
conservative. Caches and UTC quota counters persist. Zero means unlimited local
quota, while concurrency, deadlines and provider cooldowns remain enforced. A
connection failure or HTTP 502/503/504 without an explicit delay allows at most one
retry after 50 ms, with a new reservation inside the original deadline. Access
refusals and HTTP 429 are not retried immediately. Valid `Retry-After` delays are
bounded to seven days; an existing longer cooldown is preserved. See
[provider diagnostics](protection.md#diagnose-coverage-before-changing-limits).

Redirect chains share bounded capacity and an overall deadline. A slow chain does
not reserve every slot. Every hop retains DNS revalidation, pinned destination
addresses, TLS verification, private-network exclusions and a 64 KiB response-body
limit. JavaScript is not executed. Oversized or script-dependent pages can remain
incomplete; completion of the message analysis cancels its outstanding HTTP tasks.
See [URL resolution](url-resolution.md) for complete limits.

<a id="exploiter-les-diagnostics"></a>
## Use the diagnostics

**Quality & research → Rule reliability** shows requests, HTTP responses, recovered
failures, cooldowns and omitted indicators. Redirect details separate security
constraints, transport failures, unreadable content and remote responses. Select
the current engine build or all available builds explicitly. Older messages can
lack newer counters; missing history does not prove that no request occurred.

Missed-spam analysis uses only messages labelled as unwanted by an authorized
account. Operational corrections remain separate from evaluation labels. Several
failures can affect the same message; these are investigation leads, not causal
proof. Synthetic tests cover cached malicious results despite exhausted quota,
retries, mismatched targets, slow links and sender-context changes. They do not
measure recall on independent real traffic.

<a id="mémoire-comportementale-consultative"></a>
## Advisory sender history

Identity must come from a native SMTP session, a single From address and a
DMARC-aligned DKIM signature. Its key includes the recipient domain. Context uses
a fingerprint of the sole envelope recipient, at most eight link domains and six
native pattern types, without storing message text. Multi-recipient envelopes do
not retain this context; Bcc identities are not exposed to other accounts.

The reference uses earlier human labels from active administrators who can access
the message. Conflicting labels are excluded and an exact campaign contributes
once. Samples must share the feature protocol and native policy, cover at least
five wanted campaigns on three distinct days, and fall within 30 days. Partial
data, a changed policy, a timed-out query or too few examples leaves comparison
unavailable. The SQLite read is bounded to 2,000 rows and 200 ms; an interrupted
comparison does not block delivery.

Novelty flags feed only the shadow quality candidate, with explicit availability
and ablation features. They do not create a sender allowlist, alter the active
score or establish fraud. Public reports and quality exports exclude private
identity keys and reference samples. Metadata follows message retention; no
additional body is retained for this comparison.

<a id="migration-et-preuve-de-qualité"></a>
## Compatibility and quality evidence

Sender-history features were introduced with the 0.6.0 quality protocol. A model
must match the currently supported feature protocol and detector cohort; version
numbers alone do not establish compatibility. Preserve incompatible model bytes
privately and collect new compatible observations before retraining. Do not edit
cohort identities, pool incompatible vectors or reconstruct deleted messages to
make a candidate eligible. See [model provenance](model-provenance.md).

Threshold selection in `train_quality.py` applies empirical error budgets to the
selection partition and includes tied scores. Testing and prospective evaluation
exclude campaigns seen during fitting or selection. The 95% capture and 0.1%
false-positive targets require independent evidence and confidence intervals;
software tests or a small corrected sample do not establish them. Candidates are
not activated automatically. Observation and Proton validation still apply before
subject marking. Follow the [qualification procedure](filter-qualification.md).
