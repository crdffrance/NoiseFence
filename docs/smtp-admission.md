<a id="greylisting-sélectif-et-ralentissement-smtp-0162"></a>
# Selective greylisting and SMTP response delays

In **Administration → Filters → SMTP admission**, administrators configure deferrals, retry windows, rate limits, exemptions and response delays. Applying a revision takes effect without a restart and is recorded in the configuration audit. Users can inspect admission results for their messages; they cannot disable shared transport protections.

The `smtp-admission-2` policy is disabled by default. Its initial mode, `observe`, records hypothetical decisions without sending `451` or adding a delay. `enforce` applies the configured deferrals. **SMTP admission mode is separate from content observation mode**: this feature does not change scores, content classification, subject tags or quarantine decisions.

<a id="sélection-et-protection-des-expéditeurs-légitimes"></a>
## Selecting attempts for deferral

Checks run after recipient validation at RCPT, before DATA, spooling, OCR and content models:

1. A token bucket limits MAIL transactions that reach a valid recipient. Multiple RCPT commands in one transaction consume one token; a new transaction consumes another. Exceeding the quota returns `451 4.7.1` and requires a new MAIL command. RSET and STARTTLS do not reset the quota.
2. Greylisting requires a positive IP reputation result and the configured minimum number of corroborating signals, at least two. Distinct RBL operators count separately; an invalid HELO name can supplement one operator. Multiple zones from the same operator do not create additional votes. PBL and unavailable DNS results do not count. Without a positive RBL result, the message is not greylisted.
3. Explicit IP/CIDR exemptions bypass the quota and greylisting. Loopback is exempt for local operations. The envelope sender, advertised domain and headers alone do not establish trust.
4. Null-sender notifications and postmaster recipients bypass greylisting, but remain subject to the rate limit. Unknown recipients and open relay attempts are refused separately, before accessing retry state.

Greylisting tests the ability to retry, not the legitimacy of content. A spammer who retries still passes through content analysis. Legitimate platforms may retry from another network, so delivery delays remain possible. Synthetic tests do not establish a capture gain or a false-positive rate.

<a id="retry-durable-multi-mx-et-disponibilité"></a>
## Durable retry state across MX servers

The retry tuple includes the mode, connecting IP network (/24 for IPv4, /64 for IPv6), envelope sender and recipient. Envelope fingerprints are salted and separated by role. Source ports are not identities; distinct aliases and local-part case are preserved. Network grouping provides neither authentication nor a content-analysis exemption.

The first attempt sets a fixed earliest retry time. An early retry does not postpone it. A qualifying retry opens a fixed acceptance window. Observation and enforcement use separate state, so observed traffic does not silently authorize later enforcement.

The coordinator stores this state in SQLite WAL with FULL synchronization. Workers query the same authority over certificate-verified HTTPS using revocable node credentials, without redirects or implicit proxies. Only required envelope metadata and SMTP signals are transmitted, never message bodies. The coordinator validates the recipient again and uses its own policy and clock.

Local lookups allow four concurrent jobs and at most 500 ms of SMTP waiting. A timed-out SQLite job retains its permit until it finishes. A worker request is bounded to 750 ms and a 4 KiB response. On an error, saturation or coordinator failure, this layer records `unavailable` and allows processing to continue. Workers do not start independent greylisting cycles. Shared rate limits are unavailable during that failure; local connection limits and all other protections still apply. Mandatory message replication remains a separate acceptance requirement.

<a id="teergrubing-borné"></a>
## Bounded response delays

An optional asynchronous delay precedes a deferral. Policy limits bound both the delay and the total delay budget per connection; MAIL, RSET, EHLO and STARTTLS do not reset that budget. A shared permit limits concurrent delayed sessions on each MX, including across configuration revisions. When capacity is exhausted, the server skips the added delay and still returns `451`.

The delay holds no SQLite mutex or DATA-analysis permit and creates no detached task. Cancellation immediately releases its delay permit. This mechanism does not keep clients connected for minutes.

<a id="réglages"></a>
## Settings

The following server-side bootstrap example corresponds to the settings editable in the console:

```toml
[smtp_admission]
enabled = false
mode = "observe"
greylisting = true
minimum_providers = 2
retry_delay_seconds = 300
retry_max_age_seconds = 86400
retention_seconds = 604800
rate_per_minute = 120           # 0 disables; shared across MX nodes
rate_burst = 60
max_entries = 10000            # capacity; active retries are never evicted
tarpit_delay_ms = 0            # 0 disables; maximum 5000 ms
tarpit_max_concurrent = 8      # per MX; 1..64
tarpit_session_budget_ms = 5000 # maximum 10000 ms
allow_networks = []            # explicit CIDRs; maximum 128
```

IPv4 rate limits apply per IP; IPv6 limits group /64 networks to limit address rotation. Rejected attempts do not postpone token replenishment. Capacity is bounded; a full table allows new keys through this layer. Inactive quota state expires after 24 hours. Retry cleanup processes batches of 256 rows; counters and diagnostics expire after 30 days. This feature retains no additional bodies or attachments.

The console shows counters by mode and outcome and admission signals for accepted messages. Deferrals appear in `SMTP intelligent admission` logs; a `451` does not create an accepted queue item. Deduplicated diagnostics do not disclose hidden recipients. If counter storage fails, the incident remains visible in logs and in the diagnostics of any subsequently accepted message.

<a id="déploiement-et-validation"></a>
## Deployment and validation

The original feature migration was additive. Current paired installations require storage schema 5 and a compatible release. Do not downgrade the database, remove its HA marker or restore an older backup over accepted mail. See [installation](installation.md) and [HA recovery](high-availability.md) for upgrade and rollback procedures.

Tests cover durable retry state, IPv4/IPv6, concurrent attempts, saturation, mode changes, multiple recipients, exemptions, quotas, refusal before DATA, unchanged content scores, Web permissions, inter-node calls and coordinator failure. These tests do not send mail to external recipients.

References: [RFC 6647](https://www.rfc-editor.org/rfc/rfc6647.html), [Rspamd greylisting](https://docs.rspamd.com/modules/greylisting/) and [Rspamd rate limits](https://docs.rspamd.com/modules/ratelimit/). NoiseFence implements its own Rust admission layer; it does not embed the Rspamd engine.
