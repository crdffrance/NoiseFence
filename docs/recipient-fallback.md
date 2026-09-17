# Unknown-recipient fallback

NoiseFence 0.21.0 adds an optional **Unknown-recipient fallback** under Administration → Domains. Enter a canonical mailbox in the same domain, for example `postmaster@example.org`. The mailbox must exist at the downstream host. Alias chains and cross-domain fallback are rejected. Leave the field empty to preserve normal failure handling.

The normal recipient is always attempted first. Only an explicit **550 5.1.1 response to RCPT TO**, before DATA, triggers one additional RCPT attempt in the same verified TLS session. The original message, sender envelope and signed headers are unchanged. The fallback cannot itself trigger another fallback. Existing recipients, temporary failures, unqualified 550 responses, sender rejections and all DATA/content rejections keep their normal behavior. Locally generated delivery notifications are excluded. A changed downstream route does not retroactively redirect old queued deliveries through this fallback.

The live Web policy is read for each delivery attempt; the original queue destination remains recorded. Recipient-scoped SMTP logs show the original refusal and a separate `rcpt_fallback` event. Access to those diagnostics remains based on the original authorized recipient. A fallback acceptance is not a filter whitelist: the downstream service can still refuse the message during DATA, and normal retry/DSN handling applies. No new DATA copy is sent following an ambiguous DATA result or successful delivery. Ordinary SMTP duplicate-delivery limits after a lost final reply still apply.

For server configuration, the equivalent optional setting is:

```toml
[[domains]]
name = "example.org"
next_hops = ["mail.example.net"]
accept_all_recipients = true
unknown_recipient_fallback = "postmaster@example.org"
```

With multiple MX nodes, upgrade every node before activating fallback. The coordinator refuses to publish this enabled policy to incompatible workers rather than silently ignoring it. No queue schema migration is required. Disabling the Web field stops new fallback attempts; it does not recall delivered messages. Previously failed messages are not automatically resent.

## Refuse nonexistent recipients before acceptance

NoiseFence 0.23.0 adds **Verify recipients at destination** under Administration → Domains. Enable it on the canonical destination domain and leave the fallback empty. This also works with **Accept all domain addresses**: existing downstream mailboxes need no individual declaration in NoiseFence. Explicit local aliases keep their intentional mapping and use the verification policy of their canonical destination domain.

For each incoming RCPT, after local authorization and SMTP admission limits, NoiseFence checks only the explicitly configured relay hosts. It uses certificate-verified STARTTLS, the original envelope sender and the resolved recipient, then resets/closes the transaction without DATA. It never discovers routes from public MX records and never probes an unauthorized domain.

- A downstream 250/251 accepts the recipient for normal content processing and durable queuing.
- Only an explicit RCPT **550 5.1.1 from every configured host** causes an incoming **550 5.1.1**. The message body is not accepted and no delivery failure notification is created for that rejected recipient.
- Timeouts, capacity limits, DNS/TLS failures, sender refusals, unqualified 550 replies, other permanent errors and conflicting/incomplete route responses produce **451 4.4.3**. Senders can retry; an unavailable check never means a nonexistent mailbox.

The Web controls bound the entire check (default 8 seconds, maximum 15 seconds), accepted-recipient cache (default 60 seconds, maximum 300), and unknown-recipient cache (default 30 seconds, maximum 60). Set a cache TTL to zero to disable it. Route attempts share the deadline. Each process allows eight concurrent checks and at most 10,000 cached entries. Cache keys include the original sender, exact destination, routes and policy; changes cannot reuse results from a different route or policy. No raw message or address is written to verification logs. The cache is local and cleared on restart. Existing admission limits apply before network checks.

```toml
[[domains]]
name = "example.org"
next_hops = ["mail.example.net"]
accept_all_recipients = true
[domains.recipient_verification]
timeout_ms = 8000
positive_cache_seconds = 60
negative_cache_seconds = 30
```

Upgrade the coordinator first, then every worker, before enabling this setting. Older workers cannot silently ignore an enabled policy. Both fallback and verification are optional, disabled when absent, and mutually exclusive. Antispam observation does not disable this recipient authorization check.

This is an envelope check, not a delivery guarantee: mailbox state can change after acceptance, a downstream catch-all can accept every address, and later content/quota policies can still refuse delivery. Previously accepted messages keep their queue responsibility and normal retry/DSN handling; disabling fallback does not recall messages already delivered. For an immediate mailbox deletion, disable positive caching or wait for its TTL.
