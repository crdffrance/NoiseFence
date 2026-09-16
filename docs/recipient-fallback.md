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
