# Flood protection and sender verification

NoiseFence can apply transport controls independently of its **Spam / Ham / Pub** verdict. These controls are optional, disabled by default, and configured in **Administration → Filters → SMTP admission → Flood protection and sender verification**. They do not reactivate any content provider, including a suspended LLM.

## Shared flood controls

A single authority on the coordinator records fixed-window counters for each recipient:

- Messages from an envelope sender.
- Messages from an envelope sender domain.
- All messages to the recipient, including floods using rotating senders.
- Messages with an identical body (transport headers are excluded).

Workers query that authority over the existing authenticated cluster channel. RPC retries with the same transaction ID reuse the recorded result. Separate SMTP submissions, including retries after a 451, are new attempts. Rejected attempts do not extend the window.

Authenticated sender buckets require live SMTP evidence, SPF pass and DMARC pass. Unauthenticated envelope identities are scoped to the source IP (IPv6 /64); forging another person's From address cannot exhaust that person's authenticated sender bucket. Domain authentication is not proof of an individual mailbox owner's identity.

Configure the window and each quota; **0 disables that quota**. Select:

| Action | Behavior |
| --- | --- |
| Observe | Record counts and exceeded quotas without changing transport. |
| Defer | Return SMTP `451 4.7.1`; the sending server retries. |
| Quarantine | Accept durably and hold the affected recipient's delivery. |

Once a sender/source or recipient bucket is exhausted, subsequent attempts can be deferred at RCPT, before DATA and content analysis. Authenticated sender and duplicate-body checks require the current message to be analyzed. A deferral after DATA applies to the **whole SMTP transaction**, because SMTP cannot selectively reject individual recipients at this stage. Quarantine is per recipient.

Global **content observation** overrides these actions: no traffic deferral, quarantine or verification invitation. Observation and enforcement use separate counter identities. Limits intentionally count attempts, not learned spam probability. Legitimate bulk senders can exceed a quota: start in observation and size limits from actual traffic.

Exact-recipient overrides take precedence over `*@domain` overrides and defaults. Administrators can delegate customization to mailbox owners in **My filters**. Existing scope permissions are checked on the server; recipients cannot edit another user's policy. When delegation is enabled, personal policies replace the inherited traffic policy. Authenticated sender exceptions skip sender/domain/duplicate limits and verification, but retain recipient-wide limits and all content security checks.

The message detail shows the recorded transport report. `X-NoiseFence-Traffic` exposes only bounded status, action and enforcement fields, before ARC sealing. It contains no sender/recipient identity, challenge token or extra score.

## Optional sender verification

This service is **not enabled automatically** when flood protection is enabled. It needs both the global verification switch and `verify_new_senders` in the applicable recipient policy.

1. Upgrade all MX nodes to the same supporting build before adding traffic settings. Coordinated activation refuses incompatible workers.
2. Select **CAPTCHA provider**. **Self-hosted image CAPTCHA** needs no API key: NoiseFence generates and verifies the image locally. **Cloudflare Turnstile** remains optional; create a site for the console hostname and save its private secret in **Provider credentials** through the normal credential activation workflow. Only its public site key belongs in traffic settings.
3. Configure the public HTTPS origin, matching the console origin. A public site key is required only for Turnstile.
4. Configure the notification From address and explicit outbound relay hosts. The relay must permit this server to send external mail by IP and support verified TLS. Invitation SMTP AUTH is not implemented. Do not assume Proton's inbound MX hosts provide outbound relay service.
5. Set the link lifetime (1–72 hours), remembered sender period (1–90 days), and global invitation quota (1–1,000 per rolling day). An additional limit permits only one invitation per sender per rolling day across recipients.
6. Enable the service, enable verification only for selected recipient scopes, and activate the policy after checking a test mailbox. The service remains inert in observation mode.

The public page is `/verify-sender`. The capability is placed in the URL fragment, removed from the address bar after loading, and submitted in a POST body. Opening a link or fetching the page does **not** release mail. An explicit button click and successful server-side CAPTCHA validation are required. Tokens expire and cannot be reused after successful confirmation. With Turnstile, NoiseFence additionally checks the returned hostname, action and ticket binding.

Only complete **Ham** with live SMTP SPF/DMARC evidence and an envelope sender matching the single From mailbox can enter this flow. Null senders, automated response headers, list mail, multipart reports and common no-reply/bounce addresses are excluded. Incomplete content-only scans and detected malware are ineligible. A pre-existing security or user-rule quarantine takes precedence and cannot be released by a challenge. A remembered grant applies only to the exact sender/recipient pair and still requires fresh authentication and content checks.

Invitations are armed only after the local queue commit and all required replica acknowledgements. They contain no original subject, message content or recipient address. They use a null SMTP envelope sender and `Auto-Submitted: auto-replied`. If an invitation's SMTP result is failed or uncertain, it is **not automatically resent**: the original remains held and can be released manually. This avoids repeated challenges after a lost SMTP response.

### Self-hosted image CAPTCHA

Select **Self-hosted image CAPTCHA** in the sender verification service settings. New console configurations select it by default. Existing configurations that omit `captcha_provider` retain Turnstile behavior; changing provider is an explicit policy activation and requires matching MX builds.

NoiseFence generates a six-character raster PNG in Rust. It contains no text metadata or embedded answer. The page and script are served locally, and its Content Security Policy permits no external CAPTCHA resources. No message content or browser CAPTCHA interaction is sent to a third-party service in this mode.

Each challenge is bound to one already-armed sender-verification ticket. It expires after five minutes, or sooner if the invitation expires. Refreshing replaces the previous challenge. Submitting an incorrect code consumes the challenge and requires a new image. The server stores only a context-bound HMAC of the answer, using the coordinator's existing private signing secret; comparison is constant-time. Successful confirmation and creation of the scoped grant are atomic. Opening the page alone never confirms delivery.

Generation and confirmation share a four-request concurrency limit and the public verification rate limits: 120 requests globally and 12 per link per minute. The database retains at most one active challenge per ticket and 10,000 total, with expiry cleanup. SMTP acceptance never waits for CAPTCHA image generation. Challenge state is coordinator-local, like existing invitation state; include the private database in encrypted backups.

The page offers **New image**, keyboard input and case-insensitive answers. There is no audio challenge in this version: someone unable to read the image must contact the recipient for manual release. Visual CAPTCHA is an additional abuse hurdle, not a guarantee of human identity or resistance to modern OCR. Authentication, invitation quotas, expiry, durable acceptance and content-security checks still apply. See [OWASP's CAPTCHA guidance](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#captcha).

Only the Turnstile option sends CAPTCHA interaction and usual browser/network data to Cloudflare; it does not send email content or attachments. Challenge/response can inconvenience legitimate senders and cannot completely eliminate backscatter; authenticated domains do not prove individual mailbox ownership.

## Failure and recovery behavior

- On traffic authority timeout, overload or stale policy, retain the normal content decision and record the traffic check as unavailable. Do not start an independent worker counter. Existing connection, queue and disk limits remain active.
- Turnstile requires a loaded private credential before creating verification holds. Self-hosted CAPTCHA requires no provider credential. A failed or unavailable CAPTCHA never releases an existing hold.
- Disabling verification or returning to observation stops invitations and automated releases. Existing held messages remain available for manual release and expire under normal quarantine retention; disabling the switch does not silently deliver them.
- Challenge link expiration does not deliver a message. Queue retention may expire earlier than a configured link; confirmation never resurrects an expired delivery.
- Counters, tickets, grants and the signing secret live in the coordinator's private local SQLite database, alongside existing SMTP admission state. They are **not a second synchronously replicated authority**. Include the coordinator's database in encrypted backups. After an authority loss, accepted message bodies retain the normal queue replication guarantee, but pending challenges may require manual release or restoration of the coordinator state. Do not promote two independent authorities.
- Expired counters and records are pruned in bounded batches. The idempotency result cache is capped at 16 MiB, bucket/operation rows at 100,000, and verification tickets/grants at 10,000 each. Traffic state and verification state have hard capacities; overload does not evict live grants or convert missing evidence into spam.

This version detects exact-body repetition; it does not claim fuzzy campaign clustering or distributed-consensus counters. Rspamd remains an independent observer and is not consulted by these controls.

## Validation

Tests cover shared-window counting, RPC idempotence, authenticated/unauthenticated isolation, IPv6 rotation, recipient scopes, observation, stale policies, CAPTCHA hostname/action binding, token expiry/replay, and release restricted to accepted verification holds. Test the selected provider and actual outbound relay with a dedicated mailbox before enforcing challenges. Local tests cover PNG decoding, challenge replacement, wrong-answer consumption, expiry, cross-ticket isolation, scoped grant creation, origin checks, replay, observation and first-party-only browser requests. The test suite does not send real challenge emails or solve live CAPTCHAs.
