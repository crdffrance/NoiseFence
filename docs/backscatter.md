# Backscatter protection

An SMTP envelope sender can be forged. When a destination rejects an accepted message, a delivery status notification (DSN) can therefore reach an innocent third party.

The native `backscatter-2` policy applies when processing **new delivery failures**, including in observation mode. It does not change incoming SMTP acceptance, Spam/Ham/Pub decisions or filtering actions. It does not recall delivered notifications or purge queued DSNs.

## Required evidence

Suppression requires all of these conditions:

- A permanent, exact `550/554 5.7.1 rejected by rspamd filter` response after DATA, over certificate-verified TLS. The saved failure and complete delivery transcript must agree. Recipient rejection, retry expiry, generic policy errors and truncated transcripts do not qualify.
- An unwanted engine decision, with no contradictory recipient classification or Ham/Pub feedback.
- Complete authentication from the actual SMTP session: SPF fail/soft-fail and no successful or indeterminate DKIM, DMARC or ARC result. Imported messages and authenticated senders retain normal notifications.
- One of the narrow content combinations below.

| Content evidence | Additional requirements |
| --- | --- |
| Main antivirus detects malware | Complete core analysis |
| Supplementary `Sanesecurity.Phishing.*` signature plus completed LLM phishing verdict | Complete core analysis, index at least 99/100, LLM confidence and reported risk at least 0.9 |
| Supplementary `Sanesecurity.Phishing.*` signature plus native direct-extortion context | Readable content, completed clean main antivirus, no legitimate LLM opinion, and no encrypted, quoted threat-report, transactional or conditional security-notice context |

The native extortion branch does not require an active LLM or use the shadow Rspamd result. Extortion extraction requires a direct compromise/disclosure threat and a cryptocurrency demand with a wallet. A missing SMTP/DNS consistency check is permitted only by the existing partial-coverage threat contract; missing content or authentication is not.

A score, failed SPF, a remote rejection or a model opinion alone never suppresses a DSN. The quoted remote response is evidence of the destination's refusal, distinct from NoiseFence's independent Rspamd comparison. These conditions do not constitute a measured false-positive guarantee.

## Persistence and diagnostics

The recipient delivery moves to `dsn_suppressed`, shown as “Notification suppressed (backscatter protection)”. The policy version, reason and original rejection remain in the audit and delivery diagnostics. Status and audit are recorded in one transaction; no DSN is created. Restart cannot recreate that notification. Other recipients continue independently.

The original body follows normal retention: it remains while another recipient is queued or quarantined and is removed after all recipients resolve, subject to any explicitly enabled research retention. Existing queued DSNs retain their normal lifecycle.

Ordinary notifications preserve the last permanent enhanced status and bounded, ASCII-safe `Diagnostic-Code`; expired retries use `5.4.7`. Remote text cannot inject DSN fields.

## Upgrade and verification

No database schema, credentials, quotas or observation settings change. Keep mandatory peer replication and activate a compatible release on every enrolled MX. Never restore an old queue database during rollback.

Regression tests cover authenticated mail, quoted/report context, missing checks, recipient corrections, temporary errors, multiple recipients, durable suppression, restart and cluster synchronization.

Reference: [RFC 5321 §6.2](https://www.rfc-editor.org/rfc/rfc5321.html#section-6.2). Silently discarding accepted mail requires great caution and very high confidence that it is seriously fraudulent or otherwise inappropriate.
