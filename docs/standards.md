<a id="protocoles-et-dépendances"></a>
# Protocols and dependencies

The exact versions are locked in `Cargo.lock` and `web/package-lock.json`. The current compilation uses `mail-auth 0.12.1`, `mail-parser 0.11.8`, Tokio, rustls and embedded SQLite. SMTP sessions, persistence, delivery attempts, scoring engine and training are implemented in this project.

| Reference | Implementation and limits |
|---|---|
| [SMTP RFC 5321](https://www.rfc-editor.org/rfc/rfc5321) | Envelopes, transactions, CRLF/dot-stuffing, responses, liability after 250, attempts and failures. The obsolete literal domains and source routes remain out of scope. |
| [SIZE RFC 1870](https://www.rfc-editor.org/rfc/rfc1870) | Announced size and effective limit of the DATA. |
| [8BITMIME RFC 6152](https://www.rfc-editor.org/rfc/rfc6152) | 8-bit body relayed only to a relay announcing capacity. |
| [PIPELINING RFC 2920](https://www.rfc-editor.org/rfc/rfc2920) | Ordered commands and responses; DATA and STARTTLS border strict. |
| [STARTTLS RFC 3207](https://www.rfc-editor.org/rfc/rfc3207) | Resetting session after negotiation; certificate of the relay verified. |
| [Messages RFC 5322](https://www.rfc-editor.org/rfc/rfc5322), [RFC 2047](https://www.rfc-editor.org/rfc/rfc2047) | Folded headers and preserved encoded subjects, unchanged body. Raw UTF-8 headers require SMTPUTF8, disabled. |
| [SPF RFC 7208](https://www.rfc-editor.org/rfc/rfc7208), [DKIM RFC 6376](https://www.rfc-editor.org/rfc/rfc6376) | Verification on the actual and original IP, before any modification. |
| [DMARC RFC 9989](https://www.rfc-editor.org/info/rfc9989/) | `mail-auth 0.12.1` implements hierarchical DNS search and alignment; `src/dmarc/verify.rs` code control performed. No DMARC aggregated reports in this version. |
| [ARC RFC 8617](https://www.rfc-editor.org/rfc/rfc8617) | Checking the original chain and sealing after marking. No assumption that Proton trusts the intermediary. |
| [Authentication-Results RFC 8601](https://www.rfc-editor.org/rfc/rfc8601) | Incoming results deleted after checking the original, local results rebuilt. |
| [DSN RFC 3464](https://www.rfc-editor.org/rfc/rfc3464) | multipart/report notification, failed recipient and empty envelope sender. The extension ESMTP DSN is not announced. |

This table defines the scope developed. It does not constitute a certification of compliance with all RFC requirements and options. Actual interoperability and delivery tests remain necessary before MX changes.
