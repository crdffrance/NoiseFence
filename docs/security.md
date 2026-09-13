<a id="limites-et-frontières-de-confiance"></a>
# Security and trust boundaries

- The SMTP envelope is the source of the rights on recipients. `To`, `Cc`, `Bcc`, `Message-ID` and the antispam headers provided by the sender cannot give access to another account.
- The incoming `X-NoiseFence-*` headers (and the former `X-Antispam-*` prefix) and `Authentication-Results` headers are deleted after authenticating the original. Only the results calculated here are added; the previous ARC sets are retained. Authentication is recalculated from the original bytes and IP of the connection, never since a result declared by the sender.
- Incoming traffic is limited to the configured domains: boxes and explicit aliases by default, or all valid domain addresses with `accept_all_recipients = true`. This option does not cover subdomains or external domains and does not create any console rights. Locally generated failure notices can use the envelope sender's MXs. Private IP addresses, loopback and link-local are denied network delivery, except the explicit loopback test mode.
- The reception uses strict CRLF grammar, bounded lines, a state machine and a reset after STARTTLS. The preloaded clear bytes at the STARTTLS border close the connection. CHUNKING/BDAT, AUTH and SMTPUTF8 are not announced.
- SMTPUTF8 remains disabled in this first release. The encoded Unicode subjects under RFC 2047 and 8BITMIME bodies are processed. Internationalized domains/addresses must be represented in supported ASCII forms; the full support of SMTPUTF8 addresses will require further development and testing.
- The local SMTP ASCII parts, including quotation marks, are accepted; the literal domains in square brackets and the obsolete source routing remain out of scope. Explicitly configure the aliases `postmaster@domaine` and the recipient of `relay.postmaster` for the special form `RCPT TO:<Postmaster>`.
- The engine is limited to 2 MiB by default for content analysis; a larger accepted message is transmitted without prefix and reported incompletely. Attachments are neither executed nor transmitted to an external service. The ClamAV scanner is optional; this project does not have a detonation sandbox.
- The [quarantine actions](actions.md) keep the body in the private spool and recheck the rights per recipient at each release or deletion. No global release can expose the hidden copies outside the perimeter.
- The score never orders a rejection. Errors in protocol, unknown recipients, resource limits and delivery failures remain separate SMTP causes.
- HTTP sessions last eight hours and use random tokens stored as hashes, HttpOnly/SameSite cookies and Secure in production. The mutations check the origin and a CSRF token. The interface displays email texts with React escaping; it does not return their HTML.
- Passwords use Argon2id; concurrency is bounded and hashing runs outside network threads. Connection attempts are limited globally and by login. Password change and deactivation revoke sessions.
- The frontend is exported in static mode. RSC/Workers packages are used for building purposes and are not an application server exposed in production. hydration scripts currently require `script-src 'unsafe-inline'`; no email content is inserted as HTML or JavaScript.

The tests provided cover concrete regressions; they do not replace an independent audit, a long-term fuzzing campaign or the actual Proton tests. Protocol support is a tested target, not an exhaustive compliance certification.

The optional WebMCP entry point uses the same API, session and controls as the correction button. Its contract must be tested in a browser that exposes it; no validation of the WebMCP protocol is claimed in the absence of such a context.
