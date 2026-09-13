<a id="protection-contre-les-notifications-de-spam-0153"></a>
# Protection against spam notifications (0.15.3)

A SMTP sender can usurp the address of a victim. If NoiseFence accepts the message and the supplier refuses it, a notice of non-delivery (DSN) returned to that sender can reach the victim: it is the backscanter.

The native policy `backscatter-1` is active for **new notification processing** on each MX, including observation. It does not change the ranking, filtering actions, or SMTP response at reception. It does not recall the notices already delivered and does not purg the DSN already in file.

## Required conditions

The notification is blocked only after a permanent refusal of `550/554 5.7.1 rejected by rspamd filter` content after DATA, on a TLS connection whose certificate has been verified. The last log of the attempt and the persistent reason must correspond. A refusal of recipient, an expired delay, a generic response 5.7.1 or a truncated transcription are not enough.

A full analysis, a `unwanted` decision and authentication observations from the actual SMTP session are also required: SPF `fail`/`soft_fail`, authentication completed, no success or indeterminate DKIM/DMARC/ARC result. A message authenticated or imported for analysis does not benefit from this exception. A non-spam ranking from the recipient's rules or a "Legitime"/"PUB" user correction also retains normal notification.

Finally, **either**main antivirus malware detection, **or**all of the following:

- local risk index of at least 99/100 ;
- signature consultative `Sanesecurity.Phishing.*` ;
- completed LLM analysis concluding to phishing, with reported probability and confidence of at least 0.9.

These numbers do not constitute a statistical guarantee; the LLM already contributes to the score. The combination is deliberately narrow: specialized signature, authenticated remote refusal and index of usurpation complete the content. Incomplete analyses and insufficient evidence keep the DSN normal. Policy does not necessarily block all spam returns.

<a id="conservation-interface-et-redémarrage"></a>
## Storage, interface and restart

The delivery goes to `dsn_suppressed`, presented as "Blocked Notice (anti-backscatter)". The reason for the policy and the refusal remain visible in the diagnostics of the authorized recipient. This status is available in the search and goes back to the central console from the workers. The status and the audit `dsn_suppressed` are recorded in a single transaction. No DSN message is created. A resume cannot recreate this notice or replace an existing DSN.

The original body follows the usual preservation: deletion after resolution of all recipients, preservation if another delivery is still in file or quarantine. Metadata remains available for 30 days. No additional storage of content is added.

The real DSN now indicates `Status` and `Diagnostic-Code` from the last attempt, or `5.4.7` for a file expiration. Diagnostics are limited, converted to ASCII, redacted addresses and protected against field injections. Errors without usable code keep `5.0.0`.

## Operations

Deploy the coordinator 0.15.3 before the workers. No change of SQL schema, key, account or budget. The new status requires a coordinator 0.15.3 for the historical recovery; do not return to a former coordinator as long as the workers transmit this state to him. The backend must never restore an old file over the messages accepted since.

The tests cover the preservation of legitimate notifications, missing/contradictory evidence, authentication, temporary responses, injections, multiple recipients, resumption and synchronization.

Reference: [RFC 5321, §6.2](https://www.rfc-editor.org/rfc/rfc5321.html#section-6.2), which recommends avoiding notifications for hostile content when they cannot be usefully issued, and imposes great caution for exceptions to normal notification.
