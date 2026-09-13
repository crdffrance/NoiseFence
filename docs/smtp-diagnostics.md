<a id="comprendre-les-diagnostics-smtp-et-les-filtres"></a>
# Understand SMTP diagnostics and filters

In the console, open a message and see **Filters and Indices triggered** and **Message Diagnostics**.

- Filters display their identifier, explanation and recorded contribution. A zero weight indicates an advisory observation. The contributions of the model are not added a second time.
- Diagnoses retain the duration, SPF/DKIM/DMARC/ARC results, threshold and weights actually used in the analysis. There is no historical information available.
- **STP transmission by recipient** shows the servers tested, the attached IP, DNS/TCP, EHLO, STARTTLS and TLS verified, MAIL FROM, RCPT TO, DATA, the final response and re-tests. The update button reloads the new attempts.

A final `250` means that the remote server has accepted the transfer. It does not guarantee inbox ranking. A `451` is temporary and results in a retest; a `550` is final for this attempt/destination. Extended codes, for example `4.7.1` or `5.1.1`, and the server patterns remain visible.

If an attempt stops at **DNS Resolution** without SMTP code, no remote server has yet answered. The reason may come from the validation of the route, the resolution of the name or its expiration time. Since 0.4.3, MX names with a final point are accepted, including in the failed notices already in file. This point refers to an absolute DNS name ([RFC 1035, § 5.1](https://www.rfc-editor.org/rfc/rfc1035.html#section-5.1)); it is retained for resolution and removed for verification of the TLS name.

<a id="journaux-du-service"></a>
## Service logs

```sh
sudo journalctl -u noisefence --since '30 min ago' -o cat
sudo journalctl -u noisefence -f -o cat
```

File ID displayed in the console connects the events `message analyzed`, `message durably accepted` and `outbound SMTP event`. Relay tracks also carry delivery ID, attempt ID, route, phase and duration.

<a id="confidentialité-et-limites"></a>
## Confidentiality and limitations

Fees are verified for each recipient: knowing the file ID does not give access to copies of another account. Outgoing orders are represented by their phase, without their arguments; DATA is not updated.

Since 0.42, the recognizable addresses in remote responses have been hidden before truncation, including some encoded representations. This treatment also applies to the reading of old answers and errors in the console. It does not retroactively rewrite the files in the system log. Address recognition is not a tool for deleting any private content: an arbitrary sentence or opaque encoding returned by a server can remain visible.

Traces are limited: 32 events per road, 2,048 bytes per field displayed, up to 50 logs loaded for a recipient and 100 in the global view. Omissions are reported. Transcripts missing on old messages are not reconstructed. Metadata follow the retention of the message and are deleted by maintenance.
