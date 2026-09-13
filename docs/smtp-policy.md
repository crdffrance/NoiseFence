<a id="contrôles-de-cohérence-smtp-et-dns"></a>
# SMTP and DNS consistency checks

NoiseFence uses the principles of [policy-weight](https://github.com/policyd-weight/policyd-weight/tree/18d2e97a40b7d836d35e25921def508e6a719e49): Crossing the HELO/EHLO identity, the IP connection, the DNS inverse and the domain of the envelope sender, with weights and a cache. The Rust implementation is independent; no Perl code, old DNSBL list or historical coefficient is incorporated. The reference repository indicates that the project is abandoned.

The checks use the IP of the socket, the latest HELO/EHLO and MAIL FROM. The `Received`, `Authentication-Results` and `X-NoiseFence-*` headers received never provide these identities. SPF/DKIM/DMARC and Spamhaus DQS remain their own existing signals: they are not counted a second time here. The existing DQS connector also questions the HELO and MAIL FROM domain, first before the body links; it retains up to 12 unique domains and a single domain reputation contribution per message. Its activation still requires an authorized Spamhaus key; no new public list is activated implicitly. A lack of DNSBL result is not a certificate of legitimacy.

## Enable observation

Add a first-level table in the configuration, then check it and restart the service:

```toml
[smtp_policy]
contribute_to_score = false
timeout_ms = 800
max_parallel = 8
cache_entries = 4096
cache_ttl_seconds = 300
```

The missing table disables the module. With `contribute_to_score = false`, the results are calculated and visible without changing the message score. The `candidate_weight` field allows you to measure the proposed contribution. After calibration, `contribute_to_score = true` applies this contribution. The global mode `filter.mode` and Proton validation continue to control the marking.

<a id="signaux-de-la-version-smtp-policy-1"></a>
## Signs of version `smtp-policy-1`

Weights are logit contributions, not percentages or a probability measure. They are experimental and do not yet have a demonstrated capture improvement.

| Verification | Observation | Candidate weight |
|---|---|---:|
| HELO/EHLO | Name resolves to the connecting IP | −0.15 |
| HELO/EHLO | Corresponding IPv4/IPv6 | 0 |
| HELO/EHLO | Different address / no address | +0.25 / +0.5 |
| HELO/EHLO | Different literal or unusual syntax | +0.5 |
| HELO/EHLO | Client announcing the name of this gateway | +0.75 |
| PTR | At least one name confirmed by A/AAAA to IP | −0.15 |
| PTR | Absent / no confirmed name | +0.25 / +0.5 |
| MAIL FROM | MX present or implicit A/AAAA fallback without MX | 0 |
| MAIL FROM | Null envelope sender for a delivery notification | 0 |
| MAIL FROM | NULL MX or no MX/A/AAAA route | +0.75 |

The total contribution is capped between **−0.25 and +1.5**, because HELO and PTR are correlated. DNS credits never short-circuit content, authentication or reputation analysis. The MX here indicates a DNS statement: its presence does not prove the SMTP accessibility of its target nor the legitimacy of the message.

An outgoing server does not have to match the incoming MX of the domain. Dynamic names, text similarities between domains and memberships of a /24 do not constitute evidence of usurpation. Therefore, they do not receive any weight. The A/AAAA fallback is respected according to [RFC 5321 §5.1](https://www.rfc-editor.org/rfc/rfc5321.html#section-5.1). The single null MX `0 .` is distinguished from the absence of MX, following [RFC 7505](https://www.rfc-editor.org/rfc/rfc7505.html).

<a id="délais-erreurs-et-traçabilité"></a>
## Timeliness, Errors and Traceability

The module runs after DATA alongside authentication checks, within the five-second overall deadline. It does not reject mail based solely on HELO, in line with [RFC 5321 §4.1.4](https://www.rfc-editor.org/rfc/rfc5321.html#section-4.1.4), and does not save body-transfer costs before DATA. [Early IP RBL checks](early-rbl.md) provide that separate stage, with observation by default and configurable SMTP refusal policies.

Its own default time is 800 ms, at most 2,000 ms. Up to eight policy analyses are active by default; saturation makes control unavailable immediately. No detached application DNS task is launched. Names are validated and questioned as absolute names with the system resolver. No link is opened, no recipient address or content transmitted to the DNS.

The search covers no more than four PTRs, 32 responses per query and 14 A/AAAA/PTR/MX searches by analysis, without internal retransmissions of the solver. The application cache is limited in number of entries and respects positive and negative TTLs, with a configured ceiling. A zero TTL is not cached. An resolver error is stored for a second as **not available**, never as absence. The Hickory resolver also has its internal DNS cache.

SERVFAIL, REFUSED, timeout, error on an IP family, inconsistent response or overrun of the PTR budget make the result incomplete. Partial contributions are abandoned, local score is retained and delivery is done without prefix. A positive confirmation of a PTR is sufficient even if another PTR is not confirmable. Errors of other control families remain visible.

The result `smtp_policy` contains version, status, duration, observations, `candidate_weight`, `applied_weight` and `scoring_enabled`. It is stored with metadata for 30 days and subject to existing rights per recipient. Old messages without this field are read as a disabled module. The weights and characteristics of the content classifier are not changed.

<a id="tester-sans-envoyer-de-message"></a>
## Test without sending a message

```sh
noisefence --config /etc/noisefence/config.toml smtp-check \
  --source-ip 192.0.2.10 --helo mx.sender.example \
  --mail-from sender@sender.example --iterations 3
```

Replace the documentation values with a actually observed SMTP context. The command returns a JSON line by trial, without opening the queue, loading the model, calling the LLM or sending an email. It also accepts `--mail-from ''` and `--helo '[IPv6:2001:db8::10]'`. Repetitions share the cache; the first measurement must remain separate from the following. `analyze` and the `pipeline_probe` bench include these controls when the table is configured. `scan`, who does not know the original SMTP context, remains an off-grid content analysis.

The tests use deterministic DNS responses for IPv4/IPv6, multiple PTR, Null MX, implicit fold, NXDOMAIN/NODATA, temporary errors, cache, caps and time limits. Measurements on content corpus do not allow to evaluate this layer without reliable IPs and original envelopes.
