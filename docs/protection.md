# Reputation and complementary protection

These checks retain structured observations for the console and `export-learning`. They do not independently change delivery or establish a calibrated probability. HTML, QR, CRDF and VirusTotal reports about the same indicator are correlated evidence, not independent votes. Incoming headers cannot forge a locally computed observation.

Install the optional module in the initial host configuration, then manage its messaging policy through the Web console:

```toml
[protection]
timeout_ms = 1200
max_parallel = 2
crdf_per_minute = 2
crdf_per_day = 200
virustotal_per_minute = 4
virustotal_per_day = 500
```

These are conservative example budgets, not provider entitlements. Saved Web settings take precedence. Timeouts and concurrency can be changed under **Filters → Advanced settings**; accounts must have administrator access.

<a id="console-et-clés"></a>
## Console and credentials

Under **Filters → Protection & reputation**, save an authorized CRDF/VirusTotal key, select the intended connector, then **Review and apply**. Keys are private server files under `data_dir/protection/`, mode 0600 in a 0700 directory. They are not returned by subsequent API reads, exported, recorded in policy revisions or included in logs. Key saves require an active administrator session, the configured origin and CSRF protection; audit records omit the value. Rotation applies to future calls.

Identity checks, links, campaign checks, providers, URL following, protected names and reply/tracking exceptions are revisioned Web policies. An exception applies only to the named heuristic and exact domain; it does not bypass authentication, antivirus or the classifier.

<a id="quotas-configurables-depuis-045"></a>
## Quotas

Each provider card supports installation defaults, explicit per-minute/per-day limits and unlimited access. `0` means unlimited; an absent or null override inherits the installation value. Positive limits are integers up to 4,294,967,295. Both fields are required in a quota object:

```json
{"crdf_quota": {"minute": 0, "day": 0}}
```

Apply the draft explicitly. Already started transactions retain their policy. Disabling the connector stops calls; zero quota does not disable it. Counters reserve requests before HTTP, including failed or cancelled calls, and persist across restart, credential rotation and policy changes. Cached results do not consume a new request. Windows use UTC minutes and days. The administrator `/admin/protection` API exposes counters and current provider cooldowns without secrets.

Unlimited quotas remove local request ceilings only. Concurrency, deadlines, per-message indicator limits and provider cooldowns remain enforced. In a cluster, limited credits are shared by the coordinator; see [multiple MX servers](multi-mx.md). Provider failure, exhausted quota and omitted checks remain distinct from a malicious verdict.

## CRDF and VirusTotal

CRDF uses `POST search_urls.json` with the `lookup` permission and an `X-API-Key` header. It queries a synthetic HTTPS root for each domain, such as `https://example.org/`. Message paths, query strings and fragments are not sent. It does not submit URLs for scanning or call modification endpoints. An unknown result stays unknown; a path-specific match is not enough to classify an entire shared domain as malicious. Malformed, inconsistent or denied responses are unavailable evidence.

VirusTotal uses existing domain and SHA-256 file reports through `GET /api/v3/domains/{domain}` and `GET /api/v3/files/{sha256}`. It never uploads unknown attachments, message bodies, OCR text or complete private URLs. Reports older than seven days are stale. Fewer than three reporting engines remain suspicious rather than an automatic malicious result; engine counts are not independent votes or calibrated confidence.

Use provider contracts that authorize organizational filtering. A free key does not by itself establish authorization for every product or business use. See [VirusTotal’s public and premium API terms](https://docs.virustotal.com/reference/public-vs-premium-api). Provider data is not redistributed with the GPL software.

Requests use fixed APIs and certificate-verified TLS, without following API redirects. Responses are limited to 256 KiB. Extraction considers up to eight domains and eight attachment hashes, with at most 12 queries per provider/message. Active URL following can add visited domains and prioritize final destinations. A common deadline is not renewed per indicator. Caches last at most 30 minutes, or five minutes for unknown/stale results. Authorization/quota errors impose a five-minute cooldown. Reports expose omissions and failures without copying raw provider replies.

Spamhaus DQS has a separate IP/domain connector, return-code validation and DNS cache. Configure an authorized key under **Advanced settings** or through the allowed host environment; see [RBL admission](early-rbl.md).

## Impersonation and campaigns

IDNA normalization and an embedded Public Suffix List handle registrable domains, including private suffixes. Similarity checks cover common edits and selected homoglyphs; they are not exhaustive Unicode confusable detection. A display name must exactly match a configured protected name. DMARC alignment is independent: a familiar display name is not authenticated identity.

Campaign comparison uses at most 1,000 recent messages in the 30-day window. It requires feedback from active administrators and at least two distinct spam examples. Contradictory legitimate feedback cancels reinforcement. Short messages and transactions spanning multiple destination domains may lack sufficient context. Exact/SimHash comparison stays within the destination domain; it does not expose other domains or Bcc recipients. Results remain advisory and affect only future analysis.

## Local link database

Passive analysis combines text links, HTML anchors/forms and OCR/QR findings. Active following is separately enabled in the console, subject to [URL resolution limits](url-resolution.md); form actions remain passive. Local feed matches use complete URLs, including path/query, so a malicious page does not automatically condemn its whole hosting service.

Import an authorized URL-per-line feed:

```sh
sudo -u noisefence python3 /opt/noisefence/current/deploy/update-url-feed.py \
  --input /private/authorized-feed.txt
```

Alternatively, configure `NOISEFENCE_PHISHING_FEED_URL` in a private `/etc/noisefence/url-feed.env`, then install the supplied feed service/timer. No paid feed or access entitlement is bundled. The [OpenPhish community feed](https://www.openphish.com/phishing_feeds.html) is one compatible format; verify its usage terms before configuring it.

Downloads are bounded to 20 seconds, 8 MiB and 50,000 URLs. Atomic replacement follows validation; failure preserves the prior feed. Reload takes up to 60 seconds. Feeds older than 72 hours are ignored and reported as stale. Feed paths and URL parameters remain server-side. Runtime reports follow metadata retention; feed files, exports and backups have independent retention.

## Verification

Synthetic tests cover deceptive links, entities, public/private suffixes, exact exceptions, correlated OCR/HTML findings, expiry, attachment hashes, provider failures, durable quotas, contradictory feedback, administrator/CSRF controls and unchanged scoring. They do not measure traffic-wide detection quality or make paid requests.

Provider references: [CRDF API](https://threatcenter.crdf.fr/api/doc/), [VirusTotal domains](https://docs.virustotal.com/reference/domain-info), [VirusTotal files](https://docs.virustotal.com/reference/file-info).

### Partial CRDF responses

A batch must still bind every requested target exactly once. Foreign, missing or
duplicate targets invalidate the batch. Within a correctly bound batch, a
malformed individual result is unavailable and uncached while valid neighbours
remain usable. Invalid response payloads do not impose account-wide cooldown.
Provider authentication failures, explicit rate limits and bounded Retry-After
continue to back off. Unavailable, timeout and unknown are not malicious results.
