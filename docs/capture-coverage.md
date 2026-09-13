<a id="couverture-et-contexte-du-filtrage--060"></a>
# Coverage and context of filtering — 0.6.0

<a id="réputation-et-redirections"></a>
## Reputation and redirection

The cache of the twelve priority targets is consulted before capacity doors, quotas and supplier breaks. The destinations discovered remain priority. Additional targets are counted as omitted. A lack of information, an old VirusTotal report or an error is never worth the mischief.

[CRDF search_urls](https://threatcenter.crdf.fr/api/doc/) accepts a list of targets. NoiseFence brings together up to twelve domain roots per query, without email addresses, path, URL settings or body. Each response must correspond only once to a requested target. A poorly associated response invalidates the lot. Page detection does not condemn its entire domain. VirusTotal uses only existing domain reports or fingerprints; no new content submissions or file submissions.

The limit counts query reservations, after acquiring network capacity. A failure at the time of sending can keep a reservation without an answer: the meter remains cautious. Individual caches and UTC meters persist. Zero remains "unlimited", without removing the limits of parallelism and duration. The customer does not perform an implied resumption. A connection error or HTTP 502/503/504 without explicit pause allows at most one resumption, after 50 ms, with a new reservation and within the same overall delay. Errors 429/ authentication are not repeated. The `Retry-After` pause valid on 429/503 is persistent and limited to seven days; a longer time limit already recorded remains priority. See also [virusTotal errors](https://docs.virustotal.com/reference/errors).

The redirect channels use the shared capabilities available within a global timeframe. A slow string does not block other capabilities. The client keeps the DNS check of each jump, network pinning, TLS certificates, prohibited addresses and the 64 KiB playback limit. It does not run JavaScript. The bulky or dependent pages of a script remain incomplete. The end of an analysis cancels its HTTP tasks; no continuous exploration in the background.

<a id="exploiter-les-diagnostics"></a>
## Applying diagnostics

The Reliability page shows requests, HTTP responses, recovered or unretrieved incidents, pauses and indicators omitted. The reasons for redirection distinguish security constraints, transport, readability and remote responses. The current group is separated from the last 24 hours all versions combined. Older messages do not have all new meters; zero history does not prove zero query.

The context of missed spam and omissions is exclusively about spam annotated cases by the authorized account. Targeted corrections remain separate from quality annotations. Several incidents may concern the same message; they are diagnostic tracks, not causal demonstration. Synthetic regression games cover in particular quotas with malicious cache result, recoveries, poorly associated targets, slow links and corresponding changes. They do not measure the recall on the actual traffic.

<a id="mémoire-comportementale-consultative"></a>
## Consultative behavioural memory

An identity must come from a SMTP session, with a single From address and a DMARC aligned DKIM. The key includes the recipient domain. Observations include a print of the only recipient of an envelope, no more than eight fields of links cut within that perimeter and six types of native motifs, without keeping the text. A message with multiple recipients of an envelope does not keep this context; no hidden copy identity is exposed to another account.

The reference only uses the previous human labels of active administrators having access to the message. Contradictory corrections are excluded; an exact campaign contributes once. Samples must share the protocol and native policy, over 30 days, with at least five legitimate campaigns and three separate days. Partial data, an expired request, a policy change or a too small sample does not create a supposed novelty. SQLite playback is limited to 2,000 lines and 200 ms; the interruption disables comparison, without blocking delivery.

Novelty booleans feed only the quality candidate into observation, with explicit unavailable states and dedicated removal. They do not create a whitelist, do not change the active score and do not conclude that there is fraud. Public reports and quality exports remove private keys and samples. These metadata follow the retention of thirty days of messages; no additional body is retained. LLM lexical, semantic and budget weights are not modified by this version.

<a id="migration-et-preuve-de-qualité"></a>
## Migration and proof of quality

The quality protocol contains new features. A candidate prior to 0.6.0 is refused: remove his optional path before `check-config`, keep the private model apart and retrain a candidate on new compatible observations. Do not mix cohorts or rebuild deleted messages. Behavioural memory starts without reference; it must collect recent annotations. New diagnostic fields are optional for old message readers and do not add SQLite migration.

The selection of thresholds in `train_quality.py` meets the empirical budgets over the selection period only, with tied values included. The testing period and prospective evaluation keep the pre-recall campaigns away. The 95% targets and 0.1% false positives remain to be demonstrated with their intervals; a suite of software tests or a very small annotated lot does not establish them. No candidate is automatically activated. The observation mode and the Proton validation checks remain applied before any marking.
