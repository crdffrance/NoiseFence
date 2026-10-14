# Context, coverage and calibration

NoiseFence 0.31.6 records decision policy `decision-policy-12`. Recorded policy and detector versions distinguish new observations from historical results; this release does not change or activate the LLM.

## Readable content survives independent failures

LLM selection uses the stored local extraction status rather than the final completeness of every detector. A DNS, semantic or optional scanner failure no longer prevents analysing readable text. The original incomplete status remains: a successful LLM response does not repair a failed check. Configured selection intervals, the per-request text cap, concurrency and the budget still apply. Historical records without extraction status retain conservative behavior.

Encrypted PGP/MIME and opaque S/MIME bodies are explicitly recorded as limited content coverage. NoiseFence cannot inspect their plaintext and does not ask the LLM to invent a content verdict. Readable signed MIME is not classified as encrypted. Raw scores remain available as partial diagnostic indices, not calibrated probabilities. Lexical and semantic content contributions are skipped for opaque bodies, with `content_model_skipped` and `rules-partial-1` recorded. Content features are ineligible for training, while bounded transport/authentication checks continue. A low partial index is not evidence that unreadable content is safe.

## Contextual false-positive safeguard

The content parser recognizes bounded security reports, shipment notices,
completed payment receipts and passive service events without a sender allowlist.
French and English receipts require matching completed-payment evidence in the
body. Backup/integrity notifications require an operation and event in both the
subject and body. Software-update notices require explicit automatic installation.
An invoice title, a generic security alert or authentication alone is insufficient.

A high legacy index conflicting with that context first becomes an internal
abstention. The final policy accepts it as HAM (or PUB when a separate completed
mail-kind analysis establishes that type) only when gateway-observed DMARC
alignment passes, both malware/signature scans are clean and no corroborated
threat or recorded identity/reputation conflict overrides the guard. The original
numeric index stays visible as an uncalibrated diagnostic. The final decision is
not “needs review”, and acceptance does not establish safety or recipient consent.

An isolated SMTP/DNS consistency failure does not erase those observations.
Coverage stays incomplete and subject rewriting still requires its own checks.
Other core gaps, encrypted bodies, unavailable scanners and hostile LLM opinions
do not qualify. Explicit credential requests, threatened restrictions combined
with nearby mandatory activation, and urgent payment/card callback demands prevent the
guard even inside an apparent receipt or service notice. Malware and validated
fusion decisions retain their own precedence. Message-supplied authentication
headers never supply trusted alignment. URL host/path tokens, including defanged
indicators, are excluded from the new service-demand prose checks. Demands are
evaluated within individual MIME alternatives so the end of a plain-text part
and the beginning of its HTML rendering cannot create a synthetic association.

The LLM receives actual MIME plain-text and cleaned HTML excerpts. Stylesheets, scripts, head/template blocks and duplicate HTML-to-text parts are excluded. `link_context` pairs a bounded anchor label with its destination scheme/host, omitting paths, query strings and user information. This context consumes part of the same text-byte cap, rather than increasing it. Anchor labels remain untrusted email content. The LLM receives lexical domain relationships derived from this bounded payload. A host under the sender's registrable domain is distinguished from a lookalike under another domain. These facts do not establish ownership, authentication or legitimacy. No link is opened by this analysis.

Mailing categorization also separates planned service maintenance from commercial newsletters. List and unsubscribe headers combined with an offer can establish newsletter purpose even without the word “newsletter”. This purpose classification adds no spam weight and cannot override a security decision.

## Semantic deadline

An administrator can edit **Filters → Engine parameters → Semantic analysis → Maximum time (ms)**. The allowed range is 50–5,000 ms. Model paths and CPU concurrency remain installed host settings. The deadline includes waiting for a slot and inference; a timed-out task retains its slot until its CPU work actually finishes. Deadline edits reuse the loaded weights and existing limiter.

Choose a deadline based on measurements on the slowest MX. Identical software does not imply identical execution speed on different CPU allocations. A longer bounded deadline addresses unavailable inference, not a miscalibrated model. Recorded semantic failures distinguish capacity, deadline, inference and worker errors; older rows may lack this detail.

## Validate before enforcing

Do not lower a threshold just to clear a review queue or treat comparator agreement as a reference label. High raw scores on confirmed legitimate traffic call for calibration on recent labelled examples. Keep security reports, transactional notices, wanted newsletters, phishing and spam represented; deduplicate campaigns and reserve an independent evaluation set. Corrections used to develop a safeguard are development examples, not an unbiased test set.

Rspamd remains an independent observation. New prompts need evaluation on fresh results; replaying an old LLM verdict does not validate a new prompt. Historical messages and their headers are not silently rescored. User corrections do not create retrospective changes in Proton.

## Coherent, grounded second opinions

The LLM receives the gateway's current UTC analysis date and bounded SPF/DKIM/DMARC results in the system message. Only observations from an actual SMTP session qualify; content-only scans and supplied envelopes cannot invent trusted authentication. Missing or incomplete observations are null. Message-supplied Authentication-Results and Date headers cannot overwrite these facts. Domain ownership and recipient consent are never inferred. Message text remains untrusted, and report/receipt context hints are derived only from the existing bounded text payload.

Every new response records `llm.coherent`. A phishing/spam category with a probability at or below 0.5, or a legitimate category with a probability at or above 0.5, is inconsistent. The response is retained for diagnosis and accounting but has zero score weight and no definite second opinion. The console, headers and diagnostic counters distinguish this from a usable completed opinion. No retry or extra provider request is triggered. The configured text limit, concurrency, timeout and monthly budget remain enforced. These probabilities and confidence values are model assertions, not calibrated measurements.

Context safeguards now cover abuse/brand reports asking to retain a URL in a feed and completed payment receipts. They still require observed aligned authentication and only abstain; they cannot declare a sender legitimate. Explicit demands for credentials, cryptocurrency or software installation prevent use of that contextual safeguard. This is not a comprehensive intent detector or a vendor allowlist. Primary antivirus and validated fusion decisions retain priority.

## Positive evidence with partial coverage

A narrow policy preserves an unwanted risk verdict when the sole recorded incomplete control is SMTP/DNS consistency, content extraction and the primary antivirus completed, a local advisory phishing signature is present, and a coherent high-confidence phishing second opinion agrees with observed unauthenticated sender evidence (SPF fail/softfail, no successful DKIM, DMARC alignment or ARC). Reporting, receipt and encrypted contexts are excluded. The signature, failed authentication and LLM are not sufficient individually. This policy does not use the raw index as a probability.

A second narrow path recognizes explicit first-person compromise, a disclosure threat, a cryptocurrency demand and a wallet together. It still requires observed failed authentication and either an advisory phishing signature or a strong coherent phishing opinion. Only DNS/LLM incompleteness may be tolerated; a legitimate second opinion, quoted incident, report or receipt prevents this path. No phrase or wallet address alone classifies mail.

The message remains incomplete, with a partial numeric diagnostic and the reason `observed_threat_partial`. Subject rewriting and automatic quarantine remain disabled on that incomplete result. Observation mode continues to deliver. Rspamd never participates in this decision.

## What this release does not claim

No new model was trained or activated from the development examples. Context guards reduce erroneous unwanted decisions to review; they do not recalibrate the high raw indices or establish capture/false-positive rates. Confirmed legitimate receipts and wanted feeds are regression examples, not an independent evaluation set. Use recent human labels, campaign/time separation and an untouched holdout before activating a recalibrated model.

## Provider availability

Local minute/day quota exhaustion is distinct from a provider cooldown. The latter is recorded as `unavailable` with `failure_counts.provider_backoff`, even when the configured subscription has no local quota. A cooldown can follow a provider refusal or invalid response; it is neither a clean result nor a malicious hit. Cached target-bound results remain usable. Increasing a quota does not remove the cooldown or authorize extra paid requests.
