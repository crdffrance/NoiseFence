# Changelog

## 0.18.0 — Consistent assessments and English release

- Share a versioned Rust assessment across the message API, search, console and new SMTP diagnostics. Distinguish the 0–100 risk index, engine decision, recipient classification, analysis coverage, requested/effective delivery action and actual subject tag. Invalid values never become fabricated zeroes.
- Preserve recorded thresholds for historical fallback decisions in message search and dashboard counts. Expose historical provenance instead of presenting current configuration as past evidence. No retained message is rescanned or rewritten.
- Publish diagnostic header schema 3. `X-NoiseFence-Status` now means `complete` or `incomplete`; consumers must use `Category` and `Subject-Tag` for classification and modification. Add assessment, threshold, policy, delivery action and recorded-decision provenance. Keep bounded ASCII output and the ARC signing inventory aligned.
- Finish the English console and documentation. Improve filter navigation, settings search, score explanations and the distinction between draft and applied policy. Keep all messaging/filter settings in the Web console; ports, TLS, storage, model artifacts and replication installation remain host operations.
- Use English explanations in LLM prompt `noisefence-classify-3`. Its fingerprint starts a distinct observation group; previous model validation must not be reused across changed protocols. Existing explanations and user-created labels remain recorded data.
- Preserve saved adaptive pattern labels across translated-default upgrades when all semantic fields and their order match. Installed models still require an exact protocol match; configuration history and model artifacts are not rewritten.
- Add a non-root Docker image, isolated local Compose evaluation and Linux production template with host networking, durable storage, private configuration and dependency notices. Test container bootstrap, authorization, SMTP acceptance, open-relay refusal and restart persistence on amd64/arm64 in CI.
- Update native installation, security, configuration, header and two-copy recovery guides. Verify local documentation links and preserve referenced historical anchors.

**Compatibility:** storage capability remains schema 5. Upgrade the coordinator before workers; 0.17.3 remains in the audited policy window. Existing observation, provider budgets, Proton tagging gates and mandatory peer acknowledgements remain unchanged. No new detector, model training or automatic activation is included. Passing tests do not establish perfect filtering or the target capture/false-positive rates.

Earlier entries summarize the behavior introduced by each release. Use the current installation and recovery guides for supported upgrades.

## 0.17.3 — Two copies and a recovery console

Added authenticated two-copy message replication before SMTP acceptance, per-recipient progress, and conservative recovery of uncertain deliveries. Added consistent console checkpoints with models, MFA and budgets, transferred over restricted SSH. Standby promotion requires verified fencing; schema 5 prevents a return to unreplicated operation. Replaced the unpublished 0.17.0–0.17.2 candidates.

## 0.16.2 — Intelligent SMTP admission

Added selective greylisting, durable retry state shared across MX servers, IP rate limits and bounded asynchronous response delays. Web settings control exemptions, limits and enforcement. The feature is disabled by default and does not change content scores.

## 0.15.3 — 2026-09-13

Added anti-backscatter suppression after a remote antispam refusal when hostile content and unauthenticated sender evidence agree. Personal legitimate decisions and human corrections retain normal failure notifications. Added scoped diagnostics, terminal status replication and protection against overwriting retained DSN bodies.

<a id="0152--candidate-non-publiée"></a>

## 0.15.2 — Unpublished candidate

Unpublished candidate superseded by 0.15.3.

## 0.15.1 — 2026-09-13

Added an explicit rolling-upgrade compatibility window from 0.14.0, preserving policy fingerprints, node identities, budgets and cache expiry. Included the Linux hardening and MFA work from 0.15.0, which was replaced before production deployment.

## 0.15.0 — 2026-09-13

Added Debian hardening with key-only SSH, IPv4/IPv6 firewall rules, AppArmor, systemd resource limits and staged rollback. Added encrypted restic backups, isolated restore checks, TOTP MFA, encrypted secrets and single-use recovery codes. Schema 4 prevents unsafe downgrade after MFA activation. Host hardening tools are installed separately and do not automatically change mail policy or DNS.

## 0.14.0 — 2026-09-13

Added autonomous SMTP workers with a coordinator, versioned policies, verified model distribution, shared provider budgets and a central scoped history. Revocable node credentials protect remote commands. Workers use a bounded cached policy during coordinator outages. This original release did not replicate accepted message bodies.

## 0.13.0 — 2026-09-12

Moved messaging configuration into the Web console: RBLs, engine parameters, LLM budgets, OCR, redirects, credentials and configuration import/export. Added personal sensitivity, actions and rules within administrator-defined limits. Preserved shared runtime capacity and persistent usage accounting across revisions.

## 0.12.0 — 2026-09-12

Added indexed message search by subject, sender, recipient, rule, identifier, date, score and delivery state. Search supports combined terms, accents, prefixes and exact phrases, with scoped pagination and synchronized retention cleanup. No additional bodies are retained.

## 0.11.1 — 2026-09-12

Published header schema 2 with an available content or decision score, explicit partial/advisory status and bounded diagnostics aligned with the console. Added detailed checks, reasons, models, rule weights and RBL results while excluding private content. Already prepared messages were preserved; 0.11.0 was not deployed.

## 0.11.0 — 2026-09-12

Prepared diagnostic header schema 2, with separate content and decision scores and bounded ASCII fields covered by ARC where available. Superseded before deployment by 0.11.1.

## 0.10.4 — 2026-09-12

Published visible recorded scores for review and incomplete analyses, including compact views. Missing or invalid values remain unavailable. Stabilized two CRDF integration-test deadlines without weakening timeout, cache, quota or concurrency assertions. Includes the unpublished 0.10.2–0.10.3 corrections.

## 0.10.3 — 2026-09-12

Clarified advisory-score explanations while preserving recipient-rule classifications. This candidate was not deployed; the change shipped in 0.10.4.

## 0.10.2 — 2026-09-12

Kept recorded numeric scores visible for review and incomplete analyses, with distinct fusion, content and internal-value presentations. Did not rescan history or alter delivery policy. Shipped through 0.10.4.

## 0.10.1 — 2026-09-12

Improved navigation contrast, compact sensitivity controls, search layout and loading states. Preserved the marketing-signal filter, domain scope and existing authorization and delivery behavior.

## 0.10.0 — 2026-09-12

Added five sensitivity levels with organization, domain and recipient inheritance. Preserved model calibration, corroboration, conflict handling and Proton tagging gates. Simulation uses the same policy safeguards and does not activate changes.

## 0.9.0 — 2026-09-12

Added twelve native Rust HTML/MIME/content rules inspired by Rspamd techniques, with bounded parsing, configurable weights, family caps and deterministic composites. Added the local `native-rules` inspector and adversarial/counterexample tests. Signals remain advisory; no detector is activated as a delivery vote.

## 0.8.0 — 2026-09-12

Added per-domain five-class OSB Bayes and a regularized 16×16×5 neural network, with human annotations, private feature export, chronological campaign separation and independent evaluation. Models expire after 30 days and abstain on incompatibility or disagreement. Proposed actions remain observations.

## 0.7.0 — 2026-09-12

Added bounded IP DNSBL lookups before DATA, grouping results by independent operator and distinguishing error/policy codes from malicious reputation. Observation is the default; explicit enforcement can defer or refuse SMTP attempts only under configured consensus. Added local DNS/SMTP tests and diagnostics.

## 0.6.0 — 2026-09-12

Improved CRDF batching, cache-first lookup, quota reservation, retry accounting and concurrent redirect resolution. Added bounded authenticated-sender behavioral context from authorized human feedback and quality-coverage diagnostics. Candidate evaluation gained twelve ablations and explicit false-positive/false-negative budgets; no candidate was automatically activated.

## 0.5.0 — 2026-09-12

Added scoped reliability reports, collection fingerprints, rule ablations and native/campaign/Bayes inputs to candidate evaluation. Refined contextual normalization and phishing-request handling in English and French. Added ClamAV freshness and Proton compatibility checks; production accuracy still requires independent labels.

## 0.4.15 — 2026-09-12

Added a native advisory engine with compiled patterns, deterministic composites, family caps, text/HTML campaign similarity and OSB Bayes. Learning uses recent authorized feedback, excludes conflicts and separates campaigns across time. No automatic delivery action or external analysis was added.

## 0.4.13 — 2026-09-11

Separated risk prediction from six mail-kind predictions, preserving Python/Rust parity and historical candidate support. Added prospective evaluation, confidence intervals, nine ablations and score-decomposition diagnostics. Active weights, budgets and actions remained unchanged.

## 0.4.11 — 2026-09-11

Made conflicting second opinions produce a review decision while retaining the raw score and features. Preserved malware priority, fusion policy and recipient overrides. Added read-only comparisons of recent decisions without rewriting history.

## 0.4.10 — 2026-09-11

Added an optional bounded second opinion for uncorroborated high scores and normalized old filtering prefixes in model input. Added private corrective learning anchored to the existing lexical model, with a replay corpus, campaign-separated evaluation and no automatic activation.

## 0.4.9 — 2026-09-11

Added organization/domain/recipient profiles, bounded custom rules, simulation and independent delivery variants. Added expiring one-use invitations with activation-time authorization checks. Preserved observation, malware priority and Proton validation.

## 0.4.8 — 2026-09-11

Prevented the LLM from corroborating its own score contribution. Added contextual phishing evidence, exact reputation scopes, authorized correspondent history and uniform human-label samples. Candidate training remains private, versioned and separate from production decisions.

<a id="filtrage-et-validation"></a>
<a id="filtering-and-validation"></a>

## 0.4.7 - 2026-09-11

Restored URL following under systemd while retaining SSRF restrictions. Bounded reputation work and exposed omitted checks. Continued independent advisory checks after limited OCR without declaring analysis complete or losing a malware detection.

## 0.4.6 - 2026-09-11

Introduced the orange console identity, responsive navigation and clearer message/action status. Added compact views, password visibility and the Ctrl/Cmd+K search shortcut without changing API permissions or delivery policy.

## 0.4.5 - 2026-09-10

Added Web-configurable CRDF/VirusTotal quotas, explicit unlimited mode, persistent counters and provider cooldowns. Corrected domain lookup requests while keeping deadlines, concurrency and per-message limits.

## 0.4.4 - 2026-09-10

Added optional bounded HTTP/HTML redirect following for text and OCR/QR URLs, with pinned DNS, certificate verification and SSRF protections. Recorded redacted traversal diagnostics and checked discovered destinations. JavaScript and form submission remain disabled.

## 0.4.3 - 2026-09-10

Accepted terminal dots in explicit SMTP route hostnames while retaining absolute DNS lookup, certificate validation and loop checks. Covered routes with ports and locally generated delivery notifications.

## 0.4.2 - 2026-09-10

Redacted recipient addresses, aliases, hidden recipients and encoded variants from remote SMTP replies before truncation. Preserved useful protocol codes and phases while enforcing recipient access on current and historical diagnostics.

## 0.4.1 - 2026-09-09

Added per-recipient remote SMTP transcripts with TLS, response codes, timing and retry details. Added recorded analysis contributions and policy details. A disconnect after a final SMTP 250 does not trigger a second delivery.

## 0.4.0 - 2026-09-09

Published the first finalized 0.4 release, including category actions, quarantine, customizable contributions and a responsive console. Linux amd64/arm64 archives contain the static console, systemd units, configuration examples and dependency notices. Storage schema 2 protected quarantined bodies. Observation and Proton tagging validation remained the defaults; performance and detection targets were not certified.

<a id="fonctionnalités"></a>
<a id="mise-à-niveau-et-limites"></a>
<a id="040-dev4--réglages-adaptés-aux-petits-écrans"></a>
<a id="features"></a>
<a id="distribution-and-installation"></a>
<a id="upgrading-and-limitations"></a>

## 0.4.0-dev.4 — Adjustments suitable for small screens

Fixed intrinsic form widths and long select options on small screens; checked 320-pixel layouts and keyboard navigation. Superseded dev.3 before production installation.

## 0.4.0-dev.3 — Administrator and user console

Reorganized mail, administration and personal navigation, with responsive message views, filter sections, quarantine confirmation and account controls. Preserved detector and API behavior.

## 0.4.0-dev.2 - 2026-09-09

Normalized historical settings for review so displayed actions and weights match effective defaults. Added compatibility tests for old revisions; dev.1 was not installed.

## 0.4.0-dev.1 - 2026-09-09

Separated delivery, tagging and quarantine actions from classification. Added per-recipient quarantine, eight configurable heuristic contributions and storage schema 2 with rollback guards. Observation, malware priority and Proton validation remained enforced.

## 0.3.0-dev.22 - 2026-09-09

Published the consistency fixes from dev.21 with explicit risk-index terminology and bounded retries for the pinned build image. The dev.21 tag was retained after a Docker registry HTTP 502 interrupted its release; no dev.21 binary was deployed.

## 0.3.0-dev.21 - 2026-09-09

Unified classification across headers, console and counters, preserving primary malware priority without inventing a probability of 100. Aligned LLM and ZEN code interpretation and kept policy-list results separate from malicious reputation.

## 0.3.0-dev.20 - 2026-09-09

Added explicit corroboration for high content scores, retaining an undetermined decision when evidence is insufficient. Refined LLM guidance against false positives from short messages, free providers, forwarding and service notifications.

## 0.3.0-dev.19 - 2026-09-09

Pinned the transitive `sharp` dependency to 0.35.4 for GHSA-rgj7-g3m4-5g8c. Published the marketing changes after the dev.18 frontend audit interrupted that candidate.

## 0.3.0-dev.18 - 2026-09-09

Added a separate marketing/newsletter category and `[PUB]` prefix, excluding recognizable transactional and conversational mail. Preserved spam priority, binary-training label boundaries and separate Proton validation for `[PUB]`.

## 0.3.0-dev.17 - 2026-09-08

Bounded and cancelled test HTTP servers correctly so early timeouts do not leave Linux checks hanging. Separated timeout, quota and response-size test budgets; filtering behavior remained the same as dev.16.

## 0.3.0-dev.16 - 2026-09-08

Added advisory impersonation, deceptive-link, phishing-feed and repeated-campaign checks. Added bounded CRDF/VirusTotal report lookup, private credentials and explicit error states without submitting full messages or attachments. Existing scoring and delivery policies remained unchanged.

## 0.3.0-dev.15 - 2026-09-08

Kept validated lexical/semantic artifacts resident across policy changes; replacing files requires an explicit restart and validation. Retained disabled domains in authorized history searches.

## 0.3.0-dev.14 - 2026-09-08

Added Web management of domains, aliases, catch-all recipients, explicit gateways, detector settings and scoped accounts. Applied versioned policy to new SMTP transactions while preserving queued routes, loaded models and shared capacity. Added local console recovery.

## 0.3.0-dev.13 - 2026-09-08

Improved relay wakeups, buffered durable DATA writes and bounded processing concurrency. Added semantic warmup and an isolated SMTP load tool that verifies delivery, bodies, analysis coverage, latency and memory.

## 0.3.0-dev.12 - 2026-09-08

Added isolated local Tesseract/ZBar/Poppler processing for English/French text, QR codes, barcodes and scanned PDFs. Bounded all resource dimensions, integrated decoded domains with existing checks and added `vision-inspect`. No raw OCR text is retained in normal diagnostics.

## 0.3.0-dev.11 - 2026-09-07

Added frozen population evaluation with exact dataset/model provenance, campaign exclusions, missing-state accounting and conservative confidence bounds. Synthetic evaluation tests did not authorize a production model.

## 0.3.0-dev.10 - 2026-09-07

Unified persisted unwanted/legitimate/undetermined decisions and added optional validated fusion. Exported population observations without bodies, preserving unavailable and incompatible states. LLM saturation retains an undetermined decision.

## 0.3.0-dev.9 - 2026-09-07

Added the 218-field fusion contract, native export/prediction, calibrated logistic candidates and five ablations. Checked Python/Rust parity and exact source provenance. Increased the FreshClam memory ceiling to 2 GiB after signature validation exceeded 768 MiB.

## 0.3.0-dev.8 - 2026-09-07

Retained typed authentication, reputation, model and provider observations with individual completion states and model fingerprints. Distinguished received SMTP evidence from manual diagnostics and kept DQS errors unavailable. No candidate was activated.

## 0.3.0-dev.7 - 2026-09-07

Added bounded HELO/IP/PTR and envelope-domain consistency checks, with IPv6, null envelopes, Null MX and A/AAAA fallback. Added `smtp-check` and extended DQS roles without duplicating contributions. Weights remain advisory unless explicitly enabled.

## 0.3.0-dev.6 - 2026-09-07

Added explicit domain catch-all acceptance with alias priority and recipient-scoped access. Added full-processing measurements with separate warmup, failures and connector coverage; paid calls require explicit configuration.

## 0.3.0-dev.5 - 2026-09-07

Added explicit aliases across configured domains, preserving destination routing and authorization. Rejected chains, loops, collisions and undeclared destinations; retained local-part case and case-insensitive domains.

## 0.3.0-dev.4 - 2026-09-07

Separated local feature-extraction completeness from external-check failures for feedback eligibility. Moved learning snapshots to private systemd temporary storage, tested cleanup after failure, and preserved the previous candidate when training cannot proceed.

## 0.3.0-dev.3 - 2026-09-07

Added private schema-3 feedback exports with campaign and encoder provenance. Trained lexical/hybrid candidates using separate training, development, calibration and test populations. Corrections alone do not establish eligibility; activation remains manual.

## 0.3.0-dev.2 - 2026-09-07

Validated optimized Linux ARM64 semantic builds after a dependency debug-profile failure prevented dev.1 archives. Did not change weights, scores or filtering policy.

## 0.3.0-dev.1 - 2026-09-07

Added reproducible Apache/Enron/Nazario experiments, feature schema 3, logistic and Bayes candidates, and an optional pinned multilingual encoder with native Candle inference. Separated campaigns and evaluation periods, checked Python/Rust parity, and corrected MIME-decoded link extraction. Research candidates were not automatically activated.

## 0.2.0-dev.2 - 2026-09-06

Accepted an empty Scaleway `tool_calls` list while continuing to reject actual tool calls. Added Nginx/Certbot deployment, upstream ClamAV services, operational checks and executable release permissions. Proton placement validation remained incomplete.

## 0.2.0-dev.1 - 2026-09-06

Added optional ClamAV/signature and Scaleway connectors with bounded resources, typed verdicts, private credentials and durable budget reservation. Added candidate comparisons, EICAR checks and verified atomic certificate installation. No new connector was enabled by default.

## 0.1.0 - 2026-09-06

Initial GPL-3.0-only release: Rust SMTP/STARTTLS, SIZE, 8BITMIME, PIPELINING, durable disk/SQLite queue, per-recipient retries, authentication, local scoring and optional DQS. Included local-account console and Linux deployment files. Initial candidate recall was 60.94%; the 95% capture and 0.1% false-positive targets were not demonstrated. Observation was the default and SMTPUTF8 was disabled.

