# Changelog

## 0.18.0 — Consistent assessments and English release

- Share a versioned Rust assessment across the message API, search, console and new SMTP diagnostics. Distinguish the 0–100 risk index, engine decision, recipient classification, analysis coverage, requested/effective delivery action and actual subject tag. Invalid values never become fabricated zeroes.
- Preserve recorded thresholds for historical fallback decisions in message search and dashboard counts. Expose historical provenance instead of presenting current configuration as past evidence. No retained message is rescanned or rewritten.
- Publish diagnostic header schema 3. `X-NoiseFence-Status` now means `complete` or `incomplete`; consumers must use `Category` and `Subject-Tag` for classification and modification. Add assessment, threshold, policy, delivery action and recorded-decision provenance. Keep bounded ASCII output and the ARC signing inventory aligned.
- Finish the English console and documentation. Improve filter navigation, settings search, score explanations and the distinction between draft and applied policy. Keep all messaging/filter settings in the Web console; ports, TLS, storage, model artifacts and replication installation remain host operations.
- Use English explanations in LLM prompt `noisefence-classify-3`. Its fingerprint starts a distinct observation group; previous model validation must not be reused across changed protocols. Existing explanations and user-created labels remain recorded data.
- Add a non-root Docker image, isolated local Compose evaluation and Linux production template with host networking, durable storage, private configuration and dependency notices. Test container bootstrap, authorization, SMTP acceptance, open-relay refusal and restart persistence on amd64/arm64 in CI.
- Update native installation, security, configuration, header and two-copy recovery guides. Verify local documentation links and preserve referenced historical anchors.

**Compatibility:** storage capability remains schema 5. Upgrade the coordinator before workers; 0.17.3 remains in the audited policy window. Existing observation, provider budgets, Proton tagging gates and mandatory peer acknowledgements remain unchanged. No new detector, model training or automatic activation is included. Passing tests do not establish perfect filtering or the target capture/false-positive rates.

## 0.17.3 — Two copies and a recovery console

Candidates 0.17.0 to 0.17.2 are replaced before deployment after retention, recovery and HTTP flow checks.

- Rust replication by authenticated HTTPS pair, durable body and envelopes before SMTP 250; 451 response if the pair, capacity or storage is missing.
- The receiver consumes and checks the entire stream before confirmation, including for an existing copy; it is not rewritten.
- Progression by recipient, intention to send replicated before contact of relay, cleaning after confirmation and conservative resumption of uncertain shipments.
- SQLite Instants consistent, models, MFA and budgets transferred by SSH restricted; backup console activated after explicit fencing, without overwriting the worker's line.
- Claim switch with revocation of old accesses and suspension of new supplier allowances; no quorum or automatic SMTP take-over at one copy.
- Final synchronization after shutdown with `ha-flush`; the original remains on hold if a referenced notification is missing during resumption.
- Controlled re-integration with `ha-resync`, restored MFA decryption control, final snapshot strictly after the fencing and erasure of resolved incidents.
- Replication state and backup console in Infrastructure. Diagram 5 as soon as enabled; recovery guide in `docs/high-availability.md`.

## 0.16.2 — Admission SMTP intelligente

- Selective Greylisting before DATA, with durable condition common to MX and permissible withdrawal in case of coordinator failure.
- Quotas of IP attempts, controlled gusts and slow down Tokio bounded by connection and server.
- Web settings, IP/CIDR exceptions, decision meters and diagnostics without effect on score.
- Progressive deployment compatible with workers 0.15.3; default policy disabled.


## 0.15.3 — 2026-09-13

- Anti-backscatter protection after remote antispam refusal, with consistent evidence of hostile content and unauthenticated sender; score alone and control errors are not enough.
- Terminal status "Blocked notification" (anti-backscatter), search, diagnoses and replication of this state; transactional audit trace, resume without recreating notification.
- Legitimate opinions retain the extended code and diagnosis SMTP remote, bounded and protected against injections.
- Non-spam rankings of personal rules and user corrections keep normal notifications.
- Recording of DSNs without crushing their body during a recovery. The observation mode and delivery rules remain unchanged.
- Coordinator update before workers; policies compatible with 0.15.1, new delivery status supported from 0.15.3.

<a id="0152--candidate-non-publiée"></a>
## 0.15.2 — Unpublished candidate

- Replaced by 0.15.3 before deployment, to also preserve notifications of messages reclassified by their recipients. The tag remains immutable.

## 0.15.1 — 2026-09-13

- The cluster has been updated sequentially since 0.14.0: the coordinator serves the unchanged protocol to old workers and new workers can resume their policy in cache.
- Compatibility limited to explicitly verified versions; fingerprints, identities, budgets and expiry of policies remain monitored. Update the coordinator before the workers.
- Includes the hardening and MFA of candidate 0.15.0, replaced before it was put into production.

## 0.15.0 — 2026-09-13

- Debian hardening of MXs with SSH by key, IPv4/IPv6 firewall, AppArmor profiles and systemd resource budgets; transactions with temporary backlash and sequential deployment.
- Targeted audit, message content-free security reports, central collection and restic encrypted backups with network-free restoration check.
- Separate backup modes: metadata/configuration/models or full file, which requires explicitly authorized retention.
- Double TOTP authentication in "My account", encrypted secrets, single-use backup codes, server-side control and cancellation of old sessions.
- Protection against returns to a binary ignoring the MFA: schema 4 from the first activation; local procedure of recovered audited.
- Ansible role, deployment tools limited to administrator-approved releases and operating guide in `deploy/hardening/README.md`. Linux tools install separately from binary.
- No automatic change in the filtering, DNS or enrolment of existing accounts.

## 0.14.0 — 2026-09-13

- Autonomous SMTP gateways with central console, versioned configuration and HTTPS-verified models.
- Multi-MX history and node search; bodies and files remain on their original server.
- Removable node identities, remote quarantine commands and re-launch with lasting confirmation.
- LLM credits and CRDF/VirusTotal allowances shared, persistent and protected against double allocation.
- Policy cached during a coordinator's breakdown, then refusal temporary SMTP after expiration; observed retained.
- Migration to schema 3 at cluster activation; no file replication or automatic switch of console. Installation and reverse: `docs/multi-mx.md`.

## 0.13.0 — 2026-09-12

- Web configuration of RBL lists, DNS tests of drafts and detailed parameters of engines, LLM, budgets, OCR and redirections.
- Private key management Spamhaus DQS and Scaleway, export/import validated and history of change without secrets.
- "My filters" space: levels, actions, rules and inheritance by box or domain, within the limits granted by the administrator.
- Application to new SMTP transactions, limits of competition shared between revisions and maintenance of persistent budgets.
- Checking accesses at the time of registration, protecting DNS key references, priority of global rules and isolation of boxes whose breakage differs.
- Automatic migration of old revisions without policy change; backend of documented settings in `docs/web-configuration.md`.

## 0.12.0 — 2026-09-12

- Local search indexed objects, senders and rules; combined words, accents, prefixes and exact expressions, authorized identifiers and recipients.
- Advanced search by address, object, rule, ID, period, score and delivery, with exact total and pagination in the console.
- Transactional indexation of history and synchronized purging; no additional body preservation or modification of filter decisions.
- Checks for user isolation, hidden copies, revoked rights, migrations, invalid queries and partial scores.


The versions follow Semantic Versioning. The project remains in 0.x: an incompatible change requires a minor version and a documented migration.

## 0.11.1 — 2026-09-12

- Schematic 2 SMTP headers: available score, partial/indicative qualification, source/model and separate decision score aligned to the console.
- Check-bound diagnostics, causes of incompleteness, arbitration, rules and weights, antivirus, OCR/QR, LLM, CRDF/VirusTotal, RBL and native Consultative engine.
- The RBL results are transmitted from the session to the rendering, including incomplete analysis, without changing the score or the classification steps.
- ASCII fields folded and covered by ARC where possible; deletion of received results and exclusion of private content.
- Documented `X-NoiseFence-Score` migration. Already prepared rankings, templates, settings and messages are kept. Version 0.11.0 has not been deployed.

## 0.11.0 — 2026-09-12

- Figure 2 SMTP headers: available score aligned to console, partial/indicative qualification, source/model and separate decision score.
- Check-bound diagnostics, causes of incompleteness, arbitration, rules and weights, antivirus, OCR/QR, LLM, CRDF/VirusTotal, RBL and native Consultative engine.
- ASCII fields folded and fully covered by ARC where possible; deletion of results received and exclusion of private content.
- Documented migration of `X-NoiseFence-Score`, without changing the rankings, models, settings or messages already delivered/in file.

## 0.10.4 — 2026-09-12

- The log, its moving view and detail display the already recorded scores of the messages "To be verified" and "Incomplete analysis", with the words "Indicative score" or "Partial score" and the known missing controls.
- The display distinguishes the score, the engine uncertainty and the recipient's rules. The absent or invalid values never become zero.
- No historical recalculation or change in the decisions, delivery actions, models, deadlines or parameters of suppliers in production.
- Two CRDF functional tests have a bounded fixture time suitable for SQLite writings on CI machines. Claims on quotas, cache, competition and specific time-out tests are kept.
- This version includes the corrections prepared in 0.10.2 and 0.10.3, which have not been deployed in production.

## 0.10.3 — 2026-09-12

- The explanation of an indicative score describes the uncertainty of the engine while respecting the classification applied by a custom rule of the recipient.
- This version finalises the correction of the scores of 0.10.2, which was not deployed in production.

## 0.10.2 — 2026-09-12

- "To be verified" messages retain a visible score, even when the reviews are contradictory or uncertain. The ranking remains distinct from the score.
- Incomplete analyses show the score already calculated with the mention "Partial score" and the known missing controls. Limited extraction is explicitly reported; no unavailability becomes a zero score.
- The mobile journal also displays scores. The list and detail use the same presentation, which distinguishes fusion, content index and internal value.
- No recalculation of historical messages, change of delivery policy or additional call to suppliers: this correction reveals the results already kept by the engine and the API.

## 0.10.1 — 2026-09-12

- Console: contrasting navigation, more readable texts and status, adjustment maps with descriptions, more compact sensitivity levels on mobile.
- Journal: compact view, search all width, visible active criteria and perimeter reset, more explicit loading states.
- The "PUB Indices" filter remains correctly selected from the advanced menu. An empty search in a domain allows you to return to all the accesses allowed.
- The decisions, authorizations, delivery actions and supplier configurations remain unchanged.

## 0.10.0 — 2026-09-12

- Five levels of sensitivity in administration, with general choice, domain exceptions and existing recipient profiles.
- Decision threshold distinct from the calibration of the multilingual model; legacy address → domain → organization, copy of shared profiles before a targeted modification and retention of delivery actions.
- Mandatory confirmation for explicit thresholds, arbitration of conflicting notices retained and validated merge protected on server side.
- The simulation also applies the general confirmation. No automatic change of active settings, models, LLM calls or observation.
- See `docs/custom-filtering.md` for limits and return to 0.9.

## [Unreleased]

## [0.9.0] — 2026-09-12

- Twelve local HTML, MIME and ID rules displayed based on Rspamd sources, translated into Rust: password forms, external or HTTP destinations, hidden text, misleading HTTPS links, active data URLs, HTML redirects, executable/double extensions, disguised binary and obfuscated file names.
- Two composites combine evidence related to forms and attachments. Deactivation and rule weighting, family ceilings, MIME/HTML/DOM limits and diagnosis without private content.
- Order `native-rules` to view the bank or examine a local file without a network or delivery. Adverse cases and legitimate counter-examples, addition of inspection to MIME buzzing harness.
- The module remains in observation: no new signal changes the delivery score or LLM calls. In this historical release, models, SQLite schema 2 and Bayes/adaptive features remained compatible; the detector fingerprint identifies the new collection. See the [guide](docs/rspamd-rules.md) for provenance, configuration and limits.

## [0.8.0] — 2026-09-12

- Rust native learning in five categories: legitimate, advertising, spam, phishing and scam. Multiclass OSB Bayes and regulated 16×16×5 local neural network, distinct from the binary delivery engine.
- Models and policies specific to each domain, threshold and margin by class, forbearance in the event of disagreement, expired model or shared envelope between domains. Simulated actions only: no new score, marking or automatic quarantine.
- Detailed annotations in the console, access controls and server-side CSRF protection. Subsequent general corrections invalidate detailed annotations that have become obsolete.
- Private export of characteristics, offline Rust training, separate time periods, deduplication of accurate and similar campaigns, exclusion of conflicts and late annotations. Selection on validation only, independent test, confusion matrix and confidence intervals.
- Commands `adaptive-export`, `adaptive-train`, `adaptive-evaluate` and `adaptive-check`, with local measurement of latency. Limited models, 30 day expiry, no external analysis added and no actual performance assumed.
- This release retained SQLite schema 2 with an additive annotation table. It introduced a new detector fingerprint; see the [guide](docs/adaptive-filtering.md) for configuration and rollback. Existing lexical and semantic models remained independent.

## [0.7.0] — 2026-09-12

- DNSBL IP controls before DATA, storage and analysis: existing ZEN DQS Spamhaus connector and up to seven additional IP lists, with explicit codes and grouping by supplier.
- Default observation, consensus of two separate suppliers and refusal SMTP 451/550 configurable only in application mode. PBL/BCL, DNS errors, unknown codes and incomplete controls do not cause refusal.
- Competing requests, shared capacity, global budget and limited cache respecting TTL. IPv4/IPv6, normalization of mapped addresses, exclusion of private addresses and diagnostics without key or content.
- Command `rbl-check`, reports before receiving in the logs and cards of accepted messages; no extra weight in the score. Domain/URL controls after DATA remain separate.
- Local DNS/SMTP tests covering consensus, errors, cache, cancellation, refusal before storage and delivery in observation. Observation mode and active models retained. Renewed sensor imprint, SQLite remains in schema 2; see [configuration and migration](docs/early-rbl.md).

## [0.6.0] — 2026-09-12

- Grouped CRDF searches (maximum of 12 domains), results strictly associated with the targets and cache consulted before network limits. A target already in cache remains usable during a quota or unavailability.
- Quotas reserved after obtaining a query capability; only one recapture limited to certain temporary errors.Continuing consideration of `Retry-After`, counting requests, HTTP codes and incidents without keeping private responses.
- Redirections executed simultaneously within the overall time frame with a shared ceiling: a slow URL no longer systematically deprives others of control. DNS pinned, TLS, SSRF protections and read limits retained.
- Coverage diagnostics by current or historical version and context of uncaptured annotated spam, separating quality samples and targeted corrections. An association does not prove the cause of an error.
- Observation of changes in recipients, areas of links and types of requests on DKIM senders aligned, from recent legitimate human campaigns. Partitioned, minced and bounded data; insufficient shared and historical envelopes are abstinent.
- Accurate selection of empirical budget thresholds of false positives and false negatives, inclusive comparisons and tied values taken into account. Twelve ablations, including the behavioural context, with future independent test and always required intervals.
- New quality-candidate protocol: remove incompatible optional candidates before upgrading and retrain on compatible observations. This historical release kept lexical/semantic models and SQLite schema 2 unchanged; no candidate was activated automatically. See [details and migration](docs/capture-coverage.md).

## [0.5.0] — 2026-09-12

- Reliability console for administrators and users: partitioned history, separate annotations and targeted corrections, metrics with intervals, control availability, traffic variations and collection groups.
- Audit Rust limited rules: occurrences, co-occurrences, consolidations and withdrawal of weight on replayable historical observations; comparison of registered candidates without changing decisions.
- Collection compatibility related to Rust/SQL code, dependencies, compilation, parameters and models. A simple application version is no longer enough to fragment observations; the old artifacts remain strictly distinct.
- Native content entries, campaign and Bayes in the calibrated candidate, with explicit missing states and eleven ablations. No private driven model nor automatic activation.
- More contextual native grounds: limited standardization of certain invisible characters and full hunting, distinguished recovery requests from English/French warnings, inert HTML excluded from the forms.
- Local control limited to the date announced by ClamD and Proton SPAM/PUB compatibility checklists; SMTP acceptance does not validate the arrival folder.
- Migration of candidate protocols and native content; SQLite storage unchanged. See [migration and validation protocol](docs/reliability.md). The quality of capture in production remains to be measured on recent independent annotations.

## [0.4.15] — 2026-09-12

- Rust native complementary motor: compiled and grouped patterns by MIME view, explicit symbols, deterministic composites and contribution ceilings per family. The contributions replaced remain visible in the diagnostics.
- Similarity of shingles and MinHash campaigns of HTML text and structure. The memory only consults the recently authorized human corrections of the domain; contradictions, exact repetitions, delays and unavailability prevent a reinforcement.
- OSB Bayes Rust Classifier: Documentary frequencies, remote bigrams, private export with access control, training and time evaluation separating campaigns, frozen threshold and weight-related history manifest. Models expire after 30 days.
- Configuration bounded, concurrent local execution, private preservation of French characteristics and diagnostics. Control of flow measurement and comparison of group search with individually evaluated expressions.
- These mechanisms are in observation only. No new score changes arbitration, actions, external calls or delivered messages. Quality in production requires recent human annotations and an independent test; Bayes scores are not calibrated probabilities.

## [0.4.13] — 2026-09-11

- Same choice in Python and Rust when several types of mail have the same probability; parity control over categories, in addition to probabilities.
- Risk learning independent of the six types of mail: a rare or unknown type no longer blocks a risk candidate. Format 2 with distinct profiles, private manifest related to the weights and reading of former candidates retained.
- Separate prospective evaluation: previous campaigns, exclusions and omissions counted, fixed thresholds, calibration, PUB metrics and positive capture/false criteria with confidence intervals. No ratio allows automatic activation.
- Nine comparisons by removal of signal families, Python/Rust parity, MIME encoding controls and context cited. These synthetic tests do not show performance on traffic.
- Diagnostics: verified decomposition of score before saturation, aggregates of engine and second notice errors, availability and cost recorded, without exporting private content.
- Console: exploitable annotations, missing data, separate configurations and optional type. Active weights, budgets and actions remain unchanged; quality objectives still require human annotations and an independent test.

## [0.4.11] — 2026-09-11

- Explicit arbitration of the second notice: a disagreement with the historical ranking gives "To be verified", without automatically declaring the legitimate message. An ambiguous notice is dealt with separately from supplier errors.
- Preservation of raw score and characteristics, priority of the main antivirus, respect of fusion policy and consistent reapplication of profiles per recipient.
- Console and diagnostics: visible conflicting opinions, lack of misleading decision score in forbearance, meters and actions based on the final decision.
- Read-only native audit: separate comparison of detections, errors and omissions, and transitions on the 100 recent messages. No rewritten history, no new activated model, and no assumed capture rate.

## [0.4.10] — 2026-09-11

- Second optional opinion on high scores without substantiation: explicit option, motif retained even in case of cancellation, budget and deadlines unchanged.
- Normalization of the old prefixes of filtering in the object submitted to the LLM, identical to the local model, without changing the messages delivered or the active weights. These corrections do not show a rate of capture in production.

- Private corrective learning from human errors, anchored to the existing lexical model and a corpus of reminder; preservation of the IDF, bias, threshold and semantic head.
- Off-campaign comparison, time control and regression checks by corpus. A drop in false positives accompanied by a loss of capture rejects the candidate; no automatic activation.
- Regrouping human returns: keep the extreme dates of the entire transitive campaign in order not to make a future annotation for a previous observation.
- Corrective weights agree with existing Rust inference, without another calculation in the SMTP path. See the [protocol](docs/corrective-learning.md).

## [0.4.9] — 2026-09-11

- Sensitivity profiles and actions by organization, domain and recipient, with explicit legacy and priority of aliases.
- Custom rules bounded, order, expiry, ET/OR combinations, draft simulation and details of decisions by recipient.
- A common analysis, independent delivery variants and atomic acceptance after the persistence of all messages.
- Invitations to access the console: temporary single-use links, revocation, password choice, activation rights control and audit. No automatic sending.
- Observation mode, Proton validation and malware priority are preserved. Storage changes are additive; see the [rollback precautions](docs/custom-filtering.md).

## [0.4.8] — 2026-09-11

<a id="filtrage-et-validation"></a>
### Filtering and Validation

- The LLM no longer corroborates its own contribution to the historical score (`confirmation-3`). High scores that are insufficiently supported remain "To be verified"; this change may reduce the recall.
- Contextual analysis of phishing: protected name, link displayed, Reply-To and QR close to the final destination verified. Exceptions apply to the exact final site.
- CRDF and VirusTotal responses related to the requested indicator, with scope and freshness terminals. A specific CRDF URL does not become a condemnation of the entire domain.
- History of correspondents limited to the recipient domain, an aligned DKIM identity and previous corrections of authorized administrators. Expiry, conflict and diversity of campaigns; no circumvention of controls.
- "Filter quality" console for all accounts: fixed uniform prints, masked scores, risk annotation and six types of mail, pagination and authorizations per recipient.
- Versioned observations, private export without body, regulated and calibrated local training, time separation/campaigns, comparison to applied ranking, ablations and confidence intervals. JSON models checked by Python/Rust parity, exclusively in observation.
- Additive storage compatible with the return to binary 0.4.7; no activation of Proton marking, no distributed private model, no presumed production performance.

## [0.4.7] - 2026-09-11

- Restore the tracking of URLs under systemd: allow the inventory of interfaces via Netlink, keep exclusions from internal addresses and distinguish an unavailable inventory from a prohibited destination. Test Linux containment.
- Perform reputational consultations with no more than three indicators per supplier and message, under an overall shared request ceiling. Preserving the priority of final destinations, sustainable quotas and cache; counting also the indicators omitted due to a quota, failure or overall delay.
- Scroll the advisory LLM and reputation checks. Continue independent controls after a limited OCR without declaring the full analysis, without prefixing the message and without erasing an acquired antivirus detection.
- Explain LLM errors and suppliers with limited causes: delay, connection, authentication, remote quota, invalid or too large response. No supplier response body nor secret is added to the diagnostics.
- Show PUB indices even when a security decision remains a priority, with a dedicated filter that retains rights per recipient. Historical decisions and templates are not rewritten. No storage migration.

## [0.4.6] - 2026-09-11

- Rethink the console with an orange identity, clear navigation, an illustrated login page and a common dress to admin and user spaces. Adapt lists, settings and confirmations to small screens.
- Make the log more readable with separate statuses, available suspicion clues and grouped secondary filters. Add the shortcut Ctrl/的+K for searching and the possibility of temporarily displaying the password.
- Maintain existing decisions, authorizations, API requests and delivery policies. No storage migration or engine modification.

## [0.4.5] - 2026-09-10

- Configure CRDF and VirusTotal allowances per minute per day from the console, with explicit unlimited mode and legacy of server ceilings for old configurations. Apply changes without restarting or reset usage.
- Display active limits, persistent meters, their deadlines and supplier breaks. Keep cache, deadlines, limited competition and message-based work ceilings, even with unlimited key.
- Fix CRDF consultations: build an HTTPS root from the domain, the bare domains being refused by the API. No path or parameter of the transmitted mail.
- Version and control changes via the existing administration API. No change in score, models, routing or storage scheme. Before returning to a previous binary, restore a revision without quota fields.

## [0.4.4] - 2026-09-10

- Track HTTP and HTML redirects of text and OCR/QR links with explicit admin setting. Check each DNS/IP jump and TLS certificate, exclude internal addresses and limit time, volume and competition. Do not run JavaScript or submit forms.
- Compare the URLs visited to the local phishing database and consult the domains discovered via the configured connectors, with priority to the last destinations and indication of quotas and omissions.
- Display the routes and their interruptions in the diagnostics, without keeping paths, parameters or pages. Keep the existing advisory observations, models and delivery actions.
- Report this 0.5.0-dev.15 capacity to the stable 0.4.3 branch, without storage migration. Existing configurations keep tracking disabled until it is activated from the console.

## [0.4.3] - 2026-09-10

- Accept the final point of the MX names for the SMTP relay, including failed notices already in file. Keep absolute DNS resolution, canonical TLS name, certificate verification and loop checks.
- Document attempts stopped before any SMTP response and cover roads with or without port, invalid names and local delivery of notices.

## [0.4.2] - 2026-09-10

- Hide addresses that can be retrieved in remote SMTP responses, including aliases, hidden copies, and usual encoded representations. The masking occurs before truncation and also applies to viewing old logs and errors in the console.
- Keep SMTP codes, extended codes, steps, durations and reasons for diagnosis. Imported texts exceeding the inspection budget are omitted.
- Cover remote responses, structured logs and authenticated API with regressions on recipient rights and confidentiality.

## [0.4.1] - 2026-09-09

- History of outgoing SMTP by recipient: tested servers, IP, verified TLS, positive and negative responses, extended codes, duration and next attempt. Network and protocol errors keep their context; a disconnection after the final `250` does not cause any new delivery.
- Console diagnostics: triggered rules, advisory or numerical effects, model contributions, authentication, duration and settings actually applied to the analysis. No historical threshold is invented.
- Restricted tracks recorded with the delivery result and accessible only to authorized recipients. Additive migration of schema 2, deletion with metadata, no body or SMTP argument out-of-date updated.
- Structured journals enriched to link analysis, sustainable acceptance and relays. Existing models, thresholds and filtering behaviors are retained.

## [0.4.0] - 2026-09-09

Final release of the 0.4 cycle, combining the development versions up to 0.4.0-dev.4. It retains the filtering behavior of the latter candidate.

<a id="fonctionnalités"></a>
### Features

- Competitive SMTP Rust gateway, STARTTLS, durable file and delivery tracking by recipient. Domains, alias and receipt of all addresses of a domain.
- Local analysis, email authentication, advertising/newsletter detection, cross confirmations and optional connectors: OCR/QR/PDF, ClamAV, Spamhaus DQS, CRDF and VirusTotal. Models learned loaded separately.
- Actions configurable by category: transmit, tag or quarantine. Release, deletion and expiration by recipient.
- French console adapted to mobiles: messages, reasons, corrections, quarantine, personal account, domains, gateways, filters and accounts. Server-side checks; versioned settings and drafts retained.

### Distribution and installation

- Updating the search tools to PyTorch 2.13.0 and Transformers 5.10.1 for their security patches; versions recorded in new exports. Deployed models and historical results are not changed.
- Linux Archives x86-64 and ARM64: binary with available semantic engine, static frontend, systemd services, examples, documentation and licenses. Debian 12+ or Linux with glibc 2.36+, Python 3.11+ and systemd.
- SHA-256 and construction metadata linking each archive to the commit. The publication is conditioned to Rust, frontend, Python, SMTP and Linux workers tests.
- [First installation guide](https://github.com/crdffrance/NoiseFence/blob/v0.4.0/docs/getting-started.md), [contributing](https://github.com/crdffrance/NoiseFence/blob/v0.4.0/CONTRIBUTING.md) and [private security reporting](https://github.com/crdffrance/NoiseFence/blob/v0.4.0/SECURITY.md). GPL-3.0-only. No keys, production configurations, private corpora or trained models are included.

<a id="mise-à-niveau-et-limites"></a>
### Upgrading and limitations

- Since 0.4.0-dev.4: no new migration or policy changes. Since 0.3: save configuration and data at the stop before migration to the storage scheme 2. The old binary are incompatible with this scheme; follow the [restore procedure](https://github.com/crdffrance/NoiseFence/blob/v0.4.0/docs/actions.md#migration-de-stockage).
- Default observation. Marking requires corresponding Proton/ARC validations; a release does not change MX or filter mode.
- Capture ≥ 95%, false positives ≤ 0.1% and p95 analysis < 500 ms are objectives to be demonstrated on recent representative data. This publication is neither SMTP conformity certification nor a guarantee of delivery at Proton. SMTPUTF8 remains disabled; incomplete analyses are reported.

<a id="040-dev4--réglages-adaptés-aux-petits-écrans"></a>
## 0.4.0-dev.4 — Adjustments suitable for small screens

- Limit the intrinsic width of the selectors in the forms: long options no longer go beyond the policy of filtering on the phone.
- Validation of 320 pixels policy and keyboard navigation of headings.
- Version 0.4.0-dev.3 was published for validation but was not installed in production; the recast is delivered with this correction.

## 0.4.0-dev.3 — Administrator and user console

- Navigation separating messaging, administration and personal space; direct access to quarantine and mobile menu.
- Message table distinguishing classification and delivery, interactive meters, eraseable search, periodic background update and maps adapted to telephones.
- Detail giving priority to stocks and main indices, with foldable technical controls.
- Integrated quarantine confirmation: explicit recipient, keyboard cancellation, focus return and window errors.
- My account screen: authorized scope and password change with confirmation.
- Administration of filters in five headings preserving the draft; searching for accounts by name, access and role.
- Presentation tests for canonical decisions, antivirus, multiple deliveries and account search. Engine, API, storage and production policy unchanged.

## [0.4.0-dev.2] - 2026-09-09

- Normalize old settings when loading for review: the displayed actions and weights correspond to the values that the server applies, including when returning to historical policy without explicit actions.
- Show this recovery in the summary and cover compatibility of old revisions with frontend tests performed in the IC.
- Keep the dev.1 tag as a development step; it has not been installed.

## [0.4.0-dev.1] - 2026-09-09

- Separate the actions from the rankings: transmission without prefix, marking or quarantine, configurables for spam, PUB and confirmed malware. Keep the observation by default and Proton/ARC validations for marking.
- Add a durable quarantine per recipient, with release, deletion, expiration of 1 to 30 days, history, counters and session/ACL controls. The body remains retained until all copies are resolved; a release has a new SMTP retest period.
- Customize eight bounded heuristic contributions in the console, with default values restored, without changing the features learned or removing the antivirus priority and spam confirmation.
- Migrate the base to the diagram 2. Versions 0.3 refuse this scheme to protect quarantined bodies. L-installer blocks an incompatible automatic return; save before migration and consult [the procedure](docs/actions.md).

## [0.3.0-dev.22] - 2026-09-09

- Publish the consistency corrections of dev.21 with the exact wording "suspicion index": the historical score also includes the active advisory signals.
- Retry the download of the digest-locked construction image no more than three times, then fail if it remains unavailable. Integrity tests and checks remain mandatory.
- Keep the dev.21 tag; its publication was interrupted after the HTTP 502 error of the Docker register. No dev.21 binary n

## [0.3.0-dev.21] - 2026-09-09

- Give priority to malware recognized by the main antivirus, even with a low text score or advertising detection. Keep alert if another control fails, always transmitting without prefix in this case.
- Use the same decision for category, headers, meters and console. Identify the antivirus source without inventing a score of 100.
- Unify the interpretation of LLM and ZEN codes; keep PBL/BCL without the weight assigned to malicious reputation lists.
- Maintain the reasons for a new application of the confirmation, and test engine disagreements, failures and persistent alerts.
- Added the `antivirus` decision source: reading those new analyses requires dev.21 or newer; see compatibility in the [filter policy](docs/filter-policy.md).

## [0.3.0-dev.20] - 2026-09-09

- Add an option to confirm the historical score: keep suspicions in "To be checked" without sufficient additional control, with score and characteristics intact, without prefixing or reclassification as a legitimate.
- Administer this option and search for the complete analyses to be checked, keeping the authorizations per recipient and the distinction of faults.
- Specify LLM guidelines against false positives based on brevity, free provider, transfer or service notification.
- Test for retention of substantiated decisions, lack of confidence in the headers provided, supplier errors and console rights.

## [0.3.0-dev.19] - 2026-09-09

- Lock the `sharp` transitive compilation dependency on 0.35.4 to fix [GHSA-rgj7-g3m4-5g8c](https://github.com/advisories/GHSA-rgj7-g3m4-5g8c). Keep audit controls; do not downgrade Cloudflare tools.
- Publish the PUB category of dev.18 with this correction. The dev.18 tag remains unchanged; its publication was interrupted after the failure of the frontend audit.

## [0.3.0-dev.18] - 2026-09-09

- Distinguish legitimate ads and newsletters in a PUB category, without changing the antispam score; retain priority to spam and exclude transactional, service and identifiable conversations.
- Add PUB settings, filter, and history counter, reasons and explicit PUB/Spam/Legitime corrections with the same access controls.
- Prepare the prefix [PUB] with unchanged body, prefix deduplication and ARC seal; require a Proton validation specific to [PUB] before marking.
- Export PUB labels without polluting binary learning; keep the ambiguity of old votes and contradictory subtype corrections.

## [0.3.0-dev.17] - 2026-09-08

- Born and cancelled the fake HTTP server of reputation tests: an expired deadline before connection no longer leaves Linux controls waiting indefinitely.
- Separate the deadlines from quota, excessive response and expiration tests to check each error even on a loaded runner. No change in filtering behavior compared to version 0.30-dev.16.

## [0.3.0-dev.16] - 2026-09-08

- Add advisory protections against usurpation, deceptive links and repeated campaigns confirmed in the recipient domain.
- Consolidate HTML, text, and OCR/QR indices; use a local database of exact URLs, with atomic import, expiration, and optional systemd units.
- Refer to CRDF Threat Center and VirusTotal reports with separate caches, deadlines, persistent quotas and error states. Do not submit a complete message, attachment or link to suppliers.
- Administer protected names, exceptions and API keys in the console, without exposing secrets in answers, revisions or logs.
- Keep the score calibrated and delivery decisions; export the observations for independent validation before contributing to the ranking.

## [0.3.0-dev.15] - 2026-09-08

- Keep the loaded lexical model and its footprint with the multilingual engine reside during configuration changes. A file replaced on disk is enabled only upon restarting, after validation of their links.
- Maintain deactivated domains in the history selector, subject to account access, to view messages already received.

## [0.3.0-dev.14] - 2026-09-08

- Administer domains, their aliases, receiving all addresses and delivery gateways from the French console, with TLS verified.
- Apply a validated and versioned configuration without restarting, to the next SMTP transaction; preserve the routes of messages already in file. Reuse heavy engines and their limits of competition; isolate and limit SQLite searches to preserve the file entries.
- Configure the installed sensors, their contribution to the score and the observation/marking mode. Keep the calibration and validation requirements Proton/ARC. Secrets and resources remain in the server configuration.
- Give administrators overall visibility and users rights by address or domain (`*@domaine`). Reuse the same permissions for history, statistics, corrections and learning exports.
- Create, edit and disable accounts, reset their passwords, revoke their sessions, and protect the last administrator.
- Show queue, metrics and log; restart temporary deliveries, load an old revision for review and restore the initial configuration. Add `console-reset` for local recovery, service stopped.

## [0.3.0-dev.13] - 2026-09-08

- Power relay workers as soon as a delivery ends or a message is maintained, without waiting for the next pick up.
- Consolidate DATA entries by 64 Kio blocks, retain SMTP controls and confirmation after lasting synchronization of the body and SQLite.
- Configure the DATA/Analyse competition with `smtp.max_processing` (1–64), regardless of connections and relay; respond temporarily before DATA when this capacity is occupied.
- Wait briefly for the semantic engine in its total budget, preheat its kernels at startup and analyze in parallel with the local scanners.
- Provide an isolated synthetic SMTP bench: flow rate, latency, cover, integrity, unchanged body, complete analysis and memory. Check small and large mails in the IC. SMTP numbers alone do not measure full filtering.

## [0.3.0-dev.12] - 2026-09-08

- Read locally the English/French text, QR codes and barcodes of attached, integrated images and PDFs with isolated Tesseract, ZBar and Poppler.
- Time, memory, pixels, pages, bytes and outputs; make the analysis incomplete in case of failure or limit, without blocking delivery.
- Display the results in the console, integrate decoded domains with the configured reputation and keep observations without text or raw codes.
- Add `vision-inspect` to explicitly read a local `.eml` without DNS, LLM, storage or delivery. New rules remain advisory by default; no capture or false positive performance is assumed.

## [0.3.0-dev.11] - 2026-09-07

- Evaluate offline each line of a population export with `fusion-population-predict`, without turning missing or incompatible observations into legitimate messages. Check the exact meters, identities, model and bytes of the game; publish atomically without crushing.
- Compare the five candidates frozen on the entire population, with human annotations and documented arbitrations, detection of campaigns already used, counting unknowns and conservative limits. Distinguish measurements by message and stability per campaign; prevent accidental re-evaluation of the same game.
- Test the complete evaluation chain on synthetic cases including old faults, conflicts and data. These measures do not validate any models for actual traffic and do not activate any new production rankings.

## [0.3.0-dev.10] - 2026-09-07

- Unify the persistent decision between the SMTP, console, research and statistics. Distinguish undesirable, legitimate and indeterminate; keep the historical score for comparisons.
- Integrate the optional native fusion into observation, then into decision-making with detector-related model and recent validation file. Refuse the marking for unknown profiles, incomplete checks and expired validation. The Proton compatibility check remains independent and mandatory.
- Export the selected population over an interval, including incomplete, unannotated, contradictory or non-SMTP messages. Keep an original byte print even when MIME is limited, distinct from the campaign print. No body is exported.
- Correcting LLM saturation: it also makes the historical decision undetermined, without prefixing or spending. Add SMTP tests, access and consistency of exports. No new search model is enabled.

## [0.3.0-dev.9] - 2026-09-07

- Add the native fusion contract of 218 typical observations, the private export `fusion-export` and offline predictions `fusion-predict`. Check the consistency of controls, detector versions and available profiles.
- Learn a regularized logistic regression, calibrate its probabilities and select a common threshold on separate lots. Detect campaigns shared with content models or between merge lots.
- Fig five ablations before the test, publish measurements, uncertainty and coverage, and compare Python/Rust decisions in the IC. The models produced remain search candidates; the service score and MX remain unchanged.
- Include embedded Rust modules and embedded protocols in the archive source footprint, with the list of entries and an explicit schema.
- Bringing FreshClam's memory ceiling to 2 Gio: the validation of the new bases exceeded 768 Mio and caused repeated restarts due to lack of memory. Keep checking the bases and other service limits.

## [0.3.0-dev.8] - 2026-09-07

- Keep the SPF, DKIM, DMARC, ARC, reputation and other engine typed results, with individual statements and partial results despite a delay. Distinguish SMTP reception, envelope provided and local analysis; leave the old data unknown.
- Identify the bytes of loaded models and the detection settings. Keep the limits of certification of ClamAV signatures and cloud model.
- Preserving DQS categories and roles, distinguishing compromised legitimate domains from malicious domains, rejecting supplier errors as unavailable signals, and respecting positive TTL.
- Add these observations to the API and to the private export of corrections, with the existing rights and retention. The diagnoses provided manually do not become SMTP learning observations.
- Version the labelling protocol and the experience of increasing content. No new content or fusion model is enabled by this version.

## [0.3.0-dev.7] - 2026-09-07

- Add a Helo/IP consistency Rust module, confirmed PTR and envelope domain, inspired by policy-weight techniques. Respect IPv6, empty envelopes, Null MX and A/AAAA fold without MX. Outbound servers are not required to match incoming MXs.
- Start DNS searches, deadlines, competition and cache. Unavailability abandons partial contributions and keeps delivery without prefix; no SMTP rejection based on these signals.
- Observe candidate weights before explicit activation of their capped contribution. Show reasons and status in console, keep them with metadata and measure them with the complete pipeline bench.
- Extend DQS to HELO and MAIL FROM domains, priority on the body links, without duplicating contributions or activating a new list.
- Provide `smtp-check` for single DNS tests, without email or fee-based call. Test real DNS responses on local server and limit cases.

## [0.3.0-dev.6] - 2026-09-07

- Accept all valid addresses of a domain with the explicit `accept_all_recipients` option, without a mandatory list of boxes. Forward each address to itself by keeping the local part and the routes configured.
- Preserving the priority of explicit aliases and console rights by destination; refusing external domains, chains and loops of aliases. Test the SMTP relay of undeclared recipients after restarting and isolation of hidden copies.
- Full processing measuring bench with loaded model once, separate heating, connector status and p50/p95 per case. No SMTP sending, no content or registered vector; LLM calls paid only on explicit request and with the budget configured. Failures remain in the measurements.

## [0.3.0-dev.5] - 2026-09-07

- Route explicit aliases between configured domains to an authorized canonical box, with the road and the rights of this box. Allow a domain reserved for akas without clean road; refuse chains, loops, collisions and destinations absent from the authorized list.
- Compare domains without distinction of break and keep exactly the local part and canonical address used for authorizations.
- Document testing from an external provider via a pilot address, without tipping the main MXs. Check for filed content, hidden copies and body removal after resolution of all recipients.

## [0.3.0-dev.4] - 2026-09-07

- Distinguish local extraction from external checks: a failure of DNS, scanner or LLM no longer excludes corrections whose local characteristics are complete. Keep the withdrawal without prefix and exclude old incomplete results whose extraction cannot be attested.
- Place periodic learning snapshots in the temporary private systemd directory; check their removal after normal output and SIGKILL. Publish aggregate weights and metrics, without individual predictions.
- Create the start-up service directories, preserve the previous candidate when there are no corrections and record an aggregated training status. Use the same release for export and training during updates.

## [0.3.0-dev.3] - 2026-09-07

- Private and atomic export of scheme 3 corrections, with campaign footprint, semantic vector and exact encoder protocol. Exclude disagreements, revoked rights, expired lines and incompatible features.
- Train lexical/hybrid candidates based on the selected characteristics, without body or network access. Separate learning, development, calibration and campaign testing; publish together weights, tied combination and report. Corrections alone never make a candidate eligible.
- Adapt the training service to the active scheme, limit its resources and preserve the previous candidate in a failure. No automatic activation.

## [0.3.0-dev.2] - 2026-09-07

- Testing the Linux archive with the effectively distributed optimized profile. The `gemm-f16` dependency debug profile failed to compile on Linux ARM64 and prevented the publication of `0.3.0-dev.1` archives.
- Add the ARM64 control of the multilingual engine before creating a release. No change in weights, scores or filtering configuration.

## [0.3.0-dev.1] - 2026-09-07

- Reproducible R&D on Apache, Enron-Spam Crude and Nazario 2015–2025: pinned sources, grouping of close duplicates and independent scores for learning, selection, calibration and testing. Nazario 2025 remains out of learning.
- Logistical models TF-IDF and with Bayesian likelihood ratios, comparison of regularizations and JSON weight export for a native Rust inference.
- Character diagram 3: words, bigrams, character groups and structure, excluding non-visible HTML content and old antispam markers. Retention of old model support and versioning of features.
- Orders `features-export` and `analyze` for tests without SMTP delivery. No search applicants are automatically activated in production.
- Optional comparison of a local frozen multilingual encoder, with pin-pin files, logistics head and selection on development only.
- Reputation check on decoded MIME body links: Base64 and quoted-printable links no longer disappear, and the old filter headers no longer provide domains to question.
- Native measurements of the model on macOS ARM64 and Debian x86-64 of 4 vCPU / 8 GB.
- Optional multilingual encoder run in Rust with Candle, checked prints, lexical model combination and Python/Rust match controlled. Inference out of network threads, competition and bounded deadlines, calibrated fold score and visible status in console. No model activated automatically.

## [0.2.0-dev.2] - 2026-09-06

- Accept the `tool_calls: []` field actually returned by Scaleway when no tools are called; continue to refuse the actual calls and old `function_call`. HTTPS regression test and check for prohibited cases.
- Keep the analysis report of the Proton trials incomplete for diagnosis.
- Nginx HTTPS configurations, Certbot renewal via webroot and services for upstream ClamAV 1.4.6, to avoid the Debian 13 version still vulnerable.
- Periodic supervision of services, scanners, signatures, file, disk, certificate and LLM budget. The analysis remains advisory until the delivery validations.
- Normalize permissions for the installed archive to enable it to be executed by the service account after extraction into a private directory.

## [0.2.0-dev.1] - 2026-09-06

- `0.2.0-dev.1` development preversion: official ClamAV connectors and complementary signatures on separate Unix sockets, limits and verdicts visible in the console. Sanesesecurity LOW profile, pin-pinted sources and key, systemd services and actual EICAR testing provided. No quarantine implemented.
- Optional Scaleway Client: HTTPS verified, limited MIME extract, JSON closed, reserved SQLite budget before call, explicit pricing and no automatic restart. Locally tested exchanges; cloud validation still needed.
- Candidate Bernoulli Bayes and reproducible comparison with logistic regression. Activation controls retained; quality objectives not achieved.
- Recent data plan, technology comparison, calibration and validation of the complete pipeline. None of these new connectors are enabled by default.
- Emplacement of SMTP Lets Certificates Encrypt by hook Certbot: validation of name, string and key, restricted permissions, atomic tilt and reverse return if restart fails. Renewal tests added to the IC.

## [0.1.0] - 2026-09-06

First open source version of **NoiseFence**, under GPL-3.0-only.

- SMTP reception in Rust with STARTTLS, SIZE, 8BITMIME and PIPELING.
- Durable file SQLite/WAL and spool on disk, retrieved by recipient and failed notifications.
- MIME local analysis, rules, logistic regression, SPF/DKIM/DMARC/ARC and optional Spamhaus DQS connector.
- French console with local accounts, secure sessions, history, corrections and rights per recipient.
- systemd services, example configurations and Linux x86-64/ARM64 archives.
- Default observation mode; marking requires prior validation of the Proton relay.

Known limits: actual Proton compatibility not validated; historical candidate recall 60.94%, below the 95% target; the rate ≤ 0.1% of false positives is not demonstrated. The candidate model does not pass the activation check. SMTPUTF8 remains disabled.

[Unreleased]: https://github.com/crdffrance/NoiseFence/compare/v0.3.0-dev.7...HEAD
[0.3.0-dev.7]: https://github.com/crdffrance/NoiseFence/releases/tag/v0.3.0-dev.7
[0.3.0-dev.6]: https://github.com/crdffrance/NoiseFence/releases/tag/v0.3.0-dev.6
[0.3.0-dev.5]: https://github.com/crdffrance/NoiseFence/releases/tag/v0.3.0-dev.5
[0.3.0-dev.4]: https://github.com/crdffrance/NoiseFence/releases/tag/v0.3.0-dev.4
[0.3.0-dev.3]: https://github.com/crdffrance/NoiseFence/releases/tag/v0.3.0-dev.3
[0.3.0-dev.2]: https://github.com/crdffrance/NoiseFence/releases/tag/v0.3.0-dev.2
[0.3.0-dev.1]: https://github.com/crdffrance/NoiseFence/tree/v0.3.0-dev.1
[0.2.0-dev.2]: https://github.com/crdffrance/NoiseFence/releases/tag/v0.2.0-dev.2
[0.2.0-dev.1]: https://github.com/crdffrance/NoiseFence/releases/tag/v0.2.0-dev.1
[0.1.0]: https://github.com/crdffrance/NoiseFence/releases/tag/v0.1.0
