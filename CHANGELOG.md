# Changelog

## 0.28.0-rc.3 — Scoped policy inheritance (unreleased)

- Correct calibration-readiness counts: use labelled, usable observations for
  class-count checks and share eligibility between global and sample views.
  Preserve all messages/annotations and explain incompatible or missing inputs
  in the English console. Never infer an eligible count from an older API schema
  or expose previous counts while a revised dataset is loading. Independent
  qualification is still required; no scoring or production changes.

- Add an offline `scoring-compare` command for bounded, private comparison of
  frozen native SMTP observations. Separate historical scores from controlled
  aggregation projections; preserve cohort identity and unavailable inputs, and
  require explicit feature precision before reporting threshold crossings. No
  provider calls, receipt changes, calibration or production activation.

- Add evidence-aware content combination v2: require usable structured authentication, DQS and SMTP results for their retained rule weights; retain independently completed reputation hits during partial failures and exclude policy-only/error listings. Let a completed DMARC failure consume its failed SPF branch once, with an explicit receipt-time dependency. Preserve invalid-input rejection and historical v1 ledgers. Header version 7 and English diagnostics use retained contributions and adjustment codes instead of raw proposed weights. This scoring change needs fresh calibration and independent qualification; no accuracy claim or deployment.

- Pin one redacted, non-serialized provider credential set per resident runtime. CRDF/VirusTotal stop rereading keys during analysis; LLM/DQS/admission consume the same snapshot. Preserve keys for in-flight work through file replacement/removal, retain shared quota/capacity state, and prepare v2 participants from the exact authenticated credential set. Bind private durable provider generations into activation bundles; stage Web key replacements across both MXs, retain exact base/candidate sets through source loss, cold startup, abort and partial-commit recovery. Validate complete sets before installation; keep secrets out of model downloads and Web projections. Require activation protocol 2. No production enrollment.

- Capture the MAIL-pinned activation identity before analysis/header preparation. Receipt schema 2, diagnostic header version 6 and English details preserve configuration revision, sequence and bundle digest; replica/history reject contradictory identities. Keep schema-1 receipts readable without fabricating missing history, including unavailable indices. This does not change scoring or qualify production activation.

- Retain immutable installed model files during coordinated settings/preference saves, even after original source removal or replacement. Add an administrator-only Web preview and explicit digest-bound selection of server installation models, including validation reports/encoder files. Changed bytes require a new preview; model identity is not a quality claim. Stage calibration-workbench shadow selection/removal and preserve cached selected candidates across later saves. Long-lived inactive/qualified artifact catalogs remain open.

- Connect English Web settings and personal preferences to coordinated saves after explicit cluster enrollment. Show preparation, central commit, local installation and SMTP readiness separately; expose cancellation/recovery and safe persisted incidents. Recheck delegated scope, exact preference delta and account privileges before commit; do not expose global bundles or other recipients to users. Keep progress readable during SMTP write draining and preserve unsaved drafts. No production enrollment or model promotion.

- Connect coordinated activation to authenticated cluster-v2 polling, immutable model transfer and an owned authority loop. Commit console revisions and activation state in one transaction; keep all participants fenced through partial application, partitions and lost responses. Add administrator session/CSRF-protected stage/status/abort/recovery APIs with privilege revalidation before commit. Legacy synchronization is not readiness and enrolled nodes cannot downgrade. The retained artifact catalog, membership changes and production qualification remain pending.
- Load installed cached policies in CLI tools as well as daemon restarts; retain active/pending/recovery model manifests, verify streamed bytes and synchronize model directories before preparation. Lost release replies and abort-before-preparation are handled without accepting mixed policy epochs.

- Add durable coordinated-activation authority/participant journals and a local runtime preparation driver. Verify model bytes before readiness, fence new SMTP acceptance until every participant applies, preserve owned disk writes across caller cancellation, and require validation before reopening after restart. Abort only before commit; partial-commit recovery uses a higher epoch. Network orchestration is described above; Web save integration is described below; production qualification remains incomplete.
- Preserve database format guards when enabling MFA, replication or cluster support. Coordinated storage uses format 6 and starts fenced; older binaries and missing or mismatched journals must fail closed.

- Record the selected score's native operating point and fusion model/calibration identity. Keep recipient content thresholds distinct from fusion logit cutoffs in frozen receipts, English details and signed diagnostic headers. Preserve native comparisons through flat/saturated mappings and full-precision header values; missing historical fusion boundaries remain unknown. No scoring formula, action or activation policy changes.
- Enable exact JSON float round trips after replica tests exposed low-order drift in a saved fusion probability. Preserve stored numbers across queue/history serialization; allow only a few rounding units when validating calibration computations across hosts. Native cutoff comparisons remain exact. Requalify model artifacts before rollout; accepted history is not rescored.
- Share strict score validation across replica manifests and central history. Preserve explicitly unavailable content indices and frozen receipts without fabricating zero, while rejecting inconsistent or out-of-range scores. Validate complete outbound replica batches before uploading bodies; cover confirmation, fenced restoration and atomic history rollback. Upgrade both receiving endpoints before rollout.
- Remove the six-copy SMTP ceiling: share immutable bodies between policy variants, stream spool writes and replica uploads, and bound aggregate headers/metadata. Split copies at the existing 100-recipient replica limit; retain atomic batch acceptance and temporary deferral on resource failures. Check full-batch disk space and bound remote preparation as a whole.

- Add opt-in scoped inheritance across organization, alias/domain and mailbox profiles, retaining domain preferences when a mailbox adds rules. Keep legacy ordering for existing configurations. Personal rules run before administrator rules and cannot stop them; deterministic ties use the original rule IDs.
- Record recipient-specific profile inheritance, threshold ownership, matched/missing/stopped rules, winning effects and malware priority. Display the receipt trace in the English console without exposing rule values or changing accepted history. Scoped risk-index conditions use the same selected index as the receipt and UI.
- Add a Web draft comparison on 1–50 explicit message IDs for one recipient. Reuse retained detector results, freeze the evaluation time and sample fingerprint, and exclude unknown comparisons from change counts. No content is sent, rescanned or modified; truncated or unavailable facts stay unknown.
- Require fresh compatible reports from every enabled worker before scoped policy activation or edits. Refuse scoped bundles to older MX builds; retain audited support for rc.1 partial actions and rc.2 capped fusion. This is a compatibility gate, not atomic multi-node activation.
- No production deployment, model promotion or new detection-rate claim. Independent full-pipeline qualification and coordinated activation remain required.

## 0.28.0-rc.2 — Bounded fusion candidates (unreleased)

- Add a version-2 learned fusion model with explicit log-odds limits per detector family. Use the same capped likelihood during fitting and the same capped calculation for calibration, threshold selection, Python evaluation and Rust runtime prediction. Keep legacy model behavior unchanged.
- Record family contributions before and after limits, the bias, policy and model fingerprints with receipt decisions. Display the English accounting separately from legacy content-index and native-rule points.
- Expose installed fusion mode and model-contract selection in the administrator's Web engine settings. Require matching model/configuration, version-2 independent quality/latency qualification and fresh compatible MX reports before decision activation. Keep old queue prediction JSON readable and refuse capped bundles to earlier workers.
- Synthetic parity and regression tests validate software consistency, not detection quality. No fitted production model, new detection-rate claim or deployment accompanies this release candidate.

## 0.28.0-rc.1 — Unified receipt decisions (unreleased)

- Persist versioned analysis and recipient-decision snapshots before rendering SMTP copies. Preserve policy thresholds, requested/effective actions and coverage across configuration changes, queue replication and restoration.
- Share action constraints between global and scoped policies. Split copies with different effective policies instead of merging incompatible delivery and quarantine headers.
- Make history, search and statistics preserve receipt-time decisions; original policy absence remains explicit. Add version 5 headers and English console details for the canonical record.
- Record bounded, normalized detector observations with availability, provenance, scope, native units and shared evidence groups. Preserve completed provider targets across partial outages; distinguish no-hit, stale, timeout and quota results. Display the receipt-time report in English diagnostics without rebuilding historical observations.
- Add an opt-in Web policy for partial actions with recorded evidence requirements per decision. Require explicit subject-rendering readiness and retain requested/effective actions when a fallback copy cannot be tagged. Observation and Proton gates remain independent.
- Centralize the content-index calculation in a versioned receipt-time ledger: count identical message-level signals once, reject conflicting/nonfinite weighted inputs, and reconcile stale LLM signals against the usable opinion. Show retained contributions and exact historical accounting in English diagnostics. Correlated signals with different identities still require joint calibration.
- Refuse Web activation until every enabled registered MX has recently reported the new build; older workers retain parseable disabled settings. Preserve bounded wire variants. Qualified cross-family score combination, full-pipeline calibration and atomic coordinated rollout remain pending; no detection-rate claim or production activation.

## 0.27.0 — Evidence grounding and release qualification

- Assign bounded text references in Rust and validate the LLM's declared evidence against message context and observed authentication/domain facts. Keep unsupported claims out of scoring, definite opinions, fusion and backscatter corroboration; expose the diagnostic in the console and signed headers. Reference consistency does not prove semantic correctness; expose fixed response-limit/schema diagnostics without retaining provider bodies.
- Separate conditional security notifications from current action demands and quoted history. Request a separate mail kind; preserve budgets, observation policy and legacy records.
- Preserve valid CRDF targets in mixed batches without caching failed targets or imposing account-wide cooldown for a malformed response.
- Follow complete early meta redirects within a bounded oversized-page prefix. Distinguish HTTP success, body truncation and unresolved chains without relaxing SSRF protection or deadlines.
- Add recipient-scoped release-readiness counts to the quality workbench and an English qualification procedure. Statistical qualification, a new independent holdout and reference-hardware benchmarks remain required before a final accuracy claim or action activation.

## 0.26.0 — Explicit automatic score resolution

- Add an opt-in Web policy that resolves uncertain classifications using the available content index and applicable threshold, while retaining original opinions, partial coverage, malware priority and delivery guards.
- Keep historical projections consistent across lists, search, statistics and diagnostics without rewriting receipt-time records or completed deliveries. Add a signed score-resolution diagnostic header.
- Require every MX to support the policy before serving enabled settings to workers. Document calibration limits and the final release qualification plan. No detection-rate improvement or production activation is claimed.


## 0.25.2 — LLM request context and action-link inspection

- Separate current message text from bounded quoted history, normalize Latin invisible-character obfuscation, and preserve the existing shared LLM text cap. Quotation boundaries remain untrusted hints.
- Expose bounded, unverified destinations inside recognized redirect wrappers without exporting URL tokens in link context. Prioritize current HTML action links in URL inspection while retaining existing SSRF checks, opt-in fetching and provider limits.
- Version the LLM instructions to evaluate the current request and destination together, with explicit safeguards for legitimate invoices, notifications, reports and tracking links. Preserve authentication provenance, budgets, conservative arbitration and delivery policy.
- Add regression coverage for nested redirects, ambiguous parameters, thread dilution, quoted incident reports, legitimate wrappers and UTF-8 limits. No global accuracy claim or automatic model activation.

## 0.25.1 — DNS coverage and matched engine comparisons

- Verify SMTP identities using the connecting IP's address family. A verified IPv4 identity no longer depends on AAAA availability, and vice versa. An implicit MX needs one observed address; an absent route still requires both families to return empty answers.
- Check the bounded PTR alternatives concurrently under one deadline. Preserve completed HELO/PTR/sender facts and identify the missing check, with no partial score contribution or enforcement on incomplete analysis.
- Add paired NoiseFence/Rspamd metrics on the same human-labelled messages, coverage by label, shared campaign representatives and detector-profile provenance. Separate absent analyses, non-final actions, recorded engine risk and the conservative recipient-policy baseline.
- Show denominators, class-specific review counts and small-sample warnings in the calibration workbench. A retained threat verdict is no longer hidden by incomplete coverage in the paired engine comparison.
- No trained-model, LLM-prompt or action-policy change. These corrections do not demonstrate a population capture or false-positive rate.

## 0.25.0 — Calibration workbench

- Add development, regression and holdout samples with immutable purpose, cohort selection, and isolated evaluation labels. Protect reserved campaigns from periodic trainers and prevent evaluation labels from changing live sender trust.
- Add administrator research jobs, NoiseFence/Rspamd comparisons against human labels, campaign metrics, confidence intervals, abstention accounting, and historical score reliability.
- Train calibrated risk/type shadow candidates offline, verify Python/Rust prediction parity, and select or roll back candidates through versioned Web configuration distributed to MX workers.
- Add a bounded, network-isolated Linux research worker with durable job status, interruption recovery and private temporary exports. No automatic model activation or delivery-policy change.
- Version the fusion promotion contract to separate native warm-cache latency from total external-service latency, while preserving legacy validation and tightening recall/review accounting.
- No production accuracy or Rspamd parity claim: independent human labels and final qualification remain required.


## 0.24.0 — Filter regression fixes

- Inspect bounded plain-text `www.` links in reputation targets and LLM domain context. Exclude email addresses, unsupported schemes, defanged links and hosts without a recognized public suffix; preserve SSRF and fetch limits.
- Detect a narrowly defined cryptocurrency reward lure echoed in a subscription profile field. Expose its weight in Web filter settings; zero disables its contribution and corroboration. Preserve review on contradictory LLM advice and incomplete analysis, and keep malware/fusion priority.
- Recognize additional English and French promotional wording while retaining distribution evidence, multiple commercial signals and transaction/conversation exclusions. Marketing kind remains distinct from unwanted risk.
- Bridge worker quota-window rollover with a 30-second authenticated unlimited lease. Never carry finite credits into another window; revoke rollover leases on empty or bounded grants and require a bounded grant when a policy becomes finite.
- Display optional reputation, URL-resolution, RBL and PUB coverage gaps separately from core analysis completeness. Add the signed `X-NoiseFence-Supplementary-Gaps` diagnostic without changing historical decisions or the meaning of the existing status header.
- Update the versioned LLM prompt for attacker-controlled service-template fields and factual authentication explanations. This does not validate the provider's predictions or automatically retrain a model.
- Preserve destination verification, research archives, independent Rspamd comparison, observation and required peer copies during an upgrade from 0.23.0. No accuracy parity, capture target or calibrated probability is claimed.

## 0.23.0 — Downstream recipient verification

- Add opt-in, per-domain recipient verification in the Web console. Existing downstream mailboxes can keep wildcard reception while nonexistent destinations receive SMTP 550 5.1.1 before DATA, instead of redirecting to a fallback mailbox.
- Verify explicit downstream routes with authenticated TLS and envelope-only RCPT probes. Require every route to confirm an unknown recipient; temporary, sender, policy, DNS and TLS failures return a retryable 451.
- Bound probe concurrency, deadlines and sender/route-specific caches. Preserve explicit aliases, open-relay protection, content analysis, two-copy queue acceptance and observation.
- Make verification mutually exclusive with unknown-recipient fallback and require all MX nodes to support the policy before activation. No message or storage migration is included.

## 0.22.0 — Bounded content context and partial-evidence corrections

- Prepare cleaner LLM excerpts from actual MIME text parts, remove stylesheet/script blocks, avoid HTML-to-text duplication, and include bounded anchor labels with destination hosts. Link context shares the existing text byte cap; URL paths and query strings are omitted from this context. Prompt version 6 distinguishes routine notices and receipts from deceptive account-management requests.
- Skip lexical and semantic content models for encrypted or opaque bodies. Keep a finite rules-only diagnostic, explicit incomplete coverage, and transport/authentication checks. Opaque content is ineligible for content learning; a low partial index is not proof of safety.
- Recognize a narrow direct-extortion context (compromise, disclosure threat, cryptocurrency demand and wallet). Observed failed SMTP authentication plus a phishing signature or strong coherent LLM opinion can preserve an unwanted verdict when only DNS/LLM checks are missing. Quoted reports and receipts abstain; incomplete scans never enable automatic enforcement.
- Report provider cooldowns as unavailable with `provider_backoff` diagnostics, separately from configured quota exhaustion. Cached detections remain usable and unlimited subscriptions still respect provider backoff.
- Preserve 0.21.0 recipient fallback, archive and semantic settings during coordinator-first rolling upgrades. No storage migration or model recalibration is included.

Validation uses synthetic regression cases and private, offline development replay. Historical mail and shadow-engine verdicts are not relabelled, retrained on, or presented as independent accuracy evidence. No capture-rate or false-positive target is claimed by this release.

## 0.21.0 — 2026-09-16

- Ground LLM second opinions in observed SMTP authentication and the current UTC date, with explicit category/probability consistency diagnostics in the console and headers. Preserve existing provider limits and accounting.
- Extend authenticated context review to abuse reports and completed payment notices without vendor allowlists; explicit credential/payment/software demands receive no contextual safeguard.
- Preserve a corroborated phishing verdict across an isolated SMTP/DNS consistency failure while keeping coverage partial and automatic enforcement disabled.
- Add Web-configurable same-domain recipient fallback, limited to a downstream RCPT 550 5.1.1 refusal. Preserve originals, recipient-scoped logs, strict two-copy acceptance and observation.
- Retain independent Rspamd comparison and document that raw scores remain uncalibrated pending an independent, human-labeled evaluation.

## 0.20.3 — Context-aware review and resilient content analysis

- Keep readable text eligible for LLM analysis when independent SMTP/DNS, semantic or scanner checks fail; retain incomplete coverage, resource bounds and configured budgets.
- Hold authenticated security reports and shipment receipts for review when an uncorroborated legacy score contradicts their context. Never infer legitimacy, change a raw score, override malware or rewrite historical decisions.
- Improve the versioned English LLM prompt to distinguish a reported threat from a phishing attempt, ordinary order notifications from coercive requests, and parent/subdomain relationships from lookalikes. Derive bounded domain relationships locally without opening URLs.
- Identify encrypted or opaque message bodies as incomplete content analysis instead of pretending their contents were inspected.
- Distinguish scheduled service updates from newsletters; recognize commercial newsletters with list and unsubscribe context without adding spam weight.
- Expose the semantic inference deadline through the Web; update it without reloading model weights or releasing CPU permits held by cancelled work. Record capacity, deadline, inference and worker failures separately.
- Preserve archived originals, Rspamd observation, strict replicated SMTP acceptance and existing policy during a coordinator-first upgrade from 0.20.0. No retraining or enforcement is automatically enabled; accuracy still requires independent labelled evaluation.

## 0.20.1–0.20.2 — Unpublished candidates

Superseded by 0.20.3 before deployment. Validation caught a stale mailing detector version in the SMTP load test and a coordinator compatibility guard that needed the final release version. Both checks now match the implementation; no production policy was changed by these candidates.

## 0.20.0 — Temporary encrypted research originals

- Add opt-in collection of original MIME, SMTP context and engine observations after successful enqueue, with an absolute stop date, expiry and per-MX quotas.
- Keep collection separate from mail delivery, scoring and training. Bound background work and report skipped originals; preserve strict replicated SMTP acceptance.
- Add English **Filters → R&D archive** controls and per-node coverage counters, plus authenticated local operator exports with integrity and expiry checks.
- Exclude the temporary corpus and keys from built-in backups and console checkpoints. Research copies remain local to each receiving MX.
- Preserve the installed Rspamd comparison during rolling upgrades from 0.19.2 and validate admin access, exact original bytes, encrypted storage, expiry and SMTP independence.

## 0.19.2 — Independent Rspamd comparison

- Compare original incoming SMTP messages with a local Rspamd service, asynchronously and with bounded memory, concurrency and deadlines. NoiseFence decisions and delivery are unchanged.
- Inspect separate score scales, proposed actions, symbols and versioned profiles in the English console; filter disagreements with recipient-scoped coverage counts.
- Configure comparison sampling and limits through the Web. Replicate comparison metadata across MX nodes and distinguish incomplete or lost comparison jobs from message failures.
- Ship an isolated Rspamd 4.1.5 profile, systemd service, installation guide and synthetic protocol tests. No automatic training or new external content analysis.


## 0.18.0 — Consistent assessments and English release

- Share a versioned Rust assessment across the message API, search, console and new SMTP diagnostics. Distinguish the 0–100 risk index, engine decision, recipient classification, analysis coverage, requested/effective delivery action and actual subject tag. Invalid values never become fabricated zeroes.
- Preserve recorded thresholds for historical fallback decisions in message search and dashboard counts. Expose historical provenance instead of presenting current configuration as past evidence. No retained message is rescanned or rewritten.
- Publish diagnostic header schema 3. `X-NoiseFence-Status` now means `complete` or `incomplete`; consumers must use `Category` and `Subject-Tag` for classification and modification. Add assessment, threshold, policy, delivery action and recorded-decision provenance. Keep bounded ASCII output and the ARC signing inventory aligned.
- Finish the English console and documentation. Improve filter navigation, settings search, score explanations and the distinction between draft and applied policy. Keep all messaging/filter settings in the Web console; ports, TLS, storage, model artifacts and replication installation remain host operations.
- Use English explanations in LLM prompt `noisefence-classify-3`. Its fingerprint starts a distinct observation group; previous model validation must not be reused across changed protocols. Existing explanations and user-created labels remain recorded data.
- Preserve saved adaptive pattern labels across translated-default upgrades when all semantic fields and their order match. Installed models still require an exact protocol match; configuration history and model artifacts are not rewritten.
- Add a non-root Docker image, isolated local Compose evaluation and Linux production template with host networking, durable storage, private configuration and dependency notices. Test container bootstrap, authorization, SMTP acceptance, open-relay refusal, restart persistence and TCP 25 binding after privilege reduction on amd64/arm64 in CI.
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
