# Unified receipt decisions

Implementation in progress. These changes establish receipt-time consistency;
they do not qualify a new detection model or authorize enforcement.

## Implemented contract

Incoming SMTP processing captures two additive, versioned fields in the persisted
`Scan` JSON. Existing queue databases need no destructive migration:

- `analysis_result`: original content digest, detector/artifact versions, selected
  risk index, original engine verdict, coverage, missing checks and reasons.
- `recipient_decision`: preparation time, effective policy fingerprint, profile,
  matching rule IDs, detailed classification, coverage and shared assessment.

The shared assessment freezes the applied threshold, requested/effective action,
action reason, score source and semantics. A subsequent setting change does not
re-evaluate an accepted message. API history, diagnostics, search and statistics
use recorded decisions. Legacy messages retain their explicit original verdict,
or their recorded original threshold. When neither exists, the category is
historically unknown; today's settings are never substituted.

The risk index is not a calibrated spam probability. Classification, score,
coverage and delivery action remain separate. Failed content extraction does not
produce a fake zero or a verified legitimate finding. `unassessed` describes
missing or inconclusive classification; the configured automatic delivery policy
still applies. Primary malware evidence takes priority over this absence.

Global and custom policies now share operational action constraints. Observation
still delivers. Complete-analysis guards remain the default; an explicit Web
policy can evaluate partial actions against decision-specific evidence instead.
Proton marking guards remain independent.
Recipient copies only share SMTP bytes when their effective policy fingerprints
match. A different threshold, matched rule, profile or action creates a distinct
copy. Each copy exposes only its own decision in version 7 diagnostic headers.

Recipient variants share one immutable body allocation and retain their own
headers. Disk writes and replica uploads stream both chunks. The configured SMTP
recipient bound still applies, up to 1,000 total recipients/variants; each copy
contains at most 100 recipients for compatibility with the replica protocol.
Aggregate variant headers are capped at 16 MiB and serialized metadata at 32 MiB.
Disk capacity is checked for the complete wire batch plus the configured reserve.
All files are synced before a single SQLite transaction commits every recipient.
Rendering/capacity failures defer the whole SMTP transaction without changing the
detector verdict. See [queue variants](queue-variants.md) for limits and recovery.

Persisted JSON and SMTP bytes already travel in the durable replication manifest.
This change does not relax the two-copy acceptance requirement. Coordinated
upgrade, mixed-version validation and failover qualification remain required
before production rollout. A policy hash is a consistency identifier, not an
authentication mechanism.

## Recorded activation identity

Receipt schema 2 captures the MAIL-pinned activation epoch before engine analysis,
including incomplete paths and recipient rendering. Analysis, recipient receipt,
SMTP headers and English diagnostics use that identity. Replica/history validation
rejects contradictory or missing embedded epochs for schema 2. Schema 1 remains
readable without inferring missing identity from transport fields or current settings.
The Web view does not render unsafe rounded JavaScript integer identities.
These consistency checks do not attest bundle quality or establish rollout safety.

## Recorded score boundaries

`Assessment.score_boundary` freezes the operating point of its selected index.
It records the comparison's native units, value, cutoff, inclusive result and
mapped index cutoff. Fusion boundaries also retain the exact model hash and
calibration coefficients used at receipt time. Runtime capture uses the same
calibration function as prediction, including flat and saturated mappings. The
native logit comparison remains authoritative for fusion; comparing rounded
0–100 values cannot recover every boundary decision.
Transport validation tolerates a few floating-point rounding units when checking
the calibration mapping across hosts. It never rewrites recorded numbers or
relaxes the native inclusive cutoff comparison.
JSON decoding enables Serde's `float_roundtrip` feature so serialization and
replication preserve stored floating-point bits, including values next to a
cutoff. Previously accepted messages are not rescored by this change.

The shared analysis keeps its original boundary; recipient snapshots capture
their effective content thresholds or the unchanged detector-owned fusion cutoff.
Rule and evidence overrides remain separate. Boundaries do not change scoring,
classification, action eligibility or the authority of an observer. Observation
fusion retains its own diagnostic operating point without replacing the active
content boundary. No current configuration fills a missing historical fusion
boundary. Existing strict `Prediction` and `Decision` wire schemas are unchanged;
the optional fields are additive outside those schemas.
Older readers can parse the existing decisions but may omit these optional fields
when re-exporting typed metadata. Upgrade all receipt/history consumers before
qualifying boundary preservation across MX versions; an omitted boundary stays
unknown rather than being reconstructed from current settings.

The English detail panel and `X-NoiseFence-Score-Boundary` consume these snapshots.
`Content-Threshold` remains the compatibility field for content settings and is
never presented as a fusion cutoff. Canonical boundary validation is shared by
queue replication and history ingestion. These checks validate consistency, not
the authenticity of a model supplied by a trusted node or its detection quality.

## Unavailable index transport

The existing numeric `Scan.score` storage field uses exactly `-1` when the
versioned content-scoring ledger cannot produce an index. This is a storage
sentinel, not a negative risk score. Public assessments keep the raw score absent;
an independently available fusion decision can still supply a selected index.

Both replica manifests and central-history ingestion use the same validation:
the sentinel requires an incomplete scan, the supported scoring-ledger version,
absent ledger score and total, and the explicit `score_combination_invalid`
reason. Recorded snapshots must agree with this unavailable state. Other negative
values, nonfinite values, out-of-range scores, fabricated legacy scores and
inconsistent canonical score selections are rejected. Ordinary legacy 0–100
records remain supported without requiring a new ledger.

Senders validate the entire replica batch before uploading bodies. Receiving
peers also validate independently. A rejected history batch rolls back as a
whole; unavailable indices do not become zero, a clean verdict or a local queue.
Replication, confirmation and fenced recovery preserve the receipt snapshot.

Upgrade the history coordinator and both replica endpoints before enabling this
scoring implementation. Earlier receivers reject the sentinel: SMTP then defers
under the two-copy policy, and history remains pending until a compatible
receiver acknowledges it. Never translate the sentinel to zero to work around a
mixed-version rollout. This does not implement coordinated bundle activation.

## Remaining implementation and qualification

The [coordinated activation implementation](coordinated-activation.md) now provides
durable journals, runtime preparation, SMTP fences, authenticated v2 transport and
an authority loop that commits the console revision atomically. Explicit admin APIs
stage, abort and recover rollouts. English Web forms now show progress and use
coordinated saves after enrollment; personal proposals are checked against their
exact authorized delta. Provider credentials now use private epoch-bound generations with coordinated
staging and recovery. The [retained model catalog](model-catalog.md) supports
explicit dormant selection with bounded private copies and model-bound report
diagnostics. Independently audited qualification, membership and full deployment
qualification remain required before production enrollment. Ordinary
coordinated saves now retain installed model bytes; explicit Web selection of
installation files is bound to a reviewed logical-manifest digest.

1. Complete controlled score combination using normalized detector observations.
   Grouping records correlations; it is not a new weighting policy. Preserve the
   existing native family caps and exclusion of the LLM from independent
   corroboration, then qualify any scoring change separately.
2. Qualify the optional decision-specific action policy against independent
   labels, including requested/effective-action mistakes. It is not enabled by
   default and does not establish a new detection accuracy claim.
3. Qualify scoped-profile inheritance and fixed-sample policy simulation on
   representative policies before activating it across the organization.
4. Complete frozen-context parity and recovery tests across both MX versions,
   including policy/model bundle activation and rollback.
5. Evaluate the whole pipeline on recent independent human-labelled messages,
   reporting capture, false positives, precision, uncertainty, coverage and
   action-level mistakes. Regression fixtures and Rspamd agreement are not a
   substitute for ground truth.

Production must remain in observation until the existing quality, latency and
Proton gates pass. The current research model has not established the targets of
at least 95% capture and at most 0.1% false positives. No new provider or private
message disclosure is required for this structural refactor.

The [offline score comparison](score-comparison.md) measures the reconciliation
step on frozen native observations without provider calls or historical changes.
It separates the saved score from two controlled projections, excludes unknown
precision from threshold counts and keeps original artifact cohorts distinct.
It does not supply independent labels or qualify a calibrated model.

See [scoped policies and simulation](scoped-policies.md),
[automatic classification](automatic-classification.md),
[message headers](message-headers.md) and
[release qualification](final-release-plan.md).

## Normalized detector observations

New receipt snapshots include `analysis_result.observations` (schema 1). Older
snapshots remain readable and have no normalized report: API reads never infer
missing historical observations using current settings. Reports are captured
before recipient rules, replicated with the existing scan and preserved on retry.

Each observation records availability, role, scope, original measurement units,
artifact/version metadata where available, references to retained evidence and
an exclusion reason when its result cannot be used. Availability is one of
`complete`, `partial`, `unavailable`, `timeout`, `budget_exceeded`, `disabled` or
`not_applicable`. A completed LLM request with unsupported claims is explicitly
excluded; its reported confidence is not a calibrated probability. SMTP/DNS
deadlines are recorded as typed check identifiers, never reconstructed by parsing
historical prose. A completed authentication check without its required result
is invalid; imported trace headers do not supply original SMTP authentication.

CRDF and VirusTotal results preserve each completed target even if other targets
later time out or exhaust quota/capacity. Each target retains lookup time and
recorded freshness bounds. `no_hit` means not listed, not safe. Stale observations
are unavailable. A host-root lookup, domain lookup, file hash and navigated URL
have distinct scopes; successful HTTP navigation is not a clean verdict.

The same hashed queried domain links DQS, CRDF and VirusTotal observations without
retaining a plaintext domain in this report. Historical targets with no recorded
identity are not guessed. Admission RBLs share the connecting-IP evidence group
and retain their admission-only role. Native family totals retain points and
their comparison-only role, including both raw and capped contributions. Native
LLM contributions share the LLM group: they are not another independent opinion.
Rspamd remains separate post-acceptance comparison metadata and cannot mutate
the recorded detector inputs or decision.

The English diagnostics table displays these distinctions and shared groups.
Reports are bounded to 160 observations, 48 targets per reputation provider,
32 admission checks and 32 URL chains, with an explicit omitted count. They copy
no message excerpts, provider response bodies, query credentials or URL paths.
Grouping currently documents correlations; this addition does not reweight
the production score, qualify a model, change delivery actions or activate a
provider. Cross-family contribution deduplication and qualification remain open.

## Evidence requirements for actions

The 0.28.0 release candidate adds the administrator setting
`filters.partial_actions` (Web) / `filter.partial_actions` (installation), default
`false`. In the English console it is **Apply actions when decision-specific
evidence is sufficient**. With the default, partial analyses still deliver except
for the existing primary-malware quarantine exception.

When explicitly enabled, a partial action records one of these bases:

| Basis | Required facts |
| --- | --- |
| Primary malware | The main antivirus reported trusted malware |
| Explicit recipient rule | A configured rule matched available facts; this is a policy override, not detector confirmation |
| Established threat | The existing deterministic threat rule's complete evidence requirements still hold |
| Score threshold | Completed content extraction, a finite risk index, automatic score resolution enabled, and the actual recipient threshold reached |
| Validated fusion | A usable unwanted fusion decision and completed decision-mode fusion observation; expired or unsupported fusion cannot gain action authority through legacy fallback |
| Message kind | A completed promotion/newsletter finding |

An unresolved classification without an explicit matching rule supplies no
quarantine authority. Missing facts never satisfy requirements. Delivering
without a tag requires no positive threat finding and does not establish safety.

Tagging additionally requires a ready subject renderer. The live pipeline records
ARC rendering capability before recipient evaluation; its fallback path explicitly
records that rewriting is unavailable. Thus the stored effective action and the
SMTP bytes agree even when a rule requests a tag during a failed check. Configured
Proton compatibility and ARC activation validation are unchanged.

`action.coverage` records the evaluator version, selected policy, basis, required
facts and missing facts. History, rule simulation, English details and the signed
version 5 `X-NoiseFence-Action-Coverage` header use this receipt-time trace.
Observation mode always delivers, even when the evidence requirements are met.

This is an opt-in action-policy change, not a new scoring model. Qualify it before
activation. This capability was introduced in `0.28.0-rc.1`, distinct from 0.27.0
nodes: earlier workers only receive bundles with this setting omitted/disabled.
Web activation is checked in the configuration transaction and requires a recent
authenticated report of the new build from every enabled registered MX. Unreported,
stale or older workers block the revision. Deactivation remains available. This
upgrade gate does not replace the planned atomic multi-node activation protocol.

## Exact content-index accounting

The release candidate records `scoring` in the scan and the immutable
`analysis_result.scoring` snapshot. The policy is
`content-evidence-combination-2`; its version is bound into the detector artifact
fingerprint. This report is the calculation used by the content scorer, rather
than a later reconstruction from today's configuration. Diagnostics and the
English console read the stored report. Historical records without it retain
explicitly unknown accounting. Fusion estimates remain distinct from this
content index.

The calculation keeps the existing lexical output (or fixed `-5` rules baseline
when no model applies), eligible semantic contribution and configured rule
weights. All these inputs have log-odds units. It does not add native/Rspamd
points, provider probabilities, admission RBLs or comparison predictions. Missing
semantic results supply no vote; a malformed successful result does not become a
zero. Opaque bodies explicitly skip the content models.

Recognized message-level signal IDs contribute once in a deterministic order.
Identical repeated signals cannot increase either positive or mitigating weight.
Contradictory weights for the same signal, nonfinite inputs, or an unrecognized
nonzero signal make the content index unavailable. The evaluator does not choose
the largest accusation. Zero-weight incident diagnostics remain diagnostics.
LLM weight is reconciled with the current usable, coherent, grounded opinion, so
a retained old signal cannot revive an unavailable or unsupported result. The
existing ban on using that same LLM as independent score corroboration remains.

Each recorded entry contains a fixed rule ID, family, occurrence count, proposed
weight, retained weight and adjustment code. The ledger includes lexical,
semantic, baseline, retained-rule total, total log-odds and the resulting index.
It contains no message excerpts or provider response prose. Repeated evaluations
do not add previous `model_contribution` outputs again. Invalid calculations
expose a null score, not zero, in the canonical assessment. Internally, the old
nonoptional `Scan.score` uses `-1` for this case so serialization remains finite;
consumers must use the canonical assessment and validate the 0–100 range.

Version 2 also reconciles authentication, DQS and SMTP contributions with their
structured detector results. Missing, disabled, content-only, incompatible or
unusable supporting evidence excludes a retained old signal. A completed DQS hit
survives a later target failure; PBL/BCL policy listings, provider errors and
compromised legitimate-domain codes cannot supply the malicious-domain weight.
Completed SMTP contributions retain the configured bounded applied weight;
an unavailable result cannot revive an old contribution.

When completed DMARC alignment failure consumes the same observed failed SPF
branch, the SPF penalty remains visible but contributes zero. Its ledger entry
records `subsumed_evidence` and `subsumed_by: dmarc_fail`. Missing DMARC evidence
never consumes a separately completed SPF finding. Conflicting/nonfinite input
weights still invalidate the calculation rather than being concealed by this rule.

Version 1 ledgers remain readable and are never reinterpreted. Header version 7
reads retained rules from the same immutable ledger, and adds the combination
policy and bounded adjustment codes. The main English rule list consumes the
same retained ledger after diagnostics load, shows repeated occurrences only
once numerically and labels historical/unloaded weights as proposed. Neither
surface displays repeated or consumed proposed weights as actual contributions. Receivers must support the new
adjustment variants before accepting these records; upgrade receipt/history
consumers together. Do not rewrite new ledgers into old versions to bypass a
mixed-version validation failure.

This is a behavior change requiring fresh calibration and qualification, not a
claim of improved capture or false positives. Its version participates in the
artifact fingerprint. Source/build qualification changes with this calculation.
It does **not** prove independence of all signals: the lexical model can already
encode rule-related features, and content-model/LLM correlations remain. The
bounded fusion implementation below provides a separate candidate path; fitting its family limits and independent full-pipeline qualification remain
required before replacing this index. No accuracy improvement or production activation
is claimed from these structural tests.

## Bounded learned fusion

Version `0.28.0-rc.2` supports `noisefence-fusion-model-2`. Its mandatory
`combination` policy, `noisefence-fusion-family-caps-1`, gives explicit minimum and
maximum contributions for each of eight families: lexical, semantic,
authentication, SMTP policy, reputation, main antivirus, advisory signatures and
LLM. Bounds contain zero and lie within −32 to +32 **log-odds**, not native-rule
points. No default limits are silently assigned to a model. A zero-width bound
at zero disables that family's contribution.

The model learns regularized coefficients jointly, using the capped family sums
inside its training loss. Development selection, reserved calibration, threshold
selection, evaluation and Rust prediction all apply the same caps **before**
calibration. The intercept is separate. Limits are frozen in the experiment
manifest and model bytes; editing any limit invalidates the model hash in the
qualification report. Existing version-1 models retain their original uncapped
calculation and cannot carry an unrecognized cap policy.

At runtime, `fusion.family_caps = true` must match the installed version-2 model.
The Web administrator can select the installed fusion engine's operating mode and
matching contract in **Detection engines → Learned fusion model**. Model and
validation files remain installed on the server; this control does not fit or
promote a model automatically. A mismatch is rejected before a configuration
revision is committed. Changing the actual learned limits requires a new fitting
and qualification run, rather than changing a live number outside calibration.

Decision mode for a capped model requires a version-2 promotion report, including
independent human-labelled population coverage, recall/FPR confidence bounds and
separate local/pipeline latency evidence. A synthetic report is never promotion
evidence. Web activation also requires every enabled registered MX to have a
fresh authenticated report of the capable build. Version-1 model settings remain
readable by older workers; capped bundles are refused. This compatibility gate
does not implement the separately planned atomic multi-node activation protocol.

`analysis_result.fusion_combination` records every raw/retained family total,
limits, model bias, resulting logit, cap-policy fingerprint and runtime model
fingerprint. Historical diagnostics read this immutable record. The additional
ledger is outside the old strict `Prediction` JSON type so rollback readers can
still open accepted messages. Per-feature explanations use retained
contributions after proportional family adjustment. Rspamd comparisons do not
enter this model, and primary malware priority remains independent of its score.

These limits bound aggregate influence; they do not establish statistical
independence or cure a poor base model. The existing feature vector consolidates
some repeated evidence, but normalized target groups across additional providers
still require a qualified combination adapter. Fusion's existing supported-profile
and tag-eligibility restrictions remain in force. Broader partial-coverage
classification needs its own qualification; this change does not bypass it.
