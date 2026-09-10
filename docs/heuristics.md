# Heuristiques FR/EN expérimentales

`src/heuristics.rs` implements configurable Rust regex rules on decoded mail.
The supplied idea attachment motivates the FR/EN catalogue; its commercial
claims are not calibration evidence. This module addresses the heuristic row of
[the engine R&D programme](../research/engine-program.md). Synthetic tests verify
implementation behavior, not improved capture or a measured false-positive rate.
Production settings are unchanged by this module.

## Runtime and diagnostics

The optional `[heuristics]` table is validated at startup. The SMTP engine,
console diagnostics and private learning export preserve its versioned report.

```rust,ignore
// lib.rs: pub mod heuristics;
// Config: #[serde(default)] pub heuristics: Option<heuristics::Settings>;
// Config::validate: settings.validate()? for a configured module.

impl Settings {
    pub fn validate(&self) -> anyhow::Result<()>;
    pub fn rules_digest(&self) -> anyhow::Result<String>;
    pub fn settings_digest(&self) -> anyhow::Result<String>;
}
impl Runtime {
    pub fn new(settings: Settings) -> anyhow::Result<Self>;
    pub fn inspect(&self, raw: &[u8]) -> Report;
}
```

`Settings` and `Report` implement `Clone`, `Debug`, `Serialize`, and `Deserialize`.
Configuration rejects unknown fields. `Runtime` is `Send + Sync`; retain one
runtime (typically `Arc<Runtime>`) per immutable configuration. Its constructor
compiles each regex once and hashes settings once. `inspect` never compiles or
hashes patterns. An explicit `Settings::validate` performs its own startup
compilation and discards it; a later constructor compiles the retained set.
There is no global cache or configuration-dependent lazy mutation.

Inspection is synchronous CPU work. The shared runtime uses `spawn_blocking`,
`max_processing` clamped to 1–4 slots, and a 500 ms caller deadline. Retain the slot until actual CPU work
finishes, including after the awaiting caller times out. Busy, timeout, and join
errors have no usable report and add zero; do not invent a `Complete` report or
reuse one from another message. There is no internal wall-clock interrupt.

`Scan.heuristics: Option<Report>`, diagnostics, and learning export may persist
the report. Complete policy settings also belong in the global evidence digest.
Stable report fields are:

| Field | Meaning |
| --- | --- |
| `version` | Report schema, currently `heuristics-1` |
| `pattern_version` | Catalogue/extraction semantics, `heuristics-fr-en-1` |
| `settings_digest` | SHA-256 of typed settings and both versions |
| `mode` | `disabled`, `observation`, or `contribute` |
| `status` | `disabled`, `complete`, `limited`, or `invalid_message` |
| `findings` | Ordered matching rules, without message excerpts |
| `candidate_weight` | Matching rule sum, capped by `max_candidate_weight` |
| `contribution` | Experimental scaled sum; zero unless complete and opted in |
| `limits_hit` | Deduplicated typed limit codes, in encounter order |

Each finding has `id`, `label`, `family`, `scopes`, `matches`, and
`candidate_weight`. Scopes serialize as `subject`, `from`, `reply_to`, `body`.
Reports contain no regex source, captures, offsets, addresses, body text, URLs,
header values, or arbitrary parser errors. Labels come only from validated
operator configuration, never from mail or capture substitution. Display labels
as text in frontends. Reports have no elapsed-time field, so the same settings
and message produce identical reports.

## Observation and experimental contribution

Absent optional configuration creates no runtime. `Settings::default()` enables
observation with eleven illustrative FR/EN rules. Observation always returns zero
`contribution`, even with a calibration record. Disabled mode does no message
parsing. Empty `rules = []` is valid and matches nothing.

Each matching rule contributes candidate weight **once**, regardless of occurrence
count, matching scopes, or repeated MIME alternatives. Weights are finite and in
`[0, 10]`; the total candidate cap defaults to `10` and must be in `[0, 100]`.
There are no negative weights, whitelist semantics, rejection decisions, delivery
actions, or message modifications.

`Mode::Contribute` requires a `Calibration` record containing:

```text
pattern_version: current PATTERN_VERSION
rules_digest: Settings::rules_digest() for the exact evaluation configuration
artifact_sha256: 64 lowercase hexadecimal characters supplied by the operator
scale: finite number in [0, 1]
max_contribution: finite number in [0, 10]
```

**This is only an operator attestation with structural hash binding.** The module
does not load an artifact, verify its bytes against `artifact_sha256`, check
metrics, or prove calibration occurred. Any correctly formatted hash passes the
artifact-format check. This is not a verified quality or promotion gate. A future
production gate must load and hash the actual artifact and validate independent
evaluation metrics and its operating point; see the
[labeling protocol](../research/labeling-protocol.md).

Configuration validation restricts this experimental mode to global pipeline
`Mode::Observe` until real promotion exists. Store its contribution under the
aggregate `heuristics_experiment` signal, without outgoing tags or delivery
changes. Do not add individual finding weights again. Local `Mode::Contribute`
must not bypass that configuration restriction.

Only a complete inspection calculates
`min(candidate_weight * scale, max_contribution)`. Every `Limited` or
`InvalidMessage` report returns zero. Earlier segments can leave findings and
candidate weights in a limited report for R&D; they are not an actionable partial
score. The caller should additionally check `report.status == Status::Complete`
before using `report.contribution`.

## Rule configuration

Patterns use Unicode-aware Rust `regex` syntax, case sensitive unless they include
`(?i)`. Scopes are an OR selection evaluated independently per eligible segment.
IDs and families allow ASCII letters/digits, dot, underscore, and hyphen, at most
64 bytes. IDs must be unique; multiple rules can share a family. Labels are at
most 160 UTF-8 bytes and allow letters, numbers, spaces, and a small punctuation
set, excluding controls, bidi overrides, and markup delimiters.

This TOML is an example, not a production settings edit. Supplying `rules`
replaces the complete built-in list; it does not append to it.

```toml
[heuristics]
mode = "observation"
max_candidate_weight = 5.0

[[heuristics.rules]]
id = "custom.fr.account"
label = "Demande de vérification du compte"
family = "credentials"
scopes = ["subject", "body"]
pattern = '(?i)\b(?:vérifiez|confirmez)\s+votre\s+compte\b'
candidate_weight = 1.5

[[heuristics.rules]]
id = "custom.en.reply_desk"
label = "Security desk reply identity"
family = "sender_identity"
scopes = ["reply_to"]
pattern = '(?i)\bsecurity\s+team\b'
candidate_weight = 0.25
```

Built-ins cover credential verification, account suspension pressure, guaranteed
investment returns, prize claims, bank-detail changes, and security-desk display
names. “Vérifiez votre compte”, “Rendements garantis”, “Claim your prize”, and
“Updated bank details” match specific families. Legitimate security notices and
payment discussions can also match. These examples carry no measured spam
probabilities and do not prove malicious sender identity.

## Extraction and trust boundaries

The original message remains untouched. A bounded root-header preflight accepts
CRLF and LF archives, rejects duplicate Subject/From/Reply-To, orphan folds, bare
CR, malformed fields, and controls. `mail-parser` decodes RFC 2047 words and
folding. Decoded header controls are rejected. From and Reply-To match each
mailbox separately as `Display Name <address>` (or just the available name or
address). These are untrusted fields, not authenticated identities; the envelope
sender is not an input.

Only those three root headers are searched. Received, authentication results,
X-Spam, X-NoiseFence, list headers, historical filter headers, MIME metadata, and
attached-message headers are not features. There is no raw-header fallback for
an unparseable address. Subject text is decoded but not rewritten.

MIME transfer encoding and charset conversion precede matching, including base64
and quoted-printable. Eligible `text/plain` and `text/html` parts are separate
segments. Never concatenate headers, mailboxes, or MIME parts to construct a
match. Both plain and HTML alternatives can be observed; repetitions never
multiply candidate weights.

Explicit attachments, filename/name parameters (including inline files), attached
multipart subtrees, `message/rfc822`, non-body text, binary parts, PDF, and OCR are
excluded. The MIME library eagerly parses and can decode attachments inside the
bounded raw message; exclusion means their content is never passed to regexes.
No attachment execution or link fetch occurs. Encoding failures in inspected MIME
branches yield limited reports without searching undecoded fallback bytes. MIME
parsing is best effort, not full RFC conformance validation.

HTML uses the existing HTML5 parser (`scraper`), traversed iteratively. Entities
are decoded, inline fragments remain joined, and block elements insert whitespace.
Comments, attributes, head/script/style/template/noscript, iframe/object/SVG/canvas
subtrees, `hidden`, and inline `display:none`, `visibility:hidden/collapse`, and
numeric zero opacity are omitted. This is a static visible-text approximation:
external stylesheets, CSS classes, CSS escapes/comments, cascade overrides,
pseudo-elements, clipping, browser layout, and JavaScript are not evaluated. It
is not a browser visibility guarantee. Unicode whitespace folds to spaces;
accents and case remain. No transliteration or NFC normalization is performed.

## Resource budgets

Limits must be positive and at or below these ceilings. Oversized raw messages
and root headers are refused before MIME parsing; MIME part count and DOM node
count are checked after bounded-input parser allocations. These are work budgets,
not a process-RSS guarantee.

| Limit | Default | Hard ceiling |
| --- | ---: | ---: |
| Rules | 64 | 64 |
| Pattern bytes per rule | 2,048 | 4,096 |
| Total pattern bytes | 32 KiB | 64 KiB |
| Compiled regex size per rule | 1 MiB | 2 MiB |
| Regex DFA cache per rule | 256 KiB | 1 MiB |
| Regex nesting | 32 | 64 |
| Raw message bytes | 1 MiB | 4 MiB |
| Root header bytes | 32 KiB | 64 KiB |
| Root header fields | 200 | 1,000 |
| Outer MIME tree parts | 128 | 256 |
| Decoded segment bytes / HTML output | 128 KiB | 256 KiB |
| Aggregate decoded source / search input | 64 KiB | 256 KiB |
| Segments | 64 | 128 |
| DOM nodes per HTML part | 16,384 | 32,768 |
| Matches per rule | 8 | 32 |
| Matches across all rules | 128 | 512 |
| Findings | 64 | 64 |

Also, `max_rules * regex_size_limit <= 64 MiB` and
`max_rules * regex_dfa_size_limit <= 32 MiB`. Concurrent searches can allocate
additional scratch state, hence the shared concurrency limit remains necessary.
Settings deserialization belongs behind the host's configuration-file size limit.

No segment is prefix-truncated: oversized segments are skipped with a limit code,
preventing artificial end-of-input matches. HTML source consumes input budget
even if mostly hidden; UTF-8 entity expansion is charged too. Raw, root-header,
and part-count failures abort before matching; other skipped segments can leave
partial observations. Empty-input patterns fail startup. Contextual zero-width
matches such as `\b` stop their rule with `empty_match` and disable contribution.

Lookaround and backreferences are unsupported. Compiled-size and nesting budgets
constrain counted repetition and Unicode class expansion. Each Rust regex search
has `O(m*n)` worst-case cost. Unrestricted match iteration can be quadratic, so
each rule is limited to its match budget plus one overflow probe, also subject to
a global match budget. With fixed rule, compiled-size, segment, and match bounds,
regex work is linear in bounded input length. This applies to regex searches,
not HTML/MIME parsing or an absolute deadline. See the
[regex untrusted-input documentation](https://docs.rs/regex/latest/regex/#untrusted-input).

## Versioning and verification

SHA-256 inputs are compact Serde JSON tuples with fixed struct field order,
including `VERSION` and `PATTERN_VERSION`. Rule and scope order are significant
because priority affects bounded scans. JSON/TOML input key order does not affect
the digest after deserialization. No timestamps, random seeds, message data, or
environment-dependent map hashes enter these digests.

`rules_digest` includes ordered rules, limits, and candidate cap; it excludes
mode/calibration so observed rules can be bound without a circular hash.
`settings_digest` includes all settings, mode, artifact pin, and coefficients.
Rule/limit changes invalidate an old calibration binding. Bump `PATTERN_VERSION`
for changes to extraction, normalization, matching semantics, or built-ins; bump
`VERSION` for incompatible report changes. Parser/regex dependency changes need
revalidation and a semantic version bump if behavior changes. Golden tests pin
the default digests.

`tests/heuristics.rs` covers FR/EN examples, encoded
MIME and charsets, hidden/malformed HTML, attachment subtrees, scope/header
injection, limits and exact boundaries, adversarial nested quantifiers, zero-width
matching, configuration rejection, structural calibration binding, score caps,
content-free reports, concurrency, and version/digest round trips.

Use `cargo test --locked --test heuristics`.
These files do not deploy, publish, activate production rules, or promote a model.
