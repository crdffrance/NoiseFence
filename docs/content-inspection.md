# Bounded static content inspection

`src/content_inspection.rs` supplies an optional observation engine for HTML,
image, PDF and Office attachment characteristics. It never executes documents,
macros, scripts or image decoders, opens URLs, reads files, or performs network
IO. Findings indicate capabilities, format disagreement or gaps in inspection;
they are not malware verdicts or measured improvements in spam classification.
This module does not implement the dynamic Office sandboxing described in the
R&D source document.

## Pipeline contract

```rust
pub fn analyze(raw: &[u8], settings: &Settings) -> Report;
impl Settings {
    pub fn validate(&self) -> anyhow::Result<()>;
}
```

`raw` is a complete RFC 5322/MIME message, not a bare attachment. `Settings` and
`Report` implement `Clone`, `Debug`, `Serialize` and `Deserialize`. Settings also
implement `Default`, apply defaults during deserialization, and reject unknown
fields. Call `validate()` when loading configuration. The entrypoint validates
again: invalid settings produce `status = "invalid_settings"`, no parsing and
no findings. Validation messages contain only fixed configuration field names.

The integration contract is `Config.content_inspection: Option<Settings>` and
`Scan.content_inspection: Option<Report>`. `None` disables inspection. This module
contains no automatic score contribution, blocking policy, learning action or
fallback verdict. The SMTP engine records its report in console diagnostics and
private learning exports. The shared runtime limits concurrent blocking analyses
to 1–4 slots, with a 500 ms caller deadline.

The synchronous entrypoint has no wall-clock deadline or cancellation mechanism.
Run it on bounded blocking workers. A timeout stops awaiting a worker, not the
worker itself: retain its concurrency permit until it actually exits. A caller
that times out, cannot acquire capacity or observes a worker failure must expose
that separate execution state; an absent report cannot mean a successful scan.
Do not convert a worker panic into a complete report.

## Report and privacy

The current `version` is `noisefence-content-inspection-2`. The JSON contains:

| Field | Meaning |
| --- | --- |
| `status` | `complete`, `incomplete`, or `invalid_settings` |
| `advisory` | Always `true` for reports produced by this module |
| `truncated` | Work or distinct findings were omitted due to a configured or internal resource bound |
| `limits` | Copy of all numeric settings actually supplied |
| `stats` | Parts, decoded bytes, unpacked bytes, structure nodes, images, PDFs, Office documents and HTML parts |
| `parts` | Bounded list of inspected leaves with `index`, `kind`, decoded `bytes`, optional `width`, `height`, `frames`, and `complete` |
| `findings` | Deduplicated `{ "id": "stable_snake_case_id", "part": integer_or_null }` records |

Revision 2 (0.5.0-dev.7) changes PNG completeness: an ordinary highly compressible
image can complete when its exact declared scanline size fits both absolute
unpacked-byte budgets. Revision 1 incorrectly applied the generic ratio limit.
Historical reports remain readable. The native fusion binding and Python trainer
require revision 2 for new structural observations; revision-1 structural models
must be re-exported, trained and validated before use with this detector. Their
digests must not be edited to bypass the mismatch. Fusion without a structural
binding and the frozen feature catalogs are unchanged.

A **complete** report means the advertised static checks completed within their
scope. It never means safe, virus-free, renderable, or free of macros. Incomplete
reports retain earlier findings and can still be useful. Unsupported formats,
encryption, malformed input and uninspected embedded content are incomplete even
when no resource limit was exceeded. Thus `truncated = false` is not evidence of
complete inspection. Finding overflow sets incomplete/truncated without exceeding
`max_findings`; the last recorded ID need not describe that overflow.

`stats.parts` counts visited MIME entities, including multipart containers and
nested messages. Part indices are traversal ordinals, **not offsets into the
`parts` array**. A header/transfer-decoding failure may have a finding and no leaf
report. Multipart failures can affect the overall report while an individual
completed child remains complete. Image/PDF counts describe MIME candidates
selected by signature or metadata, including malformed candidates. GIF frames
are a separate per-part count. HTML referenced remote images and images/pages
inside PDFs or ZIP members are not included in these counts. Office counts
include recognized Office ZIPs and CFB MIME candidates, not nested VBA projects.

Reports contain no source text, filenames, paths, sender addresses, URL values,
macro source, object strings, hashes of message material, or parser exception
text. `kind` and finding IDs come from closed enums. Numeric size/dimension/count
metadata is intentionally retained. Do not add raw decoder errors to downstream
logs. Tests exercise JSON round trips and absence of planted secrets.

## Resource bounds

MiB means 1,048,576 bytes. All limits are checked at runtime as well as configuration
validation. Byte, structure and finding counters are shared across the message.

| Setting | Default | Valid range / relationship |
| --- | ---: | --- |
| `max_raw_bytes` | 8 MiB | 1–16 MiB; checked before MIME parsing |
| `max_parts` | 64 | 1–256; checked before descending to another entity |
| `max_mime_depth` | 8 | 1–16; root has depth 0 |
| `max_header_bytes` | 32 KiB | 1–64 KiB, including header/body separator |
| `max_part_bytes` | 4 MiB | 1–8 MiB and no greater than total decoded budget |
| `max_total_decoded_bytes` | 8 MiB | At least per-part limit and at most 16 MiB |
| `max_html_bytes` | 256 KiB | 1–512 KiB, checked **before** HTML5 tree construction |
| `max_archive_entries` | 256 | 1–1024 ZIP records / visited CFB entries per container |
| `max_unpacked_bytes` | 4 MiB | 1–8 MiB per inflation/member |
| `max_total_unpacked_bytes` | 8 MiB | At least per-inflation limit and at most 32 MiB |
| `max_compression_ratio` | 100 | 1–200; PDF/ZIP output ≤ compressed input × ratio; PNG uses its exact IHDR length and the absolute byte budgets |
| `max_structure_nodes` | 50,000 | 1–100,000 shared tokens/nodes/chunks/blocks/records |
| `max_nesting` | 32 | 1–64 PDF values/literal parentheses, XML depth, CFB path components |
| `max_findings` | 128 | 1–512 distinct `(id, part)` pairs |
| `max_image_pixels` | 16,000,000 | 1–100,000,000; advisory dimension threshold |
| `max_images` | 20 | 1–256; advisory count threshold, does not skip later images |

Nested messages charge both their decoded envelope and their children to the
decoded budget. Stored ZIP members also consume the unpacked budget. Inflation
uses fixed 8 KiB scratch buffers, checks actual output independently of declared
sizes, and may read a single probe byte beyond a cap to detect overflow. That
probe is not retained or included in `stats.unpacked_bytes`. Allocation capacity,
parser trees, metadata and transient copies are additional overhead; these
settings are not a process RSS quota.

MIME headers are parsed separately using `mail-parser`, after bounding their
input. Multipart delimiter traversal stops before the next part allocation;
base64 and quoted-printable decoding are bounded and invalid encodings are not
silently treated as decoded data. HTML node limits apply during traversal;
HTML5 tree construction is bounded by the HTML input cap, **not** by the later
node counter. CFB initialization likewise precedes entry traversal: its actual
reader is additionally limited to four times input bytes read and twice input
bytes in read/seek operations. This prevents repeated-sector amplification in a
malicious FAT/DIFAT from consuming unbounded parser reads or allocations. CFB
stream buffers are configured to 8 KiB. There is no claim of a hard execution-time
or operating-system memory limit.

## Structural coverage

### HTML

The existing `scraper`/HTML5 parser provides entity decoding, element/attribute
parsing, foreign content handling, comments, raw-text handling and browser error
recovery. Checks identify active elements, event attributes, JavaScript/VBScript
URL schemes (including entity encoding and permitted embedded ASCII whitespace),
meta refresh, `srcdoc` and data URLs. Attribute values are inspected transiently.
Comments or text that merely mention script syntax do not count as elements.

No JavaScript or CSS is evaluated. Data URLs and `srcdoc` are presence signals,
not recursive analysis. This is not a sanitizer or an exact simulation of every
mail client, legacy CSS extension, template activation or DOM mutation. Only
UTF-8/ASCII HTML is covered. Other declared charsets, non-UTF-8 or NUL-bearing
input, and HTML encoding overrides are incomplete. Unlabelled HTML hidden in an
unknown binary attachment is not automatically recognized; that attachment is
unsupported/incomplete. HTML mislabeled as ordinary unadorned text/plain can
remain outside HTML coverage, as it would not normally render as HTML.

### Images

Signature, declared MIME type and recognized filename extension are compared.
Signatures select the actual parser, so a PNG labeled JPEG still gets PNG checks.
Unexpected bytes after a supported image terminator are incomplete and flagged
as trailing data, including common appended polyglots. This does not prove the
absence of every possible polyglot.

* PNG: chunk framing, CRCs, IHDR dimensions/bit-depth/color combinations, palette
  presence, IDAT ordering, complete bounded zlib inflation, exact non-interlaced
  row byte count and scanline filter values. Interlaced PNG, APNG and unknown
  critical chunks are unsupported/incomplete. Pixel reconstruction, color
  semantics and all optional-chunk ordering rules are not validated.
  Inflation checks each scanline filter with fixed 8 KiB scratch storage, without
  retaining pixel rows. Exact IHDR size, full stream consumption, checksum and
  both absolute unpacked-byte caps are required. The length calculation follows
  the [PNG scanline and compression specification](https://www.w3.org/TR/png-3/#10Compression).
  A forged shorter declaration is detected with at most one discarded extra
  byte. PDF and Office inflation still enforce the compression-ratio limit.
* JPEG: bounded markers and segment lengths, supported SOF dimensions, SOS
  framing, entropy byte stuffing/restart markers and EOI. Baseline/extended and
  progressive DCT headers are covered; other SOF types are incomplete. Huffman
  tables, coefficient decoding and pixel validity are **not** validated.
* GIF: logical dimensions, color-table extents, block/sub-block framing, frame
  rectangles within the canvas, LZW code-size range and trailer. Frame counts
  come from image descriptors. LZW output, extension semantics and pixel validity
  are **not** validated.
* Other image formats are unsupported/incomplete. No image is rendered or sent
  to the vision worker by this module.

Large dimension/count findings are conservative characteristics, not evidence
that an image is spam. The metadata-only JPEG/GIF contract can complete for a
framed image whose compressed pixels would fail an actual decoder.

### PDF

A dedicated bounded lexical/object parser distinguishes names, numbers,
references, arrays, dictionaries, literal strings, hexadecimal strings and
comments. `#xx` escapes are decoded inside names. Active-name findings therefore
come from parsed names, never keyword searching strings or binary stream data.
Physical objects across incremental sections are inspected conservatively,
including superseded objects; this can report inactive historical content.

Stream extents use **direct** `/Length` values. Uncompressed and single-Flate
`/ObjStm` streams are parsed using validated `/N`, `/First`, unique object IDs and
ordered offsets. Inflation requires a real Deflate/zlib end marker and consumes
all supplied compressed bytes; truncation, trailing compressed junk and bombs
are not accepted. Stream payloads are never delimited by searching for the word
`endstream`.

True limitations:

* Indirect stream lengths stop parsing with `pdf_unsupported_structure`. This
  deliberately covers a common valid-PDF case as incomplete rather than guessing
  binary boundaries. Later physical objects then remain uninspected.
* Non-Flate filters, filter chains and object-stream decode parameters are
  incomplete. Encrypted PDFs and embedded file payloads are incomplete.
* Ordinary content/image/font streams are not decompressed or semantically
  validated. Cross-reference streams are not decoded; xref tables receive basic
  framing/range checks, without complete reference resolution, page-tree
  validation or renderer-equivalence guarantees.
* No JavaScript execution, page rendering, OCR, PDF image extraction or page
  dimension/count validation. Active names show syntax presence, not reachability
  or malicious behavior.

### Office ZIP / CFB

Classic single-disk ZIP central records and local extents are preflighted **before**
constructing `zip::ZipArchive`. Checks include actual record counts, local/central
name and method agreement, sizes, CRCs, data descriptors, extents and duplicate
case-folded names. Only stored and Deflate members are covered. Actual bounded
inflation additionally requires exact compressed-stream consumption. No member
is extracted to disk. Entry names are capped at 512 bytes and extra fields at
4096 bytes. ZIP64, encryption, unsupported flags/methods, split archives,
non-contiguous or overlapping extents, path traversal, percent-escaped names,
backslash names and ambiguous records are incomplete. Some valid but unusual ZIP
layouts therefore remain incomplete.

Office candidates are identified by `[Content_Types].xml`. That file and `.rels`
members are parsed with the namespace-aware `quick-xml` parser, with explicit
nesting/event bounds and end-tag checks. XML 1.0 is supported (implicit or explicit);
XML 1.1 and other declarations/encodings are incomplete. DTDs and general entity
references are unsupported and never resolved. Attributes use XML 1.0 entity
normalization. Wrong/missing OPC namespaces and wrong roots are incomplete;
this is not full OOXML schema validation.

The parser records macro-enabled content types, VBA project parts/relationships,
XLM macrosheet package entries, external relationships and embedded-object
relationships. Marker findings describe presence/declarations; they do not prove
that a well-formed executable macro project exists. A `vbaProject.bin` member is
also passed to the CFB parser. Case-folding is conservative. Nested archives,
embedded objects and opaque binary Office parts such as XLSB are incomplete.
Unknown generic ZIP archives are incomplete even if their CRCs can be checked.

CFB uses `cfb::OpenOptions::strict()` over bounded in-memory reads. Storage trees,
FAT/DIFAT and directory structure are parsed by the real CFB implementation;
validated entries named `VBA`, `_VBA_PROJECT` or `_VBA_PROJECT_CUR` supply VBA
presence signals. Encryption and embedded-object markers are reported. Every
CFB inspection includes `office_legacy_coverage` and is **incomplete**: stream
payloads, VBA source/p-code, macro execution, legacy BIFF XLM macros, WordBasic,
DDE and all encryption variants are not comprehensively decoded.

## Stable finding IDs

All IDs are serialized snake_case and deduplicated by MIME part. There is no
freeform message or severity field.

| Area | IDs |
| --- | --- |
| MIME / budgets | `raw_limit`, `part_limit`, `mime_depth_limit`, `header_limit`, `decoded_limit`, `malformed_mime`, `unsupported_encoding`, `html_limit`, `structure_limit`, `decompression_limit` |
| HTML | `html_active_element`, `html_event_handler`, `html_active_url`, `html_refresh`, `html_embedded_content` |
| Types / images | `type_mismatch`, `unsupported_format`, `image_dimensions`, `image_count`, `image_structure_invalid`, `trailing_data` |
| PDF | `pdf_active_name`, `pdf_malformed`, `pdf_encrypted`, `pdf_unsupported_filter`, `pdf_unsupported_structure`, `pdf_embedded_file`, `pdf_external_reference` |
| ZIP | `archive_malformed`, `archive_entry_limit`, `archive_encrypted`, `archive_unsupported`, `archive_ambiguous` |
| Office | `office_vba_project`, `office_macro_enabled`, `office_xlm_macros`, `office_external_relationship`, `office_embedded_object`, `office_malformed_xml`, `office_unsupported_xml`, `office_encrypted`, `compound_malformed`, `compound_io_limit`, `office_legacy_coverage` |

## Dependencies and verification

The manifest locks these direct dependencies:

```toml
flate2 = { version = "1.1", default-features = false, features = ["rust_backend"] }
crc32fast = "1.5"
zip = { version = "8.6", default-features = false, features = ["deflate-flate2"] }
cfb = "0.14"
quick-xml = "0.42"
```

Existing `anyhow`, `base64`, `mail-parser`, `scraper` and serde dependencies are
reused. No optional plugin or external worker is required.

Focused unit tests live in `tests/content_inspection/cases.rs`, included only
under `#[cfg(test)]` by the module:

```sh
cargo test --offline --lib content_inspection::tests
```

The suite covers strict settings and report serde, privacy, MIME transfer and
nesting budgets, HTML entity/raw-text behavior, image framing and CRC failures,
PDF escaped names, lexical false positives, Flate object streams, truncated and
forged compression, ZIP record inconsistencies, encryption, XML version/namespace
semantics, VBA CFB storage, malicious FAT read amplification, and deterministic
truncation/bit-mutation probes. These are regression tests, not a formal parser
verification, full fuzzing campaign, antivirus validation or corpus-based spam
accuracy measurement. No deployment or publishing is part of this change.
