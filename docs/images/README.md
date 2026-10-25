# README screenshots

These are unedited browser captures of the actual English NoiseFence console, taken on 2026-10-04 with the local 0.29.3 development binary at a 1440 × 1050 viewport. WebP quality 85 keeps the three files small without introducing external image hosting.

All six messages and all addresses are synthetic. The instance uses `example.test`, a separate local data directory, loopback SMTP and HTTP listeners, observation mode, no external provider credentials and no trained model. SMTP authentication checks are disabled for this isolated fixture. The upstream test sink is absent, so messages remain queued and display **In progress**. No production mailbox, recipient, secret, learned model or traffic statistic appears in these images.

The displayed scores are actual demo outputs, not manually edited values or a quality benchmark. In particular, the synthetic security exercise does not measure phishing detection with configured engines. The optional marketing classifier and external checks are not enabled.

| File | Console view |
| --- | --- |
| `console-messages.webp` | All messages: scope, search, classifications and delivery |
| `console-analysis.webp` | Invoice message: verdict, index, coverage, action and feedback |
| `console-filters.webp` | Administration → Filters: policy and settings navigation |

## Refreshing the captures

1. Build the console and binary from the release being documented. Follow the development section of the root README.
2. Copy `config/development.toml` to a private configuration. Set a **new isolated data directory**, free loopback ports, the exact browser origin and the built static directory. Keep observation enabled, authentication checks disabled and external providers unconfigured. Never point this fixture at a production database or upstream.
3. Run `init` and `user-add demo-admin --admin` with that configuration; choose a local disposable password. Start `serve`.
4. Follow the synthetic SMTP example in [installation](../installation.md), using only `example.test` addresses. Suitable subjects include project updates, an invoice, a meeting confirmation and a newsletter. Do not import real messages or annotate demo results as production ground truth.
5. Open a fresh browser session, sign in locally, set the viewport to 1440 × 1050, and capture the three views above after loading completes. Use the browser's WebP screenshot output at quality 85; do not alter verdicts, scores or UI elements for the capture.
6. Inspect every image at full size for readability and private data, update this provenance note, and stop the demo server. Keep demo configuration, credentials and queue data out of Git.

If configured models or providers are needed for future screenshots, document that change and obtain the appropriate authorization before transmitting any content. Keep screenshot data synthetic and do not present demo scores as measured accuracy.

## Identity workspace captures

`console-directory.jpg` was captured on 25 October 2026 from the local Vite
browser-memory fixture in the integrated browser, at a 1280 × 720 viewport:
`http://127.0.0.1:3013/demo.html?administration=identity`.
It shows **Filters → Identity protection → Organization directory → People**,
scrolled to the directory workspace. Names, revision, source generation and
freshness are synthetic values. The screenshot is an unedited JPEG captured from
the running development UI. It is not a connected tenant, SMTP analysis or
production mailbox. The feature is not part of previously published archives.

`console-identity.webp` is the earlier 1440 × 1200 capture of the domain-based
protected-name editor, now available under **Domain-based name checks**.

Refresh using the [console preview procedure](../console.md#identity-editor-preview).
Select the synthetic organization source and capture the rendered page without
changing UI elements or values for the image. Keep real identities, provider
credentials and message data out of these captures. Inspect every image for
readability and private data before adding it to documentation.

### Automatic correspondent memory

`console-contact-memory.jpg` is an unedited 1280×720 browser capture from the
local synthetic administration demo on 25 October 2026. It shows reviewed memory
settings, not a connected production installation or measured detection accuracy.
The sample contains no real messages, identities, keys or provider accounts.

- `console-entra-sync.jpg`: unedited local in-app browser capture on 25 October 2026, 1280×720. Synthetic Entra collection and installed policy result only; no tenant connection, actual directory, real credential or email was used.

`console-okta-sync.jpg` is an unedited local browser capture of the directory
workspace after a simulated Okta candidate has been reviewed and applied in the
synthetic demo. Names, source data, revisions and receipts are fixtures. No
production identities, OAuth tokens or connected provider are shown.

`console-contact-comparison.jpg` is an unedited 1280×720 integrated-browser capture
from `http://127.0.0.1:3013/demo.html?contacts=1&case=spam` on 25 October 2026.
It demonstrates a recurring claimed address whose current DKIM alignment failed,
excluded from automatic learning but compared with authenticated history. Every
message, identifier and result is synthetic; no production accuracy is implied.

`console-google-sync.jpg` is an unedited 1280×720 integrated-browser capture on
25 October 2026 from the local synthetic identity demo. It shows the Google
candidate review and explicit membership coverage exclusions. Customer, names,
counts, token and responses are fixtures; no external provider was contacted.

`console-directory-access.jpg` is an unedited 1280×720 integrated-browser capture
on 25 October 2026. The local identity demo shows explicitly saved access and a
separate completed collection receipt. Source, tenant UUID, account, generation,
expiry and provider response are synthetic; no real secret or identity provider
was used. Saving, collection, replacement and revocation were verified in the
browser-memory fixture. This image does not establish production readiness.

`console-directory-schedule.jpg` is an unedited 1280×720 integrated-browser capture
from the local identity demo on 25 October 2026. It shows the separate finite
background-collection authorization. Tenant, owner and credential are synthetic;
the browser-memory fixture does not run a provider scheduler or contact an IdP.
The authorize → recorded → stop → stopped flow was checked visually while the
installed policy remained revision 25. Actual durable scheduling is covered by
SQLite/PostgreSQL and synthetic collector tests, not established by this screenshot.

## Identity correlation capture

`console-identity-correlation.jpg` is an unedited 1280 × 720 integrated-browser
capture from 25 October 2026, using the synthetic Vite fixture
`http://127.0.0.1:3013/demo.html?administration=identity&contacts`.
It shows the **Corroborated identity changes** report in observation mode. The
proposal, historical campaigns and SMTP results are fixture data, not measured
traffic or detector accuracy. No real sender, mailbox, credential or provider
request is included. A separate draft-policy exercise was cancelled; the demo's
installed observation revision remained unchanged.

`console-memory-private.jpg` is an unedited 1280×720 integrated-browser capture
from `http://127.0.0.1:3013/demo.html?administration=identity&contacts=` on 25 October
2026. It shows the corrected contribution settings and private-key readiness in
the synthetic memory fixture, after a disable/review draft was cancelled. Installed
revision 25 and observation were retained. No real secret, message, provider or
production host was used. The synthetic readiness label is not a deployment proof.

`console-aws-directory.jpg` is an unedited 1280×720 local integrated-browser
capture on 25 October 2026. It shows the AWS read-only connection form with an
example source and no credentials. The collection button remained disabled, the
draft was discarded, and revision 25 stayed unchanged. No AWS account or real
identity was connected.

`console-ad-import.jpg` is an unedited 1280×720 integrated-browser capture on
25 October 2026 from the local identity demo. It shows the signed AD upload form
after simulated public-key enrollment. The source, authority, UUID and saved
access state are synthetic browser-memory fixtures. No live AD connection or
server-side key enrollment occurred. The upload draft was cancelled and policy
revision 25 remained in observation. The Rust API is tested independently with
signed synthetic exports; the screenshot does not prove Windows AD compatibility.
