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
