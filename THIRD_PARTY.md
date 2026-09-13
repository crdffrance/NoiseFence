# Composants tiers

The NoiseFence code is distributed under GPL-3.0-only. Dependencies keep their respective licenses. `Cargo.lock` and `web/package-lock.json` identify the exact versions and allow their sources to be found in official records.

The server uses, among other things, Tokio, rustls/ring, mail-auth, mail-parser, Axum, rusqlite/SQLite, Argon2 and reqwest (MIT/Apache-2.0). The graphical components are derived from shadcn/ui (MIT) and Base UI (MIT), with React (MIT) and Lucide (ISC). The generated components in `web/components/ui` are derived from shadcn/ui; their records are reproduced in `licenses/shadcn-ui-MIT.txt`.

The release build collects the license texts available from the sources of the npm crates and packages installed under `third-party-licenses`. The JSON manifest in this folder links each dependency to its license declaration and records.

The public corpus SpamAssassin downloads separately at the operator's request. The corpus emails, trained models and user annotations are not distributed as project code.

ClamAV installs separately and retains its GPL license. The optional program clamav-unofficial-sigs retains its BSD-3-Clause license and its original mentions; the downloader also recovers its LICENSE file, to be installed with the program. The signature bases have their own terms of use and are not redistributed in the NoiseFence archives. The manifest pins the sources of the program, not a perpetual copy of the databases. Scaleway access falls under the account and the conditions of the provider; no LLM model or secret is distributed.

The optional OCR worker uses the Tesseract system packages and its English/French, ZBar, Pillow and Poppler data. They install separately via Debian/Ubuntu repositories; no third-party OCR binary or file is included in the NoiseFence archive. Their records and licenses are provided by the packages under `/usr/share/doc`. `vision-worker.py --capabilities` records the actual versions and prints of OCR data to trace the backend used.

The link protection uses scraper (ISC) and html5ever (MIT/Apache-2.0), as well as psl (MIT/Apache-2.0) and its public Suffix List embedded. IDNA retains its MIT/Apache-2.0 license. The records in the crates are collected with those of other dependencies. CRDF and VirusTotal APIs and phishing streams are optional, subject to vendor licenses; no data set, secret or redistribution rights are included in NoiseFence.

`src/native_filter/content_rules.rs`'s structured Rust rules are an independent implementation, inspired by the HTML, MIME and D-header controls of Rspamd (Apache-2.0). The sources consulted are pinned to the `e2de26d28ce857d5c48ac82703cf26b681bd1d89` revision; their correspondence and differences are documented in `docs/rspamd-rules.md`. The upstream notice is kept in `licenses/rspamd-Apache-2.0.md`. No Lua/C code, remote list, prompt GPT nor weight of a Rspamd model is embedded or executed.
