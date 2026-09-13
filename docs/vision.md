# OCR, QR codes and barcodes

NoiseFence can read locally attached or integrated MIME images (`cid:`), `data:image/...;base64` images and PDF pages, including scanned PDFs. Tesseract reads English and French; ZBar decodes QR codes and its barcode formats, including EAN and Code 128. PNG, JPEG, GIF, WebP, TIFF and BMP images are supported. Remote images are never downloaded, links are not opened and documents are never executed.

## Debian / Ubuntu installation

After installing the binary and frontend of the same version:

```sh
sudo sh /opt/noisefence/current/deploy/install-vision.sh
```

Add to `/etc/noisefence/config.toml` :

```toml
[vision]
socket = "/run/noisefence-vision/worker.sock"
timeout_ms = 3000
max_parallel = 1
max_parts = 6
max_part_bytes = 4194304
max_total_bytes = 8388608
max_pixels = 8000000
max_pages = 4
max_text_chars = 16000
max_codes = 16
contribute_to_score = false
# Optional: digest shown by vision-worker.py --capabilities.
# backend_sha256 = "..."
```

Then `sudo -u noisefence /opt/noisefence/noisefence --config /etc/noisefence/config.toml check-config` and `sudo systemctl restart noisefence`. The service only receives parts selected by a local Unix socket accessible to the `noisefence` group. Each request has its process, without network, access to secrets or access to SMTP file; memory, CPU, pixels, pages, files, outputs and duration are limited. Temporary files disappear after the request. Renewing security packages can change the footprint of the backend; update a possible lock after testing.

<a id="consulter-la-lecture"></a>
## See reading

In the details of a message, the console displays the OCR result, the number of characters, pages and codes, the domains of the links counted and the reasons. The "Spam" / "Legitime" corrections remain available.

To see the exact text and values of the local file codes:

```sh
sudo -u noisefence /opt/noisefence/noisefence \
  --config /etc/noisefence/config.toml vision-inspect /chemin/message.eml
```

This command displays JSON, without delivery, database, DNS or LLM. It reads the file explicitly provided; its output may contain secrets present in QR codes. SMTP history only retains meters, indicators, technical errors and versions, never this text nor raw codes.

<a id="effet-sur-la-décision-et-limites"></a>
## Effect on decision and limitations

The domains of the retrieved links join the DQS reputation checks, when an authorized key is configured, within the common limit of twelve domains. SMTP identities remain priority, then the visual links precede the other links of the body to avoid their removal by a large footer. The recovered text also receives a separate local lexical logit, advisory: it does not replace text features of the existing model and is never added to LLM calls.

A QR code, link or text in an image is not enough to mark an email. The optional `contribute_to_score` rule adds up to 0.75 to the logit when the visual content combines urgency, ID request and link. It remains disabled by default pending independent calibration. New observations are kept for analysis; they are not entries of the current fusion model to 218 characteristics. The policy change invalidates the link of an old fusion model, which needs to be revalidated.

A failure, saturation, limit or unreadable part makes the analysis incomplete: the message is transmitted without prefix and the incident is visible. This includes documents that are too large, encrypted, SVGs and pages or frames that are surplus. Poor quality images and some QR codes can remain unreadable even when decoders end normally. This is not a guarantee of capture; false positives and capture rates remain to be measured on recent independent messages. The 500 ms p95 target of text messages is not an OCR measure; visual processing has its separate budget.

<a id="mise-à-jour-et-supervision"></a>
## Updating and monitoring

The main installer restarts the already installed worker to track the new version. When first activated, install the worker before adding the `[vision]` section. Control `systemctl status noisefence-vision.socket noisefence-vision.service`, OCR states in the console and memory limits. To go back, restore binary set, worker and configuration.

Real local tests, without email or network, on synthetic images and PDF:

```sh
sudo apt-get install --no-install-recommends qrencode fonts-dejavu-core
/usr/bin/python3 tests/vision_worker.py
sudo /usr/bin/python3 tests/systemd_vision.py
```
