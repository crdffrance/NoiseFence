# Temporary research archive

NoiseFence 0.20 can keep an independent, encrypted copy of newly accepted SMTP originals for research. It is disabled by default. This is a temporary corpus collector, not a quarantine, mailbox, delivery queue, automatic learning system or public dataset.

## Configure collection

Open **Filters → R&D archive** as an organization administrator. Enable collection, choose an absolute stop date, a retention period, a per-MX storage quota, a whole-message size limit and a domain scope. Save the configuration using the normal versioned configuration controls. Workers receive the same policy; the interface reports their individual counters and status age. An unavailable worker is not presented as an empty archive.

The initial defaults are 30 days of retention, 5,120 MiB per receiving MX and originals up to 25 MiB. Enabling the Web form without a date proposes a stop 30 days ahead. Collection can be scheduled at most 90 days ahead and retention is limited to 1–90 days. The server enforces the deadline even without a browser or a working coordinator connection. Restarting or saving another setting never extends it.

An empty domain selection includes all configured recipient domains. With a selected scope, every original envelope recipient must belong to it; otherwise the entire transaction is skipped. This prevents archiving recipients outside the research scope through a mixed-domain or blind-copy message. Original bytes are never redacted or truncated in place. Each accepted SMTP transaction has its own archive ID; delivery variants share that original.

Stopping collection leaves existing originals until their recorded expiry. A new retention value applies to future originals, without extending or shortening existing records. Expired originals cannot be exported, and maintenance deletes them in batches every 30 seconds while the service is running. Following downtime, expiry checks still deny access and maintenance catches up. When collection is stopped and the archive is empty, its encryption key is removed. To end the experiment, disable collection and allow the recorded retention periods to expire.

## What is retained

Each record includes:

- The exact MIME bytes received after SMTP dot unstuffing, before NoiseFence adds headers or modifies a subject, including attachments.
- The socket peer IP, HELO, original envelope sender and recipients, receiving hostname, receipt time and transport TLS flag.
- Application version, configuration SHA-256, original SHA-256 and local delivery-variant IDs.
- NoiseFence observations and the independent Rspamd report, when available. Maintenance updates the encrypted observation snapshot after the asynchronous comparator finishes. Interrupted or unavailable checks remain explicit; they are not invented as successful results.

The files live below `<data_dir>/research-archive`, with a separate SQLite index, a private `archive.key`, and authenticated AES-256-GCM encrypted original/context files. Nonces are random and associated data binds each object to its archive ID and kind. Directories are private and exported files use mode 0600. Anyone who can read both the files and the key can decrypt them; this does not protect against a compromised host administrator or mail-service account.

The Web provides administration and aggregate counters only. It never renders archived HTML or exposes raw originals to ordinary console users. Local exports require filesystem access to the archive and its key. Collection does not visit URLs, execute attachments, call external analysis services or train either engine. Existing separately configured live analysis remains independent.

## Delivery and coverage

Only successfully enqueued SMTP messages are eligible. Invalid or interrupted DATA, rejected enqueue attempts, generated DSNs and previously delivered history are not added. Delivered bodies continue to leave the operational spool on the existing schedule.

The collector transfers ownership of the existing original buffer to bounded background work. It allows at most eight outstanding writes and a 64 MiB admission budget for original buffers plus context allowance. Encryption uses additional bounded working buffers; the admission budget is not a claim about total process RSS. Disk writes are serialized. The archive keeps at least 2 GiB plus working headroom free, or the configured larger SMTP reserve. A separate maintenance task handles expiry and result updates.

If capacity is exhausted, an original is too large, the quota or 100,000-record ceiling is reached, or a write fails, mail delivery continues and archive counters record the gap. Lowering a quota pauses additional collection instead of silently evicting unexpired examples. An abrupt process crash can lose research jobs that were still in memory; normal shutdown gives writes a bounded drain interval. **The corpus is therefore not a lossless mail journal.** Pending research writes are separate from the strict durable-copy requirement for SMTP acceptance.

Each receiving MX owns its own corpus. **Research originals and keys are not replicated or included in built-in operational backups or console checkpoints.** The existing replicated delivery queue is unchanged. A lost MX can therefore lose its research corpus. This deliberate temporary-storage scope prevents backup generations from silently retaining new research copies after expiry. Review custom backups separately; previously configured backups of operational spool data retain their existing lifecycle.

## Local inspection and export

Run with the service account on the MX that received the message, using its usual configuration and environment:

```sh
noisefence --config /etc/noisefence/config.toml research-archive-status
noisefence --config /etc/noisefence/config.toml research-archive-list
noisefence --config /etc/noisefence/config.toml research-archive-export ARCHIVE_UUID \
  --output /private/research/example-001
```

The list shows up to 100 recent unexpired IDs, dates and sizes. The export parent must exist; the destination must be new. Export verifies authentication, the original digest and expiry, then writes `message.eml` and `context.json`. Export attempts and successful exports are audited locally with the operating-system user ID. Treat the output as sensitive mail. **The operator is responsible for removing exports and any copies: archive expiry cannot erase files copied elsewhere.** Never commit real messages, context, the index or encryption keys to an open-source repository.

An original and recorded observations are useful research evidence, not a complete reproducible snapshot of the Internet. DNS and reputation may change, LLM calls may vary, and absent observations remain absent. Keep candidate models/configurations and human annotations separately; identify a fresh online evaluation as a new experiment. Do not use either engine's verdict as a human label. A fair benchmark still needs independent, campaign-separated test data and measured false positives.
