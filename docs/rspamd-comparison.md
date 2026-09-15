# Independent Rspamd comparison

NoiseFence 0.19 adds an optional **local Rspamd 4.1.5 scanner on each receiving MX**. It is separate from NoiseFence's native Rust rules inspired by Rspamd. It observes new accepted SMTP messages and never changes NoiseFence scores, analysis completeness, headers, LLM selection, delivery or training labels.

The original MIME bytes, socket IP, HELO, envelope sender and original envelope recipients are posted to `/checkv2` on a literal loopback address. Rspamd performs its own reverse DNS lookup. No recipient rewriting, subject tags or NoiseFence-generated headers are included in that request. The comparison runs alongside NoiseFence and waits asynchronously for the durable enqueue result before saving its report. The SMTP session never waits for Rspamd. A failed SMTP enqueue cancels the comparison.

## Console

Open **Engine comparison** in the mail navigation. Use **More filters → Engine comparison → Engines disagree** to prioritize human review. Domain and advanced search criteria apply, and users only see messages covered by their current recipient grants. Counts use that same scope and deduplicate delivery variants by comparison job (or original transaction ID when no comparison exists); historical rows without either identifier are counted separately. Pagination still counts delivery variants. An organization administrator sees the organization view.

Message details show the NoiseFence index / 100 next to the **signed Rspamd points**, its reported threshold, proposed action, rule symbols and elapsed time. These are different scales. The Rspamd action is never executed. `add header`, `rewrite subject` and `reject` are compared with NoiseFence's recorded unwanted verdict; `no action` and `accept` with its legitimate verdict (including marketing). Recipient-specific delivery policies remain separate. Greylisting, soft rejection, custom actions and an undetermined NoiseFence verdict are inconclusive. Historical decisions are not reconstructed using today's threshold.

The report includes the installed profile identity, comparison settings SHA-256 and server identification when returned. Only symbol names and numeric contributions are retained; symbol options, URLs, email addresses, suggested rewrites and the raw Rspamd response are discarded. This prevents another recipient's address from appearing through Rspamd options.

**Agreement is not accuracy.** The agreement denominator contains only comparable completed verdicts. Coverage also includes historical messages, skipped work and failures. An early Rspamd decision, such as GTUBE, can contain valid points with `is_skipped=true`: those points are displayed, but the skipped scan is excluded from agreement statistics. Use human annotations on both disagreements and a random sample of agreements to assess quality.

## Administrator controls

Under **Filters → Engines → Rspamd · independent comparison**, an administrator can enable or disable comparison, set its sampling percentage, message-size ceiling, concurrent scans, waiting jobs and deadline. These organization settings are versioned and distributed to the MX workers. Users can inspect comparisons for their own messages; they cannot change an organization-wide comparison through personal preferences.

Defaults after installation are 100% sampling, 4 MiB per message, 2 concurrent requests, 4 waiting jobs and a 5-second deadline **including the wait for a scanner slot**. The feature is disabled in the example configuration. Admission never waits; saturation produces `busy`. Raw messages are not truncated for comparison. Oversize messages and messages outside the deterministic transaction-ID sample have explicit statuses. Supplier errors are not spam evidence.

The process shares its admission gates and a fixed **64 MiB original-buffer budget** across configuration revisions. At most 8 concurrent requests and 32 waiting jobs can be configured, with the additional aggregate memory constraint. HTTP responses are bounded at 128 KiB, with at most 512 symbols. Redirects and environment HTTP proxies are disabled. Endpoints and installed profile identities remain host installation parameters; Web patches and coordinator bundles cannot replace a worker's local endpoint or profile.

## Debian installation

Use a maintained, signed package from the [official Rspamd stable repository](https://docs.rspamd.com/downloads/). The supplied profile is audited for **4.1.5**, including its MIME recursion security fix. Check the package version before installation. Do not enable the vendor service alongside an existing mail integration. On a fresh NoiseFence MX with no Rspamd integration:

```sh
# As root, after configuring the official signed APT repository:
systemctl mask rspamd.service
apt-get update
apt-cache policy rspamd
apt-get install --no-install-recommends rspamd

# From the verified NoiseFence release directory:
sudo sh deploy/install-rspamd.sh 127.0.0.53
```

The DNS argument must point to an installed **local caching resolver** (supported addresses: 127.0.0.1, 127.0.0.53 or 127.0.0.54). Verify it can resolve public SPF, DKIM, DMARC, PTR and address records. The service permits loopback network traffic only, so using an external resolver directly will fail.

The installer creates a separate `/etc/noisefence-rspamd` profile and `noisefence-rspamd.service`. It refuses an existing profile or an active vendor Rspamd service. It does not change NoiseFence's configuration or restart NoiseFence. Rspamd listens only on `127.0.0.1:11333`; no controller, proxy, learning endpoint or public port is enabled. Its service has a 384 MiB memory cap, 50% of one CPU, 32 tasks, an unprivileged account and no capabilities. Network filtering also blocks accidental outbound content requests by future modules. Check that systemd's IP filtering is supported on the host; retain the firewall restriction as well.

Append the fragment from `config/rspamd.example.toml` to the host configuration. Replace `profile` with the exact contents of `/etc/noisefence-rspamd/profile-id`, keep `enabled=false`, run `noisefence --config /etc/noisefence/config.toml check-config`, then restart NoiseFence. Enable comparison in the console once the local scanner is healthy. The profile manifest hashes the installed executable, package rules/modules/maps and comparison configuration. The service verifies those hashes before starting. After a package or profile update, stop comparison, generate and verify a new profile, update its identity in the host config, and restart both services. Do not overwrite an existing profile while it is running.

The initial profile includes packaged header, MIME, HTML, URL-text, identity and authentication rules. It omits Bayes classifiers, neural learning, Redis history, external fuzzy services, RBL providers, GPT/LLM plugins, URL visits, signing and content exporters. Packaged maps are used instead of remote map updates. This is a reproducible rules/authentication baseline, **not a trained Rspamd deployment with all external services**. Rspamd may log missing dependencies for freemail composites whose external modules are disabled, and a warning that the controller is intentionally absent. Neither warning enables those checks or services.

## Multiple MX servers and availability

Upgrade every node to 0.19 or later before enabling comparison. During a coordinator-first upgrade, bundles sent to older supported workers omit the new comparison settings. Install the local scanner and disabled host configuration on **every node first**, then activate the shared policy. Otherwise a worker will refuse a policy requiring a local scanner that is not installed.

Each accepted message initially contains a pending or skipped comparison report. After enqueue, the owning MX patches **only** that report. Existing HA and worker-history triggers replicate the metadata update; they do not transfer queue ownership or rewrite the delivered body. Strict two-copy acceptance remains unchanged. A crash can lose the RAM-only comparison job, not an accepted message. After its bounded completion window, a pending report is displayed as interrupted. Comparisons are never replayed from retained/delivered mail.

Raw comparison buffers are released when the bounded request ends. They do not create a new message archive or delay body deletion after delivery. Reports follow the existing metadata retention and recipient authorization rules. A failed comparator, unavailable DNS, full comparison queue or a comparison metadata-write failure never prevents delivery. Pending metadata that cannot be saved becomes interrupted rather than a fabricated score.

To roll back the comparison, disable it in the console and stop `noisefence-rspamd.service` on each MX. Returning to a pre-0.19 binary also requires removing the new host and Web comparison settings through the normal versioned configuration/rollback procedure. Do not restore an old mail database over accepted traffic.

## Validation and operations

Run `cargo test --locked rspamd --lib`, `cargo test --locked --test message_search rspamd`, the Web tests, and the isolated real-scanner smoke test in `tests/rspamd_smoke.py`. All test messages are synthetic and stay in the test container. The SMTP test deliberately holds the Rspamd response and verifies durable SMTP acceptance proceeds. Other tests cover malformed responses, bounded capacity, grant isolation, cancellation and metadata-only replication.

In production, inspect `systemctl status noisefence-rspamd`, its journal, comparison coverage and the pending/unavailable filters. Check both MX identities and profile fingerprints. Validate a recent human-labeled sample before drawing conclusions about false positives or capture rate; an empty or old corpus cannot establish either.
