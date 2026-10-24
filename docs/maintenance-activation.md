# Coordinated native release activation

`deploy/postgresql/upgrade_activation.py` continues the [held promotion procedure](maintenance-promotion.md).
It implements durable host promises, one coordinator decision, ordinary startup,
fresh runtime verification and completion. Use the complete reviewed helper
directory on both hosts; Python 3.11+ and the native Linux/systemd layout are
required. Release-origin authentication, archive staging, backup/restore and
exact-release qualification remain prerequisites.

This is an operator-driven protocol, not an unattended updater or a Web installer.
Reports must move over authenticated channels with verified host identities. The
[restricted SSH completion helper](maintenance-exchange.md) automates the final
proof/verification/finish sequence after both normal daemons have started. Keep
them in physical root-owned mode-0600 files under private directories. Their
hashes bind identities and contents; they are not cryptographic signatures. Root
is the trust boundary. Do not accept reports from messages or untrusted HTTP input.

## Decision boundary

Before either ordinary daemon starts, both hosts must durably promise to retain
the promoted pair, and both must record the same `activate` decision. A worker
cannot promise first: it requires the coordinator's durable `armed` report. This
ensures an abort authority exists if the second preparation fails or expires.

Once a host is armed, the earlier promotion `restore` and reservation `cancel`
commands refuse. Only the recorded coordinator can choose `activate` or `abort`.
That choice is immutable. No timeout, controller disconnect or failed startup
changes it. An `abort` decision restores the original pair before resuming normal
services. An `activate` decision requires forward recovery of the committed pair;
it does not permit a silent downgrade after a candidate may have written data.

Persistent records are under `/var/lib/noisefence-upgrade`:

- `<UUID>-activation.json`: full pair, decision and progress;
- `activation.json`: active owner, retained through recovery;
- `activation-jobs.json`: additional hold for auxiliary services and timers.

The existing host operation lock serializes each command. The persistent markers
retain ownership between commands and across reboots. Both source epochs,
management database, original/candidate manifests, policy and service definitions
remain bound to the prepared reports. Ordinary operation begins only after the
durable decision, including normal Web APIs and in-process delivery/retention.
Auxiliary systemd jobs remain stopped until both runtimes are verified.

New promises and new `activate` decisions require a strictly newer candidate
version on both nodes. Earlier uncommitted downgrade preparations can still be
aborted and restored. An already durable `activate` decision remains immutable:
recovery continues that exact committed pair, even if its receipt predates this
version-direction check. This exception recovers existing state; it does not
authorize a new downgrade or same-version replacement.

## Arm the pair

First promote both release pointers under their existing holds, keeping both
promoted reports. Run the following in root shells with `umask 077`. Set
`OPERATION` to the same canonical UUID used for reservation and promotion; use
fresh output filenames and keep the preceding evidence.

On the **coordinator**, with the worker's promoted report:

```sh
python3 /usr/local/libexec/noisefence-management/upgrade_activation.py arm \
  --operation "$OPERATION" --peer-report /root/worker-promoted.json \
  > /root/coordinator-armed.json
```

Transfer that report to the **worker** and arm it:

```sh
python3 /usr/local/libexec/noisefence-management/upgrade_activation.py arm \
  --operation "$OPERATION" --peer-report /root/coordinator-armed.json \
  > /root/worker-armed.json
```

A durable receipt is written before its marker. Even if that second write fails,
the earlier cancellation paths detect the receipt and remain blocked. `status`
returns saved progress without starting services or claiming live readiness.

## Commit and start

On the coordinator, import the worker's armed report and record the decision:

```sh
python3 /usr/local/libexec/noisefence-management/upgrade_activation.py decide \
  --operation "$OPERATION" --outcome activate \
  --peer-report /root/worker-armed.json > /root/coordinator-decision.json
```

The decision requires both valid promises and an unexpired preparation. Transfer
it to the worker and record the identical decision there:

```sh
python3 /usr/local/libexec/noisefence-management/upgrade_activation.py accept \
  --operation "$OPERATION" --peer-report /root/coordinator-decision.json \
  > /root/worker-decided.json
```

Transfer the worker's decided report back. Start the coordinator using that
report, and start the worker using the coordinator's decided or started report:

```sh
python3 /usr/local/libexec/noisefence-management/upgrade_activation.py start \
  --operation "$OPERATION" --peer-report /root/peer-decided.json \
  > /root/mx-started.json
```

Each host publishes the auxiliary job hold and systemd conditions before removing
its ordinary daemon hold. The start intent precedes removal and service startup.
The application runs with its existing account and hardening; no certificate,
provider setting, model, threshold or two-copy policy is changed. A lost response
can be recovered with the same reports. Startup does not mark the upgrade healthy.
If the peer remains unavailable, mandatory replication continues to defer mail.

## Verify actual operation and complete

Exchange started reports. On each MX, request a fresh proof:

```sh
python3 /usr/local/libexec/noisefence-management/upgrade_activation.py check \
  --operation "$OPERATION" --peer-report /root/peer-started.json \
  > /root/mx-runtime-proof.json
```

A proof requires all of the following:

- the actual unprivileged process, boot identity and process start time are stable
  across the observation, with the exact prepared executable path and SHA-256;
- the numeric loopback `/healthz` reports ordinary SMTP readiness; proxies and
  redirects are disabled and the response is bounded;
- the installed selection, configuration, service definitions and settled policy
  still match the preparation;
- a policy synchronization timestamp later than the relevant starts and recent
  within the configured polling window; the worker records this only after an
  authenticated policy exchange, while the coordinator synchronizes its own
  authority;
- a replica success later than startup and no older than 15 seconds, mandatory
  two-copy state, no missing initial acknowledgement and no pending generation.

The two proofs together establish fresh ordinary operation; a cached health flag
alone does not. This aggregate observation supplements per-message body/manifest
receipts and is not a permanent availability guarantee. Clock skew, a restarted
process, missing data or unavailable checks fail closed. Retry observations until
the pair converges; do not substitute a stored validation-mode report.

Exchange the proofs and verify both hosts:

```sh
python3 /usr/local/libexec/noisefence-management/upgrade_activation.py verify \
  --operation "$OPERATION" --peer-report /root/peer-runtime-proof.json \
  > /root/mx-verified.json
```

Exchange the verified reports and finish on each host:

```sh
python3 /usr/local/libexec/noisefence-management/upgrade_activation.py finish \
  --operation "$OPERATION" --peer-report /root/peer-verified.json
```

Proofs and the first completion authorization must be no more than 30 seconds old.
If they expire before either node saves `finishing`, repeat `check` and `verify` on
both hosts. Automate authenticated report exchange when an interactive sequence
cannot meet this bound. A `finishing` or `complete` report includes the counterpart
verification that authorized that decision. Send this latest report to a delayed
counterpart so it can complete the already-authorized operation, even after the
30-second window or a subsequent policy change. The installed release and actual
executable are still checked; this historical completion certificate is not a
claim of current mail-delivery health.

After a local `finishing` intent is saved, retries finish that same intent and
reconcile interrupted removal of service conditions. Only previously active
timers resume; interrupted oneshot jobs are not replayed. Completed receipts
remain available. Recovered receipts are synchronized to disk before publication
so a peer cannot act on a decision that exists only in the filesystem cache.
The reservation owner is removed last, after holds and activation markers are
cleaned, so another supported operation cannot take over partial cleanup.

## Abort before ordinary startup

If the coordinator is armed but no activation decision exists, it can choose
`abort`, including after preparation expires and before the worker has armed:

```sh
python3 /usr/local/libexec/noisefence-management/upgrade_activation.py decide \
  --operation "$OPERATION" --outcome abort > /root/coordinator-abort.json
```

The worker accepts that coordinator report with `accept`. It can do so without an
armed receipt only for this abort path, while retaining its exact prepared pair.
On each host, restore using `abort` and exchange the resulting reports:

```sh
python3 /usr/local/libexec/noisefence-management/upgrade_activation.py abort \
  --operation "$OPERATION" > /root/mx-aborted.json
python3 /usr/local/libexec/noisefence-management/upgrade_activation.py cancel \
  --operation "$OPERATION" --peer-report /root/peer-aborted.json
```

Cancellation requires both originals restored under the same abort decision.
It uses the existing unchanged-installation reservation checks, resumes only the
recorded daemon/timers and retains ownership until activation cleanup completes.
It does not restore databases, erase accepted mail or invent a candidate success.

## Recovery and qualification limits

On any failure, inspect `status` with the same operation UUID. Preserve all reports
and repair the diagnosed condition. Do not delete markers, replace a decision,
create a new operation to adopt the hold, or switch pointers manually. A committed
startup failure needs repair and retry of the exact committed installation; a
separate, explicitly qualified rollback protocol is still required for downgrade.

The disposable [paired lifecycle fixture](paired-upgrades.md#run-the-disposable-archive-pair-fixture)
can exercise a real candidate with these helpers after the published archive
rehearsal: abort with an unarmed peer, mutual-decision startup guards, actual
ordinary SMTP/policy/replica checks, committed startup failure and forward retry,
auxiliary timer fencing, authenticated SSH completion and two-copy synthetic
acceptance. It also discards a real completion reply, waits for temporary proofs
to expire, resumes the delayed counterpart and repeats completion without changing
the durable decision. It records the installed helper hashes. This does not qualify other
architectures, arbitrary release pairs, production security profiles, independent
backup restoration or detection accuracy. Those remain separate release gates.
