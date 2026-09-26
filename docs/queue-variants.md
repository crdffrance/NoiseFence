# Multiple recipient decisions and durable queue copies

One SMTP transaction can contain recipients with different thresholds, rules,
actions or receipt traces. NoiseFence renders a separate copy for each distinct
effective policy. Recipients only share a copy when their recorded policy hashes
match. Copies also split at 100 recipients to retain the existing replica protocol
limit, even when their policies are identical.

## Bounded memory and work

The former six-variant ceiling is removed. The installation's
`smtp.max_recipients` still limits SMTP admission; the internal batch limit is
1,000 recipients and 1,000 variants. Worker configuration retains its existing
100-recipient limit. These are ceilings, not a throughput guarantee.

Every rendered variant holds its own header prefix and a reference to the same
immutable message body. The renderer verifies body equality before discarding
its temporary contiguous output. It does not retain a full body-sized allocation
behind each header slice. Disk writers and HTTP replica uploads consume these
chunks without concatenating a full message for every retained variant.

The original message, the shared body and one temporary render may coexist.
Rendering/ARC may still need a contiguous temporary message and CPU proportional
to message size. Signing and rendering hand off the Tokio worker in the
multithreaded server runtime. Additional limits are:

- At most 16 MiB of aggregate retained variant headers.
- At most 32 MiB of serialized scans and recipient policies per batch, counted
  without allocating another serialized batch. Object overhead is additional.
- A 30-second rendering budget, checked between recipients/copies. A synchronous
  render already running finishes before this check; this is not preemptive.
- One `replication.timeout_seconds` deadline for the complete remote preparation
  batch, rather than renewing the budget for each copy.

The configured processing semaphore limits simultaneous analyses. Size, fan-out,
metadata, disk and CPU still matter when sizing a server. The existing optional
research archive retains its own context-size budget; oversized research capture
can be skipped and counted without changing SMTP acceptance.

## All-or-nothing acceptance

1. Authorize recipients and receive/validate the original SMTP message.
2. Analyze once, freeze each recipient decision and build bounded wire variants.
3. Check free disk space for every wire copy plus `smtp.minimum_free_bytes`.
4. When replication is required, upload and durably acknowledge each body and
   candidate manifest. Partial remote candidates remain inert.
5. Recheck local capacity, create each spool file exclusively, write its chunks
   and sync every file plus the spool directory.
6. Insert every message, delivery and policy in one SQLite transaction.
7. Return SMTP `250` only when the batch has completed successfully.

The free-space checks are admission checks, not filesystem reservations against
concurrent writers. Actual file/transaction errors still roll back the batch and
produce SMTP `451`; cleanup never overwrites an existing spool file. Rendering
and capacity errors do not masquerade as missing detector checks or trigger a
different spam score. Analysis timeouts keep their separately documented fallback.

Restart recovery removes orphan files and verifies that every accepted local
queue record has its body. A failed remote preparation does not create local
delivery ownership. Existing replica generation confirmation, fencing and manual
recovery rules remain unchanged. Acceptance uncertainty during disaster recovery
is retained explicitly; this change does not add automatic failover. A lost final
SMTP response can still cause a sender retry and duplicate delivery.

No provider/model is added and no detection accuracy or reference-hardware
throughput claim follows from this capacity change.
