# Scoped filtering policies

Available in 0.28.0-rc.3. This release candidate does not enable the policy on an
existing installation. In the administrator console, open custom filtering and
select **Scoped inheritance**, test the draft, then save a configuration revision.
New Web drafts select scoped inheritance; existing policies without `ordering`
retain **Legacy priority ordering**. Installation settings remain server-side.

## Profiles and inheritance

The most specific applicable profile selects action mappings and quarantine
duration. A missing threshold inherits the next profile with an explicit
threshold, then the global filter threshold. Profiles never rescale detector
measurements or recalibrate a model. Qualified fusion retains its own threshold.

From most to least specific, scopes are:

1. Original recipient address.
2. Alias destination address, when different.
3. Original recipient domain.
4. Alias destination domain, when different.
5. Organization (`*`).

In scoped mode a personal profile precedes the administrator profile at the same
scope, within administrator-configured self-service limits. A personal inherited
threshold can therefore fall through to the administrator profile at that scope.
A mailbox preference containing only rules does not discard a domain profile or
domain rules. The recorded trace distinguishes the profile supplying actions
from the profile supplying the threshold. Mailbox scopes preserve case.

Legacy mode retains the previous most-specific personal preference behavior and
priority ordering. A legacy personal threshold may already have been resolved
during composition; its trace describes the resulting effective profile, not a
reconstructed original inheritance chain.

## Rule precedence

Scoped mode applies personal rules first and administrator rules last. Within
each authority, rules run from broadest to most specific scope, then ascending
numeric priority, then original rule ID. An administrator organization rule can
override a personal mailbox rule. A matching administrator stop prevents all
later rules, including more specific ones. Personal rules cannot stop processing.

A later match may replace an earlier classification or action. Changing the
classification resets the requested action to that category's profile mapping;
an explicit action on the same rule then overrides that mapping. Engine-category
conditions always refer to the common detector classification before custom
rules, not a previous rule's override. Scoped score conditions use the canonical
selected risk index shown in the receipt. Legacy score conditions retain their
original content-index semantics, which may differ from a fusion index.

Disabled, expired and unrelated-scope rules do not participate. A missing fact
cannot satisfy a negative condition. OR rules can match another known true
condition, but the trace still lists unavailable facts. Primary malware evidence
overrides custom rule effects. Observation, partial-action requirements and
Proton marking validation constrain the requested action afterwards.

The console exposes applicable profiles, threshold source, matched rules, missing
facts, skipped rules after a stop, and winning effects. The trace is saved in the
recipient decision and replicated with the queue. It includes no rule condition
values or message bodies and excludes unrelated recipient scopes. Incoming Web
or disk policies cannot supply the trusted personal-authority metadata.

## Simulate before saving

The synthetic form tests entered facts with saved global settings and personal
preferences. It does not perform DNS, reputation or antivirus checks.

**Compare the draft on a fixed message sample** accepts 1–50 distinct queue UUIDs
and one configured original recipient. It is administrator-only and requires a
valid session and CSRF token. Other recipients' copies are not substituted.
The endpoint is `POST /api/v1/admin/filtering/sample`:

```json
{
  "policy": {"ordering": "scoped", "profiles": [], "bindings": [], "rules": []},
  "recipient": "alice@example.test",
  "message_ids": ["00000000-0000-4000-8000-000000000001"],
  "at": 1790000000
}
```

Omit `at` or use `null` for the server time. Reuse the returned evaluation time
for comparisons involving expiry. The response includes the saved configuration
revision, a fingerprint of the selected retained records, before/after outcomes,
effective actions and policy traces. The UI identifies results from an earlier
draft when inputs change. The endpoint reads at most 16 MiB of scan metadata.

Only retained detector results and metadata are reused. No message is delivered,
reanalysed, changed or sent to a provider. This does not simulate a different
detector model or unsaved global/personal settings. Bodies and sizes are unknown;
subjects at the 500-character retention limit are unknown because their suffix
may have been discarded. Unknown facts do not match absence conditions.

Change counts and the transition matrix include only comparisons with a recorded
recipient decision, known original action and no unavailable rule conditions.
They measure changes in classification and effective action, not just a changed
threshold or requested action. Saved observation mode still delivers.
Other rows remain explicitly incomplete. These are policy-effect comparisons,
not measurements of detection accuracy or ground-truth labels. Accepted history,
delivered headers and quarantine actions remain unchanged.

## Multiple MXs and rollback

Every enabled worker must report a fresh build supporting scoped inheritance
before activation or edits. An older worker is refused a scoped bundle rather
than silently executing different precedence. Legacy bundles remain compatible
with audited older builds. The UI stores configuration revisions; restore the
previous revision or switch back to legacy ordering to revert future policy use.
Original receipts keep their original decisions.

This compatibility check does not yet provide atomic activation across MXs.
Full frozen-context parity, coordinated activation and failover qualification are
part of the remaining [unification work](unified-decisions.md). Maintain the
existing observation and quality gates before enforcement.
