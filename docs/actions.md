# Actions and quarantine

Classification and delivery action are separate. Under **Filters → Policy & actions**, choose an action for confirmed malware, spam and marketing (PUB).

| Action | Behavior |
| --- | --- |
| Deliver without a tag | Record analysis and relay the message |
| Tag and deliver | Add `[SPAM]` or `[PUB]`, then relay; requires the corresponding Proton and ARC validation |
| Quarantine | Accept and retain each affected delivery until release, discard or expiry |

**Observation** makes content-filter actions deliver without tagging or quarantine. Separately configured protocol, traffic-limit and sender-verification controls can still defer or hold mail. `filter.mode = "enforce"` applies configured actions. The legacy `tag` mode remains supported; upgrading does not activate enforcement. Without an explicit action policy, the previous behavior is retained.

Primary antivirus malware detection takes priority, then spam, then wanted marketing. The recorded action-coverage requirements determine whether a requested action can run. With partial actions disabled, incomplete analysis delivers unchanged except for explicitly configured primary-malware quarantine. With partial actions enabled, qualifying evidence or an authorized matching recipient rule can support an action despite unrelated gaps; subject rewriting has its own safeguards. Historical unresolved decisions remain historical evidence. Current decisions and requested/effective actions are separate; advisory results alone do not override them.

Quarantine does not modify the subject and does not require a Proton prefix report. Tagging requires a separate report for `[SPAM]` and `[PUB]`. See [filter policy](filter-policy.md) for precedence and [custom rules](custom-filtering.md) for recipient overrides.

<a id="gérer-les-messages-retenus"></a>
## Manage held messages

Open **Messages → Quarantine** and select a message. For each authorized recipient:

- **Release and transmit** returns that delivery to the queue without adding a prefix. It preserves classification, original route and envelope sender. The retry period starts at release.
- **Discard delivery** ends that delivery permanently without sending it. This does not immediately erase a payload still needed by another recipient, a replica or a backup.

The confirmation identifies the recipient. The server rechecks the session, CSRF token, origin, permissions and current delivery state in the transaction. Other recipients, including hidden copies outside the user’s grants, are unaffected. Repeated or expired releases are refused. Remote requests wait for their owning MX. A deadline or revocation can close a request before an execution receipt arrives; a later receipt remains visible separately.

Expand **Quarantine history** for the selected recipient, or use **Refresh quarantine history** for a fresh read. The view records the current delivery state, original retention deadline, release time, and up to 50 local actions and 50 remote requests. More entries are explicitly marked as omitted. It loads operational metadata only. It rechecks current mailbox/domain grants, account state, session expiry and MFA; another recipient's entries are never included.

A request is not an execution receipt, and an execution receipt is not SMTP acceptance by the destination. If a request expires without a receipt, the console does not claim it never ran. If the MX confirms it later, both facts are shown. Central and replicated views display their delivery snapshot timestamp: until a newer snapshot arrives, a completed command can coexist with a recorded quarantined state. The console then disables another action and asks for a refresh. A failed history read is an error, never proof of completion.

Release/discard controls are disabled at the known retention deadline, even before cleanup changes the delivery state. An unavailable deadline cannot enable an action. Release starts a new SMTP retry period; the original quarantine deadline no longer applies. Successful actions return keyboard focus to the recipient's history. Cancelling a confirmation restores the action button.

Action records are retained with the normal 30-day audit history. New local records bind the immutable message UUID and original recipient; historical integer-only audit references are deliberately not joined because delivery row IDs can be reused. Central views show command receipts and synchronized delivery state, not the local MX audit table. Metadata retention and missing historical records are explicit limitations, not proof that no earlier action occurred.

Spam, marketing or legitimate feedback supports evaluation and training; it does not release quarantine or modify mail already delivered. Releasing malware does not erase the detection. The console does not render message bodies, attachment contents or HTML.

Retention is 1–30 days, default 14. The expiry is fixed at acceptance; later policy edits do not change it. At expiry, cleanup marks the delivery expired without sending it or creating a non-delivery notification. Release is refused after expiry even if cleanup has not run yet.

Bodies remain private while any recipient is pending, sending, unresolved or quarantined, and while required replication acknowledgements remain outstanding. Unresolved mail stays searchable beyond the usual 30-day metadata period. Monitor held deliveries, queue age and free space. Backup retention is separate.

<a id="personnaliser-les-filtres"></a>
## Customize filters

All messaging controls are mapped in [Web configuration](web-configuration.md). Rule weights adjust eight content contributions: urgency, credential requests, financial promises, HTML forms, IDN links, IP links, reply-domain mismatch and uppercase subjects.

Weights range from 0 to 3 in log-odds units, before conversion to the 0–100 index. Zero removes the explicit numerical contribution but preserves the observation and model features. Restoring defaults removes overrides. Corroboration, antivirus priority and validated fusion remain in force. Evaluate false positives and recall on independent messages after any weight change.

Initial TOML example; saved Web settings subsequently take precedence:

```toml
[actions]
spam = "quarantine"
publicity = "deliver"
malware = "quarantine"
quarantine_days = 14

[filter]
mode = "observe"
threshold = 95.0
require_corroboration = true

[filter.rule_weights]
urgency = 0.1
```

<a id="migration-de-stockage"></a>
## Storage and upgrades

Quarantine introduced schema 2. Later clustering, admission and paired replication require newer schemas, up to schema 5. Use the release’s declared storage capability and [upgrade procedure](installation.md), not the version that first introduced quarantine. Never downgrade the schema or restore an old database over accepted mail.
