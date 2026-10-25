# Web configuration

The console manages **messaging and filter policies**. Installation settings stay on the host: listening ports, TLS certificates and keys, storage, worker sockets, model files, replication identities and recovery tooling.

## Where to find each setting

| Area | Controls | Who can change it |
| --- | --- | --- |
| Domains | Guided setup, draft/DNS/recipient checks, enabled state, recipients, catch-all and aliases | Administrator |
| Gateways | Explicit upstream hosts, route assignment and destination port | Administrator |
| Filters → Policy & actions | Observation/enforcement, reference threshold, sensitivity, spam/marketing/malware actions and quarantine retention | Administrator |
| Filters → Rules & profiles | Profiles, domain/address assignments, conditions, rule priority, expiry and actions | Administrator |
| Filters → Rule weights | Bounded contributions of supported content signals | Administrator |
| Filters → Detection engines | Installed checks and optional score contributions | Administrator |
| Filters → Providers & budgets | Read-only loaded configuration, credential state, reserved quotas, LLM accounting, recent coverage and incidents | Administrator |
| Filters → IP reputation · RBL | DNSBL providers, exact return codes, IPv6, independent-provider threshold, timeout, cache, concurrency and admission action | Administrator |
| Filters → SMTP admission | Greylisting, rate limits and bounded delays | Administrator |
| Filters → Advanced settings | Analysis limits; LLM model/project, selection, budget and pricing date; OCR limits; DNS checks; URL following; native patterns, composites and family caps | Administrator |
| Filters → Identity protection | Automatic correspondent memory, retention and recurrence thresholds; identity contribution mode and cap; manual sources, people, groups, roles, delegation, reviewed CSV imports; separate domain-based name checks | Administrator |
| Filters → Protection & reputation | CRDF/VirusTotal keys and quotas, exceptions and indicator checks | Administrator |
| Filters → Marketing & newsletters | Marketing recognition and newsletter policy | Administrator |
| Filters → User preferences | Permitted personal actions, sensitivity bounds, rule limits and existing preferences | Administrator |
| My filters | Preferences and rules for authorized mailboxes or domains | Authorized user |
| Accounts & access | Accounts, grants, invitations and revocation | Administrator |
| My account | Password, MFA and recovery codes | Account owner |
| Server status → Configuration history & audit | Read-only revision comparison, reviewed restoration and searchable recent events | Administrator |
| MX servers | Enrolment, policy synchronization, health and replication status | Administrator; host setup remains server-side |

Some modules require a host-installed worker, model or initial provider configuration before they can be enabled. Unavailable modules are identified in the console. Trained model replacement and adaptive protocol changes retain their validation gates.

## Save, review and apply

Edits form one shared draft across **Domains**, **Gateways**, **Filters** and **Server status**. Moving between those sections preserves it. Leaving for another workspace, navigating away with an unfinished domain wizard or choosing **Cancel** in the save bar requires explicit discard confirmation. Cancelling or pressing Escape preserves the draft.

**Review and apply** shows the loaded and proposed values for all changed fields. Search by section or JSON pointer; array indexes are zero-based and preserve rule/route order. Large or deeply nested branches appear as complete old/new values rather than silently disappearing. This is a configuration comparison, not a prediction of message classifications. Use the separately labelled sample simulation where applicable. Provider key bytes and host installation settings are excluded.

The confirmation is bound to the exact submitted payload, base revision and any explicit model-file selection. Editing any of them requires review again. Only **Apply settings** (or **Stage settings** in coordinated installations) submits it. The server still validates administrator access, CSRF, the complete configuration, model bindings and revision. A conflict retains the unsaved draft; inspect the error and discard/reload before editing against the new revision. The console never silently overwrites another administrator's changes. Advanced JSON blocks must be validated before saving the overall draft; JSON import prepares a validated draft and export omits secrets.

A successful save has its own receipt. If the following read fails, the console keeps that receipt, marks displayed settings as potentially stale and disables editing until **Refresh installed settings** succeeds. Do not resubmit an acknowledged save. A staged receipt is not proof of installation: follow the activation panel for each MX, the committed revision and local SMTP readiness.

New SMTP transactions use installed settings. A transaction already in progress retains its policy snapshot, and accepted messages are not rescanned, retagged or redelivered. Lowering a concurrency limit waits for already admitted work; it does not cancel it. Provider accounting is not reset by saving a configuration.

## History, audit and restoration

**Server status → Configuration history & audit** loads the latest 100 retained revisions and 200 audit events independently. A metrics, queue or audit failure does not hide the other successful reads. Unavailable queue data never means the queue is empty. Each history panel shows its capture time; audit search and category filters apply only to the loaded window, not the entire database. Local MX audit events are not automatically aggregated across servers.

**Preview revision** compares retained values with the loaded editor without replacing the draft. **Use revision as draft** asks before replacing existing unsaved work and clears explicit model-file selections. Review and apply the resulting draft as a new revision. Missing historical fields use current compatibility defaults; this does not restore old provider credentials, model files, messages or databases. A changed base revision invalidates an open historical preview. **Base configuration** means current bootstrap policy for local SQLite deployments and retained revision 0 for central management; it is not necessarily the original installation policy.

Audit entries distinguish recorded configurations from staged or cancelled activation proposals. Only configuration-revision events link to a revision; activation sequence numbers are separate identifiers. Neither an audit event nor its timestamp proves installation on every MX. A missing historical revision produces an explicit error without changing the draft.

The risk index, classification, analysis coverage and delivery action are separate. Changing sensitivity does not change a previously recorded decision. Observation, malware priority, incomplete-analysis safeguards and Proton tagging validation still apply to personal rules.

## Provider credentials and limits

Scaleway and Spamhaus credentials are under Advanced settings; CRDF and VirusTotal are under Protection & reputation. Only configured/missing status is returned to the browser. Keys are stored in a private `data_dir/credentials/` directory (0700; files 0600), written durably, and excluded from configuration revisions, audit records and JSON exports. Include this directory in private backups.

A Web-managed key takes precedence over its provider's environment variable. Rotation reloads the saved settings, not an unsaved draft, and does not enable a disabled provider. If reload fails, the console reports that the key was saved but the configuration must be reapplied. Restoring a policy revision does not restore an older key.

CRDF/VirusTotal quota **zero explicitly means unlimited**; an empty or invalid input does not. A missing override inherits installation defaults. Provider cooldowns still apply with unlimited quotas. LLM budgets use euros in the UI and integer micro-euros on the server; a zero LLM budget disables calls. Pricing verification dates are not renewed automatically.

RBL presets are configuration shortcuts, not permission to use a provider. Check access terms and exact response codes. Provider errors and unknown codes are unavailable signals, not listings. Spamhaus DQS has dedicated IP/domain handling; do not duplicate its ZEN results with SBL/XBL/PBL. Custom RBL credentials can only be used with their configured provider and zone.

## User preferences and inheritance

A mailbox preference belongs to the mailbox, not the account that edited it. Authorized users of a shared mailbox share its preferences. Removing a user's access does not delete those preferences. `*@example.org` grants domain scope; a grant to one mailbox does not grant domain administration. Permissions and the session are checked again in the save transaction.

Preference selection follows the original SMTP address, canonical alias destination, original domain, then destination domain. An exact preference replaces a domain preference; its threshold may still inherit administrator profiles. Deleting a preference restores inheritance. Personal rules run before administrator rules and cannot stop the global rules.

Within administrator limits, users can choose sensitivity, actions for spam/marketing/review, quarantine duration and up to 20 rules with 1–8 conditions. Conditions cover envelope sender, From, subject, MIME text, recipient, size, score, category, signal and DMARC. There is no executable user code or arbitrary user regex. Recipient data outside the user's grants is excluded from the API, including Bcc recipients.

## Upgrade and recovery

Older saved settings inherit missing module parameters from the host configuration. An explicitly empty RBL list remains empty. Upgrading does not activate providers, personal preferences or enforcement.

Local storage uses **format 5 for paired replication, 6 for management transport and 7 for selected PostgreSQL management**. The maximum supported format in `build.json` does not by itself establish compatibility with a selected authority. Never downgrade an active HA queue to a pre-0.17.3 binary, remove its `ha_required` marker, or restore an older database over accepted mail. A policy revision rollback is different from a binary/database rollback. See [operations](operations.md) and [high availability](high-availability.md) for compatible recovery procedures.

Destination verification is available under **Administration → Domains → Verify recipients at destination**, together with bounded deadlines and positive/negative cache TTLs. It can accompany wildcard domain reception but cannot accompany recipient fallback. See [recipient verification and fallback](recipient-fallback.md).

### LLM pricing availability

Advanced LLM settings and Server status show the cost-verification deadline,
including a warning during its final seven days and an explicit suspension notice
after 30 days. This mirrors the existing server guard; it does not renew dates,
raise budgets or enable a provider. Verify the provider's actual prices before
saving a new date. A current date does not guarantee capacity, credentials or
budget availability. If external analysis is intentionally suspended, leave it
suspended; an unavailable opinion is not a spam detection.

### Directory collection

Use **Filters → Identity protection → Directory synchronization** to collect
users and groups from Entra, Google Workspace or Okta. Credentials are request-only
by default. Administrators may explicitly save [encrypted access](directory-credential-storage.md),
set its expiry, replace or revoke it. Collection and activation remain separate
actions. Job receipts are durable and contain no secrets. Review and activate
the prepared directory separately. See [Entra setup](identity-entra.md), [Google setup](identity-google.md) or [Okta setup](identity-okta.md) and their shared job states.
Scheduled synchronization is not yet available.

Optional background collection is configured in **Saved directory access → Set up
automatic collection**. Only the access owner can authorize it, with a 15-minute to
24-hour interval and an end time bounded by credential expiry. Administrators can
stop it and inspect the last durable receipt. Each candidate still requires the
normal review and MX policy activation; see [schedule semantics](directory-credential-storage.md#automatic-collection).
