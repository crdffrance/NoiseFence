# Web configuration

The console manages **messaging and filter policies**. Installation settings stay on the host: listening ports, TLS certificates and keys, storage, worker sockets, model files, replication identities and recovery tooling.

## Where to find each setting

| Area | Controls | Who can change it |
| --- | --- | --- |
| Domains | Accepted domains, enabled state, recipients, catch-all and aliases | Administrator |
| Gateways | Explicit upstream hosts, route assignment and destination port | Administrator |
| Filters → Policy & actions | Observation/enforcement, reference threshold, sensitivity, spam/marketing/malware actions and quarantine retention | Administrator |
| Filters → Rules & profiles | Profiles, domain/address assignments, conditions, rule priority, expiry and actions | Administrator |
| Filters → Rule weights | Bounded contributions of supported content signals | Administrator |
| Filters → Detection engines | Installed checks and optional score contributions | Administrator |
| Filters → IP reputation · RBL | DNSBL providers, exact return codes, IPv6, independent-provider threshold, timeout, cache, concurrency and admission action | Administrator |
| Filters → SMTP admission | Greylisting, rate limits and bounded delays | Administrator |
| Filters → Advanced settings | Analysis limits; LLM model/project, selection, budget and pricing date; OCR limits; DNS checks; URL following; native patterns, composites and family caps | Administrator |
| Filters → Protection & reputation | CRDF/VirusTotal keys and quotas, protected identities, exceptions and indicator checks | Administrator |
| Filters → Marketing & newsletters | Marketing recognition and newsletter policy | Administrator |
| Filters → User preferences | Permitted personal actions, sensitivity bounds, rule limits and existing preferences | Administrator |
| My filters | Preferences and rules for authorized mailboxes or domains | Authorized user |
| Accounts & access | Accounts, grants, invitations and revocation | Administrator |
| My account | Password, MFA and recovery codes | Account owner |
| MX servers | Enrolment, policy synchronization, health and replication status | Administrator; host setup remains server-side |

Some modules require a host-installed worker, model or initial provider configuration before they can be enabled. Unavailable modules are identified in the console. Trained model replacement and adaptive protocol changes retain their validation gates.

## Save, review and apply

Edits form a draft. Review its changes and apply it explicitly. The server validates the complete configuration, checks the revision and records the change. A conflicting revision requires a reload; it never silently overwrites another administrator's work. Advanced JSON blocks must be validated before saving the overall draft. JSON import prepares a validated draft; export omits secrets.

The last 100 configuration revisions are available for review. New SMTP transactions use the new settings. A transaction already in progress retains its policy snapshot, and accepted messages are not rescanned, retagged or redelivered. Lowering a concurrency limit waits for already admitted work; it does not cancel it. Provider accounting is not reset by saving a configuration.

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

Storage is **schema 5 once paired replication is activated**. Never downgrade an active HA queue to a pre-0.17.3 binary, remove its `ha_required` marker, or restore an older database over accepted mail. A policy revision rollback is different from a binary/database rollback. See [operations](operations.md) and [high availability](high-availability.md) for compatible recovery procedures.
