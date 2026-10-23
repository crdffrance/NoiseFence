# Administration and user console

The English console uses the Rust API and a static frontend. Install the first local administrator with `user-add admin --admin`; there is no default password. Accounts protect the NoiseFence console, independently of upstream mailbox credentials.

## Console navigation

- **Messages** provides scoped search, the selected risk index, classification, analysis coverage, feedback and delivery state.
- **Message details** explains model/rule contributions and each recipient’s remote SMTP attempts. Acceptance by an upstream is not proof of inbox placement.
- **My filters** lets authorized users set mailbox/domain preferences within administrator limits.
- **My account** manages passwords, TOTP and one-time recovery codes.
- **Administration** manages domains, gateways, filters, accounts, MX nodes and operational status.
- **Quality & research → Samples & evaluation** provides frozen samples for human annotation. **Rule reliability** reports check availability and diagnostic comparisons without silently activating a model.

See [Web configuration](web-configuration.md) for the complete control map. Global filtering, domain profiles and recipient exceptions are separate scopes. Changes are drafted, reviewed and explicitly applied to future mail.

## Quality & research

One navigation entry contains three keyboard-accessible tabs:

| Tab | Purpose | Direct link |
| --- | --- | --- |
| Samples & evaluation | Annotate frozen samples, compare candidates and inspect qualification requirements. | `/?view=quality&tab=samples` |
| Engine comparison | Inspect the separate Rspamd opinion and scoped disagreements. | `/?view=quality&tab=comparison` |
| Rule reliability | Review errors on available labels, check coverage and rule contributions. | `/?view=quality&tab=reliability` |

![Quality and research comparison with synthetic messages](images/console-quality.png)

*The screenshot uses synthetic messages and illustrative scores; it contains no private mail and is not an accuracy benchmark.*

Left/Right and Home/End move between tabs. Links survive sign-in, but never grant access. Existing `/?view=quality&sample=<UUID>` links continue to open the annotation sample. Switching away from the samples tab removes its identifier from the URL. Comparison resets keep the comparison scope; they do not switch silently to all mail. The message list shows the NoiseFence category/index and the Rspamd action/points side by side. Their units remain separate; a Rspamd deferral is not a spam verdict.

Annotation samples appear first. Create another sample or inspect **Data readiness and release qualification** in the expandable panels below. Risk (wanted/unwanted) is separate from mail type. Wanted marketing belongs to the wanted denominator when measuring false positives. Rspamd agreement, software tests and successful deployment are not evidence of calibrated filtering quality.

<a id="parcours"></a>
## Everyday workflow

Choose an authorized domain or all accessible messages, then search subjects, sender/recipient addresses, rule identifiers or queue IDs. Filter by classification, partial analysis, score, delivery state, date or MX node. Score searches use the same risk value shown in the list. Bodies and attachments are not indexed. See [message search](message-search.md).

Open a message to inspect its NoiseFence verdict independently from the risk index and analysis coverage. A high index can coexist with Ham when a recorded safeguard or recipient policy takes precedence; the verdict banner explains that basis. The index is not a spam probability. Historical projections are identified separately from decisions saved at receipt.

The message view separates five questions:

- **NoiseFence verdict:** the recorded category and its basis, including recipient overrides or contextual safeguards.
- **Risk index:** the recorded numeric result. An unavailable score stays blank; it never becomes an invented zero.
- **Analysis coverage:** which checks completed or were limited. A completed check does not establish safety.
- **Action at receipt:** the effective policy action, such as delivery in observation mode. This is distinct from the current delivery state.

- **Last recorded delivery:** the latest available state for authorized recipients. “Accepted by destination” means SMTP acceptance, not inbox placement. Per-recipient status, quarantine commands and remote SMTP replies remain available below.

Under **Filters & evidence**, expand a family in **Checks at a glance** to inspect each detector's state, result and role. **Signals & explanations** supports search by signal name, identifier, evidence or recorded family. Use **Raises index**, **Lowers index** or **Context & exclusions** to narrow the list. Retained weights come from the recorded calculation; without that ledger, weights are explicitly proposed. They are not percentage points, do not sum to 100, and model summaries must not be added again.

Expand the accounting, authentication or SMTP sections for technical details. If diagnostics fail to load, the page retains available signals and offers a retry without claiming the missing checks passed. Rspamd remains a separate comparison and never determines the NoiseFence verdict or action.

Use **Correct classification** for verified mistakes: Ham, Spam or Pub. Additional learning labels are available in their own disclosure. Feedback never changes an already delivered Proton message and does not release quarantine. Operational corrections and evaluation-sample labels remain separate records with separate provenance; correcting a message does not silently label a protected evaluation sample.

Quarantine actions apply to one authorized delivery at a time and require a concrete confirmation. Use the [actions guide](actions.md) before releasing or discarding mail.

<a id="ajouter-un-domaine"></a>
## Add a domain

1. Create its explicit upstream route in **Gateways**. Use receiving hosts independent of the public MX records; configure the correct SMTP port and require certificate-verified TLS for public routes.
2. Add the domain in **Domains** and assign the route. Enter recipients and aliases, or enable **Accept all domain addresses** to use downstream mailbox names without individual declarations. Enable [**Verify recipients at destination**](recipient-fallback.md#refuse-nonexistent-recipients-before-acceptance) to refuse nonexistent mailboxes during SMTP reception; keep **Unknown-recipient fallback** empty.
3. Review and apply. Grant user access to individual recipients or `*@example.org` under **Accounts & access**.
4. Validate delivery and actual mailbox placement with authorized test recipients before changing public DNS. A console domain does not create an upstream mailbox or publish MX records.

Invite users with a one-time expiring link. They choose their own password; no invitation email is sent automatically. Revocation invalidates unused links. Administrator invitations grant organization-wide configuration and message access.

<a id="autorisations-et-confidentialité"></a>
## Permissions and privacy

Administrators can see all organization messages. Users see only granted recipients/domains; alias destinations and Bcc permissions are checked server-side. Shared mailbox preferences belong to the mailbox, not the editor’s account. Every mutation rechecks active sessions and current grants.

Passwords use Argon2id. Production sessions use secure cookies, origin validation and CSRF protection. Account disablement, password changes and relevant access changes revoke sessions. Provider credentials are stored privately and never returned in exports, history or subsequent API reads. Historic explanations and user-defined labels remain recorded data in their original language; software-generated labels and new explanations are English.

<a id="persistance-application-et-restauration"></a>
## Revisions and recovery

Local SQLite deployments store configuration revisions, accounts and history in WAL mode. Installations using the [PostgreSQL management backend](../deploy/postgresql/README.md) store shared console data there; each MX still keeps its durable message queue locally. Concurrent edits use a revision check; a stale draft cannot overwrite a newer change. The last 100 configuration revisions can be loaded, reviewed and applied as a new revision. Existing transactions and accepted deliveries retain their captured policy and route.

If a saved policy prevents startup, first back up the current state. On a coordinator or standalone host, stop the service and restore the bootstrap TOML policy without removing accounts, queue or history:

```sh
sudo systemctl stop noisefence
sudo -u noisefence /opt/noisefence/noisefence --config /etc/noisefence/config.toml console-reset
sudo systemctl start noisefence
```

This is a policy reset, not a password reset or database rollback. A worker refuses local console reset. Paired installations must preserve HA configuration and follow the [recovery guide](high-availability.md).

<a id="validation-automatisée"></a>
## Verification

Console tests cover administrator/domain/mailbox grants, aliases and Bcc, statistics, search, CSRF, account revocation, revision conflicts, durable settings, secret protection, quarantine and routing changes during SMTP transactions. Read queries are bounded and isolated from durable queue writes. The configured backend supplies the console data; neither a slow report nor an unavailable central database should extend an already captured SMTP transaction with an unbounded query. Frontend tests, type checks, lint and static builds run in CI.

## Synthetic local demo

From a source checkout, use the Node.js version required by `web/package.json`:

```sh
cd web
npm ci
npm run dev -- --host 127.0.0.1 --port 3011
```

Open `http://127.0.0.1:3011/demo.html?case=ham&role=user` for a synthetic user account, or omit `role=user` for the administrator layout. Other message cases are `spam`, `pub`, `quarantine`, `encrypted` and `error`. Use `open=list` to start in the message log. Add `view=quality&tab=comparison` or `view=quality&tab=reliability` for the research tabs. The example sample ID is `00000000-0000-4000-8000-000000000002`.

The demo intercepts every API request. Bulk annotations only change browser-memory fixtures; reloading resets them. Other writes are refused and unsupported API views display an explicit fixture error. No mailbox, provider key or running Rust service is required. This is a UI demonstration, not a filtering benchmark or an authentication test. The production Vite build includes only the normal console entry, not `demo.html` or its fixtures. Do not expose the development server publicly.
