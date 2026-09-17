# Administration and user console

The English console uses the Rust API and a static frontend. Install the first local administrator with `user-add admin --admin`; there is no default password. Accounts protect the NoiseFence console, independently of upstream mailbox credentials.

## Console navigation

- **Messages** provides scoped search, the selected risk index, classification, analysis coverage, feedback and delivery state.
- **Message details** explains model/rule contributions and each recipient’s remote SMTP attempts. Acceptance by an upstream is not proof of inbox placement.
- **My filters** lets authorized users set mailbox/domain preferences within administrator limits.
- **My account** manages passwords, TOTP and one-time recovery codes.
- **Administration** manages domains, gateways, filters, accounts, MX nodes and operational status.
- **Filter quality** provides frozen samples for human annotation. **Reliability** reports check availability and diagnostic comparisons without silently activating a model.

See [Web configuration](web-configuration.md) for the complete control map. Global filtering, domain profiles and recipient exceptions are separate scopes. Changes are drafted, reviewed and explicitly applied to future mail.

<a id="parcours"></a>
## Everyday workflow

Choose an authorized domain or all accessible messages, then search subjects, sender/recipient addresses, rule identifiers or queue IDs. Filter by classification, partial analysis, score, delivery state, date or MX node. Score searches use the same risk value shown in the list. Bodies and attachments are not indexed. See [message search](message-search.md).

Open a message to inspect its classification independently from its risk index and coverage. A high index with an undetermined decision is a visible disagreement or missing-evidence case, not proof that the message is legitimate. Mark verified mistakes as spam, marketing or legitimate. Feedback never changes an already delivered Proton message and does not release quarantine.

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

SQLite WAL stores configuration revisions, accounts and history durably. Concurrent edits use a revision check; a stale draft cannot overwrite a newer change. The last 100 configuration revisions can be loaded, reviewed and applied as a new revision. Existing transactions and accepted deliveries retain their captured policy and route.

If a saved policy prevents startup, first back up the current state. On a coordinator or standalone host, stop the service and restore the bootstrap TOML policy without removing accounts, queue or history:

```sh
sudo systemctl stop noisefence
sudo -u noisefence /opt/noisefence/noisefence --config /etc/noisefence/config.toml console-reset
sudo systemctl start noisefence
```

This is a policy reset, not a password reset or database rollback. A worker refuses local console reset. Paired installations must preserve HA configuration and follow the [recovery guide](high-availability.md).

<a id="validation-automatisée"></a>
## Verification

Console tests cover administrator/domain/mailbox grants, aliases and Bcc, statistics, search, CSRF, account revocation, revision conflicts, durable settings, secret protection, quarantine and routing changes during SMTP transactions. Read queries use bounded read-only SQLite connections so slow reports do not hold the durable-write lock. Frontend tests, type checks, lint and static builds run in CI.
