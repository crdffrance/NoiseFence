<a id="règles-profils-et-invitations-049"></a>
# Rules, profiles and invitations (0.4.9)

In **Administration → Filters → Rules & profiles**, create profiles and then assign them. The general application button records an atomic revision; the draft and its simulation do not change the received messages. The settings are not retroactive.

<a id="portées-et-niveaux"></a>
## Scope and levels

`*` means the organization, `*@exemple.fr` means a domain configured and a complete address an accepted recipient. Priority of assignments: initial SMTP address, destination of the alias, initial domain, destination domain, organization. Only one assignment is allowed for each range. An unassigned profile has no effect.

A profile defines the actions Spam, Advertising and To Examine, the duration of quarantine (1 to 30 days), substantiation and a inherited or personalized threshold. Since 0.10.0, **Filters → Politics** offers five levels for organization and exceptions per domain. The profiles also allow exceptions per address and a personalized threshold of 50 to 100.

| Niveau | Decision threshold |
| --- | ---: |
| 1 · Very tolerant | 99.5 |
| 2 · Tolerant | 98 |
| 3 · Balanced | 95 |
| 4 · Strict | 90 |
| 5 · Very strict | 85 |

An index equal to the threshold is eligible for the Spam ranking, subject to confirmations and arbitration. Lowering the threshold increases the candidate messages to the ranking: without confirmation, they remain to be examined. These indices are not probabilities and these names do not guarantee any capture rate. Each explicit threshold imposes server-side substantiation, even if the customer submits `require_corroboration: false`. Provider errors, a LLM notification alone and native observation rules do not provide this confirmation. Arbitration of conflicting notices and the antivirus priority remain applied. The explicit administrator rules then apply and retain their effects.

The operating threshold applies **after** the common analysis. It does not change the coefficients or the reference threshold of the multilingual combination, nor does it change the selection, text or budget of LLM calls. A fusion model in decision-making mode retains only its validated threshold: the profile thresholds are then rejected.

A `null` threshold inherits the first explicit threshold in the parent ranges, then the engine reference threshold. Example: Strict organization, Tolerant domain, inheriting address → threshold 98 for this address. Actions remain those of the most specific profile. Creating a level in the simplified view takes over the current actions; a shared profile is copied before changing a single assignment. Removing the threshold does not remove the actions from the profile. A substantiation required globally cannot be disabled by a profile.

The upgrade does not create a profile, does not change any active threshold and keeps the observation. The application button of the configuration is necessary to save a new level. Previous messages keep their evaluation.

The rules then apply, by increasing priority and stable identifier to divide the equities. They combine 1 to 8 conditions with ET or OR. A following rule may replace a previous effect; "Stop" prevents this. An expiration is exclusive and expressed in UTC. Limits: 100 rules, 32 profiles, 1,000 assignments. The values are literals of 256 bytes maximum, insensitive to the break, without regular expression or executable code.

The conditions relate to the envelope, From, the decoded object, the MIME text, the recipient, the size, the original index, the original category, a signal or DMARC. The SMTP and From sender can be falsified: a wide exception based only on these fields is not recommended. For an exception, combine the necessary evidence and use a limited scope.

A missing data because a control has not been performed is **unknown**, including for the "Is absent". Bodies exceeding MIME/text limits or HTML messages without text are not evaluated by the text conditions. The existing HTML detection engine continues to work. Simulation uses only the captured facts: no remote control, no delivery and no training. It does not measure accuracy.

<a id="priorités-et-livraison"></a>
## Priorities and delivery

A malware detection by the main antivirus retains the spam category and general antivirus action. Observation forces transmission; incomplete analysis prevents tagging and custom actions, except for the 40th of a confirmed malware provided by the overall policy. Explicit rules can change a category without altering the original evidence or scores. Prefixes remain subject to Proton validation, authentication and ARC.

Content and network controls are executed once. Common conditions are reused by recipients; each delivery maintains its own evaluation. Up to six variants of category/prefix may be required. Their files are synchronized on disk before a single SQLite transaction, then only the server answers 250. An error leaves no sub-set accepted. SMTP duplicates after loss of the final response remain possible.

The original body remains the same in each variant. Variations appear as separate entries in the history; the common `transaction_id` is kept in the metadata. Console statistics count variants, not exclusively SMTP transactions. Training campaigns remain deduplicated by their original fingerprints. An evaluation per recipient contains the profile, the triggered rules, the action requested/applied and the imprint of the policy, without body or value of the conditions. ACL filter these evaluations, including for hidden copies.

## Invite a user

In **Administration → Accounts & Access → Invite a user**, choose a new identifier, addresses/domains, role and validity from 1 to 7 days. Copy the link displayed only once and share it with the data subject. No email is sent automatically. A new link for the same identifier revokes the previous ones. The list also allows for immediate revocation.

The recipient sees his access, chooses and confirms his password (12 to 128 bytes), then uses the normal connection. The account is created only upon activation. The invitation never resets an existing account. Only an administrator can invite; the rights of the creator and the accesses configured are checked for activation. Changing the account of the creator invalidates his pending invitations.

The 256-bit random token is stored as a hash in SQLite, expires, and can be used only once. It is transmitted in a fragment of URL, removed immediately from the address bar, and then stored only in memory. The protections Origin, CSRF administrator, frequency limitation and Argon2id apply. These choices are based on the principles of token management of the [OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html). The expired invitations are deleted after 30 days; the actions are audited.

<a id="mise-à-niveau-et-retour-arrière"></a>
## Upgrading and back-up

The new tables are additive to scheme 2. Existing revisions are unchanged and `custom_filtering` is absent as long as no rule is saved. The existing observation mode and settings are kept on deployment.

The binary 0.4.8 can deliver the standard variants already in file. If a custom policy has been saved, **before** back to this binary, disable it by a new configuration revision containing `custom_filtering: null` then check that the field has been omitted in the serialized revision. The API accepts this removal; the history of the old revisions remains retained. Also check the general policy marking validations. Never restore an old database: it could lose messages accepted since.

<a id="retour-de-010-à-09"></a>
### Historical compatibility note

The JSON format of policies and evaluations remains the same. However, 0.9 refuses the explicit thresholds of profiles with the active multilingual model. Before a return to 0.9, put these thresholds on Heritage and apply a new revision with 0.10; check the actual configuration with the old binary. The legacy of thresholds between ranges does not exist in 0.9. Keep history and current queue, without restoring an old database.
