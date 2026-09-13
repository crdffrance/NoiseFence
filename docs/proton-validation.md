<a id="valider-le-relais-devant-proton"></a>
# Validate relay in front of Proton

The gateway retains Proton as its destination. Its production depends on the tests below, not on the success of a SMTP dialogue.

<a id="préparer-lenvironnement"></a>
## Preparing the environment

1. Use a controlled test address or subdomain in Proton, and a controlled test sender. Inform addresses and test server in a local configuration excluded from Git.
2. Confirm with the host that TCP/25 is available in both directions. Check A/AAAA, DNS reverse and bridge certificate. Only publish AAAA if the IPv6 routing works.
3. Copy `config/production.example.toml` to `config/local.toml`, provide actual recipients and certificates, keep `mode = "observe"`.
4. Prepare an ARC RSA key and publish the public key under `SELECTOR._domainkey.example.org`. Provide the private key, domain and selector in the configuration. PKCS#1 and PKCS#8 PEM keys are accepted. The key remains readable only by the service.
5. Check the current support of the relay with Proton. [Proton describes an ARC confidence limited to certain intermediaries](https://proton.me/blog/what-is-authenticated-received-chain-arc); a valid ARC string is not enough to add us to this list. ARC remains implemented for Proton interoperability; the historical protocol is not presented as a guarantee of delivability.

<a id="adresse-pilote-sans-bascule-du-domaine-principal"></a>
## Pilot address without changing the main MX

A controlled subdomain can receive the trials on the gateway and route them to an existing Proton box. This allows sending from a normal account of another provider, with the signatures and SMTP IP of that provider. Keep the MX of the main domain and `observe` mode during these tests.

Example to be adapted in the private configuration:

```toml
[[domains]]
name = "example.org"
next_hops = ["mail.protonmail.ch", "mailsec.protonmail.ch"]
recipients = ["canonical@example.org"]

[[domains]]
name = "pilot.example.org"
recipients = []
[domains.aliases]
"test@pilot.example.org" = "canonical@example.org"
```

Publish an MX from the subdomain to the gateway. A host with an A/AAAA address but no MX record can also receive via the implicit MX fold from [SMTP, section 5.1](https://www.rfc-editor.org/rfc/rfc5321.html#section-5.1). Check the actual public DNS result: an existing MX, including a null MX, changes this behavior. Also check TCP/25 and STARTTLS from the outside.

The alias must directly target an address of `recipients` or an address of a domain with `accept_all_recipients = true`, possibly in another domain configured. The outgoing route and the console rights are those of that destination. The alias chains and loops remain prohibited, even between domains accepting all addresses. The domains are compared without regard to the case; the local part remains accurate. `user-add --addresses` waits for the canonical address of destination, not the address of the alias.

After `check-config` and restart, send some legitimate messages from a controlled external account to the alias. Connect to the console with the account allowed for the canonical box: entries show the received aliases, score, reasons, incomplete controls and delivery status. All aliases received in hidden copy remain limited to the account allowed for their own destination. Also confirm the arrival folder in Proton and keep the headers of the allowed examples to compare SPF, DKIM and DMARC before and after relay.

The modification is for the outgoing envelope recipient. The envelope sender and the original content are kept in observation; the gateway's internal headers are added as for an ordinary reception. An offline `.eml` scan, such as `scan` or `analyze`, does not create a delivery input in the console.

This pilot does not validate the `[SPAM]` prefix, ARC, Proton internal routing or bypass paths alone. Some legitimate tests do not measure the capture rate or false positives on a representative corpus.

<a id="comparaison-contrôlée"></a>
## Controlled comparison

For each family of messages, keep three copies and their result: direct delivery, relayed delivery without prefix, relayed delivery with prefix. Check arrival, delay, folder, object and `Authentication-Results` in Proton. SMTP `250` acceptance does not guarantee a main box arrival.

Prepare variants of a controlled test message, providing the actual IP of its SMTP sender and envelope. This command writes files and performs DNS checks; it does not send any emails and does not activate the gateway marking:

```sh
noisefence --config config/local.toml proton-prepare test.eml \
  --source-ip SENDER_IP \
  --helo SENDER_HOST \
  --mail-from TEST_SENDER \
  --output reports/probe
```

The directory receives `direct.eml`, `relay-untagged.eml`, `relay-tagged.eml` and `analysis.json`. For direct comparison, submit the original from the test sender's infrastructure in order to keep its SPF context. Submit the copies relayed from the gateway to the Proton MX. The submission tool requires TLS validated and an explicit recipient:

```sh
python3 scripts/send_probe.py reports/probe/relay-tagged.eml \
  --host mail.protonmail.ch --helo mx.example.org \
  --mail-from TEST_SENDER --recipient TEST_RECIPIENT
```

Without `--send`, no sending takes place. After checking the settings, add this flag to send exactly a message. Use only controlled recipient accounts.

| Case in the report | Verification |
|---|---|
| `dkim` | Original DKIM valid; observe difference when Subject is changed |
| `spf_only` | Legitimate message without DKIM; measure the impact of the change of IP |
| `dmarc_reject` | Test area with strict policy and identifiers aligned at origin |
| `mailing_list` | Headers and signatures of a real test list |
| `forwarded` | Pre-existing ARC chain and legitimate transfer |
| `international_subject` | UTF-8 objects encoded RFC 2047, folded, empty and prefixed |
| `bypass` | Direct delivery to MX Proton despite public gateway MXs |
| `proton_internal` | Messages from Proton likely to be routed internally |

For `bypass` and `proton_internal`, `passed` means that the actual coverage has been measured and documented. This does not mean that these paths have been blocked. Inform `bypass_limit_accepted` only after explicit acceptance of this limit by the operator. The product filters the traffic that is passing through its SMTP; it does not control the internal flows to Proton.

<a id="décision-de-bascule"></a>
## MX cutover decision

```sh
noisefence --config config/local.toml proton-report-template reports/proton-validation.json
```

The report template is voluntarily not validated. After testing, enter the Unix date, the result of each case, and a detailed reference of evidence (message identifiers, authentication results, capture location or export). Do not put any secrets in it. A report must correspond to the hostname and domains, carry on `[SPAM]` and date less than 30 days to allow booting in `tag` mode.

If the prefix degrades delivery, leave the current observation mode and MX. Proton wording via Sieve can then be studied as a behavioral change, but this project does not perform this substitution automatically.

The DNS switch remains manual: to publish only the MX of the filtering gateways, and to keep a procedure for returning to the two current Proton MXs. Adding Proton as a secondary MX during filtering would create a bypass path. After rollback, let the relay drain the already accepted messages before stopping.
