<a id="limiter-les-classements-spam-insuffisamment-étayés"></a>
# Corroboration and review decisions

The `filter.require_corroboration = true` option, also available in console settings, adds abstention to the historical score. When this score exceeds the threshold but has no confirmation below, the decision becomes **Needs review** (`undetermined`). The message is transmitted without prefix. Its score, characteristics and analysis status remain retained. This is neither proof of legitimacy nor a PUB category.

The confirmations taken into account by `confirmation-3` are:

- malware detection by the main antivirus;
- a verified DMARC failure on both alignment possibilities;
- a verified DQS response indicating an unfavourable reputation for an IP (ZEN 2, 3, 4, 9) or a domain (DBL 2, 4, 5, 6).

Unavailable responses, error codes, IP policy lists (PBL), legitimate compromised domains, SPF alone, SMTP inconsistencies, Advisory signatures and HTML/OCR indices are not enough. Lexical and semantic are already the content score: they are not counted as two confirmations. Since 0.4.8, the LLM remains a limited contributor to the content score and no longer constitutes an independent confirmation, even with high confidence declared. A SPF/DKIM/DMARC success does not exempt controls: malicious messages can be properly authenticated. Message headers cannot provide these internal results.

Sources can be correlated. The numbers reported by LLM are not validated probabilities. This caution rule **can reduce the recall**, especially for spams recognized only by the model. Measure the spams placed "Needs review", as well as the false positives, before enabling the marking. The false positives counter must be accompanied by the abstentions: move an error to "Needs review" does not amount to properly classifying this message.

The fusion learned, when activated with its own validation report, retains its confirmation policy. The [antivirus priority](filter-policy.md) applies after the fusion as well as after the historical score. An incomplete analysis remains incomplete. No additional control or network call is triggered by this option, which does not change the thresholds or weights of the loaded model. Its status and version are part of the policy footprint; the fusion artifacts must match.

The old files and revisions keep the default `false` value. The production configuration model offers `true`. The administrator can explicitly activate with a new revision. Historical decisions and already delivered messages are not rewritten. The **Needs review** filter selects new complete analyses whose decision is not known; **Incomplete analysis** retains its operational meaning.

The LLM prompt `noisefence-classify-4` specifies that brevity, free providers, forwarding and service notifications are not spam proofs. It also distinguishes reported threats from attacks and ordinary shipment timing from coercive requests. A forwarding prefix does not guarantee content safety. See [context-aware review](context-review.md). These instructions alone do not establish a measured quality gain.

<a id="vérification"></a>
## Verification

`cargo test --test confirmation --test console` covers decisions without confirmation, weak/strong reviews, malware, unavailable controls, reputation, SPF/DMARC, falsified headers, retained body, filters and rights per recipient. Fixtures are synthetic and do not publish any production message. Actual corrections must remain private and be evaluated without changing the labels or the weights on the lot used to measure the result.

`noisefence audit-confirmation /var/lib/noisefence/state.sqlite3` compares historical decisions to this rule by re-using recorded observations. It opens SQLite read-only, does not access bodies, loads no models and makes no external calls. The output contains only meters, including omissions on legitimate and spam. The rights of the annotators, their deactivation, conflicts and 30-day retention are verified. Decisions that are absent, incomplete or resulting from a fusion model are counted separately. A set of corrections is biased; this balance does not measure the rate of false positives on all traffic. It does not replay the new prompt LLM. Since dev.21, `with_decision_policy` also measures the effect of the antivirus priority on these same observations, without re-calculating the score or DQS searches.

The distinction of DQS codes follows the [Table of Spamhaus Zones](https://docs.spamhaus.com/datasets/docs/source/10-data-type-documentation/datasets/040-zones.html).
