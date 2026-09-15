<a id="analyse-facultative-avec-scaleway"></a>
# Optional analysis with Scaleway

The Rust client is implemented, tested against a local HTTPS server and confronted with the real Scaleway API. Synthetic tests have confirmed access in the dedicated project and an HTTP 403 refusal in another project. No account, project ID deployed or production key is integrated into the repository.

The actual response contains `tool_calls: []` in the absence of a tool call. This form is accepted from 0.2-dev.2, as well as an absent or null field. A non-empty list, another type or a non-zero `function_call` remains refused. These tests validate the integration, not a detection rate on a real corpus.

## Isolation and activation

With `scw`, create a `noisefence-llm` project in the authorized organization, then a dedicated IAM application. Add a policy associated only with this application with `GenerativeApisModelAccess` and `rules.0.project-ids.0` equal to the new project. Do not replace this scope with `rules.0.organization-id`. Also check policies inherited by all applications: another attribution can expand the actual rights. Serverless APIs do not require permanent GPUs.

Examples of creation commands, with already verified identifiers:

```sh
scw account project create organization-id="$NF_ORG_ID" name=noisefence-llm
scw iam application create organization-id="$NF_ORG_ID" name=noisefence-llm
scw iam policy create organization-id="$NF_ORG_ID" name=noisefence-model-access \
  application-id="$NF_APP_ID" rules.0.project-ids.0="$NF_PROJECT_ID" \
  rules.0.permission-set-names.0=GenerativeApisModelAccess
```

Then create a key for this application and record its response directly in a private file, without printing the secret in the terminal or logs. The key must expire and be renewed before this deadline. Test with it the access to the model of the new project and the refusal of access to another project before activation. Keep the identifiers of the resources created for audits and revocation.

On the server, place the secret in `NOISEFENCE_SCALEWAY_API_KEY` of the `/etc/noisefence/secrets.env` file, belonging to root, mode 0600. The organization's administration key should not be used by NoiseFence. Inform the `[llm]` section of the TOML model with the isolated project ID, model, verified prices and an explicit budget. With `monthly_budget_micro_eur = 0`, no calls are made.

The client uses the HTTPS endpoint `https://api.scaleway.ai/PROJECT_ID/v1/chat/completions` exclusively, checks the certificate and refuses redirections. Start with authorised synthetic messages, check the JSON schema, the accounting and the deadlines, and then observe ambiguous messages.

<a id="données-et-décision"></a>
## Data and decision

The request contains the subject, the sender domain, the number of attachments and an extract of text/HTML made limited to 12,000 bytes by default. To/Bcc fields, the sender's full address, the attachment names and their binary content are not serialized. The text of the message may nevertheless contain personal data: this is not an anonymization. The activation therefore allows an external processing of text extracts, different from the entirely local mode.

The model receives a classification instruction and no tools. Only a closed JSON containing category, estimate, confidence and short reason is accepted. Additional fields, actions, tool calls, truncated outputs and too large responses are refused. The confidence declared by the model is not a calibrated measure.

The prefixes of previous filters (`[SPAM]`, `[JUNK]`, `[PHISHING]`, `[BULK]`) at the beginning of the subject are removed from the extract, as for the local model. The subject delivered and the citations in the body remain intact. These tags do not constitute proof of spam.

The verdict is an advisory second opinion. Its configured contribution and disagreement arbitration do not turn model confidence into a calibrated probability. It does not order any delivery, deletion, quarantine or configuration changes. Incomplete or already detected malicious messages are not submitted to the LLM. A failure, an exceeded deadline or an invalid response makes the analysis incomplete and prevents the prefix. A budget reached or an expired rate lets local engines work.

<a id="budget-et-rapidité"></a>
## Budget and speed

The price of the example corresponds, on 6 September 2026, to 0.15 €/million input tokens and 0.35 €/million output tokens for `mistral-small-3.2-24b-instruct-2506`. Check them again on the [Scaleway tariff page](https://www.scaleway.com/en/pricing/model-as-a-service/). The configuration amounts are expressed in micro-euros: 20 000 000 = 20 €. Calls stop if the price verification date exceeds 30 days.

A durable SQLite booking precedes each call. Concurrent calls and restarts keep this local ceiling; a response whose billing is uncertain keeps its reservation maximum. A valid response adjusts the amount according to the declared usage. The client does not automatically restart HTTP requests. This estimated limit does not replace the provider's billing alerts. The `/api/v1/metrics` admin API displays reservations, requests and ceiling.

By default at most two LLM calls run concurrently within the configured score interval. `review_unconfirmed_high = true` additionally selects scores above `score_high` that lack corroboration under `confirmation-3`; a high score alone should not prevent a second opinion from finding a false positive. This option is disabled by default and can increase transmitted excerpts, within the same budget, concurrency and timeout limits. Malware evidence and incomplete local extraction remain excluded. `scan.llm.selection` records selection even when budget or cancellation prevents completion; old records may omit it. Selection alone never lowers a score. Advisory weights are unchanged. To select all eligible messages, configure the complete score range in the Web console and authorize the corresponding text disclosure.

The 2.5 seconds LLM delay is one of five seconds shared with the DNS checks. Measure the overall p95 with this option: an LLM does not guarantee the 500 ms target. The price per message and the proportion submitted to the LLM must be included in the quality comparisons.

References: [Generative APIs](https://www.scaleway.com/en/docs/generative-apis/api-cli/using-generative-apis/), [structured outputs](https://www.scaleway.com/en/docs/generative-apis/how-to/use-structured-outputs), [IAM policies](https://www.scaleway.com/en/docs/iam/reference-content/policy/).

New explanations use English with prompt version `noisefence-classify-4`. The prompt distinguishes reported threats from attacks and adds bounded, locally derived link-domain relationships. See [context-aware review](context-review.md). Existing stored explanations are not rewritten. The prompt digest changes the observation group used for evaluation; do not mix groups or reuse an earlier validation automatically.
