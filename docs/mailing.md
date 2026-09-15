<a id="publicités-et-newsletters-pub"></a>
# Advertising and newsletters (PUB)

NoiseFence distinguishes legitimate advertisements from spam. The visible category follows the security decision: **priority spam**, then PUB if the analysis is complete, then legitimate. Undetermined analysis does not receive a PUB category. The local `mailing-2` detector never decreases the spam score and does not add any network calls. It distinguishes scheduled service updates from newsletters and requires body offer evidence when recognizing a newsletter from list and unsubscribe headers. See [context-aware review](context-review.md).

<a id="détection-et-limites"></a>
## Detection and limitations

The `List-Unsubscribe`, `List-ID` and `Precedence: bulk/list` headers, or a statement of unsubscribe in the body, indicate a collective distribution. These linked indices count as a single family. An advertisement also requires several indices of commercial content: offers/remises, call for purchase, promotional code or delivery offered. A newsletter requires a broadcast index and information letter content. The administrator may exclude editorial newsletters.

Invoice, receipt, order, login code, security alert, calendar, automatic response or conversation are not enough for the PUB category. Correspondence is a FR/EN heuristic with some other language terms; it does not prove a subscription or the safety of a message. A fraudster can imitate them, but security ranking remains a priority. No PUB capture rates or false positives have yet been measured on a recent independent population.

The treatment is based on the original MIME decoded. Limitations: no more than 2 MiB (or the bounded analysis), 200 parts, 20 text and 20 HTML; any truncation of 32,000 text characters or 500 object characters makes categorization limited. Ambiguous or excessive list headers have the same effect. In these cases, no PUB classification or prefix is applied. The report contains only predefined reasons, Boolean indicators, version and duration.

The observed syntaxes are documented in [RFC 2919](https://www.rfc-editor.org/rfc/rfc2919), [RFC 8058](https://www.rfc-editor.org/rfc/rfc8058) and [RFC 3834](https://www.rfc-editor.org/rfc/rfc3834). The presence of the unsubscribe syntax in one click does not constitute a validation of its DKIM coverage. NoiseFence does not open any links and does not trigger any unsubscribe.

## Configuration

Install the module in the server file, at the root level:

```toml
[mailing]
# Required only for the prefix, with global mode tag:
# proton_report = "/etc/noisefence/proton-validation-pub.json"

[mailing.policy]
include_newsletters = true
tag_subject = true
```

After restarting, activate **Filters → Ads and newsletters** in the console and apply the modification if an existing revision still disables the module. The parameters are global; the consultation and corrections follow permissions by recipient and domain, including hidden copies.

In global mode `observe`, the new PUB messages appear in history and statistics, without changing the object on delivery. In `tag` mode, `tag_subject=true` adds `[PUB]` only after validation of the Proton-specific prefix and ARC configuration. A `[SPAM]` ratio does not replace a `[PUB]` ratio: you must repeat the same delivery cases with this exact prefix, the current domains and host name, for less than 30 days. `tag_subject` can be turned off to keep the PUB ranking without its prefix. Never make a report to bypass this validation.

Marking retains the byte body for byte, processes RFC 2047 objects, avoids repeated prefixes and replaces an old prefix managed when the decision requires it. Incoming `X-NoiseFence-*` results are removed; the local result `X-NoiseFence-Category` is covered by ARC. Editing the object may invalidate DKIM; ARC does not guarantee acceptance by Proton. An error in analysis or sealing transmits the message without new prefixes.

## Console, API and feedback

- History: **PUB** filter, dedicated meter, distinction between detected PUB and `[PUB]` actually added; the score displayed remains the spam score.
- Detail: reasons for category and corrections **Legislative**, **Spam**, **PUB**.
- API: `GET /api/v1/messages?filter=publicity` and `publicity` field statistics. `POST /api/v1/messages/{id}/feedback` accepts `{"category":"publicity"}` (or `spam` / `legitimate`). The old `{"spam":false}` body remains accepted.
- The corrections do not alter the historical decision or message in Proton. PUB means non-spam for existing binary drive. Exports add the explicit category and the PUB report to prepare a dedicated calibration. The PUB rule detector is not automatically re-entered by these corrections.
- Contradictory PUB/legitimate opinions retain the binary label non-spam but rule out the subtype. An old non-spam vote does not automatically become a "non-advertising" label. An old customer who updates his vote invalidates his former explicit category.

The existing history is not reanalyzed: already deleted bodies are no longer available. New metadata follows the 30 day retention. SQLite migration is additive; it keeps messages, queues and votes.

<a id="vérification-locale"></a>
## Local verification

`cargo test --test mailing --test authentication --test gates --test console --test learning` covers concordant and isolated indices, exclusions, MIME/UTF-8, the ideal prefix, the unchanged body, ARC and its falsification, spam priority, limits, authorizations and compatible exports. MIME fuzzing includes the detector and PUB prefix. These software tests do not constitute a quality measurement on real messages or a Proton delivery validation.

To prepare the delivery tests, `proton-report-template rapport-pub.json --category publicity` creates a blank `[PUB]` report, with all unvalidated tests. `proton-prepare` also accepts `--category publicity`: the test file must be a recognized and unclassified spam ad/newsletter, with complete checks and ARC. It only produces local files; it does not enable the marking and does not send any email. See the other parameters and the trial matrix in [Proton procedure](proton-validation.md).
