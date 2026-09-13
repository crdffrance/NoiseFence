<a id="recherche-dans-les-messages"></a>
# Search Messages

In **Messages**, enter words or open **Advanced search**. Search covers retained subjects, envelope senders, authorized addresses and aliases, NoiseFence identifiers and rule IDs in `scan.reasons`. Examples: `invoice sept`, `"team meeting"`, an address or `suspicious_link`. All terms are required. Indexed words support prefixes and ignore case/accents; quotes require an exact phrase. Addresses and identifiers also support fragments. `*`, `%`, `OR` and `NOT` do not enable SQL or an unrestricted query language.

The advanced criteria are combined with each other and with the classification and the field:

- sender, consignee/alias, object, rule and ID NoiseFence;
- visible delivery status (delivery, waiting, quarantine, failure, etc.);
- reception dates, with end day included in the browser zone;
- minimum and maximum score, corresponding to the number displayed by the console.

A partial or indicative score remains searchable without becoming a spam verdict. An absent value does not become zero. A recipient and a delivery state provided together must correspond to the same authorized delivery.

The results are sorted from the most recent to the oldest, by pages of 50. The total corresponds to all the criteria and current user rights. It is read in the same SQLite snapshot as the page. The arrival of new messages between two pages can shift the pagination; no search list is frozen.

<a id="conservation-et-confidentialité"></a>
## Retention and confidentiality

The search covers the 30 days stored metadata and messages whose file is still kept for file/quarantine resolution. Bodies, attachments, OCR texts, link contents and LLM reasoning are not indexed. Bodies already deleted after delivery cannot be searched. No request or content is sent to an external service.

Recipients are never placed in the common index: their search is through the authorizations in effect in `console_access`, including for the admin account and access to a domain. An unauthorized hidden copy does not produce results or totals. The selected domain also limits the returned recipients. The interface does not record searches in the browser's persistent storage; as with the old GET API, the parameters can be included in the proxy access logs. Protect and limit these logs.

## API

`GET /api/v1/search/messages` requires an authenticated session. Optional parameters: `q`, `filter` (default `all`), `domain`, `node`, `offset`, `sender`, `recipient`, `subject`, `rule`, `id`, `status`, `after`, `before`, `min_score`, `max_score`. `after` is an inclusive Unix timestamp and `before` is exclusive. Scores use the selected 0–100 assessment value, including partial scores. Response:

```json
{"messages": [], "total": 0, "offset": 0, "has_more": false}
```

The old `/api/v1/messages` route keeps its answer in table form and uses the same engine. Invalid queries receive HTTP 400. Free search is limited to 600 bytes, 12 terms of 200 bytes, fields at 256 bytes. Plays use up to four concurrent WAL snapshots, with SQLite interruption after three seconds. Saturation returns a service error, never an empty list presented as a successful result.

<a id="index-et-mise-à-niveau"></a>
## Index and upgrade

At the first start, a transactional migration adds an index [SQLite FTS5](https://www.sqlite.org/fts5.html), its source view and three triggers. It indexes history without rewriting analyses or delivery records. The object is limited to 4096 characters, the sender to 1024 and the list of rules to
16384. The insertions, modifications and deletions remain synchronized in the original transaction; a failure in indexing does not confirm an unpersistent SMTP acceptance.

The search index is additive. Current HA storage requires schema 5; older index-only compatibility does not authorize a downgrade. Its secure erasure FTS5 requires SQLite 3.42 or more recent for tools handling this index. Do not open or modify FTS5 tables with an old SQLite tool. Save the database consistently before upgrading; the index increases storage and its first filling depends on the size of the history. The triggers also remove inputs and old chips when purging metadata. The WAL and backups follow their own storage cycle.
