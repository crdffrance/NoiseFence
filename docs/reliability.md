<a id="fiabilité-du-filtre"></a>
# Reliability of the filter

Since 0.5.0, the page **Reliability** completes the annotation with hidden scores in **Quality of the filter**. It does not write any setting and does not activate any model.

<a id="lire-le-bilan"></a>
## Read the report

The windows cover 1 to 29 days, up to 5,000 recent accessible messages, 32 MiB of diagnostics and two seconds of calculation. Lines of more than 512 KiB or illegible are indicated. SQLite limits and the competition of readings remain those of the console. A partial balance does not calculate a distribution change alert. The same message with several authorized recipients counts once. Only the current account annotations are used; the rights to the recipients are reverified at each request.

- **Quality annotations**: explicit risk corrections, including those stored in batches. **Target corrections**: historical returns out of these annotations, often focused on errors.
- Uncertain answers never become legitimate. Abstention on a spam reduces the recall; an abstention is not a false positive marking.
- Reminder, false positives, precision and forbearance relate to the annotations available. The 95% Wilson intervals do not correct the selection bias or the dependence between campaigns. Without annotations, the result is unavailable. Zero error on ten messages does not show 0.1% false positives.
- Variations compare the last 24 hours to the rest of the period: at least 30 observations in each group, increase by at least 15 points and separate intervals. These are descriptive alerts to be examined, not statistical evidence of regression, nor an automatic deactivation mechanism.
- Quotas, limits and unavailability remain distinct from a lack of detection. Availability alerts require at least three incidents out of 10% of the configured controls observed in the last 24 hours.

The p95 latency is the one recorded by the analysis route, with its external checks. It does not measure the total SMTP delay or the warm cache benchmark.

<a id="mesurer-lapport-des-règles"></a>
## Measuring the contribution of rules

The table retains occurrences, annotations, groupings and co-occurrences. For complete historical observations whose score can be reconstructed and the policy of decision replayed, the withdrawal of a weight recalculates the decision. It counts the false positives avoided and the detected spams that would be lost.

This removal removes **the weight only**: antivirus, evidence, corroboration and LLM notice remain frozen. It does not simulate new calls, actions per recipient or Proton folder. Native symbols remain advisory; no fictitious effect on delivery is attributed to them.

Candidate comparisons use only the recorded predictions and the same annotated messages. The selection of the cases covered should be examined in the independent evaluation described in [the quality protocol](quality.md).

<a id="stabiliser-la-collecte-et-entraîner"></a>
## Stabilize collection and train

Compatibility links all Rust and SQL sources, protocols and runtime auxiliaries, locked dependencies, compiler, target, compilation options, models and parameters. Only the version of our own package is normalized in the manifests; the published version and the raw lock remain as source. The existing `application` field carries the version and the fingerprint in the `-nf1.…` suffix, without adding any field to the strict format read by the old binary. HTTP verification agents have their own protocol version, independent of the software version.

A modification of the engine, model, compilation system or parameters creates a new group. The old records without compatibility imprint remain strictly separate. An update of the frontend alone or version number can preserve the group, with motor, compilation and identical parameters. This mechanism does not pretend to freeze external reputational bases or their responses.

1. Keep collection and parameters stable. Use the start of collection of the current engine proposed in the console. The draw includes incomplete analyses and is never based on the score.
2. Annotate the originals, then export a private lot with `quality-export`. Keep the old lots; do not recalculate their signals from the only objects.
3. Run `train_quality.py` using the [quality procedure](quality.md). Native content, campaign and Bayes contributions are additional inputs with availability states. Bayes logits are bounded and are not calibrated probabilities. Historical lexical weights are not counted twice.
4. The candidate compares eleven ablations, of which no native motor and no native Bayes. If annotations or campaigns are missing in the five periods, no model is produced. A mixing sample of groups is refused: choose a homogeneous period, keep the exclusions and their scope in the report.
5. Freeze the model, thresholds and manifest. Draw a new batch, independent of previous learning campaigns and tests. Run `evaluate_quality.py`. Measure coverage, forbearance, calibration, recall, errors and intervals.
6. Do not activate a candidate solely on the basis of agreement with the existing filter or a handful of corrections. Targets ≥95% / ≤0.1% remain to be demonstrated.

Local report orders (no content exported or policy changes):

```sh
noisefence --config /etc/noisefence/config.toml reliability-audit \
  --username "$ANNOTATOR" --days 7 --domain example.org
noisefence --config /etc/noisefence/config.toml proton-check
```

`GET /api/v1/quality/reliability?days=7&domain=example.org` requires a session. Users only see their scope. Proton system controls and reports are reserved for administrators. No key or gross supplier response is included in the report.

## Signatures and Proton

The administration questions ClamD with `zVERSION`, without sending a message: two competing local queries at the maximum, 500 ms delay, response of 512 bytes maximum. An unrecognized date or an unavailable command give an unknown state. L-absence of a spindle in the date imposes an uncertainty of ±14 h. The freshness is compared to three days; it does not certify the exact set of loaded signatures. See the [official ClamD protocol](https://docs.clamav.net/manual/Usage/ClamdProtocol.html).

SPAM and PUB checklists control existing reports: prefix, domains, host, date, eight documented cases and accepted bypass limit. SMTP acceptance alone does not prove arrival in receipt. Follow the [proton-validation.md matrix](proton-validation.md), with direct arrival, intact relays, marked relays, record folder and final headers. The observation mode remains necessary as long as this validation is missing.

## Migration 0.4.x → 0.5.0

The new observation protocol adds native entries. The native content protocol moves to `noisefence-native-content-2` to exclude inert HTML examples. The old joint candidate models, OSB models and fusion artifacts are incompatible: remove their optional paths before `check-config`, then collect and train new candidates. The historical lexical/semantic model retains its format and behavior. Explicitly check any installation using a decision-based merge before updating.

This feature’s original migration was additive. Current paired installations require storage schema 5 and a compatible release. Do not downgrade the database, remove its HA marker or restore an older backup over accepted mail. See [installation](installation.md) and [HA recovery](high-availability.md) for current upgrade and rollback procedures.