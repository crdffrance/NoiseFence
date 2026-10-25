"""Prioritize native filter regressions from recorded, independent second opinions.

Symbols are associations for investigation, never learned labels or new weights.
No network, training, policy changes, message text, or recipient identifiers.
"""
from collections import Counter, defaultdict
import math
from recorded_decisions import engine_outcome


def diagnose(rows):
    from compare_quality import rspamd_outcome
    statuses, pairs, actions = Counter(), Counter(), Counter()
    cohorts, symbols = defaultdict(Counter), defaultdict(Counter)
    errors = Counter()
    for row in rows:
        report = row.get('rspamd') or {}
        status = report.get('status') or 'missing'
        statuses[status] += 1
        native, other = engine_outcome(row), rspamd_outcome(row)
        pairs[native, other] += 1
        if status != 'complete':
            continue  # Stale symbols on a failed report are not observations.
        actions[report.get('action') or 'missing'] += 1
        quality = row.get('quality') or {}
        cohort = (quality.get('artifacts_sha256') or 'missing',
                  report.get('settings_sha256') or 'missing')
        bucket = cohorts[cohort]
        bucket['messages'] += 1
        bucket['nonfinal'] += native == 'review' or other == 'review'
        bucket['disagreements'] += native != other and 'review' not in (native, other)
        risk = row.get('risk')
        label = risk if risk in ('legitimate', 'spam') else 'unlabelled'
        bucket[label] += 1
        # Recipient-confirmed preference is the reference, including wanted PUB.
        native_fp = label == 'legitimate' and native == 'spam'
        native_fn = label == 'spam' and native == 'legitimate'
        other_fp = label == 'legitimate' and other == 'spam'
        other_fn = label == 'spam' and other == 'legitimate'
        for key, value in [('native_false_positive', native_fp),
                           ('native_missed_spam', native_fn),
                           ('rspamd_false_positive', other_fp),
                           ('rspamd_missed_spam', other_fn)]:
            bucket[key] += value
            errors[key] += value
        seen = set()
        for symbol in report.get('symbols') or []:
            name, score = symbol.get('name'), symbol.get('score')
            if (not isinstance(name, str) or not name or name in seen
                    or type(score) not in (int, float) or not math.isfinite(score)):
                continue
            seen.add(name)
            target = symbols[cohort + (name,)]
            target['messages'] += 1
            target[label] += 1
            target['positive' if score > 0 else 'negative' if score < 0 else 'zero'] += 1
            target['native_false_positive'] += native_fp
            target['native_missed_spam'] += native_fn
            target['rspamd_false_positive'] += other_fp
            target['rspamd_missed_spam'] += other_fn
    return {
        'schema': 'noisefence-rspamd-diagnostics-1',
        'availability': dict(sorted(statuses.items())),
        'actions': dict(sorted(actions.items())),
        'pairs': [{'native': a, 'rspamd': b, 'messages': n}
                  for (a, b), n in sorted(pairs.items())],
        'confirmed_errors': dict(sorted(errors.items())),
        'cohorts': [dict(native_artifacts_sha256=a, rspamd_settings_sha256=b, **counts)
                    for (a, b), counts in sorted(cohorts.items())],
        'symbol_slices': [dict(native_artifacts_sha256=a, rspamd_settings_sha256=b,
                              symbol=s, **counts)
                          for (a, b, s), counts in sorted(symbols.items())],
        'independent_validation': False,
        'may_activate': False,
        'limitations': [
            'Human labels are the reference. Unlabelled disagreements are candidates, not errors.',
            'Greylist, custom actions and missing results remain nonfinal, even with a high score.',
            'Symbol presence is an association, not causal benefit or a learned weight.',
            'Native and Rspamd scores use different scales; their points are never combined.',
            'Slices are receipt-time observations by native and Rspamd artifact cohort.',
            'Rows can repeat campaigns; use the paired campaign report before interpreting rates.',
            'No content, labels, models, thresholds or delivery policies are changed.',
        ],
    }
