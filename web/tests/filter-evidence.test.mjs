import assert from 'node:assert/strict';
import test from 'node:test';
import { evidenceRows, matchesEvidence, detectorGroups } from '../app/filter-evidence.ts';

const reason = (id, weight, detail = 'Recorded evidence') => ({ id, weight, detail });
test('searching never promotes a duplicate or an excluded proposed weight', () => {
  const rows = evidenceRows([reason('spf_fail', 3), reason('repeat', 2, 'first'), reason('repeat', 2, 'second')], {
    contributions: [{ id: 'spf_fail', retained: 0 }, { id: 'repeat', retained: 2 }],
  });
  assert.deepEqual(rows.map(r => r.effect), ['other', 'raises', 'other']);
  const filtered = rows.filter(r => matchesEvidence(r, 'second', 'all'));
  assert.equal(filtered[0].value, 0);
  assert.equal(filtered[0].duplicate, true);
  assert.equal(rows.filter(r => matchesEvidence(r, 'spf', 'raises')).length, 0);
  assert.equal(matchesEvidence(rows[0], 'authentication failed', 'all'), true);
});
test('missing weights, model summaries and antivirus priority are not additive votes', () => {
  const rows = evidenceRows([reason('unknown', 4), reason('model_contribution', 10), reason('malware_priority', 100), reason('context', -2)], { contributions: [{ id: 'context', retained: -2 }] });
  assert.deepEqual(rows.map(r => r.effect), ['other', 'other', 'other', 'lowers']);
  assert.equal(rows[0].value, null);
  assert.equal(evidenceRows([reason('invalid', NaN)])[0].value, null);
  assert.equal(matchesEvidence(rows[3], '  CONTEXT ', 'lowers'), true);
});
const observation = (id, state, extra = {}) => ({ id, state, family: 'authentication', role: 'decision_input', exclusion: null, ...extra });
test('coverage separates absent checks, exclusions and comparison-only observations', () => {
  const report = { version: 3, observations: [observation('spf', 'complete'), observation('dkim', 'unavailable'), observation('native', 'complete', { role: 'comparison', family: 'content' }), observation('llm', 'disabled', { family: 'content' }), observation('crdf.0', 'complete', { family: 'url_threat', exclusion: 'stale_result' })] };
  const groups = detectorGroups(report);
  assert.equal(groups[0].state, 'Limited');
  assert.equal(groups[0].limited, 1);
  assert.equal(groups[1].state, 'Inactive');
  assert.equal(groups[1].observations.length, 1);
  assert.equal(groups[2].excluded, 1);
  assert.equal(groups[2].state, 'Complete'); // Completed lookup does not mean usable evidence or safety.
  assert.equal(report.observations.length, 5);
  assert.deepEqual(detectorGroups(null), []);
  assert.deepEqual(detectorGroups({ ...report, version: 99 }), []);
});
test('unknown states remain limited and untrusted family names are not promoted to labels', () => {
  const [group] = detectorGroups({ version: 3, observations: [observation('x', 'new_state', { family: '<script>unsafe</script>' })] });
  assert.equal(group.state, 'Limited');
  assert.equal(group.label, 'Other checks');
});
