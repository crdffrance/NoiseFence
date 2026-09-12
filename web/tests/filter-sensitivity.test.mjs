import assert from 'node:assert/strict';
import test from 'node:test';
import { scopedProfile, setScopeThreshold, levelValue } from '../app/filter-sensitivity.ts';

const actions = { spam: 'quarantine', publicity: 'tag', malware: 'quarantine', quarantine_days: 12 };
const id = () => 'unique';
test('changing sensitivity preserves delivery actions and uses existing revision fields', () => {
  const p = setScopeThreshold(null, '*', 90, actions, id);
  const profile = scopedProfile(p, '*');
  assert.deepEqual(profile, { id: 'unique', name: 'Organisation', threshold: 90, require_corroboration: true, spam: 'quarantine', publicity: 'tag', review: 'deliver', quarantine_days: 12 });
  assert.equal(setScopeThreshold(null, '*', null, actions), null);
  assert.deepEqual(Object.keys(p).sort(), ['bindings', 'profiles', 'rules']);
  const inherited = setScopeThreshold(p, '*', null, actions);
  assert.equal(scopedProfile(inherited, '*').threshold, null);
  assert.equal(scopedProfile(inherited, '*').spam, 'quarantine');
  assert.equal(scopedProfile(p, '*').threshold, 90);
});
test('domain overrides copy shared profiles without changing other domains, recipients or rules', () => {
  const p = setScopeThreshold(null, '*', 98, actions, id);
  p.bindings.push({ scope: '*@example.test', profile: 'unique' }, { scope: 'alice@example.test', profile: 'unique' });
  p.rules.push({ id: 'keep' });
  const changed = setScopeThreshold(p, '*@example.test', 85, actions, () => 'domain');
  assert.equal(scopedProfile(changed, '*@example.test').threshold, 85);
  assert.equal(scopedProfile(changed, '*').threshold, 98);
  assert.equal(scopedProfile(changed, 'alice@example.test').threshold, 98);
  assert.equal(scopedProfile(p, '*@example.test').threshold, 98);
  assert.equal(changed.rules, p.rules);
  assert.equal(changed.profiles.length, 2);
});
test('new domain profiles inherit existing actions and custom values are preserved', () => {
  const p = setScopeThreshold(null, '*', 98, actions, id);
  p.profiles[0].review = 'quarantine';
  const changed = setScopeThreshold(p, '*@example.test', 97.3, actions, () => 'domain');
  assert.equal(scopedProfile(changed, '*@example.test').review, 'quarantine');
  assert.equal(scopedProfile(changed, '*@example.test').threshold, 97.3);
  assert.equal(levelValue(97.3, [{ id: 'lenient', threshold: 98 }]), 'custom');
  assert.equal(levelValue(null, []), 'inherit');
  assert.equal(levelValue(98, [{ id: 'lenient', threshold: 98 }]), 'lenient');
});
test('profile quotas, invalid values and names are bounded before saving', () => {
  for (const t of [0, 49.9, 100.1, NaN, Infinity]) assert.throws(() => setScopeThreshold(null, '*', t, actions));
  const p = { profiles: Array.from({length: 32}, (_, i) => ({ id: `${i}` })), bindings: [], rules: [] };
  assert.throws(() => setScopeThreshold(p, '*', 95, actions));
  assert.equal(scopedProfile(setScopeThreshold(null, `*@${'a'.repeat(200)}`, 95, actions, id), `*@${'a'.repeat(200)}`).name.length, 100);
});
